//! Host-initiated, device-code enrollment with an Ultramarine Dashboard.

use std::{env, io::Write, process::Command, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::agent::{crypto::public_key_fingerprint, identity::HostIdentity};

#[derive(Debug, Clone)]
pub struct Options {
    pub dashboard_url: Option<String>,
    pub agent_url: Option<String>,
    pub listen: Option<String>,
    pub display_name: Option<String>,
    pub approval_file: Option<std::path::PathBuf>,
    pub verification_url: Option<String>,
    pub identity_dir: String,
    pub config_dir: String,
    pub hostname: Option<String>,
    pub insecure: bool,
    pub skip_service: bool,
}

#[derive(Debug, Serialize)]
struct CreateRequest<'a> {
    display_name: &'a str,
    hostname: &'a str,
    agent_url: &'a str,
    host_public_key: &'a str,
    tls_ca_certificate: &'a str,
}

#[derive(Debug, Deserialize)]
struct CreateResponse {
    device_code: String,
    user_code: String,
    #[serde(rename = "verification_uri")]
    _verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    status: String,
    controller_public_key: Option<String>,
}

#[allow(clippy::too_many_lines)]
pub async fn run(mut options: Options) -> Result<()> {
    let dashboard_url = options
        .dashboard_url
        .take()
        .unwrap_or_else(|| prompt("Dashboard URL", "http://127.0.0.1:3000"));
    let dashboard_url = dashboard_url.trim().trim_end_matches('/').to_owned();
    ensure!(!dashboard_url.is_empty(), "Dashboard URL cannot be empty");
    let verification_url = options
        .verification_url
        .take()
        .unwrap_or_else(|| dashboard_url.clone());

    let hostname = options
        .hostname
        .take()
        .unwrap_or_else(|| env::var("HOSTNAME").unwrap_or_else(|_| "tetra-host".into()));
    let display_name = options
        .display_name
        .take()
        .unwrap_or_else(|| prompt("Host display name", &hostname));
    let agent_url = options
        .agent_url
        .take()
        .unwrap_or_else(|| prompt("Tetra WebSocket URL", &format!("wss://{hostname}:7780")));
    let listen = options
        .listen
        .take()
        .unwrap_or_else(|| prompt("Tetra listener address", "0.0.0.0:7780"));
    ensure!(
        listen.parse::<std::net::SocketAddr>().is_ok(),
        "listener address must be in HOST:PORT format"
    );
    ensure!(
        agent_url.starts_with("ws://") || agent_url.starts_with("wss://"),
        "agent URL must use ws:// or wss://"
    );
    if agent_url.starts_with("ws://") && !options.insecure {
        bail!("agent URL uses plaintext ws://; pass --insecure only for local development");
    }

    let identity = HostIdentity::load_or_generate(&options.identity_dir)?;
    let host_public_key = URL_SAFE_NO_PAD.encode(identity.verifying_key().as_bytes());
    let fingerprint = public_key_fingerprint(&identity.verifying_key());
    let (tls_key, tls_cert) = generate_tls_material(&options.config_dir, &hostname)?;

    println!("Host identity: {}", identity.path().display());
    println!("Host fingerprint: {fingerprint}");
    println!("TLS certificate: {}", tls_cert.display());

    let ca_certificate = std::fs::read_to_string(&tls_cert).with_context(|| {
        format!(
            "failed to read generated certificate `{}`",
            tls_cert.display()
        )
    })?;
    let client = Client::builder()
        .danger_accept_invalid_certs(options.insecure)
        .build()
        .context("failed to create Dashboard HTTP client")?;
    let response = client
        .post(format!("{dashboard_url}/api/tetra/device"))
        .json(&CreateRequest {
            display_name: &display_name,
            hostname: &hostname,
            agent_url: &agent_url,
            host_public_key: &host_public_key,
            tls_ca_certificate: &ca_certificate,
        })
        .send()
        .await
        .context("failed to create Dashboard enrollment request")?;
    let response = check_response(response).await?;
    let device: CreateResponse = response
        .json()
        .await
        .context("invalid Dashboard enrollment response")?;
    if let Some(path) = &options.approval_file {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "verification_uri": format!("{}/tetra/device", verification_url.trim_end_matches('/')),
                "user_code": device.user_code,
                "expires_in": device.expires_in
            }))?,
        )?;
    }

    println!();
    println!(
        "Open {}/tetra/device?code={}",
        verification_url.trim_end_matches('/'),
        device.user_code
    );
    println!("Enter enrollment code: {}", device.user_code);
    println!("Waiting for Dashboard approval...");

    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(device.expires_in))
        .context("enrollment expiry is outside the supported time range")?;
    loop {
        let response = client
            .put(format!("{dashboard_url}/api/tetra/device"))
            .json(&serde_json::json!({ "device_code": device.device_code }))
            .send()
            .await
            .context("failed to poll Dashboard enrollment")?;
        let status: PollResponse = check_response(response).await?.json().await?;
        match status.status.as_str() {
            "authorization_pending" => {
                if std::time::Instant::now() >= deadline {
                    bail!("Dashboard enrollment expired");
                }
                sleep(Duration::from_secs(device.interval.max(1))).await;
            }
            "approved" => {
                let controller_key = status
                    .controller_public_key
                    .context("Dashboard approval did not include a controller public key")?;
                identity.enroll_controller_key(&controller_key)?;
                write_enrollment_config(
                    &options.config_dir,
                    &agent_url,
                    &tls_cert,
                    &tls_key,
                    &options.identity_dir,
                    &listen,
                )?;
                if !options.skip_service {
                    enable_service()?;
                }
                println!(
                    "Enrollment approved. Controller key saved under {}.",
                    options.identity_dir
                );
                println!("Enabled and started tetra.service.");
                return Ok(());
            }
            "access_denied" => bail!("Dashboard denied the enrollment request"),
            "expired_token" => bail!("Dashboard enrollment expired"),
            other => bail!("Dashboard returned unknown enrollment status `{other}`"),
        }
    }
}

async fn check_response(response: reqwest::Response) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    bail!("Dashboard request failed with HTTP {status}: {body}")
}

fn prompt(label: &str, default: &str) -> String {
    print!("{label} [{default}]: ");
    std::mem::drop(std::io::stdout().flush());
    let mut value = String::new();
    if std::io::stdin().read_line(&mut value).is_err() {
        return default.to_owned();
    }
    let value = value.trim();
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

fn generate_tls_material(
    config_dir: &str,
    hostname: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create `{config_dir}`"))?;
    let key = std::path::Path::new(config_dir).join("tetra.key");
    let cert = std::path::Path::new(config_dir).join("tetra.crt");
    if key.exists() && cert.exists() {
        return Ok((key, cert));
    }
    let status = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj",
        ])
        .arg(format!("/CN={hostname}"))
        .args(["-addext", &format!("subjectAltName=DNS:{hostname}")])
        .args(["-keyout"])
        .arg(&key)
        .args(["-out"])
        .arg(&cert)
        .status()
        .context("failed to run openssl; install openssl before enrolling")?;
    ensure!(status.success(), "openssl failed to generate TLS material");
    Ok((key, cert))
}

fn enable_service() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["enable", "--now", "tetra.service"])
        .status()
        .context("failed to run systemctl; is systemd installed?")?;
    ensure!(
        status.success(),
        "systemctl failed to enable and start tetra.service"
    );
    Ok(())
}

fn write_enrollment_config(
    config_dir: &str,
    agent_url: &str,
    cert: &std::path::Path,
    key: &std::path::Path,
    identity_dir: &str,
    listen: &str,
) -> Result<()> {
    let path = std::path::Path::new(config_dir).join("enrollment.json");
    let value = serde_json::json!({
        "agent_url": agent_url,
        "tls_cert": cert,
        "tls_key": key,
        "identity_dir": identity_dir
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&value)?)?;
    let environment_path = std::path::Path::new(config_dir).join("enrollment.env");
    std::fs::write(environment_path, format!("TETRA_LISTEN={listen}\n"))?;
    Ok(())
}
