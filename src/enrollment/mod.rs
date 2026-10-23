//! Host-initiated, device-code enrollment for outbound remote control.
//!
//! The host generates a key pair and a certificate signing request with the
//! `clientAuth` extended key usage. Once an administrator approves the
//! request, the controller signs it and returns the client certificate that
//! `agent-connect` (or `agent-serve` with `remote.enabled`) presents over
//! mTLS. Nothing is registered for inbound connections: the host only ever
//! dials out. See `docs/remote-enrollment.md` for the controller side.

pub mod renewal;
pub mod store;

use std::{io::Write, path::PathBuf, process::Command, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use reqwest::Client;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::agent::config::RuntimeConfig;
use store::{ControllerRecord, Credentials, Enrollment};

/// Version of the enrollment request/response shape. See
/// `docs/remote-enrollment.md`.
const ENROLLMENT_VERSION: u32 = 2;

#[derive(Debug, Clone)]
pub struct Options {
    pub dashboard_url: Option<String>,
    pub display_name: Option<String>,
    pub approval_file: Option<PathBuf>,
    pub verification_url: Option<String>,
    /// Runtime config whose `remote.enabled` gates enrollment.
    pub runtime_config: PathBuf,
    /// Where the key, certificate and controller record are stored.
    pub enrollment_dir: PathBuf,
    pub hostname: Option<String>,
    pub insecure: bool,
    pub skip_service: bool,
}

#[derive(Debug, Clone)]
pub struct UnenrollOptions {
    pub enrollment_dir: PathBuf,
    pub skip_service: bool,
}

#[derive(Debug, Serialize)]
struct CreateRequest<'a> {
    enrollment_version: u32,
    display_name: &'a str,
    hostname: &'a str,
    csr: &'a str,
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
    #[serde(flatten)]
    approval: Option<Approval>,
}

/// Fields the controller returns with `"status": "approved"`.
#[derive(Debug, Deserialize)]
struct Approval {
    host_id: String,
    control_plane_url: String,
    /// PEM client certificate signed from our CSR, leaf first.
    client_certificate: String,
    /// PEM CA bundle for the controller's WSS endpoint.
    server_ca_certificate: String,
}

/// Enroll this host for outbound remote control.
///
/// Refuses to run while `remote.enabled` is off or while an enrollment (even a
/// partial one) is already stored.
#[allow(clippy::too_many_lines)]
pub async fn run(mut options: Options) -> Result<()> {
    let runtime = RuntimeConfig::load(&options.runtime_config)?;
    ensure!(
        runtime.remote.enabled,
        "remote control is disabled; set remote.enabled to true in `{}` before enrolling",
        options.runtime_config.display()
    );
    ensure!(
        !Enrollment::exists(&options.enrollment_dir),
        "this host is already enrolled (`{}`); run `tetra unenroll` first",
        options.enrollment_dir.display()
    );

    let dashboard_url = options
        .dashboard_url
        .take()
        .unwrap_or_else(|| prompt("Controller URL", ""));
    let dashboard_url = dashboard_url.trim().trim_end_matches('/').to_owned();
    ensure!(!dashboard_url.is_empty(), "controller URL cannot be empty");
    // The server CA arrives over this channel, so it must be authenticated.
    if !dashboard_url.starts_with("https://") && !options.insecure {
        bail!("controller URL must use https://; pass --insecure only for local development");
    }
    let verification_url = options
        .verification_url
        .take()
        .unwrap_or_else(|| dashboard_url.clone());

    let hostname = options
        .hostname
        .take()
        .or_else(crate::agent::websocket::hostname)
        .unwrap_or_else(|| "tetra-host".into());
    let display_name = options
        .display_name
        .take()
        .unwrap_or_else(|| prompt("Host display name", &hostname));

    let key_pair = KeyPair::generate().context("failed to generate client key pair")?;
    let csr = certificate_signing_request(&key_pair, &hostname)?;

    // reqwest uses the process-wide provider; `main` installs it, library
    // callers may not have.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let client = Client::builder()
        .danger_accept_invalid_certs(options.insecure)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create controller HTTP client")?;
    let response = client
        .post(format!("{dashboard_url}/api/tetra/device"))
        .json(&CreateRequest {
            enrollment_version: ENROLLMENT_VERSION,
            display_name: &display_name,
            hostname: &hostname,
            csr: &csr,
        })
        .send()
        .await
        .context("failed to create enrollment request")?;
    let response = check_response(response).await?;
    let device: CreateResponse = response
        .json()
        .await
        .context("invalid enrollment response")?;
    if let Some(path) = &options.approval_file {
        // Atomic, so whatever watches the file never reads half of it.
        let approval = serde_json::to_vec_pretty(&serde_json::json!({
            "verification_uri": format!("{}/tetra/device", verification_url.trim_end_matches('/')),
            "user_code": device.user_code,
            "expires_in": device.expires_in
        }))?;
        crate::auth::store::replace(path, &approval, 0o644)?;
    }

    println!(
        "Open {}/tetra/device?code={}",
        verification_url.trim_end_matches('/'),
        device.user_code
    );
    println!("Enter enrollment code: {}", device.user_code);
    println!("Waiting for approval...");

    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(device.expires_in))
        .context("enrollment expiry is outside the supported time range")?;
    let poll_every = Duration::from_secs(device.interval.clamp(1, 60));
    let approval = loop {
        // A transient network error must not throw away the generated key
        // (and with it an approval the admin may be about to give).
        let response = match client
            .put(format!("{dashboard_url}/api/tetra/device"))
            .json(&serde_json::json!({ "device_code": device.device_code }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) if std::time::Instant::now() < deadline => {
                eprintln!("failed to poll enrollment, retrying: {error}");
                sleep(poll_every).await;
                continue;
            }
            Err(error) => return Err(error).context("failed to poll enrollment"),
        };
        let status: PollResponse = check_response(response).await?.json().await?;
        match status.status.as_str() {
            "authorization_pending" => {
                if std::time::Instant::now() >= deadline {
                    bail!("enrollment expired");
                }
                sleep(poll_every).await;
            }
            "approved" => {
                break status
                    .approval
                    .context("approval is missing host_id, control_plane_url or certificates")?;
            }
            "access_denied" => bail!("the enrollment request was denied"),
            "expired_token" => bail!("enrollment expired"),
            other => bail!("controller returned unknown enrollment status `{other}`"),
        }
    };

    check_approval(&approval, &key_pair)?;
    let enrollment = Enrollment::save(
        &options.enrollment_dir,
        ControllerRecord {
            host_id: approval.host_id,
            control_plane_url: approval.control_plane_url,
            dashboard_url,
        },
        Credentials {
            client_key: &key_pair.serialize_pem(),
            client_certificate: &approval.client_certificate,
            server_ca: &approval.server_ca_certificate,
        },
    )?;
    println!(
        "Enrollment approved as host `{}`. Client certificate: {}",
        enrollment.controller.host_id,
        enrollment.client_certificate_path().display()
    );

    if !options.skip_service {
        systemctl(&["enable", "tetra.service"])?;
        systemctl(&["reload-or-restart", "tetra.service"])?;
        println!("tetra.service reloaded; it will connect out while remote.enabled is true.");
    }
    Ok(())
}

/// Remove the stored client certificate, key and controller record.
///
/// Works whether or not remote control is enabled, and succeeds when the host
/// is not enrolled.
pub fn unenroll(options: &UnenrollOptions) -> Result<()> {
    if !Enrollment::remove(&options.enrollment_dir)? {
        println!("This host is not enrolled.");
        return Ok(());
    }
    println!(
        "Removed the enrollment in {}.",
        options.enrollment_dir.display()
    );
    if !options.skip_service {
        // Reloading makes a running agent drop its remote session.
        systemctl(&["try-reload-or-restart", "tetra.service"])?;
    }
    Ok(())
}

/// PEM CSR for `key_pair`, requesting a `clientAuth`-only certificate.
pub(crate) fn certificate_signing_request(key_pair: &KeyPair, hostname: &str) -> Result<String> {
    let mut params = CertificateParams::default();
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, hostname);
    params.distinguished_name = subject;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .serialize_request(key_pair)
        .context("failed to create certificate signing request")?
        .pem()
        .context("failed to encode certificate signing request")
}

/// Check that the approval carries a usable outbound identity: a currently
/// valid `clientAuth` certificate for our key and a server CA that loads.
fn check_approval(approval: &Approval, key_pair: &KeyPair) -> Result<()> {
    ensure!(
        !approval.host_id.trim().is_empty() && !approval.host_id.contains(char::is_control),
        "controller returned an invalid host id"
    );
    ensure!(
        approval.control_plane_url.starts_with("wss://"),
        "controller returned a control-plane URL that is not wss://"
    );

    check_client_certificate(&approval.client_certificate, key_pair)?;

    let mut roots = rustls::RootCertStore::empty();
    for ca in pem_certificates(&approval.server_ca_certificate, "server CA")? {
        roots
            .add(ca)
            .context("failed to add server CA certificate")?;
    }
    ensure!(!roots.is_empty(), "server CA bundle is empty");
    Ok(())
}

/// Check that `pem` holds a currently valid `clientAuth` certificate for
/// `key_pair` that can be used for mTLS.
pub(crate) fn check_client_certificate(pem: &str, key_pair: &KeyPair) -> Result<()> {
    let chain = pem_certificates(pem, "client certificate")?;
    let leaf = chain.first().context("client certificate is empty")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|error| anyhow::anyhow!("failed to parse client certificate: {error}"))?;
    ensure!(
        certificate.public_key().raw == key_pair.subject_public_key_info().as_slice(),
        "client certificate is not for the key generated by this host"
    );
    let client_auth = certificate
        .extended_key_usage()
        .context("failed to parse client certificate extended key usage")?
        .is_some_and(|usage| usage.value.client_auth);
    ensure!(client_auth, "client certificate does not allow clientAuth");
    ensure!(
        certificate.validity().is_valid(),
        "client certificate is not currently valid"
    );

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    // Explicit provider: library callers may not have installed a default.
    rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS")?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_client_auth_cert(chain, key)
    .context("client certificate and key cannot be used for mTLS")?;
    Ok(())
}

fn pem_certificates(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("failed to parse {what} PEM"))
}

async fn check_response(response: reqwest::Response) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    bail!("controller request failed with HTTP {status}: {body}")
}

fn prompt(label: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
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

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .context("failed to run systemctl; is systemd installed?")?;
    ensure!(status.success(), "`systemctl {}` failed", args.join(" "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, IsCa, Issuer};
    use x509_parser::prelude::FromDer;

    use super::*;

    fn approval_for(key_pair: &KeyPair, usage: ExtendedKeyUsagePurpose) -> Approval {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut params = CertificateParams::default();
        params.extended_key_usages = vec![usage];
        let certificate = params.signed_by(key_pair, &issuer).unwrap();
        Approval {
            host_id: "host-01".into(),
            control_plane_url: "wss://control.example.test/tetra/agent".into(),
            client_certificate: certificate.pem(),
            server_ca_certificate: ca.pem(),
        }
    }

    #[test]
    fn csr_requests_client_auth() {
        let key_pair = KeyPair::generate().unwrap();
        let csr = certificate_signing_request(&key_pair, "host.example.test").unwrap();
        let der = rustls::pki_types::CertificateSigningRequestDer::from_pem_slice(csr.as_bytes())
            .unwrap();
        let (_, request) =
            x509_parser::certification_request::X509CertificationRequest::from_der(der.as_ref())
                .unwrap();
        let client_auth = request.requested_extensions().unwrap().any(|extension| {
            matches!(
                extension,
                x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(usage)
                    if usage.client_auth && !usage.server_auth
            )
        });
        assert!(client_auth);
    }

    #[test]
    fn accepts_client_auth_certificate_for_our_key() {
        let key_pair = KeyPair::generate().unwrap();
        let approval = approval_for(&key_pair, ExtendedKeyUsagePurpose::ClientAuth);
        check_approval(&approval, &key_pair).unwrap();
    }

    #[test]
    fn rejects_server_certificate() {
        let key_pair = KeyPair::generate().unwrap();
        let approval = approval_for(&key_pair, ExtendedKeyUsagePurpose::ServerAuth);
        let error = check_approval(&approval, &key_pair).unwrap_err();
        assert!(error.to_string().contains("clientAuth"), "{error:#}");
    }

    #[test]
    fn rejects_certificate_for_another_key() {
        let key_pair = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let approval = approval_for(&other, ExtendedKeyUsagePurpose::ClientAuth);
        let error = check_approval(&approval, &key_pair).unwrap_err();
        assert!(error.to_string().contains("not for the key"), "{error:#}");
    }

    #[test]
    fn rejects_plaintext_control_plane() {
        let key_pair = KeyPair::generate().unwrap();
        let mut approval = approval_for(&key_pair, ExtendedKeyUsagePurpose::ClientAuth);
        approval.control_plane_url = "ws://control.example.test/tetra/agent".into();
        check_approval(&approval, &key_pair).unwrap_err();
    }
}
