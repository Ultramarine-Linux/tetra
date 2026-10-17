//! `tetra enroll` / `tetra unenroll` against an in-process test controller.
//!
//! The controller serves the device-code enrollment API over plain HTTP
//! (`--insecure`), signs the host's CSR with its client CA, and runs an mTLS
//! WSS endpoint that only accepts certificates from that CA. `agent-connect`
//! is run as the real binary against it.

#![allow(clippy::tests_outside_test_module)]

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::StreamExt;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    RootCertStore,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tetra::{
    agent::{config::RuntimeConfig, remote},
    enrollment::{self, store::Enrollment},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

const HOST_ID: &str = "host-test-01";
const WAIT: Duration = Duration::from_secs(30);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

fn ca(name: &str) -> (Issuer<'static, KeyPair>, rcgen::Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let certificate = params.self_signed(&key).unwrap();
    (Issuer::new(params, key), certificate)
}

/// How the test controller signs the host's CSR.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signing {
    ClientAuth,
    /// A misbehaving controller that issues a server certificate.
    ServerAuth,
}

#[derive(Debug)]
struct Hello {
    frame: Value,
    peer_certificate: CertificateDer<'static>,
}

struct TestController {
    url: String,
    requests: Arc<AtomicUsize>,
    hellos: mpsc::UnboundedReceiver<Hello>,
    server_ca_pem: String,
    wss_url: String,
}

impl TestController {
    async fn start(signing: Signing) -> Self {
        let (client_ca, client_ca_certificate) = ca("test client CA");
        let (server_ca, server_ca_certificate) = ca("test server CA");
        let server_ca_pem = server_ca_certificate.pem();
        let (wss_url, hellos) = serve_wss(client_ca_certificate.der().clone(), &server_ca).await;

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", http.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(DeviceState {
            signing,
            client_ca,
            server_ca_pem: server_ca_pem.clone(),
            wss_url: wss_url.clone(),
            csr: Mutex::new(None),
            requests: Arc::clone(&requests),
        });
        tokio::spawn(async move {
            loop {
                let (stream, _) = http.accept().await.unwrap();
                tokio::spawn(serve_http(stream, Arc::clone(&state)));
            }
        });

        Self {
            url,
            requests,
            hellos,
            server_ca_pem,
            wss_url,
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    async fn hello(&mut self) -> Hello {
        timeout(WAIT, self.hellos.recv())
            .await
            .expect("agent-connect never completed the mTLS handshake")
            .unwrap()
    }
}

struct DeviceState {
    signing: Signing,
    client_ca: Issuer<'static, KeyPair>,
    server_ca_pem: String,
    wss_url: String,
    csr: Mutex<Option<String>>,
    requests: Arc<AtomicUsize>,
}

impl DeviceState {
    fn create(&self, request: &Value) -> Value {
        assert_eq!(request["enrollment_version"], 2);
        for removed in [
            "agent_url",
            "listen",
            "tls_ca_certificate",
            "host_public_key",
        ] {
            assert!(
                request.get(removed).is_none(),
                "request still sends {removed}"
            );
        }
        let csr = request["csr"].as_str().unwrap().to_owned();
        assert_csr_requests_client_auth(&csr);
        *self.csr.lock().unwrap() = Some(csr);
        json!({
            "device_code": "device-code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "/tetra/device",
            "expires_in": 60,
            "interval": 1
        })
    }

    fn approve(&self) -> Value {
        let csr = self.csr.lock().unwrap().clone().unwrap();
        let csr = CertificateSigningRequestParams::from_pem(&csr).unwrap();
        // The controller sets identity and usage itself rather than trusting
        // the requested subject.
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, HOST_ID);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![match self.signing {
            Signing::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
            Signing::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
        }];
        let certificate = params.signed_by(&csr.public_key, &self.client_ca).unwrap();
        json!({
            "status": "approved",
            "host_id": HOST_ID,
            "control_plane_url": self.wss_url,
            "client_certificate": certificate.pem(),
            "server_ca_certificate": self.server_ca_pem,
        })
    }
}

fn assert_csr_requests_client_auth(csr: &str) {
    use x509_parser::{
        certification_request::X509CertificationRequest, extensions::ParsedExtension,
        prelude::FromDer,
    };
    let der = rustls_pemfile::csr(&mut csr.as_bytes()).unwrap().unwrap();
    let (_, request) = X509CertificationRequest::from_der(der.as_ref()).unwrap();
    request.verify_signature().unwrap();
    let client_auth = request.requested_extensions().unwrap().any(|extension| {
        matches!(extension, ParsedExtension::ExtendedKeyUsage(usage) if usage.client_auth)
    });
    assert!(client_auth, "CSR does not request clientAuth");
}

/// One HTTP/1.1 request per connection; just enough for reqwest.
async fn serve_http(mut stream: TcpStream, state: Arc<DeviceState>) {
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "client closed mid-request");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end.saturating_add(4);
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while buffer.len() < header_end.saturating_add(length) {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        buffer.extend_from_slice(&chunk[..read]);
    }
    let request: Value = serde_json::from_slice(&buffer[header_end..]).unwrap();

    state.requests.fetch_add(1, Ordering::SeqCst);
    let body = match head.split_whitespace().take(2).collect::<Vec<_>>()[..] {
        ["POST", "/api/tetra/device"] => state.create(&request),
        ["PUT", "/api/tetra/device"] => {
            assert_eq!(request["device_code"], "device-code");
            state.approve()
        }
        _ => panic!("unexpected request: {head}"),
    }
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

/// mTLS WSS endpoint that requires a client certificate signed by `client_ca`
/// and reports each agent's `hello` frame with the certificate it presented.
async fn serve_wss(
    client_ca: CertificateDer<'static>,
    server_ca: &Issuer<'static, KeyPair>,
) -> (String, mpsc::UnboundedReceiver<Hello>) {
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_ca).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider())
        .build()
        .unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&server_key, server_ca)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("wss://{}/tetra/agent", listener.local_addr().unwrap());
    let (sender, hellos) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                // Handshakes without a valid client certificate fail here.
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let peer_certificate = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
                let mut socket = tokio_tungstenite::accept_async(tls).await.unwrap();
                if let Some(Ok(Message::Text(text))) = socket.next().await {
                    let frame = serde_json::from_str(&text).unwrap();
                    sender
                        .send(Hello {
                            frame,
                            peer_certificate,
                        })
                        .ok();
                }
            });
        }
    });
    (url, hellos)
}

/// A host with its own runtime config and enrollment directory.
struct Host {
    _root: TempDir,
    config: PathBuf,
    enrollment_dir: PathBuf,
}

impl Host {
    fn new(remote_enabled: Option<bool>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let host = Self {
            config: root.path().join("tetra.json"),
            enrollment_dir: root.path().join("var/lib/tetra/remote"),
            _root: root,
        };
        if let Some(enabled) = remote_enabled {
            host.set_remote_enabled(enabled);
        }
        host
    }

    fn set_remote_enabled(&self, enabled: bool) {
        std::fs::write(
            &self.config,
            json!({ "remote": { "enabled": enabled } }).to_string(),
        )
        .unwrap();
    }

    async fn enroll(&self, controller: &TestController) -> anyhow::Result<()> {
        enrollment::run(enrollment::Options {
            dashboard_url: Some(controller.url.clone()),
            display_name: Some("Test host".into()),
            approval_file: None,
            verification_url: None,
            runtime_config: self.config.clone(),
            enrollment_dir: self.enrollment_dir.clone(),
            hostname: Some("test-host".into()),
            insecure: true,
            skip_service: true,
        })
        .await
    }

    fn unenroll(&self) -> anyhow::Result<()> {
        enrollment::unenroll(&enrollment::UnenrollOptions {
            enrollment_dir: self.enrollment_dir.clone(),
            skip_service: true,
        })
    }

    fn agent_connect(&self) -> AgentConnect {
        AgentConnect(
            Command::new(env!("CARGO_BIN_EXE_tetra"))
                .arg("agent-connect")
                .arg("--runtime-config")
                .arg(&self.config)
                .arg("--enrollment-dir")
                .arg(&self.enrollment_dir)
                .env_remove("TETRA_HOST_ID")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }
}

/// Kills the `agent-connect` child when dropped.
struct AgentConnect(Child);

impl AgentConnect {
    /// Wait for the process to exit on its own, returning its stderr.
    fn refused(mut self) -> String {
        let status = self.0.wait().unwrap();
        assert!(
            !status.success(),
            "agent-connect should have refused to run"
        );
        self.stderr()
    }

    /// Stop the still-running process, returning its stderr.
    fn stop(mut self) -> String {
        assert!(self.0.try_wait().unwrap().is_none(), "agent-connect exited");
        self.0.kill().unwrap();
        self.0.wait().unwrap();
        self.stderr()
    }

    fn stderr(&mut self) -> String {
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut self.0.stderr.take().unwrap(), &mut stderr).unwrap();
        stderr
    }
}

impl Drop for AgentConnect {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn pem_certificate(path: &Path) -> CertificateDer<'static> {
    let pem = std::fs::read(path).unwrap();
    rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn enroll_issues_a_client_certificate_that_agent_connect_uses() {
    let mut controller = TestController::start(Signing::ClientAuth).await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();

    let enrollment = Enrollment::load(&host.enrollment_dir).unwrap().unwrap();
    assert_eq!(enrollment.controller.host_id, HOST_ID);
    assert_eq!(enrollment.controller.control_plane_url, controller.wss_url);
    assert_eq!(mode(&host.enrollment_dir), 0o700);
    for file in [
        "client.key",
        "client.crt",
        "server-ca.crt",
        "controller.json",
    ] {
        assert_eq!(mode(&host.enrollment_dir.join(file)), 0o600, "{file}");
    }
    assert_eq!(
        std::fs::read_to_string(host.enrollment_dir.join("server-ca.crt")).unwrap(),
        controller.server_ca_pem
    );

    let client_certificate = pem_certificate(&enrollment.client_certificate_path());
    let (_, parsed) = x509_parser::parse_x509_certificate(&client_certificate).unwrap();
    assert!(
        parsed
            .extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .client_auth
    );

    let _agent = host.agent_connect();
    let hello = controller.hello().await;
    assert_eq!(hello.frame["type"], "hello");
    assert_eq!(hello.frame["host_id"], HOST_ID);
    assert_eq!(hello.peer_certificate, client_certificate);
}

#[tokio::test]
async fn controller_rejects_a_client_without_the_enrolled_certificate() {
    let mut controller = TestController::start(Signing::ClientAuth).await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();

    // Same key and server CA, but a certificate the client CA never signed.
    let key = KeyPair::from_pem(
        &std::fs::read_to_string(host.enrollment_dir.join("client.key")).unwrap(),
    )
    .unwrap();
    let mut params = CertificateParams::default();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    std::fs::write(
        host.enrollment_dir.join("client.crt"),
        params.self_signed(&key).unwrap().pem(),
    )
    .unwrap();

    let agent = host.agent_connect();
    timeout(Duration::from_secs(3), controller.hellos.recv())
        .await
        .expect_err("controller accepted a certificate its client CA did not sign");
    let stderr = agent.stop();
    assert!(
        stderr.contains("failed to connect to control plane"),
        "{stderr}"
    );
}

#[tokio::test]
async fn enroll_refuses_while_remote_is_disabled() {
    let controller = TestController::start(Signing::ClientAuth).await;
    for host in [Host::new(None), Host::new(Some(false))] {
        let error = host.enroll(&controller).await.unwrap_err();
        assert!(error.to_string().contains("remote.enabled"), "{error:#}");
        assert!(!host.enrollment_dir.exists());
    }
    assert_eq!(controller.requests(), 0, "enroll contacted the controller");
}

#[tokio::test]
async fn disabling_remote_keeps_the_enrollment_but_stops_connecting() {
    let controller = TestController::start(Signing::ClientAuth).await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();
    let config = RuntimeConfig::load(&host.config).unwrap();
    assert!(remote::connection_from(&config, &host.enrollment_dir).is_some());

    host.set_remote_enabled(false);
    let config = RuntimeConfig::load(&host.config).unwrap();
    assert_eq!(remote::connection_from(&config, &host.enrollment_dir), None);
    let stderr = host.agent_connect().refused();
    assert!(stderr.contains("remote control is disabled"), "{stderr}");
    assert!(
        Enrollment::load(&host.enrollment_dir).unwrap().is_some(),
        "turning remote off removed the enrollment"
    );

    // Re-enrolling is refused while the old enrollment is still stored.
    host.set_remote_enabled(true);
    let requests = controller.requests();
    let error = host.enroll(&controller).await.unwrap_err();
    assert!(error.to_string().contains("already enrolled"), "{error:#}");
    assert_eq!(controller.requests(), requests);
}

#[tokio::test]
async fn unenroll_removes_the_certificate_and_controller_record() {
    let controller = TestController::start(Signing::ClientAuth).await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();

    // Works with remote control off.
    host.set_remote_enabled(false);
    host.unenroll().unwrap();
    assert!(!Enrollment::exists(&host.enrollment_dir));
    host.unenroll().unwrap();

    host.set_remote_enabled(true);
    let config = RuntimeConfig::load(&host.config).unwrap();
    assert_eq!(remote::connection_from(&config, &host.enrollment_dir), None);
    let stderr = host.agent_connect().refused();
    assert!(stderr.contains("not enrolled"), "{stderr}");

    // The host can enroll again afterwards.
    host.enroll(&controller).await.unwrap();
}

#[tokio::test]
async fn enroll_rejects_a_certificate_without_client_auth() {
    let controller = TestController::start(Signing::ServerAuth).await;
    let host = Host::new(Some(true));
    let error = host.enroll(&controller).await.unwrap_err();
    assert!(error.to_string().contains("clientAuth"), "{error:#}");
    assert!(!Enrollment::exists(&host.enrollment_dir));
}
