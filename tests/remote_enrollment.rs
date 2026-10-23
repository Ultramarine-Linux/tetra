//! `tetra enroll` / `tetra unenroll` against an in-process test controller.
//!
//! The controller serves the device-code enrollment API over plain HTTP
//! (`--insecure`), signs the host's CSR with its client CA, and runs an mTLS
//! WSS endpoint that only accepts certificates from that CA and answers
//! certificate renewal requests. `agent-connect` and `agent-serve` are run as
//! the real binary against it.

use std::{
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    RootCertStore,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
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
    net::{TcpListener, TcpStream, UnixStream},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

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

/// How the test controller signs the host's CSR at enrollment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signing {
    ClientAuth,
    /// A misbehaving controller that issues a server certificate.
    ServerAuth,
}

/// How the test controller answers a `renew` frame.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Renewal {
    /// Sign the CSR with the client CA.
    Sign,
    /// Answer `renew_failed`.
    Refuse,
    /// Sign the CSR with a CA the WSS endpoint does not trust, so the agent's
    /// own checks pass but the reconnect with it is refused.
    UntrustedIssuer,
}

#[derive(Clone, Copy)]
struct Setup {
    signing: Signing,
    renewal: Renewal,
    /// Issue the enrollment certificate already due for renewal: valid from
    /// two hours ago until one hour from now.
    due_for_renewal: bool,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            signing: Signing::ClientAuth,
            renewal: Renewal::Sign,
            due_for_renewal: false,
        }
    }
}

#[derive(Debug)]
struct Hello {
    frame: Value,
    peer_certificate: CertificateDer<'static>,
}

/// What the WSS endpoint saw.
#[derive(Debug)]
enum Event {
    Hello(Hello),
    Renew { csr: String },
    Closed,
}

struct TestController {
    url: String,
    requests: Arc<AtomicUsize>,
    events: mpsc::UnboundedReceiver<Event>,
    server_ca_pem: String,
    wss_url: String,
}

impl TestController {
    async fn start(signing: Signing) -> Self {
        Self::start_with(Setup {
            signing,
            ..Setup::default()
        })
        .await
    }

    async fn start_with(setup: Setup) -> Self {
        let (client_ca, client_ca_certificate) = ca("test client CA");
        let client_ca = Arc::new(client_ca);
        let (server_ca, server_ca_certificate) = ca("test server CA");
        let server_ca_pem = server_ca_certificate.pem();
        let (wss_url, events) = serve_wss(
            client_ca_certificate.der().clone(),
            Arc::clone(&client_ca),
            &server_ca,
            setup.renewal,
        )
        .await;

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", http.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(DeviceState {
            setup,
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
            events,
            server_ca_pem,
            wss_url,
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    async fn event(&mut self) -> Event {
        timeout(WAIT, self.events.recv())
            .await
            .expect("the agent never reached the controller")
            .unwrap()
    }

    /// The next `hello`, skipping the ends of earlier sessions.
    async fn hello(&mut self) -> Hello {
        loop {
            match self.event().await {
                Event::Hello(hello) => return hello,
                Event::Closed => {}
                Event::Renew { .. } => panic!("expected hello, got a renewal request"),
            }
        }
    }

    /// The next renewal request's CSR.
    async fn renew(&mut self) -> String {
        match self.event().await {
            Event::Renew { csr } => csr,
            other => panic!("expected a renewal request, got {other:?}"),
        }
    }

    /// Assert the agent stays connected and quiet for `period`.
    async fn expect_quiet(&mut self, period: Duration) {
        if let Ok(event) = timeout(period, self.events.recv()).await {
            panic!("expected no activity, got {event:?}");
        }
    }
}

struct DeviceState {
    setup: Setup,
    client_ca: Arc<Issuer<'static, KeyPair>>,
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
        let usage = match self.setup.signing {
            Signing::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
            Signing::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
        };
        let validity = self.setup.due_for_renewal.then(|| {
            let now = time::OffsetDateTime::now_utc();
            (
                now.checked_sub(time::Duration::hours(2)).unwrap(),
                now.checked_add(time::Duration::hours(1)).unwrap(),
            )
        });
        let certificate = sign(&csr, &self.client_ca, usage, validity);
        json!({
            "status": "approved",
            "host_id": HOST_ID,
            "control_plane_url": self.wss_url,
            "client_certificate": certificate.pem(),
            "server_ca_certificate": self.server_ca_pem,
        })
    }
}

/// Sign `csr` the way the controller should: identity and usage are set by
/// the controller rather than copied from the request.
fn sign(
    csr: &str,
    issuer: &Issuer<'static, KeyPair>,
    usage: ExtendedKeyUsagePurpose,
    validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
) -> rcgen::Certificate {
    let csr = CertificateSigningRequestParams::from_pem(csr).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, HOST_ID);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    if let Some((not_before, not_after)) = validity {
        params.not_before = not_before;
        params.not_after = not_after;
    }
    params.signed_by(&csr.public_key, issuer).unwrap()
}

fn assert_csr_requests_client_auth(csr: &str) {
    use x509_parser::{
        certification_request::X509CertificationRequest, extensions::ParsedExtension,
        prelude::FromDer,
    };
    let der =
        rustls::pki_types::CertificateSigningRequestDer::from_pem_slice(csr.as_bytes()).unwrap();
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
/// and reports each agent's `hello` (with the certificate it presented),
/// renewal requests and disconnects.
async fn serve_wss(
    client_ca_certificate: CertificateDer<'static>,
    client_ca: Arc<Issuer<'static, KeyPair>>,
    server_ca: &Issuer<'static, KeyPair>,
    renewal: Renewal,
) -> (String, mpsc::UnboundedReceiver<Event>) {
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_ca_certificate).unwrap();
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
    let renewal_issuer = match renewal {
        Renewal::UntrustedIssuer => Arc::new(ca("untrusted client CA").0),
        Renewal::Sign | Renewal::Refuse => client_ca,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("wss://{}/tetra/agent", listener.local_addr().unwrap());
    let (sender, events) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let session = AgentSession {
                events: sender.clone(),
                renewal,
                issuer: Arc::clone(&renewal_issuer),
            };
            tokio::spawn(async move {
                // Handshakes without a valid client certificate fail here.
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                session.serve(tls).await;
            });
        }
    });
    (url, events)
}

/// One agent connection to the test WSS endpoint.
struct AgentSession {
    events: mpsc::UnboundedSender<Event>,
    renewal: Renewal,
    issuer: Arc<Issuer<'static, KeyPair>>,
}

impl AgentSession {
    async fn serve(self, tls: TlsStream<TcpStream>) {
        let peer_certificate = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
        let mut socket = tokio_tungstenite::accept_async(tls).await.unwrap();
        let mut peer_certificate = Some(peer_certificate);
        while let Some(Ok(message)) = socket.next().await {
            let Message::Text(text) = message else {
                continue;
            };
            let frame: Value = serde_json::from_str(&text).unwrap();
            match frame["type"].as_str() {
                Some("hello") => {
                    let peer_certificate = peer_certificate.take().unwrap();
                    self.events
                        .send(Event::Hello(Hello {
                            frame,
                            peer_certificate,
                        }))
                        .ok();
                }
                Some("renew") => self.renew(&mut socket, &frame).await,
                _ => {}
            }
        }
        self.events.send(Event::Closed).ok();
    }

    async fn renew(&self, socket: &mut WebSocketStream<TlsStream<TcpStream>>, frame: &Value) {
        let csr = frame["csr"].as_str().unwrap().to_owned();
        assert_csr_requests_client_auth(&csr);
        let reply = match self.renewal {
            Renewal::Refuse => json!({ "type": "renew_failed", "error": "renewal refused" }),
            Renewal::Sign | Renewal::UntrustedIssuer => {
                let certificate = sign(
                    &csr,
                    &self.issuer,
                    ExtendedKeyUsagePurpose::ClientAuth,
                    None,
                );
                json!({ "type": "renewed", "client_certificate": certificate.pem() })
            }
        };
        self.events.send(Event::Renew { csr }).ok();
        socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .ok();
    }
}

/// A host with its own runtime config and enrollment directory.
struct Host {
    root: TempDir,
    config: PathBuf,
    enrollment_dir: PathBuf,
}

impl Host {
    fn new(remote_enabled: Option<bool>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let host = Self {
            config: root.path().join("tetra.json"),
            enrollment_dir: root.path().join("var/lib/tetra/remote"),
            root,
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

    fn file(&self, name: &str) -> PathBuf {
        self.enrollment_dir.join(name)
    }

    /// Every file in the enrollment directory with its contents.
    fn enrollment_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(&self.enrollment_dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        files.sort();
        files
    }

    /// Run `agent-serve` the way systemd starts it from `tetra.socket`: the
    /// listener is passed as fd 3 with `LISTEN_PID` and `LISTEN_FDS`.
    fn agent_serve(&self, listener: &std::os::unix::net::UnixListener) -> Agent {
        let fd = listener.as_raw_fd();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            // `exec` keeps the shell's pid, which is the pid LISTEN_PID names.
            .arg(r#"LISTEN_PID=$$; export LISTEN_PID; exec "$@""#)
            .arg("sh")
            .arg(env!("CARGO_BIN_EXE_tetra"))
            .arg("agent-serve")
            .arg("--config")
            .arg(&self.config)
            .arg("--socket")
            .arg(self.root.path().join("not-activated.sock"))
            .arg("--identity-dir")
            .arg(self.root.path().join("identity"))
            .arg("--enrollment-dir")
            .arg(&self.enrollment_dir)
            // Keep the daemon's state out of /var/lib, so this runs without
            // root.
            .arg("--state-dir")
            .arg(self.root.path().join("state"))
            .arg("--caddy-sites-dir")
            .arg(self.root.path().join("caddy-sites"))
            .arg("--public-dir")
            .arg(self.root.path().join("public"))
            .env("LISTEN_FDS", "1")
            .env_remove("TETRA_CONTROLLER_PUBLIC_KEY")
            .env_remove("TETRA_ENROLLMENT_TOKEN")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // SAFETY: the closure runs in the forked child before exec and only
        // calls dup2 and fcntl, which are async-signal-safe. `fd` stays open
        // in the parent for the duration of the spawn.
        unsafe {
            command.pre_exec(move || {
                // dup2 clears close-on-exec on the copy; fcntl covers fd == 3.
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        };
        Agent(command.spawn().unwrap())
    }

    fn agent_connect(&self) -> Agent {
        Agent(
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

/// Kills the `agent-connect` or `agent-serve` child when dropped.
struct Agent(Child);

impl Agent {
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

impl Drop for Agent {
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
    CertificateDer::from_pem_slice(&pem).unwrap()
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
    // The certificate is nowhere near due, so the session just stays up.
    controller.expect_quiet(Duration::from_secs(2)).await;
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
    // The handshake fails, so the endpoint never sees a hello.
    controller.expect_quiet(Duration::from_secs(3)).await;
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

#[tokio::test]
async fn renewal_swaps_in_a_new_certificate_and_reconnects() {
    let mut controller = TestController::start_with(Setup {
        due_for_renewal: true,
        ..Setup::default()
    })
    .await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();
    let old_certificate = pem_certificate(&host.file("client.crt"));
    let old_key =
        KeyPair::from_pem(&std::fs::read_to_string(host.file("client.key")).unwrap()).unwrap();

    let agent = host.agent_connect();
    assert_eq!(controller.hello().await.peer_certificate, old_certificate);
    let csr = controller.renew().await;
    let csr_key = CertificateSigningRequestParams::from_pem(&csr)
        .unwrap()
        .public_key
        .subject_public_key_info();
    assert_ne!(
        csr_key,
        old_key.subject_public_key_info(),
        "renewal reused the old key"
    );

    // The agent reconnects with the renewed certificate.
    let hello = controller.hello().await;
    assert_eq!(hello.frame["host_id"], HOST_ID);
    assert_ne!(hello.peer_certificate, old_certificate);
    let (_, renewed) = x509_parser::parse_x509_certificate(&hello.peer_certificate).unwrap();
    assert_eq!(renewed.public_key().raw, csr_key.as_slice());

    // It now lives in the enrollment, with its key, and nothing is staged.
    assert_eq!(
        pem_certificate(&host.file("client.crt")),
        hello.peer_certificate
    );
    let key =
        KeyPair::from_pem(&std::fs::read_to_string(host.file("client.key")).unwrap()).unwrap();
    assert_eq!(key.subject_public_key_info(), csr_key);
    let files: Vec<_> = host
        .enrollment_files()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        files,
        [
            "client.crt",
            "client.key",
            "controller.json",
            "server-ca.crt"
        ]
    );
    for file in &files {
        assert_eq!(mode(&host.file(file)), 0o600, "{file}");
    }

    // The renewed certificate is not due, so nothing else happens.
    controller.expect_quiet(Duration::from_secs(2)).await;
    let stderr = agent.stop();
    assert!(
        stderr.contains("renewed client certificate accepted"),
        "{stderr}"
    );
}

#[tokio::test]
async fn refused_renewal_keeps_the_old_certificate() {
    let mut controller = TestController::start_with(Setup {
        due_for_renewal: true,
        renewal: Renewal::Refuse,
        ..Setup::default()
    })
    .await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();
    let before = host.enrollment_files();
    let old_certificate = pem_certificate(&host.file("client.crt"));

    let agent = host.agent_connect();
    assert_eq!(controller.hello().await.peer_certificate, old_certificate);
    controller.renew().await;

    // The session stays up on the old certificate and the agent does not
    // retry straight away.
    controller.expect_quiet(Duration::from_secs(3)).await;
    assert_eq!(host.enrollment_files(), before);
    let stderr = agent.stop();
    assert!(stderr.contains("refused to renew"), "{stderr}");
}

#[tokio::test]
async fn renewed_certificate_the_controller_rejects_is_discarded() {
    let mut controller = TestController::start_with(Setup {
        due_for_renewal: true,
        renewal: Renewal::UntrustedIssuer,
        ..Setup::default()
    })
    .await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();
    let before = host.enrollment_files();
    let old_certificate = pem_certificate(&host.file("client.crt"));

    let agent = host.agent_connect();
    assert_eq!(controller.hello().await.peer_certificate, old_certificate);
    controller.renew().await;

    // The reconnect with the renewed certificate fails the handshake, so the
    // next session the endpoint sees is back on the old certificate.
    assert_eq!(controller.hello().await.peer_certificate, old_certificate);
    controller.expect_quiet(Duration::from_secs(3)).await;
    assert_eq!(host.enrollment_files(), before);
    let stderr = agent.stop();
    assert!(
        stderr.contains("renewed client certificate did not work"),
        "{stderr}"
    );
    assert!(
        stderr.contains("discarded the renewed client certificate"),
        "{stderr}"
    );
}

#[tokio::test]
async fn agent_serve_stays_connected_with_no_local_clients() {
    let mut controller = TestController::start(Signing::ClientAuth).await;
    let host = Host::new(Some(true));
    host.enroll(&controller).await.unwrap();

    let socket_path = host.root.path().join("tetra.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let agent = host.agent_serve(&listener);

    // No local client has connected, yet the socket-activated daemon dials
    // out and keeps the session up instead of exiting when idle.
    assert_eq!(controller.hello().await.frame["host_id"], HOST_ID);
    controller.expect_quiet(Duration::from_secs(2)).await;

    // The activated socket is the one being served.
    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (mut socket, _) = tokio_tungstenite::client_async("ws://localhost/", stream)
        .await
        .unwrap();
    let frame = timeout(WAIT, socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
    assert!(frame["type"].is_string(), "{frame}");

    let stderr = agent.stop();
    assert!(stderr.contains("socket-activated listener"), "{stderr}");
    assert!(!socket_path.with_file_name("not-activated.sock").exists());
}
