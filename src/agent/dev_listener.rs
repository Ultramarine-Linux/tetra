//! Development TCP listener for the authenticated WebSocket protocol
//! (`agent-ws-serve`).
//!
//! Compiled only with the `dev-listener` feature, so release builds cannot
//! listen on the network. Production clients use [`super::local_socket`].

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::websocket_server::ServerState;

#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    pub listen: SocketAddr,
    /// Explicit controller key for development. Once enrolled, the persisted
    /// key under `identity_dir` is used on subsequent starts.
    pub controller_public_key: Option<String>,
    /// One-time token accepted only while no controller key is enrolled.
    pub enrollment_token: Option<String>,
    pub identity_dir: PathBuf,
    /// Paths to TLS certificate and key
    pub tls_cert_key_path: Option<(PathBuf, PathBuf)>,
}
impl WebSocketServerConfig {
    fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        Ok((self.tls_cert_key_path.as_ref())
            .map(Self::load_tls_config)
            .transpose()?
            .map(Arc::new)
            .map(TlsAcceptor::from))
    }

    fn load_tls_config((cert_path, key_path): &(PathBuf, PathBuf)) -> Result<rustls::ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
        let certificates = CertificateDer::pem_file_iter(cert_path)
            .with_context(|| format!("failed to open TLS certificate `{}`", cert_path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse TLS certificate PEM")?;
        let key = PrivateKeyDer::from_pem_file(key_path)
            .with_context(|| format!("failed to read TLS key `{}`", key_path.display()))?;
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .context("invalid TLS certificate/private-key pair")
    }

    pub async fn serve(self) -> Result<()> {
        let tls_acceptor = self.tls_acceptor()?;
        validate_listener_security(&self.listen, tls_acceptor.is_some())?;

        let state = ServerState::load(
            &self.identity_dir,
            self.controller_public_key,
            self.enrollment_token,
        )?;
        let listener = TcpListener::bind(self.listen).await.with_context(|| {
            format!(
                "failed to bind development WebSocket listener on {}",
                self.listen
            )
        })?;

        eprintln!(
            "serving authenticated Tetra WebSocket on {}://{}",
            if tls_acceptor.is_some() { "wss" } else { "ws" },
            self.listen
        );
        state.log_identity();

        loop {
            let (stream, peer) = listener.accept().await?;
            let state = state.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                match tls_acceptor {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(stream) => state.handle(stream, peer.to_string()).await,
                        Err(error) => eprintln!("TLS peer {peer} failed handshake: {error}"),
                    },
                    None => state.handle(stream, peer.to_string()).await,
                }
            });
        }
    }
}

#[inline]
fn validate_listener_security(listen: &SocketAddr, tls_enabled: bool) -> Result<()> {
    ensure!(
        listen.ip().is_loopback() || tls_enabled,
        "non-loopback WebSocket listeners require --tls-cert and --tls-key"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_plaintext_listener() {
        let address: SocketAddr = "192.0.2.1:7780".parse().unwrap();
        validate_listener_security(&address, false).unwrap_err();
        validate_listener_security(&address, true).unwrap();
        validate_listener_security(&"127.0.0.1:7780".parse().unwrap(), false).unwrap();
    }
}
