use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{AgentCommand, AgentResponse};

/// The byte-stream contract a transport must implement to carry commands and
/// responses between the control plane and the agent.
///
/// Each concrete transport (WSS, vsock) adapts this trait to its own framing.
#[allow(clippy::missing_errors_doc)]
pub trait Transport {
    fn connect(&mut self) -> Result<()>;
    fn receive(&mut self) -> Result<Option<AgentCommand>>;
    fn send(&mut self, response: AgentResponse) -> Result<()>;
}

/// Connection parameters the `agent-connect` subcommand loads from a JSON
/// config file.
///
/// The `control_plane_url` selects the transport; the TLS paths are used only
/// for `wss://` endpoints (mTLS to the control plane).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransportConfig {
    /// The control-plane URL, which selects the transport kind and endpoint.
    pub control_plane_url: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_path: Option<String>,
}

impl TransportConfig {
    /// Parse `control_plane_url` into a concrete endpoint kind.
    ///
    /// This is where the URL scheme (`wss://`, `ws://`, `vsock://`) decides which transport
    /// implementation will be used.
    ///
    /// # Errors
    /// Returns an error if the `control_plane_url` is not a supported address scheme.
    pub fn endpoint(&self) -> Result<TransportEndpoint> {
        self.control_plane_url.parse()
    }

    /// Reject production WSS configurations until the transport has enough TLS material for explicit mutual authentication.
    ///
    /// The current connector still needs a custom rustls client setup to consume these files;
    /// failing closed is safer than silently using platform roots and ignoring the configured mTLS paths.
    ///
    /// # Errors
    /// Returns an error if the `control_plane_url` is `ws://` or if any of the TLS paths are missing.
    /// `ws://` should only be used in development, and the TLS paths are required for production WSS connections.
    pub fn validate(&self, url: &str) -> Result<()> {
        if url.starts_with("ws://") {
            bail!("outbound production transport requires wss://; ws:// is development-only")
        }
        if self.client_cert_path.is_none()
            || self.client_key_path.is_none()
            || self.server_ca_path.is_none()
        {
            bail!(
                "wss control-plane transport requires client_cert_path, client_key_path, and server_ca_path"
            )
        }
        Ok(())
    }
}

/// The transport kind selected by the `control_plane_url` scheme.
///
/// `vsock://` URLs target a VM's virtio-vsock address; `ws://`/`wss://` target
/// a control-plane WebSocket. Other schemes are rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEndpoint {
    WebSocket { url: String },
    Vsock(VsockEndpoint),
}

impl FromStr for TransportEndpoint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.starts_with("wss://") || value.starts_with("ws://") {
            return Ok(Self::WebSocket {
                url: value.to_owned(),
            });
        }

        let Some(address) = value.strip_prefix("vsock://") else {
            bail!("unsupported control plane transport `{value}`");
        };

        Ok(Self::Vsock(address.parse()?))
    }
}

/// A `vsock://CID:PORT` endpoint. CIDs identify the guest/host/named context
/// in the virtio-vsock addressing model; see [`parse_cid`] for the symbolic
/// aliases (`hypervisor`, `local`, `host`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockEndpoint {
    pub cid: u32,
    pub port: u32,
}

impl FromStr for VsockEndpoint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (cid, port) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("vsock endpoint must be `vsock://CID:PORT`"))?;

        if port.is_empty() {
            bail!("vsock endpoint port cannot be empty");
        }

        Ok(Self {
            cid: parse_cid(cid)?,
            port: port.parse()?,
        })
    }
}

/// Parse a vsock CID, accepting the standard symbolic aliases in addition to
/// numeric values. Well-known CIDs per the Linux vsock(7) convention:
/// - `hypervisor` → 0
/// - `local` → 1 (the host, when addressed from the host itself)
/// - `host` → 2 (the host, when addressed from a guest)
fn parse_cid(value: &str) -> Result<u32> {
    match value {
        "hypervisor" => Ok(0),
        "local" => Ok(1),
        "host" => Ok(2),
        "" => bail!("vsock endpoint CID cannot be empty"),
        cid => Ok(cid.parse()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_websocket_control_plane_url() {
        let config = TransportConfig {
            control_plane_url: "wss://dashboard.example.com/tetra/agent".into(),
            client_cert_path: Some("/etc/tetra/agent.crt".into()),
            client_key_path: Some("/etc/tetra/agent.key".into()),
            server_ca_path: Some("/etc/tetra/dashboard-ca.crt".into()),
        };

        assert_eq!(
            config.endpoint().unwrap(),
            TransportEndpoint::WebSocket {
                url: "wss://dashboard.example.com/tetra/agent".into()
            }
        );
    }

    #[test]
    fn parses_vsock_control_plane_url() {
        let config = TransportConfig {
            control_plane_url: "vsock://host:2048".into(),
            ..Default::default()
        };

        assert_eq!(
            config.endpoint().unwrap(),
            TransportEndpoint::Vsock(VsockEndpoint { cid: 2, port: 2048 })
        );
    }

    #[test]
    fn parses_numeric_vsock_cid() {
        assert_eq!(
            "vsock://42:2048".parse::<TransportEndpoint>().unwrap(),
            TransportEndpoint::Vsock(VsockEndpoint {
                cid: 42,
                port: 2048
            })
        );
    }

    #[test]
    fn deserializes_vsock_config_without_tls_paths() {
        let config: TransportConfig =
            serde_json::from_str(r#"{ "control_plane_url": "vsock://host:2048" }"#).unwrap();

        assert_eq!(config.client_cert_path, None);
        assert_eq!(
            config.endpoint().unwrap(),
            TransportEndpoint::Vsock(VsockEndpoint { cid: 2, port: 2048 })
        );
    }
}
