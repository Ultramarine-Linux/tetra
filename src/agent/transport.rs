use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Connection parameters the `agent-connect` subcommand loads from a JSON
/// config file.
///
/// `control_plane_url` must be `wss://`; the TLS paths configure mTLS to the
/// control plane.
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
    /// The `wss://` control-plane URL, once the mTLS material is configured.
    ///
    /// # Errors
    /// Fails for any other scheme (`ws://` is development-only and not
    /// accepted here) or when a TLS path is missing.
    pub fn wss_url(&self) -> Result<&str> {
        let url = self.control_plane_url.as_str();
        ensure!(
            url.starts_with("wss://"),
            "outbound control-plane transport requires a wss:// URL, got `{url}`"
        );
        ensure!(
            self.client_cert_path.is_some()
                && self.client_key_path.is_some()
                && self.server_ca_path.is_some(),
            "wss control-plane transport requires client_cert_path, client_key_path, and server_ca_path"
        );
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(url: &str) -> TransportConfig {
        TransportConfig {
            control_plane_url: url.into(),
            client_cert_path: Some("client.crt".into()),
            client_key_path: Some("client.key".into()),
            server_ca_path: Some("ca.crt".into()),
        }
    }

    #[test]
    fn accepts_only_complete_wss_configurations() {
        let url = "wss://dashboard.example.com/tetra/agent";
        assert_eq!(config(url).wss_url().unwrap(), url);
        for url in ["ws://127.0.0.1:7780", "vsock://host:2048", "https://x"] {
            config(url).wss_url().unwrap_err();
        }
        let incomplete = TransportConfig {
            control_plane_url: url.into(),
            ..Default::default()
        };
        incomplete.wss_url().unwrap_err();
    }
}
