//! Runtime configuration read from `/etc/tetra/tetra.json`.
//!
//! The file is optional: a missing file means every setting takes its default,
//! and every remote-facing feature defaults to off. Tetra re-reads the file on
//! `SIGHUP` (`systemctl reload tetra.service`).
//!
//! After `tetra enroll`, turning remote control on only needs the gate; the
//! host id and transport come from the enrollment record:
//!
//! ```json
//! { "remote": { "enabled": true } }
//! ```
//!
//! `remote.host_id` and `remote.transport` override the enrollment when set.

use std::{fs, io::ErrorKind, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{transport::TransportConfig, websocket::WebSocketAgentConfig};
use crate::enrollment::store::Enrollment;

/// Default runtime configuration path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tetra/tetra.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub remote: RemoteConfig,
}

/// Settings for the outbound mTLS control-plane connection (`remote.*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteConfig {
    /// Whether Tetra may connect out at all. Off by default.
    pub enabled: bool,
    /// Stable control-plane host id for this agent. Defaults to the enrolled
    /// host id.
    pub host_id: Option<String>,
    /// Control-plane URL and mTLS material. Defaults to the enrollment.
    pub transport: Option<TransportConfig>,
    /// Reconnect with backoff when the session closes.
    pub reconnect: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host_id: None,
            transport: None,
            reconnect: true,
        }
    }
}

impl RuntimeConfig {
    /// Read the config at `path`. A missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read config `{}`", path.display()));
            }
        };
        serde_json::from_str(&text)
            .with_context(|| format!("failed to parse config `{}`", path.display()))
    }

    /// Read the config at `path` for the purpose of deciding whether to
    /// connect out. Fails closed: an unreadable or invalid file disables the
    /// remote connection rather than keeping a stale setting.
    #[must_use]
    pub fn load_or_disabled(path: &Path) -> Self {
        Self::load(path).unwrap_or_else(|error| {
            eprintln!("{error:#}; remote control disabled until the config is fixed");
            Self::default()
        })
    }
}

impl RemoteConfig {
    /// The outbound connection to run, or `None` when remote control is
    /// disabled. Settings missing from the config come from `enrollment`.
    /// Errors when it is enabled but neither supplies them.
    ///
    /// Disabling remote control leaves the enrollment in place; it only stops
    /// the connection.
    pub fn connection(
        &self,
        enrollment: Option<&Enrollment>,
    ) -> Result<Option<WebSocketAgentConfig>> {
        if !self.enabled {
            return Ok(None);
        }
        let host_id = self
            .host_id
            .clone()
            .or_else(|| enrollment.map(|enrollment| enrollment.controller.host_id.clone()))
            .context("remote.enabled is true but this host is not enrolled; run `tetra enroll` or set remote.host_id")?;
        let transport = self
            .transport
            .clone()
            .or_else(|| enrollment.map(Enrollment::transport))
            .context("remote.enabled is true but this host is not enrolled; run `tetra enroll` or set remote.transport")?;
        Ok(Some(WebSocketAgentConfig {
            transport,
            host_id,
            reconnect: self.reconnect,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_disables_remote() {
        let dir = tempfile::tempdir().unwrap();
        let config = RuntimeConfig::load(&dir.path().join("tetra.json")).unwrap();
        assert!(!config.remote.enabled);
        assert_eq!(config.remote.connection(None).unwrap(), None);
    }

    #[test]
    fn invalid_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tetra.json");
        fs::write(&path, r#"{ "remote": { "enabled": true, "typo": 1 } }"#).unwrap();
        RuntimeConfig::load(&path).unwrap_err();
        assert!(!RuntimeConfig::load_or_disabled(&path).remote.enabled);
    }

    #[test]
    fn enabled_remote_requires_host_id_and_transport() {
        let remote = RemoteConfig {
            enabled: true,
            ..Default::default()
        };
        remote.connection(None).unwrap_err();
    }

    #[test]
    fn enabled_remote_yields_connection() {
        let config: RuntimeConfig = serde_json::from_str(
            r#"{ "remote": {
                "enabled": true,
                "host_id": "host-01",
                "transport": { "control_plane_url": "wss://control.example.test/tetra" }
            } }"#,
        )
        .unwrap();
        let connection = config.remote.connection(None).unwrap().unwrap();
        assert_eq!(connection.host_id, "host-01");
        assert!(connection.reconnect);
    }

    fn enrollment() -> Enrollment {
        Enrollment {
            directory: "/var/lib/tetra/remote".into(),
            controller: crate::enrollment::store::ControllerRecord {
                host_id: "enrolled-host".into(),
                control_plane_url: "wss://control.example.test/tetra/agent".into(),
                dashboard_url: "https://control.example.test".into(),
            },
        }
    }

    #[test]
    fn enabled_remote_uses_the_enrollment() {
        let config: RuntimeConfig =
            serde_json::from_str(r#"{ "remote": { "enabled": true } }"#).unwrap();
        let enrollment = enrollment();
        let connection = config
            .remote
            .connection(Some(&enrollment))
            .unwrap()
            .unwrap();
        assert_eq!(connection.host_id, "enrolled-host");
        assert_eq!(connection.transport, enrollment.transport());
    }

    #[test]
    fn disabled_remote_keeps_the_enrollment_but_does_not_connect() {
        let config: RuntimeConfig =
            serde_json::from_str(r#"{ "remote": { "enabled": false } }"#).unwrap();
        assert_eq!(config.remote.connection(Some(&enrollment())).unwrap(), None);
    }

    #[test]
    fn explicit_settings_override_the_enrollment() {
        let config: RuntimeConfig = serde_json::from_str(
            r#"{ "remote": { "enabled": true, "host_id": "configured-host" } }"#,
        )
        .unwrap();
        let enrollment = enrollment();
        let connection = config
            .remote
            .connection(Some(&enrollment))
            .unwrap()
            .unwrap();
        assert_eq!(connection.host_id, "configured-host");
        assert_eq!(connection.transport, enrollment.transport());
    }
}
