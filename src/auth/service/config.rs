//! [`AuthConfig`]: where the auth service keeps its files.

use crate::{
    auth::{sessions::SessionPolicy, setup::SetupPaths},
    prelude::*,
};

use super::CADDY_SITES_DIR;

/// Filesystem locations.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// `/var/lib/tetra`.
    pub state_dir: PathBuf,
    /// `/run/tetra`.
    pub run_dir: PathBuf,
    /// `/run/issue.d`.
    pub issue_dir: PathBuf,
    /// Caddy site directory (terra-caddy's `/etc/caddy/Caddyfile.d`) for the
    /// dashboard's and the OOBE's sites.
    pub caddy_sites_dir: PathBuf,
    /// DNS-01 credentials for Caddy (`/etc/caddy/tetra-dns.env`).
    pub caddy_env_file: PathBuf,
    /// The root certificate of Caddy's internal CA, whose fingerprint the
    /// console shows during setup.
    pub caddy_root_ca: PathBuf,
    /// Unit drop-ins (`/etc/systemd/system`).
    pub systemd_dir: PathBuf,
    /// The dashboard container's environment (`/etc/ultramarine-dashboard/env`).
    pub dashboard_env_file: PathBuf,
    /// This binary, run by the handoff timer.
    pub tetra_binary: PathBuf,
    /// Dashboard address for the Caddy site when `access.set` does not name
    /// one.
    pub dashboard_upstream: String,
    /// Where the launcher's public page is written, readable by Caddy.
    pub public_dir: PathBuf,
    pub session_policy: SessionPolicy,
}

impl AuthConfig {
    /// Production paths under `state_dir`
    /// ([`DEFAULT_STATE_DIR`](super::DEFAULT_STATE_DIR) unless moved).
    #[must_use]
    pub fn system(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            run_dir: "/run/tetra".into(),
            issue_dir: "/run/issue.d".into(),
            caddy_sites_dir: CADDY_SITES_DIR.into(),
            caddy_env_file: "/etc/caddy/tetra-dns.env".into(),
            // `caddy.service` runs as `caddy` with HOME=/var/lib/caddy, so
            // its data directory is ~/.local/share/caddy.
            caddy_root_ca: "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt"
                .into(),
            systemd_dir: "/etc/systemd/system".into(),
            dashboard_env_file: "/etc/ultramarine-dashboard/env".into(),
            tetra_binary: "/usr/bin/tetra".into(),
            dashboard_upstream: crate::auth::access::DEFAULT_DASHBOARD_UPSTREAM.to_owned(),
            public_dir: crate::auth::launcher::DEFAULT_PUBLIC_DIR.into(),
            session_policy: SessionPolicy::default(),
        }
    }

    /// The agent's modules, with the ones that keep files under these
    /// directories (remote access and updates) using these paths.
    #[must_use]
    pub fn dispatcher(&self) -> crate::agent::Dispatcher {
        let dispatcher = crate::agent::Dispatcher::full().with_session_revocation(
            crate::auth::users::UserStore::new(self.auth_dir().join("users")),
            std::sync::Arc::new(crate::auth::accounts::SystemAccounts::default()),
        );
        #[cfg(feature = "updates")]
        let dispatcher = {
            use crate::agent::modules::updates::{Paths, UpdatesModule};
            dispatcher.with_module(UpdatesModule::with_paths(Paths::for_config(self)))
        };
        #[cfg(feature = "remote-access")]
        let dispatcher = {
            use crate::agent::modules::remote_access::{Paths, RemoteAccessModule};
            dispatcher.with_module(RemoteAccessModule::with_paths(Paths::for_config(self)))
        };
        dispatcher
    }

    #[must_use]
    pub fn auth_dir(&self) -> PathBuf {
        self.state_dir.join("auth")
    }

    #[must_use]
    pub fn access_path(&self) -> PathBuf {
        self.state_dir.join("access.json")
    }

    /// Sealed credentials for other services.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    #[must_use]
    pub fn launcher_path(&self) -> PathBuf {
        self.state_dir.join("launcher.json")
    }

    #[must_use]
    pub fn store_key_path(&self) -> PathBuf {
        self.auth_dir().join("store-key.cred")
    }

    #[must_use]
    pub fn setup_paths(&self) -> SetupPaths {
        SetupPaths {
            state_dir: self.state_dir.clone(),
            auth_dir: self.auth_dir(),
            run_dir: self.run_dir.clone(),
            issue_dir: self.issue_dir.clone(),
        }
    }
}
