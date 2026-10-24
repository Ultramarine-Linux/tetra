//! On-disk record of a completed remote-control enrollment.
//!
//! Everything lives in one root-only directory (default
//! `/var/lib/tetra/remote`, mode `0700`, files `0600`):
//!
//! - `client.key`: PKCS#8 private key generated on this host. Never leaves it.
//! - `client.crt`: client certificate (and any chain) signed by the controller.
//! - `server-ca.crt`: CA bundle that verifies the controller's WSS endpoint.
//! - `controller.json`: host id, control-plane URL and enrollment URL.
//! - `client.crt.next`, `client.key.next`: a renewed certificate and its key,
//!   present only while a renewal is being tried (see [`super::renewal`]).
//!
//! `controller.json` is written last and removed first, so its presence is
//! what marks the host as enrolled.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use crate::agent::transport::TransportConfig;
use crate::prelude::*;

/// Default enrollment directory.
pub const DEFAULT_ENROLLMENT_DIR: &str = "/var/lib/tetra/remote";

const RECORD_FILE: &str = "controller.json";
const CLIENT_KEY_FILE: &str = "client.key";
const CLIENT_CERT_FILE: &str = "client.crt";
const SERVER_CA_FILE: &str = "server-ca.crt";

/// Record and credential files, in the order [`Enrollment::remove`] deletes them.
const FILES: [&str; 4] = [
    RECORD_FILE,
    CLIENT_CERT_FILE,
    CLIENT_KEY_FILE,
    SERVER_CA_FILE,
];
/// Renewal files staged next to the credentials, in the order
/// [`Enrollment::remove`] deletes them (key first, like a discarded renewal).
const STAGED_FILES: [&str; 2] = ["client.key.next", "client.crt.next"];

/// The controller this host is enrolled with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerRecord {
    /// Host id the controller assigned; sent in the `hello` frame.
    pub host_id: String,
    /// `wss://` endpoint the agent dials out to.
    pub control_plane_url: String,
    /// Base URL used for enrollment.
    pub dashboard_url: String,
}

/// PEM material saved alongside the [`ControllerRecord`].
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    pub client_key: &'a str,
    pub client_certificate: &'a str,
    pub server_ca: &'a str,
}

/// A completed enrollment loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub directory: PathBuf,
    pub controller: ControllerRecord,
}

impl Enrollment {
    /// Load the enrollment in `directory`, or `None` when the host is not
    /// enrolled.
    pub fn load(directory: &Path) -> Result<Option<Self>> {
        let path = directory.join(RECORD_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read enrollment `{}`", path.display()));
            }
        };
        let controller = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse enrollment `{}`", path.display()))?;
        Ok(Some(Self {
            directory: directory.to_owned(),
            controller,
        }))
    }

    /// Whether any enrollment file is present, including the leftovers of an
    /// interrupted enrollment.
    #[must_use]
    pub fn exists(directory: &Path) -> bool {
        FILES
            .iter()
            .chain(&STAGED_FILES)
            .any(|file| directory.join(file).exists())
    }

    /// Write the credentials and record into `directory`, creating it
    /// root-only. The record goes last so a partial write is never mistaken
    /// for a complete enrollment.
    pub fn save(
        directory: &Path,
        controller: ControllerRecord,
        credentials: Credentials<'_>,
    ) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .with_context(|| format!("failed to create `{}`", directory.display()))?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to restrict `{}`", directory.display()))?;

        write_private(&directory.join(CLIENT_KEY_FILE), credentials.client_key)?;
        write_private(
            &directory.join(CLIENT_CERT_FILE),
            credentials.client_certificate,
        )?;
        write_private(&directory.join(SERVER_CA_FILE), credentials.server_ca)?;
        write_private(
            &directory.join(RECORD_FILE),
            &serde_json::to_string_pretty(&controller)?,
        )?;
        Ok(Self {
            directory: directory.to_owned(),
            controller,
        })
    }

    /// Delete the record and credentials in `directory`. Returns whether
    /// anything was removed.
    pub fn remove(directory: &Path) -> Result<bool> {
        let mut removed = false;
        for file in FILES.into_iter().chain(STAGED_FILES) {
            let path = directory.join(file);
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to remove `{}`", path.display()));
                }
            }
        }
        Ok(removed)
    }

    /// Path of the client certificate.
    #[must_use]
    pub fn client_certificate_path(&self) -> PathBuf {
        self.directory.join(CLIENT_CERT_FILE)
    }

    /// Path of the client private key.
    #[must_use]
    pub fn client_key_path(&self) -> PathBuf {
        self.directory.join(CLIENT_KEY_FILE)
    }

    /// Outbound transport settings for this enrollment.
    #[must_use]
    pub fn transport(&self) -> TransportConfig {
        let path = |file: &str| Some(self.directory.join(file).to_string_lossy().into_owned());
        TransportConfig {
            control_plane_url: self.controller.control_plane_url.clone(),
            client_cert_path: path(CLIENT_CERT_FILE),
            client_key_path: path(CLIENT_KEY_FILE),
            server_ca_path: path(SERVER_CA_FILE),
        }
    }
}

/// Atomically write `contents` to `path` with mode `0600`.
pub(crate) fn write_private(path: &Path, contents: &str) -> Result<()> {
    let file_name = path
        .file_name()
        .context("enrollment path has no file name")?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("failed to create `{}`", temporary.display()))?;
    io::Write::write_all(&mut file, contents.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write `{}`", temporary.display()))?;
    // `mode` only applies to new files; a leftover temporary keeps its mode.
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict `{}`", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("failed to install `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ControllerRecord {
        ControllerRecord {
            host_id: "host-01".into(),
            control_plane_url: "wss://control.example.test/tetra/agent".into(),
            dashboard_url: "https://control.example.test".into(),
        }
    }

    const CREDENTIALS: Credentials<'static> = Credentials {
        client_key: "key",
        client_certificate: "cert",
        server_ca: "ca",
    };

    #[test]
    fn save_is_root_only_and_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("remote");
        let saved = Enrollment::save(&directory, record(), CREDENTIALS).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), 0o700);
        for file in FILES {
            assert_eq!(mode(&directory.join(file)), 0o600, "{file}");
        }
        assert_eq!(Enrollment::load(&directory).unwrap(), Some(saved.clone()));

        let transport = saved.transport();
        assert_eq!(
            transport.control_plane_url,
            "wss://control.example.test/tetra/agent"
        );
        assert_eq!(
            transport.client_key_path.as_deref(),
            Some(directory.join("client.key").to_str().unwrap())
        );
        transport.validate(&transport.control_plane_url).unwrap();
    }

    #[test]
    fn remove_deletes_everything_and_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("remote");
        Enrollment::save(&directory, record(), CREDENTIALS).unwrap();

        assert!(Enrollment::remove(&directory).unwrap());
        assert!(!Enrollment::exists(&directory));
        assert_eq!(Enrollment::load(&directory).unwrap(), None);
        assert!(!Enrollment::remove(&directory).unwrap());
    }

    #[test]
    fn remove_deletes_a_staged_renewal() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("remote");
        let saved = Enrollment::save(&directory, record(), CREDENTIALS).unwrap();
        let files =
            crate::enrollment::renewal::ClientFiles::from_transport(&saved.transport()).unwrap();
        files.stage("new key", "new cert").unwrap();
        for file in STAGED_FILES {
            assert!(directory.join(file).exists(), "{file}");
        }

        assert!(Enrollment::remove(&directory).unwrap());
        assert!(!Enrollment::exists(&directory));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    }

    #[test]
    fn partial_enrollment_exists_but_does_not_load() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(CLIENT_KEY_FILE), "key").unwrap();
        assert!(Enrollment::exists(root.path()));
        assert_eq!(Enrollment::load(root.path()).unwrap(), None);
    }
}
