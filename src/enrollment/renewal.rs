//! Client certificate renewal over the outbound mTLS session.
//!
//! At two-thirds of the client certificate's lifetime the agent generates a
//! fresh key and CSR and sends it in a `renew` frame. When the controller
//! answers with a signed certificate, the new key and certificate are staged
//! next to the current ones as `<file>.next`, the session is closed, and the
//! agent reconnects with the staged pair. Only once that connection is
//! accepted are the staged files renamed over the current ones; if it is
//! refused, the staged pair is discarded and the old certificate stays in use.
//! See `docs/remote-enrollment.md` for the controller side.
//!
//! The certificate and key cannot be swapped in one rename, so the order of
//! file operations is fixed and [`ClientFiles::recover`] finishes or undoes
//! whatever an interrupted run left behind:
//!
//! - staging writes `client.crt.next`, then `client.key.next`;
//! - promotion renames `client.crt.next`, then `client.key.next`;
//! - discarding removes `client.key.next`, then `client.crt.next`.
//!
//! So a lone `client.key.next` can only mean promotion was interrupted (finish
//! it), and a lone `client.crt.next` that staging or discarding was (remove
//! it).

use std::time::Duration;

use rcgen::KeyPair;

use super::{certificate_signing_request, check_client_certificate, store::write_private};
use crate::agent::transport::TransportConfig;
use crate::prelude::*;

/// Suffix of a staged certificate or key.
const STAGED_SUFFIX: &str = ".next";
/// Bounds for the wait before retrying a failed renewal.
const MIN_RETRY_DELAY: Duration = Duration::from_mins(1);
const MAX_RETRY_DELAY: Duration = Duration::from_hours(1);

/// The client certificate and key an outbound connection presents, and where
/// a renewed pair is staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl ClientFiles {
    /// The client files `transport` uses, or `None` when it has no client
    /// certificate (an incomplete config).
    #[must_use]
    pub fn from_transport(transport: &TransportConfig) -> Option<Self> {
        Some(Self {
            certificate: transport.client_cert_path.as_deref()?.into(),
            key: transport.client_key_path.as_deref()?.into(),
        })
    }

    fn staged_certificate(&self) -> PathBuf {
        staged(&self.certificate)
    }

    fn staged_key(&self) -> PathBuf {
        staged(&self.key)
    }

    /// Whether a renewed pair is staged and waiting to be tried.
    #[must_use]
    pub fn is_staged(&self) -> bool {
        self.staged_certificate().exists() && self.staged_key().exists()
    }

    /// `transport` with the staged pair in place of the current one.
    #[must_use]
    pub fn staged_transport(&self, transport: &TransportConfig) -> TransportConfig {
        let path = |path: PathBuf| Some(path.to_string_lossy().into_owned());
        TransportConfig {
            client_cert_path: path(self.staged_certificate()),
            client_key_path: path(self.staged_key()),
            ..transport.clone()
        }
    }

    /// Stage a renewed key and certificate without touching the current ones.
    pub fn stage(&self, key: &str, certificate: &str) -> Result<()> {
        write_private(&self.staged_certificate(), certificate)?;
        write_private(&self.staged_key(), key)
    }

    /// Replace the current pair with the staged one.
    pub fn promote(&self) -> Result<()> {
        rename(&self.staged_certificate(), &self.certificate)?;
        rename(&self.staged_key(), &self.key)
    }

    /// Delete the staged pair, keeping the current one.
    pub fn discard(&self) -> Result<()> {
        remove_if_present(&self.staged_key())?;
        remove_if_present(&self.staged_certificate())
    }

    /// Finish a promotion or drop a partial stage left by an interrupted run.
    pub fn recover(&self) -> Result<()> {
        match (
            self.staged_certificate().exists(),
            self.staged_key().exists(),
        ) {
            (false, true) => {
                eprintln!("finishing an interrupted client certificate renewal");
                rename(&self.staged_key(), &self.key)
            }
            (true, false) => remove_if_present(&self.staged_certificate()),
            _ => Ok(()),
        }
    }
}

fn staged(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(STAGED_SUFFIX);
    name.into()
}

fn rename(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)
        .with_context(|| format!("failed to move `{}` to `{}`", from.display(), to.display()))
}

fn remove_if_present(path: &Path) -> Result<()> {
    crate::auth::store::remove(path)
}

/// Validity window of a client certificate, in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime {
    not_before: i64,
    not_after: i64,
}

impl Lifetime {
    /// Read the leaf certificate's validity from the PEM file at `path`.
    pub fn read(path: &Path) -> Result<Self> {
        use rustls::pki_types::{CertificateDer, pem::PemObject as _};
        let pem = fs::read(path)
            .with_context(|| format!("failed to read client certificate `{}`", path.display()))?;
        let leaf = CertificateDer::pem_slice_iter(&pem)
            .next()
            .context("client certificate PEM is empty")?
            .context("failed to parse client certificate PEM")?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&leaf)
            .map_err(|error| anyhow::anyhow!("failed to parse client certificate: {error}"))?;
        let validity = certificate.validity();
        Ok(Self {
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
        })
    }

    /// When renewal is due: two-thirds of the way through the lifetime.
    #[must_use]
    pub fn renew_at(&self) -> SystemTime {
        let lifetime = self.not_after.saturating_sub(self.not_before);
        unix_time(
            self.not_before
                .saturating_add(lifetime.saturating_mul(2) / 3),
        )
    }

    /// How long to wait after a failed renewal: a tenth of the remaining
    /// lifetime, between one minute and one hour.
    #[must_use]
    pub fn retry_delay(&self, now: SystemTime) -> Duration {
        unix_time(self.not_after)
            .duration_since(now)
            .unwrap_or_default()
            .checked_div(10)
            .unwrap_or_default()
            .clamp(MIN_RETRY_DELAY, MAX_RETRY_DELAY)
    }
}

fn unix_time(seconds: i64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(u64::try_from(seconds).unwrap_or(0)))
        .unwrap_or(UNIX_EPOCH)
}

/// A renewal in flight: the freshly generated key and the CSR sent for it.
#[derive(Debug)]
pub struct Request {
    key_pair: KeyPair,
    pub csr: String,
}

impl Request {
    /// Generate a new key and a `clientAuth` CSR for it.
    pub fn new(common_name: &str) -> Result<Self> {
        let key_pair = KeyPair::generate().context("failed to generate client key pair")?;
        let csr = certificate_signing_request(&key_pair, common_name)?;
        Ok(Self { key_pair, csr })
    }

    /// Check the controller's certificate against our key and stage it with
    /// the key in `files`. Nothing is written if the check fails.
    pub fn stage(&self, files: &ClientFiles, certificate: &str) -> Result<()> {
        check_client_certificate(certificate, &self.key_pair)
            .context("controller returned an unusable renewed certificate")?;
        files.stage(&self.key_pair.serialize_pem(), certificate)
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose};

    use super::*;

    fn files(root: &Path) -> ClientFiles {
        let files = ClientFiles {
            certificate: root.join("client.crt"),
            key: root.join("client.key"),
        };
        fs::write(&files.certificate, "old cert").unwrap();
        fs::write(&files.key, "old key").unwrap();
        files
    }

    fn contents(files: &ClientFiles) -> (String, String) {
        (
            fs::read_to_string(&files.certificate).unwrap(),
            fs::read_to_string(&files.key).unwrap(),
        )
    }

    fn certificate_for(key_pair: &KeyPair) -> String {
        let mut params = CertificateParams::default();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.self_signed(key_pair).unwrap().pem()
    }

    #[test]
    fn staged_files_sit_next_to_the_current_ones() {
        let transport = TransportConfig {
            control_plane_url: "wss://control.example.test/tetra/agent".into(),
            client_cert_path: Some("/var/lib/tetra/remote/client.crt".into()),
            client_key_path: Some("/var/lib/tetra/remote/client.key".into()),
            server_ca_path: Some("/var/lib/tetra/remote/server-ca.crt".into()),
        };
        let files = ClientFiles::from_transport(&transport).unwrap();
        let staged = files.staged_transport(&transport);
        assert_eq!(
            staged.client_cert_path.as_deref(),
            Some("/var/lib/tetra/remote/client.crt.next")
        );
        assert_eq!(
            staged.client_key_path.as_deref(),
            Some("/var/lib/tetra/remote/client.key.next")
        );
        assert_eq!(staged.server_ca_path, transport.server_ca_path);
    }

    #[test]
    fn promote_replaces_the_current_pair() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        files.stage("new key", "new cert").unwrap();
        assert!(files.is_staged());
        assert_eq!(contents(&files), ("old cert".into(), "old key".into()));

        files.promote().unwrap();
        assert!(!files.is_staged());
        assert_eq!(contents(&files), ("new cert".into(), "new key".into()));
    }

    #[test]
    fn discard_keeps_the_current_pair() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        files.stage("new key", "new cert").unwrap();
        files.discard().unwrap();
        files.discard().unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
        assert_eq!(contents(&files), ("old cert".into(), "old key".into()));
    }

    #[test]
    fn recover_finishes_an_interrupted_promotion() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        files.stage("new key", "new cert").unwrap();
        // Crash after the certificate was renamed but before the key was.
        rename(&files.staged_certificate(), &files.certificate).unwrap();

        files.recover().unwrap();
        assert_eq!(contents(&files), ("new cert".into(), "new key".into()));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn recover_drops_a_partial_stage() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        // Crash after the certificate was staged but before the key was.
        write_private(&files.staged_certificate(), "new cert").unwrap();

        files.recover().unwrap();
        assert_eq!(contents(&files), ("old cert".into(), "old key".into()));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn recover_leaves_a_complete_stage_to_be_tried() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        files.stage("new key", "new cert").unwrap();
        files.recover().unwrap();
        assert!(files.is_staged());
        assert_eq!(contents(&files), ("old cert".into(), "old key".into()));
    }

    #[test]
    fn request_stages_a_certificate_for_its_key() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        let request = Request::new("host-01").unwrap();
        request
            .stage(&files, &certificate_for(&request.key_pair))
            .unwrap();
        assert!(files.is_staged());
        assert_eq!(
            fs::read_to_string(files.staged_key()).unwrap(),
            request.key_pair.serialize_pem()
        );
    }

    #[test]
    fn request_refuses_a_certificate_for_another_key() {
        let root = tempfile::tempdir().unwrap();
        let files = files(root.path());
        let request = Request::new("host-01").unwrap();
        let other = KeyPair::generate().unwrap();
        let error = request.stage(&files, &certificate_for(&other)).unwrap_err();
        assert!(
            format!("{error:#}").contains("not for the key"),
            "{error:#}"
        );
        assert!(!files.staged_certificate().exists());
        assert!(!files.staged_key().exists());
        assert_eq!(contents(&files), ("old cert".into(), "old key".into()));
    }

    #[test]
    fn renewal_is_due_at_two_thirds_of_the_lifetime() {
        let lifetime = Lifetime {
            not_before: 1_000,
            not_after: 4_000,
        };
        assert_eq!(lifetime.renew_at(), unix_time(3_000));
    }

    #[test]
    fn retry_delay_is_bounded() {
        let day = 86_400;
        let lifetime = Lifetime {
            not_before: 0,
            not_after: 90 * day,
        };
        assert_eq!(lifetime.retry_delay(unix_time(0)), MAX_RETRY_DELAY);
        assert_eq!(
            lifetime.retry_delay(unix_time(90 * day - 60)),
            MIN_RETRY_DELAY
        );
        // Already expired.
        assert_eq!(lifetime.retry_delay(unix_time(91 * day)), MIN_RETRY_DELAY);
        let lifetime = Lifetime {
            not_before: 0,
            not_after: 10_000,
        };
        assert_eq!(
            lifetime.retry_delay(unix_time(0)),
            Duration::from_secs(1_000)
        );
    }
}
