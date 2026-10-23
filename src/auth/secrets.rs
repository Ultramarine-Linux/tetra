//! Credentials Tetra holds for other services: `/var/lib/tetra/secrets`.
//!
//! DNS-01 credentials for Caddy and the Cloudflare Tunnel token are each
//! sealed with the [`Sealer`] (`systemd-creds encrypt`, bound to the TPM2
//! when there is one) under their credential name and kept as
//! `<name>.cred`, root-only. Because the file is an ordinary encrypted
//! systemd credential, a unit can load it directly with
//! `LoadCredentialEncrypted=<name>:<path>` without Tetra ever writing the
//! plain value to disk; Tetra unseals it again when it needs the value itself.
//!
//! Values never appear in command lines, unit files or logs.

use crate::prelude::*;

use super::{seal::Sealer, store};

/// Credential name of the DNS-01 credentials for the dashboard's site.
pub const DNS_CREDENTIALS: &str = "tetra-dns-credentials";
/// Credential name of the Cloudflare Tunnel token.
pub const CLOUDFLARED_TOKEN: &str = "tetra-cloudflared-token";

/// Sealed credentials in one directory.
#[derive(Debug, Clone)]
pub struct SecretStore {
    dir: PathBuf,
}

impl SecretStore {
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The file holding `name`, whether or not it exists.
    ///
    /// # Errors
    /// Fails when `name` is not a valid credential name.
    pub fn path(&self, name: &str) -> Result<PathBuf> {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "invalid credential name `{name}`"
        );
        Ok(self.dir.join(format!("{name}.cred")))
    }

    /// Seal `value` under `name`, replacing any previous value.
    ///
    /// # Errors
    /// Fails when the value cannot be sealed or written.
    pub fn put(&self, sealer: &dyn Sealer, name: &str, value: &[u8]) -> Result<PathBuf> {
        let path = self.path(name)?;
        let blob = sealer
            .seal(name, value)
            .with_context(|| format!("failed to seal {name}"))?;
        store::write_bytes(&path, &blob, 0o600)?;
        Ok(path)
    }

    /// Unseal `name`, or `None` when it is not stored.
    ///
    /// # Errors
    /// Fails when the file cannot be read or unsealed.
    pub fn get(&self, sealer: &dyn Sealer, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(name)?;
        let blob = match fs::read(&path) {
            Ok(blob) => blob,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read `{}`", path.display()));
            }
        };
        sealer
            .unseal(name, &blob)
            .with_context(|| format!("failed to unseal `{}`", path.display()))
            .map(Some)
    }

    /// Forget `name`. Missing is fine.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be removed.
    pub fn remove(&self, name: &str) -> Result<()> {
        store::remove(&self.path(name)?)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::auth::testing::FakeSealer;

    #[test]
    fn values_are_sealed_private_and_removable() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretStore::new(dir.path().join("secrets"));
        let path = secrets
            .put(&FakeSealer, CLOUDFLARED_TOKEN, b"token-value")
            .unwrap();
        assert_eq!(
            path,
            dir.path().join("secrets/tetra-cloudflared-token.cred")
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // Sealed under its own name: the blob does not unseal as another one.
        assert_eq!(
            secrets
                .get(&FakeSealer, CLOUDFLARED_TOKEN)
                .unwrap()
                .unwrap(),
            b"token-value"
        );
        fs::copy(&path, secrets.path(DNS_CREDENTIALS).unwrap()).unwrap();
        secrets.get(&FakeSealer, DNS_CREDENTIALS).unwrap_err();

        secrets.remove(CLOUDFLARED_TOKEN).unwrap();
        secrets.remove(CLOUDFLARED_TOKEN).unwrap();
        assert_eq!(secrets.get(&FakeSealer, CLOUDFLARED_TOKEN).unwrap(), None);
    }

    #[test]
    fn names_cannot_escape_the_directory() {
        let secrets = SecretStore::new("/var/lib/tetra/secrets".into());
        for name in ["", "../x", "a/b", "UPPER", "x.cred"] {
            secrets.path(name).unwrap_err();
        }
    }
}
