//! Persistent Tetra host identity for authenticated transport enrollment.

use crate::prelude::*;

use ed25519_dalek::{SigningKey, VerifyingKey};

const PRIVATE_KEY_FILE: &str = "ed25519-private.key";
const CONTROLLER_PUBLIC_KEY_FILE: &str = "controller-ed25519-public.key";
const PRIVATE_KEY_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct HostIdentity {
    signing_key: SigningKey,
    path: PathBuf,
}

impl HostIdentity {
    /// Load an existing host identity from the given directory, or generate a new one if none exists.
    ///
    /// # Errors
    /// Returns an error if the identity directory cannot be created, or the private key cannot be
    /// generated or is invalid.
    pub fn load_or_generate<P: AsRef<Path>>(directory: P) -> Result<Self> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory).with_context(|| {
            format!(
                "failed to create identity directory `{}`",
                directory.display()
            )
        })?;
        let path = directory.join(PRIVATE_KEY_FILE);
        let bytes: [u8; PRIVATE_KEY_BYTES] = if path.exists() {
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read host identity `{}`", path.display()))?;
            (bytes.try_into()).map_err(|_| anyhow::anyhow!("host identity length checked"))?
        } else {
            let mut bytes = [0_u8; PRIVATE_KEY_BYTES];
            rand::fill(&mut bytes);
            let temporary =
                directory.join(format!(".{PRIVATE_KEY_FILE}.tmp-{}", std::process::id()));
            fs::write(&temporary, bytes).with_context(|| {
                format!(
                    "failed to write temporary host identity `{}`",
                    temporary.display()
                )
            })?;
            fs::set_permissions(&temporary, permissions_private()).with_context(|| {
                format!("failed to restrict host identity `{}`", temporary.display())
            })?;
            fs::rename(&temporary, &path)
                .with_context(|| format!("failed to install host identity `{}`", path.display()))?;
            bytes
        };

        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
            path,
        })
    }

    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the directory that holds the identity files.
    ///
    /// # Panics
    ///
    /// Panics if the identity path somehow has no parent directory. This
    /// should never happen because the path is built from a directory plus
    /// a filename.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.path
            .parent()
            .expect("identity path always has a parent")
    }

    /// Load the controller public key from the identity directory, if it exists.
    ///
    /// # Errors
    /// Returns an error if the controller public key file exists but cannot be read or is empty.
    /// Note that `Ok(None)` is returned if the file does not exist, which is not considered an error.
    pub fn load_controller_key(&self) -> Result<Option<String>> {
        let path = self.directory().join(CONTROLLER_PUBLIC_KEY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read controller key `{}`", path.display()))?;
        let value = value.trim().to_owned();
        ensure!(!value.is_empty(), "controller public key is empty");
        Ok(Some(value))
    }

    /// Enroll the given controller public key.
    ///
    /// # Errors
    /// Returns an error if the public key is empty, or if the controller public key file cannot be written or is restricted.
    pub fn enroll_controller_key(&self, public_key: &str) -> Result<()> {
        let public_key = public_key.trim();
        ensure!(
            !public_key.is_empty(),
            "controller public key cannot be empty"
        );
        let path = self.directory().join(CONTROLLER_PUBLIC_KEY_FILE);
        let temporary = self.directory().join(format!(
            ".{CONTROLLER_PUBLIC_KEY_FILE}.tmp-{}",
            std::process::id()
        ));
        fs::write(&temporary, format!("{}\n", public_key.trim())).with_context(|| {
            format!(
                "failed to write temporary controller key `{}`",
                temporary.display()
            )
        })?;
        fs::set_permissions(&temporary, permissions_private()).with_context(|| {
            format!(
                "failed to restrict controller key `{}`",
                temporary.display()
            )
        })?;
        fs::rename(&temporary, &path)
            .with_context(|| format!("failed to install controller key `{}`", path.display()))?;
        Ok(())
    }
}

#[cfg(unix)]
fn permissions_private() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(0o600)
}

#[cfg(not(unix))]
fn permissions_private() -> std::fs::Permissions {
    std::fs::Permissions::readonly()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persists_identity_across_loads() {
        let directory = tempdir().unwrap();
        let first = HostIdentity::load_or_generate(directory.path()).unwrap();
        let first_public = first.verifying_key();
        let second = HostIdentity::load_or_generate(directory.path()).unwrap();
        assert_eq!(first_public, second.verifying_key());
        assert_eq!(second.path(), directory.path().join(PRIVATE_KEY_FILE));
    }
}
