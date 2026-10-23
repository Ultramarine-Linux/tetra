//! Persistent Tetra host identity.
//!
//! An Ed25519 key generated on first start. Its public key is the host
//! fingerprint Tetra reports in the session protocol's `hello` frame, so a
//! client can tell when it is talking to a different (or reinstalled) host.

use crate::prelude::*;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};

const PRIVATE_KEY_FILE: &str = "ed25519-private.key";
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
        let bytes: [u8; PRIVATE_KEY_BYTES] = match fs::read(&path) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("host identity `{}` is corrupt", path.display()))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut bytes = [0_u8; PRIVATE_KEY_BYTES];
                rand::fill(&mut bytes);
                crate::auth::store::replace(&path, &bytes, 0o600)?;
                bytes
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read host identity `{}`", path.display()));
            }
        };

        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
            path,
        })
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Return a compact public-key fingerprint for `hello` and logs.
#[must_use]
pub fn public_key_fingerprint(verifying_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
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
