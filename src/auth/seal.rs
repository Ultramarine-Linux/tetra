//! Encryption at rest for stored secrets (TOTP secrets, the setup code).
//!
//! One random 32-byte store key protects every secret. The key itself is
//! sealed with `systemd-creds` (`--with-key=auto`: bound to the TPM2 when the
//! machine has one, plus the host key in `/var/lib/systemd`) and kept at
//! `/var/lib/tetra/auth/store-key.cred`. Tetra unseals it once and then
//! encrypts individual values with XChaCha20-Poly1305, binding each one to
//! its purpose through the associated data, so a ciphertext copied into
//! another record does not decrypt.
//!
//! The key is not bound to TPM PCRs, so firmware or Secure Boot updates do not
//! lock the server out. If the key ever cannot be unsealed (for example after
//! clearing the TPM), Tetra refuses TOTP logins for enrolled users instead of
//! starting without the key; `tetra auth reset-2fa` recovers them from the
//! console.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

use crate::prelude::*;

use super::store;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
/// Credential name passed to `systemd-creds`; the sealed blob only decrypts
/// under the same name.
const CREDENTIAL_NAME: &str = "tetra-auth-store";

/// Seals and unseals small blobs with a host-bound key.
pub trait Sealer: Send + Sync {
    /// # Errors
    /// Fails when the backend cannot seal the value.
    fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// # Errors
    /// Fails when the blob was not sealed by this host under `name`.
    fn unseal(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>>;
}

/// [`Sealer`] backed by `systemd-creds encrypt`/`decrypt`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemdCreds;

impl SystemdCreds {
    fn run(args: &[String], input: &[u8]) -> Result<Vec<u8>> {
        let mut child = Command::new("systemd-creds")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to run systemd-creds")?;
        child
            .stdin
            .take()
            .context("systemd-creds stdin")?
            .write_all(input)?;
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "systemd-creds {} failed: {}",
            args.first().map_or("", String::as_str),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }
}

impl Sealer for SystemdCreds {
    fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::run(
            &[
                "encrypt".into(),
                format!("--name={name}"),
                "--with-key=auto".into(),
                // No PCR binding: firmware updates must not brick logins.
                "--tpm2-pcrs=".into(),
                "-".into(),
                "-".into(),
            ],
            plaintext,
        )
    }

    fn unseal(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        Self::run(
            &[
                "decrypt".into(),
                format!("--name={name}"),
                "-".into(),
                "-".into(),
            ],
            sealed,
        )
    }
}

/// An encrypted value as stored in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Base64 `XChaCha20` nonce.
    pub nonce: String,
    /// Base64 ciphertext with the Poly1305 tag.
    pub ciphertext: String,
}

/// The unsealed store key.
pub struct StoreKey {
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(..)")
    }
}

impl StoreKey {
    /// Unseal the key at `path`, or create and seal a new one when the file
    /// does not exist. An existing key that fails to unseal is an error and is
    /// never replaced automatically.
    ///
    /// # Errors
    /// Fails when the key cannot be unsealed, generated or written.
    pub fn load_or_create(path: &Path, sealer: &dyn Sealer) -> Result<Self> {
        let key = if let Some(blob) = read_optional(path)? {
            let key = sealer
                .unseal(CREDENTIAL_NAME, &blob)
                .with_context(|| format!("failed to unseal `{}`", path.display()))?;
            ensure!(key.len() == KEY_BYTES, "store key has the wrong length");
            key
        } else {
            let mut key = vec![0_u8; KEY_BYTES];
            rand::fill(&mut key[..]);
            let blob = sealer.seal(CREDENTIAL_NAME, &key)?;
            store::write_bytes(path, &blob, 0o600)?;
            key
        };
        Ok(Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
        })
    }

    /// Encrypt `plaintext` for `purpose`, which must be passed again to
    /// decrypt.
    ///
    /// # Errors
    /// Fails only if the AEAD implementation rejects the input.
    pub fn encrypt(&self, purpose: &str, plaintext: &[u8]) -> Result<Sealed> {
        let mut nonce = [0_u8; NONCE_BYTES];
        rand::fill(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt {purpose}"))?;
        Ok(Sealed {
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    /// Decrypt a value produced by [`Self::encrypt`] for the same `purpose`.
    ///
    /// # Errors
    /// Fails when the value was tampered with, encrypted under another key,
    /// or encrypted for another purpose.
    pub fn decrypt(&self, purpose: &str, sealed: &Sealed) -> Result<Vec<u8>> {
        let nonce = STANDARD.decode(&sealed.nonce).context("invalid nonce")?;
        ensure!(nonce.len() == NONCE_BYTES, "invalid nonce length");
        let ciphertext = STANDARD
            .decode(&sealed.ciphertext)
            .context("invalid ciphertext")?;
        self.cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to decrypt {purpose}"))
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read `{}`", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::FakeSealer;

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store-key.cred");
        let first = StoreKey::load_or_create(&path, &FakeSealer).unwrap();
        let sealed = first.encrypt("totp:1000", b"secret").unwrap();
        let second = StoreKey::load_or_create(&path, &FakeSealer).unwrap();
        assert_eq!(second.decrypt("totp:1000", &sealed).unwrap(), b"secret");
    }

    #[test]
    fn purpose_is_bound_to_the_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::load_or_create(&dir.path().join("key"), &FakeSealer).unwrap();
        let sealed = key.encrypt("totp:1000", b"secret").unwrap();
        key.decrypt("totp:1001", &sealed).unwrap_err();
    }

    #[test]
    fn a_key_that_fails_to_unseal_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"not sealed by this host").unwrap();
        StoreKey::load_or_create(&path, &FakeSealer).unwrap_err();
        assert_eq!(fs::read(&path).unwrap(), b"not sealed by this host");
    }
}
