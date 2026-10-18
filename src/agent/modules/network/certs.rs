//! 802.1X certificates and keys sent as PEM contents.
//!
//! NetworkManager keyfiles refer to certificates by path, so PEM contents in
//! a `wired_8021x` or `wpa-enterprise` request are stored in one directory
//! per profile under [`CERTS_DIR`] (directories `0700`, files `0600`, root
//! only) and the request is rewritten to point at them ([`externalize`]).
//! `/etc/pki` keeps the `cert_t` SELinux label, which NetworkManager and
//! `wpa_supplicant` may read.
//!
//! Each file is named after a hash of its contents, so writing a new
//! profile never changes a file the previous one (which a rollback may
//! restore) points at. Once a change settles, [`prune`] removes every file
//! the profile on disk no longer names, and the directory with the last one.

use std::{fmt::Write as _, io, os::unix::fs::PermissionsExt as _};

use sha2::{Digest as _, Sha256};

use super::paths::write_keyfile;
use crate::prelude::*;
use crate::types::{Wired8021x, is_pem};

/// Where PEM contents are stored, one directory per connection profile.
pub const CERTS_DIR: &str = "/etc/pki/tetra/802-1x";

/// PEM contents to store at `path`. `Debug` leaves the contents out.
pub struct PemFile {
    pub path: PathBuf,
    contents: Vec<u8>,
}

impl std::fmt::Debug for PemFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PemFile").field("path", &self.path).finish_non_exhaustive()
    }
}

/// Replace each PEM value in `settings` with the path it is stored at in
/// `dir` (the profile's directory), returning the files to write.
#[must_use]
pub fn externalize(settings: &mut Wired8021x, dir: &Path) -> Vec<PemFile> {
    let mut files = Vec::new();
    for (stem, value) in [
        ("ca-cert", &mut settings.ca_cert),
        ("client-cert", &mut settings.client_cert),
        ("private-key", &mut settings.private_key),
    ] {
        let Some(pem) = value.take_if(|value| is_pem(value)) else {
            continue;
        };
        let digest = Sha256::digest(pem.as_bytes());
        let mut name = format!("{stem}-");
        for byte in &digest[..16] {
            let _ok: std::fmt::Result = write!(name, "{byte:02x}");
        }
        name.push_str(".pem");
        let path = dir.join(name);
        *value = Some(path.to_string_lossy().into_owned());
        files.push(PemFile {
            path,
            contents: pem.into_bytes(),
        });
    }
    files
}

/// Write `files` (all in one profile's directory), creating the directory
/// and [`CERTS_DIR`]-style parent `0700`. Files already holding the same
/// contents are left alone. Returns the files written.
///
/// # Errors
/// Errs when a directory is a symlink or any filesystem step fails.
pub fn write(files: &[PemFile]) -> Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    for file in files {
        let dir = file.path.parent().context("certificate path has no parent")?;
        create_private_dir(dir)?;
        if let Some(parent) = dir.parent() {
            create_private_dir(parent)?;
        }
        if fs::read(&file.path).ok().as_deref() == Some(file.contents.as_slice()) {
            continue;
        }
        write_keyfile(&file.path, &file.contents)?;
        written.push(file.path.clone());
    }
    Ok(written)
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create `{}`", dir.display()))?;
    let metadata = fs::symlink_metadata(dir)?;
    ensure!(metadata.is_dir(), "`{}` is not a directory", dir.display());
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict `{}`", dir.display()))
}

/// Remove the files in `dir` that `keyfile` (the profile now on disk, if
/// any) does not name, and `dir` itself once it is empty. Failures are
/// logged, not returned: the profile change itself has already happened.
pub fn prune(dir: &Path, keyfile: Option<&[u8]>) {
    let keyfile = keyfile.map(String::from_utf8_lossy).unwrap_or_default();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            eprintln!("failed to read `{}`: {error}", dir.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if keyfile.contains(&*path.to_string_lossy()) {
            continue;
        }
        if let Err(error) = fs::remove_file(&path) {
            eprintln!("failed to remove `{}`: {error}", path.display());
        }
    }
    // Fails (and is meant to) while files remain.
    let _removed: io::Result<()> = fs::remove_dir(dir);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIBVQ-S3CRET\n-----END PRIVATE KEY-----\n";
    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBca\n-----END CERTIFICATE-----\n";

    fn settings() -> Wired8021x {
        serde_json::from_value(json!({
            "eap": "tls",
            "identity": "host/server",
            "ca_cert": CA,
            "client_cert": "/etc/pki/tls/certs/client.pem",
            "private_key": KEY,
            "private_key_password": "key-S3CRET-pass",
        }))
        .unwrap()
    }

    #[test]
    fn pem_contents_become_root_only_files_named_by_their_hash() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("802-1x/eth0");
        let mut settings = settings();
        let files = externalize(&mut settings, &dir);

        assert_eq!(files.len(), 2);
        let ca = settings.ca_cert.clone().unwrap();
        let key = settings.private_key.clone().unwrap();
        assert!(ca.starts_with(&*dir.join("ca-cert-").to_string_lossy()), "{ca}");
        assert!(Path::new(&key).extension().is_some_and(|extension| extension == "pem"));
        assert_eq!(settings.client_cert.as_deref(), Some("/etc/pki/tls/certs/client.pem"));
        assert!(!format!("{settings:?} {files:?}").contains("S3CRET"));

        assert_eq!(write(&files).unwrap().len(), 2);
        assert_eq!(fs::read_to_string(&key).unwrap(), KEY);
        for path in [Path::new(&key), &dir, &root.path().join("802-1x")] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, if path.is_dir() { 0o700 } else { 0o600 }, "{}", path.display());
        }
        // Writing the same contents again changes nothing.
        assert_eq!(write(&files).unwrap(), Vec::<PathBuf>::new());
        // The same contents always get the same path.
        let mut again = self::settings();
        let _files = externalize(&mut again, &dir);
        assert_eq!(again.private_key.as_deref(), Some(key.as_str()));
    }

    #[test]
    fn prune_keeps_only_what_the_profile_names() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("eth0");
        let mut settings = settings();
        let files = externalize(&mut settings, &dir);
        write(&files).unwrap();
        let key = settings.private_key.unwrap();
        let keyfile = format!("[802-1x]\nprivate-key={key}\n");

        prune(&dir, Some(keyfile.as_bytes()));
        assert!(Path::new(&key).exists());
        assert!(!Path::new(&settings.ca_cert.unwrap()).exists());

        // No profile left: everything goes, directory included.
        prune(&dir, None);
        assert!(!dir.exists());
        prune(&dir, None);
    }
}
