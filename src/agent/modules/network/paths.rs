//! Confinement of keyfile reads and writes to NetworkManager's
//! `system-connections` directory.
//!
//! Tetra runs as root, so every keyfile path from a payload is checked here:
//! it must name a `.nmconnection` file directly inside the directory, contain
//! no `..`, and (when it exists) be a regular, singly-linked file rather than
//! a symlink. Reads open with `O_NOFOLLOW`; writes go through a fresh `0600`
//! temporary file that is renamed into place, so a symlink planted at the
//! target is replaced rather than followed.

use std::{
    fs::OpenOptions,
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Component,
};


use crate::prelude::*;

/// Where NetworkManager reads system-wide keyfile profiles from.
pub const SYSTEM_CONNECTIONS_DIR: &str = "/etc/NetworkManager/system-connections";

/// Keyfile extension NetworkManager loads from [`SYSTEM_CONNECTIONS_DIR`].
pub const KEYFILE_EXTENSION: &str = ".nmconnection";

/// Largest keyfile Tetra will read or write.
const MAX_KEYFILE_BYTES: u64 = 1024 * 1024;

/// Check that `path` names a keyfile directly inside `dir`.
///
/// # Errors
/// Errs when the path is relative, contains `..`, lives outside `dir`, does
/// not end in `.nmconnection`, or exists as anything other than a regular
/// file (a symlink, directory, FIFO, ...).
pub fn validate_keyfile_path(dir: &Path, path: &Path) -> Result<PathBuf> {
    let display = path.display();
    ensure!(path.is_absolute(), "keyfile path `{display}` must be absolute");
    ensure!(
        !path.as_os_str().as_encoded_bytes().windows(2).any(|w| w == b".."),
        "keyfile path `{display}` must not contain `..`"
    );
    // `components()` silently drops `.` and repeated or trailing slashes, so
    // also require the path to already be in that normalized form.
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str(),
        "keyfile path `{display}` must be normalized"
    );
    ensure!(
        path.parent() == Some(dir),
        "keyfile path `{display}` must be directly inside {}",
        dir.display()
    );
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .with_context(|| format!("keyfile path `{display}` must have a UTF-8 file name"))?;
    validate_file_name(name)?;
    ensure_regular_or_missing(path)?;
    Ok(path.to_path_buf())
}

/// The keyfile path for connection `name` inside `dir`.
///
/// # Errors
/// Errs when `name` would not produce a valid keyfile name.
pub fn keyfile_path_for(dir: &Path, name: &str) -> Result<PathBuf> {
    validate_keyfile_path(dir, &dir.join(format!("{name}{KEYFILE_EXTENSION}")))
}

fn validate_file_name(name: &str) -> Result<()> {
    let stem = name
        .strip_suffix(KEYFILE_EXTENSION)
        .with_context(|| format!("keyfile `{name}` must end in `{KEYFILE_EXTENSION}`"))?;
    ensure!(!stem.is_empty(), "keyfile `{name}` needs a name before the extension");
    // NetworkManager ignores hidden files; Tetra's own temporary files are
    // hidden, so never let a payload address one.
    ensure!(!stem.starts_with('.'), "keyfile `{name}` must not be hidden");
    ensure!(
        !name.chars().any(char::is_control),
        "keyfile name must not contain control characters"
    );
    Ok(())
}

fn ensure_regular_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "`{}` is not a regular file",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect `{}`", path.display()))
        }
    }
}

/// Read a validated keyfile, returning `None` when it does not exist.
///
/// # Errors
/// Errs when the file is a symlink, not a regular file, hard-linked
/// elsewhere, too large, or unreadable.
pub fn read_keyfile(path: &Path) -> Result<Option<Vec<u8>>> {
    let display = path.display();
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            bail!("`{display}` is a symlink")
        }
        Err(error) => return Err(error).with_context(|| format!("failed to open `{display}`")),
    };
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "`{display}` is not a regular file");
    ensure!(metadata.nlink() == 1, "`{display}` has other hard links");
    ensure!(metadata.len() <= MAX_KEYFILE_BYTES, "`{display}` is too large");
    let mut contents = Vec::new();
    file.take(MAX_KEYFILE_BYTES)
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read `{display}`"))?;
    Ok(Some(contents))
}

/// Atomically replace a validated keyfile with `contents`, mode `0600`.
///
/// # Errors
/// Errs when the contents are too large or any filesystem step fails.
pub fn write_keyfile(path: &Path, contents: &[u8]) -> Result<()> {
    ensure!(
        u64::try_from(contents.len()).is_ok_and(|len| len <= MAX_KEYFILE_BYTES),
        "keyfile contents are too large"
    );
    crate::auth::store::replace(path, contents, 0o600)
}

/// Remove a validated keyfile; a missing file is not an error.
///
/// # Errors
/// Errs when the path exists but cannot be removed.
pub fn remove_keyfile(path: &Path) -> Result<()> {
    crate::auth::store::remove(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    const DIR: &str = "/etc/NetworkManager/system-connections";

    fn check(path: &str) -> Result<PathBuf> {
        validate_keyfile_path(Path::new(DIR), Path::new(path))
    }

    #[test]
    fn accepts_keyfiles_directly_in_the_directory() {
        check("/etc/NetworkManager/system-connections/eth0.nmconnection").unwrap();
        check("/etc/NetworkManager/system-connections/Wired connection 1.nmconnection").unwrap();
    }

    #[test]
    fn rejects_paths_outside_the_directory() {
        for path in [
            "/etc/shadow",
            "/etc/passwd.nmconnection",
            "/etc/NetworkManager/NetworkManager.conf",
            "/etc/NetworkManager/system-connections.nmconnection",
            "/etc/NetworkManager/system-connections/sub/eth0.nmconnection",
            "/etc/NetworkManager/system-connections/../system-connections/eth0.nmconnection",
            "/etc/NetworkManager/system-connections/../../shadow.nmconnection",
            "/etc/NetworkManager/system-connections/./eth0.nmconnection",
            "/etc/NetworkManager/system-connections/..nmconnection",
            "/etc/NetworkManager/system-connections/a..b.nmconnection",
            "/run/NetworkManager/system-connections/eth0.nmconnection",
            "etc/NetworkManager/system-connections/eth0.nmconnection",
            "eth0.nmconnection",
        ] {
            assert!(check(path).is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn rejects_wrong_extensions_and_hidden_files() {
        for path in [
            "/etc/NetworkManager/system-connections/eth0",
            "/etc/NetworkManager/system-connections/eth0.nmconnection.bak",
            "/etc/NetworkManager/system-connections/eth0.conf",
            "/etc/NetworkManager/system-connections/.nmconnection",
            "/etc/NetworkManager/system-connections/.hidden.nmconnection",
            "/etc/NetworkManager/system-connections/",
            "/etc/NetworkManager/system-connections",
        ] {
            assert!(check(path).is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn rejects_symlinks_and_non_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("link.nmconnection");
        symlink(&target, &link).unwrap();
        let subdir = dir.path().join("subdir.nmconnection");
        fs::create_dir_all(&subdir).unwrap();

        validate_keyfile_path(dir.path(), &link).unwrap_err();
        validate_keyfile_path(dir.path(), &subdir).unwrap_err();
        // Even when called directly, reads refuse to follow the link.
        assert!(read_keyfile(&link).unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn write_replaces_a_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("eth0.nmconnection");
        symlink(&target, &link).unwrap();

        write_keyfile(&link, b"[connection]\n").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "secret");
        assert!(fs::symlink_metadata(&link).unwrap().is_file());
    }

    #[test]
    fn writes_with_mode_0600_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = keyfile_path_for(dir.path(), "eth0").unwrap();
        assert_eq!(read_keyfile(&path).unwrap(), None);

        write_keyfile(&path, b"[connection]\nid=eth0\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(read_keyfile(&path).unwrap().unwrap(), b"[connection]\nid=eth0\n");
        // No temporary files are left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

        remove_keyfile(&path).unwrap();
        remove_keyfile(&path).unwrap();
        assert_eq!(read_keyfile(&path).unwrap(), None);
    }

    #[test]
    fn read_rejects_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        fs::write(&original, "secret").unwrap();
        let linked = dir.path().join("linked.nmconnection");
        fs::hard_link(&original, &linked).unwrap();
        read_keyfile(&linked).unwrap_err();
    }
}
