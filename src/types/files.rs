//! File payloads, and the bounded text I/O the configuration payloads share.

use crate::agent::module_support::SelinuxOptions;
use crate::prelude::*;

pub(super) fn read_text(path: &Path) -> Result<String> {
    use std::io::Read as _;
    let file = open_regular(path, fs::OpenOptions::new().read(true))?;
    let mut text = String::new();
    file.take(MAX_TEXT_LEN + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("failed to read `{}`", path.display()))?;
    ensure!(
        u64::try_from(text.len()).is_ok_and(|len| len <= MAX_TEXT_LEN),
        "`{}` is larger than {MAX_TEXT_LEN} bytes",
        path.display()
    );
    Ok(text)
}

/// Replace `path` with `contents` unless `dry_run`. Writes in place so the
/// file keeps its owner, mode and SELinux label.
pub(super) fn write_text(path: &Path, contents: &str, dry_run: bool) -> Result<()> {
    use std::io::Write as _;
    if !dry_run {
        let mut file = open_regular(path, fs::OpenOptions::new().write(true).create(true))?;
        file.set_len(0)
            .and_then(|()| file.write_all(contents.as_bytes()))
            .with_context(|| format!("failed to write `{}`", path.display()))?;
    }
    Ok(())
}

/// Largest file [`read_text`] returns (a response must fit one WebSocket
/// message).
const MAX_TEXT_LEN: u64 = 16 << 20;

/// Open `path` only if it is a regular file. `O_NONBLOCK`, so a FIFO fails
/// instead of blocking the agent's one-at-a-time dispatch queue forever; a
/// device such as `/dev/zero` is refused before it fills memory.
fn open_regular(path: &Path, options: &mut fs::OpenOptions) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = options
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .with_context(|| format!("failed to open `{}`", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "`{}` is not a regular file",
        path.display()
    );
    Ok(file)
}

#[derive(Debug, Deserialize)]
pub struct FileReadRequest {
    pub path: PathBuf,
}

impl FileReadRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct FileWriteRequest {
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl FileWriteRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_write_request_honors_dry_run_and_writes_when_requested() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("managed.conf");
        let dry_run = FileWriteRequest {
            path: path.clone(),
            contents: "dry run".into(),
            dry_run: true,
            selinux: None,
        };
        dry_run.write().unwrap();
        assert!(!path.exists());

        let write = FileWriteRequest {
            path: path.clone(),
            contents: "written".into(),
            dry_run: false,
            selinux: None,
        };
        write.write().unwrap();
        assert_eq!(FileReadRequest { path }.read().unwrap(), "written");
    }
}
