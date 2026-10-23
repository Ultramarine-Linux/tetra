//! Action log of every module action Tetra dispatched.
//!
//! One JSON line per action, tagged with where it came from (`local` dashboard user, `setup` session, or `remote`
//! controller), so the dashboard can show a remote action log.
//!
//! Written to `/var/lib/tetra/audit/actions.jsonl` (root-only). When the file
//! passes [`MAX_BYTES`] it is rotated to `actions.jsonl.1`, keeping one old
//! generation. Payloads are never logged; they may contain secrets.

use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{Arc, Mutex},
};

use crate::prelude::*;

use super::{sessions::ClientKind, store};

pub const DEFAULT_DIR: &str = "/var/lib/tetra/audit";
const FILE: &str = "actions.jsonl";
const ROTATED: &str = "actions.jsonl.1";
/// Size at which the log rotates.
pub const MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// A logged-in user through a local client.
    Local,
    /// The OOBE's setup session.
    Setup,
    /// The outbound remote-control connection.
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at: i64,
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Control-plane host id, for remote actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub command_id: String,
    pub module: String,
    pub action: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What else is worth knowing, built by Tetra (never from client text):
    /// for a web shell, its unit and how it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Append-only action log. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuditLog {
    dir: PathBuf,
    write: Arc<Mutex<()>>,
}

impl AuditLog {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            write: Arc::new(Mutex::new(())),
        }
    }

    /// Append `entry`. Failures are logged, never returned: a full disk must
    /// not block administration.
    pub fn record(&self, entry: &Entry) {
        if let Err(error) = self.try_record(entry) {
            eprintln!("failed to write the action log: {error:#}");
        }
    }

    fn try_record(&self, entry: &Entry) -> Result<()> {
        let _guard = self
            .write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store::private_dir(&self.dir)?;
        let path = self.dir.join(FILE);
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_BYTES) {
            fs::rename(&path, self.dir.join(ROTATED))?;
        }
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?
            .write_all(&line)?;
        Ok(())
    }

    /// The newest `limit` entries (optionally only from `origin`), newest
    /// first.
    ///
    /// # Errors
    /// Fails when a log file exists but cannot be read.
    pub fn recent(&self, limit: usize, origin: Option<Origin>) -> Result<Vec<Entry>> {
        // Keep only the newest `limit` while streaming, instead of parsing
        // both files (up to 8 MiB) into memory first.
        let mut entries = VecDeque::with_capacity(limit.min(1024));
        if limit == 0 {
            return Ok(Vec::new());
        }
        for name in [ROTATED, FILE] {
            let path = self.dir.join(name);
            let file = match fs::File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            // Split on bytes: a torn (non-UTF-8) line after a crash is
            // skipped like any other unparsable line, not a hard error.
            for line in BufReader::new(file).split(b'\n') {
                let line = line.with_context(|| format!("failed to read `{}`", path.display()))?;
                let Ok(entry) = serde_json::from_slice::<Entry>(&line) else {
                    continue;
                };
                if origin.is_some_and(|origin| entry.origin != origin) {
                    continue;
                }
                if entries.len() == limit {
                    entries.pop_front();
                }
                entries.push_back(entry);
            }
        }
        Ok(entries.into_iter().rev().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(origin: Origin, action: &str) -> Entry {
        Entry {
            at: 1,
            origin,
            client: None,
            uid: None,
            username: None,
            host_id: None,
            command_id: "cmd".into(),
            module: "services".into(),
            action: action.into(),
            ok: true,
            error: None,
            detail: None,
        }
    }

    #[test]
    fn records_and_filters_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit"));
        log.record(&entry(Origin::Local, "list"));
        log.record(&entry(Origin::Remote, "restart"));
        log.record(&entry(Origin::Remote, "stop"));
        let remote = log.recent(10, Some(Origin::Remote)).unwrap();
        assert_eq!(
            remote.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            ["stop", "restart"]
        );
        assert_eq!(log.recent(1, None).unwrap().len(), 1);
    }

    #[test]
    fn entries_from_a_newer_build_are_skipped_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf());
        let mut future = serde_json::to_value(entry(Origin::Local, "future")).unwrap();
        future["origin"] = "federated".into();
        let line = format!("{future}\n");
        fs::write(dir.path().join(FILE), &line).unwrap();
        log.record(&entry(Origin::Local, "list"));
        let actions: Vec<_> = log
            .recent(10, None)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["list"]);
        // The log is append-only, so the line stays for the build that wrote it.
        assert!(
            fs::read_to_string(dir.path().join(FILE))
                .unwrap()
                .starts_with(&line)
        );
    }

    #[test]
    fn rotates_large_logs() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().to_path_buf());
        fs::write(
            dir.path().join(FILE),
            vec![b'\n'; usize::try_from(MAX_BYTES).unwrap()],
        )
        .unwrap();
        log.record(&entry(Origin::Remote, "restart"));
        assert!(dir.path().join(ROTATED).exists());
        assert_eq!(log.recent(10, None).unwrap().len(), 1);
    }
}
