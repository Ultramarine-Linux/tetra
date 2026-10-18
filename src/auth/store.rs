//! Versioned, root-only JSON files under `/var/lib/tetra`.
//!
//! Every file Tetra stores for login and authorization goes through this
//! module so the rollback rules live in one place (expand/contract, so a
//! bootc rollback to the previous release keeps working):
//!
//! - Each file carries a [`Header`]: `schema` is the version of the build that
//!   wrote it, and `compat` is the oldest schema that can safely read it. A
//!   reader refuses a file whose `compat` is newer than its own [`SCHEMA`].
//! - New fields are added with `#[serde(default)]`, never removed or
//!   repurposed in the same release, and stored records never use
//!   `deny_unknown_fields`.
//! - Records keep fields they do not know in an `extra` map (`#[serde(flatten)]`),
//!   so an older build that rewrites a file does not drop data a newer build
//!   added.
//! - Enums stored on disk are read through [`Tolerant`]: a variant this build
//!   does not know (a new page, mode or kind) is kept as opaque JSON that
//!   grants nothing and is written back unchanged, instead of making the
//!   whole file unreadable.
//!
//! Writes are atomic (temporary file, `fsync`, `rename`), files are created
//! `0600` and directories `0700`. [`StoreLock`] serializes read-modify-write
//! cycles between the daemon and the root-only CLI.

use std::{
    fs::{File, OpenOptions, Permissions},
    io::{ErrorKind, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

use nix::fcntl::{Flock, FlockArg};
use serde::de::DeserializeOwned;
use serde_json::Map;

use crate::prelude::*;

/// Schema version written by this build.
pub const SCHEMA: u32 = 1;
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;
const LOCK_FILE: &str = ".lock";

/// Unknown fields preserved across a read-modify-write cycle.
pub type Extra = Map<String, Value>;

/// A stored value that may come from a newer build: [`Tolerant::Known`] when
/// this build understands it, the raw JSON otherwise. Serializes back to
/// exactly what was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Tolerant<T> {
    Known(T),
    Unknown(Value),
}

impl<T> Tolerant<T> {
    /// The value, if this build understands it.
    #[must_use]
    pub const fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }
}

impl<T: Default> Default for Tolerant<T> {
    fn default() -> Self {
        Self::Known(T::default())
    }
}

impl<T> From<T> for Tolerant<T> {
    fn from(value: T) -> Self {
        Self::Known(value)
    }
}

/// Version header present at the top level of every stored file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Schema of the build that last wrote the file.
    pub schema: u32,
    /// Oldest schema that can safely read the file.
    pub compat: u32,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            compat: 1,
        }
    }
}

/// A top-level stored file.
pub trait Record: Serialize + DeserializeOwned {
    /// Oldest schema that can read what this build writes. Raise it only in
    /// the "contract" release, after a release that already understood the
    /// new shape.
    const COMPAT: u32 = 1;

    fn header(&self) -> &Header;
    fn header_mut(&mut self) -> &mut Header;
}

/// Read `path`, returning `None` when it does not exist.
///
/// # Errors
/// Fails when the file cannot be read or parsed, or was written by a build
/// that requires a newer reader.
pub fn read<T: Record>(path: &Path) -> Result<Option<T>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read `{}`", path.display()));
        }
    };
    let record: T = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse `{}`", path.display()))?;
    let header = record.header();
    ensure!(
        header.compat <= SCHEMA,
        "`{}` needs schema {} or newer, this Tetra reads schema {SCHEMA}",
        path.display(),
        header.compat
    );
    Ok(Some(record))
}

/// Atomically write `record` to `path` with mode `0600`, stamping the header
/// with this build's schema.
///
/// # Errors
/// Fails when the parent directory cannot be created or the file cannot be
/// written or renamed into place.
pub fn write<T: Record>(path: &Path, record: &mut T) -> Result<()> {
    *record.header_mut() = Header {
        schema: SCHEMA,
        compat: T::COMPAT,
    };
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    write_bytes(path, &bytes, FILE_MODE)
}

/// Atomically replace `path` with `bytes`, created with `mode`, in a private
/// (`0700`) parent directory.
///
/// # Errors
/// Fails when the file cannot be written or renamed into place.
pub fn write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    private_dir(parent_of(path)?)?;
    replace(path, bytes, mode)
}

/// Atomically replace `path` with `bytes`, created with `mode`. The parent
/// directory must exist; its mode is left alone, so this is for files in
/// shared directories such as `/run/tetra`.
///
/// # Errors
/// Fails when the file cannot be written or renamed into place.
pub fn replace(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = parent_of(path)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .with_context(|| format!("`{}` has no file name", path.display()))?;
    let temporary = parent.join(format!(
        ".{name}.tmp-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("failed to create `{}`", temporary.display()))?;
        // The umask may have narrowed the mode; set it explicitly.
        file.set_permissions(Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to install `{}`", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        fs::remove_file(&temporary).ok();
    }
    result
}

fn parent_of(path: &Path) -> Result<&Path> {
    path.parent()
        .with_context(|| format!("`{}` has no parent directory", path.display()))
}

/// Remove `path`, treating a missing file as success.
///
/// # Errors
/// Fails when the file exists but cannot be removed.
pub fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove `{}`", path.display())),
    }
}

/// Create `path` (and parents) if needed and restrict it to `0700`.
///
/// # Errors
/// Fails when the directory cannot be created or its mode cannot be set.
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create `{}`", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("failed to restrict `{}`", path.display()))
}

/// Exclusive advisory lock on a store directory, held for one
/// read-modify-write cycle. Released on drop.
pub struct StoreLock {
    _lock: Flock<File>,
}

impl StoreLock {
    /// Block until the lock for `dir` is held.
    ///
    /// # Errors
    /// Fails when the lock file cannot be opened or locked.
    pub fn acquire(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let path = dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(FILE_MODE)
            .open(&path)
            .with_context(|| format!("failed to open `{}`", path.display()))?;
        let lock = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, errno)| errno)
            .with_context(|| format!("failed to lock `{}`", path.display()))?;
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct Example {
        #[serde(flatten)]
        header: Header,
        #[serde(default)]
        value: u32,
        #[serde(flatten)]
        extra: Extra,
    }

    impl Record for Example {
        fn header(&self) -> &Header {
            &self.header
        }
        fn header_mut(&mut self) -> &mut Header {
            &mut self.header
        }
    }

    #[test]
    fn missing_file_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read::<Example>(&dir.path().join("none.json"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn writes_private_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/example.json");
        write(&path, &mut Example::default()).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), FILE_MODE);
        assert_eq!(mode(path.parent().unwrap()), DIR_MODE);
        // No temporary files are left behind.
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn rewrite_keeps_fields_from_a_newer_schema() {
        // A file written by a future build that added `newer` and still
        // declares that schema 1 can read it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.json");
        let future = json!({"schema": 2, "compat": 1, "value": 1, "newer": {"kept": true}});
        fs::write(&path, future.to_string()).unwrap();

        let mut record = read::<Example>(&path).unwrap().unwrap();
        assert_eq!(record.value, 1);
        record.value = 2;
        write(&path, &mut record).unwrap();

        let rewritten: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rewritten["newer"], json!({"kept": true}));
        assert_eq!(rewritten["value"], 2);
        assert_eq!(rewritten["schema"], SCHEMA);
        assert_eq!(rewritten["compat"], 1);
    }

    #[test]
    fn refuses_files_that_need_a_newer_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.json");
        let future = json!({"schema": SCHEMA + 1, "compat": SCHEMA + 1});
        fs::write(&path, future.to_string()).unwrap();
        read::<Example>(&path).unwrap_err();
    }

    #[test]
    fn tolerant_values_round_trip_unknown_variants() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Mode {
            Old,
        }
        let known: Tolerant<Mode> = serde_json::from_value(json!("old")).unwrap();
        assert_eq!(known.known(), Some(&Mode::Old));
        let unknown: Tolerant<Mode> =
            serde_json::from_value(json!({"kind": "new", "x": 1})).unwrap();
        assert_eq!(unknown.known(), None);
        assert_eq!(
            serde_json::to_value(&unknown).unwrap(),
            json!({"kind": "new", "x": 1})
        );
    }

    #[test]
    fn lock_can_be_reacquired_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        drop(StoreLock::acquire(dir.path()).unwrap());
        drop(StoreLock::acquire(dir.path()).unwrap());
    }
}
