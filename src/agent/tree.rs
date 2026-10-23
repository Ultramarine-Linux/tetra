//! File operations below a directory, resolved from a directory file
//! descriptor so a symlink planted on the way is never followed.
//!
//! The apps account's home (see [`crate::agent::apps_account`]) belongs to
//! an account that runs third-party containers, and the root of a rootless
//! container is that account on the host. Anything there can change between
//! a check by path and a use by path, so Tetra, which works there as root,
//! never uses a path below the home:
//!
//! - the home is opened once per operation (`O_DIRECTORY | O_NOFOLLOW`);
//!   for a write, it must belong to the account or to Tetra itself (a home
//!   Tetra just created), and is then handed to the account;
//! - every directory below it is opened with `openat2` relative to its
//!   parent's descriptor, with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//!   RESOLVE_NO_MAGICLINKS`, so a symlink anywhere on the way (the last
//!   component included) fails with `ELOOP` instead of being followed. A
//!   missing directory is made with `mkdirat` on its parent's descriptor and
//!   then opened the same way; its mode and owner are set with `fchmod` and
//!   `fchown` on that descriptor;
//! - a file is written to an unnamed `O_TMPFILE` in its directory (a named
//!   `O_CREAT | O_EXCL | O_NOFOLLOW` file where the filesystem has no
//!   `O_TMPFILE`), given its owner and mode with `fchown`/`fchmod`, synced,
//!   linked under a random name (`linkat` of `/proc/self/fd/N` with
//!   `AT_SYMLINK_FOLLOW`, or `AT_EMPTY_PATH`, which needs
//!   `CAP_DAC_READ_SEARCH`, without `/proc`) and `renameat`-ed over the
//!   target in the same directory, which replaces a symlink there instead
//!   of following it. The directory is synced last;
//! - files are read through `openat2` too (`O_NOFOLLOW | O_NONBLOCK`, so a
//!   FIFO cannot hang the agent), and must be regular files with a single
//!   link, so a hard link to a file elsewhere is not read;
//! - removal is `unlinkat` on the parent's descriptor, which removes a
//!   symlink rather than its target; directories are emptied the same way,
//!   entry by entry.
//!
//! `RESOLVE_NO_XDEV` is not used: the account cannot mount anything in the
//! host's mount namespace (a container's mounts live in its own), so a
//! mount point below the home is the administrator's, such as a separate
//! disk for app data, and should keep working.
//!
//! A directory that is not below the account's home (system scope, a
//! payload's `base_dir`, a recipe's output directory) is root's and trusted:
//! it is the anchor itself, opened by path and created with
//! `create_dir_all` when missing. Everything below it is still resolved
//! from its descriptor, so there is one code path.
//!
//! `openat2` is Linux 5.6 and later. All of this is blocking I/O: modules run
//! on Tokio's blocking pool ([`crate::agent::queue`], and `spawn_blocking`
//! in the one-shot `agent-dispatch`), never on an async worker.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read as _, Write as _},
    os::{
        fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd},
        unix::{ffi::OsStringExt as _, fs::DirBuilderExt as _},
    },
    path::Component,
};

use anyhow::anyhow;
use rustix::{
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    io::Errno,
};

use crate::agent::apps_account::Owner;
use crate::prelude::*;

/// How every path below an anchor is resolved.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Flags to open a directory. Below the anchor, [`RESOLVE`] refuses a
/// symlink at the last component too (`ELOOP`; with `O_NOFOLLOW` as well,
/// `O_DIRECTORY` would make that `ENOTDIR`).
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// Mode of the account's home, when Tetra creates it.
const HOME_MODE: u32 = 0o700;
/// Mode of directories Tetra creates below an anchor.
const DIR_MODE: u32 = 0o755;

/// Largest file [`Tree::read`] reads: manifests, companions and templates
/// are small, and the WebSocket frame cap is the same 16 MiB.
pub const MAX_READ: u64 = 16 << 20;

/// A directory tree Tetra reads and writes as root: every operation takes an
/// absolute path below the tree's anchor and resolves it from the anchor's
/// descriptor (see the [module docs](self)).
#[derive(Debug, Clone)]
pub struct Tree {
    /// Where resolution starts.
    anchor: PathBuf,
    /// Whether the anchor is the apps account's home, rather than a
    /// directory root owns.
    home: bool,
    /// Who directories and files written here are handed to.
    owner: Option<Owner>,
}

/// What a directory entry is, without following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

impl Kind {
    const fn of(file_type: FileType) -> Self {
        match file_type {
            FileType::RegularFile => Self::File,
            FileType::Directory => Self::Dir,
            FileType::Symlink => Self::Symlink,
            _ => Self::Other,
        }
    }
}

impl Tree {
    /// The tree `dir` belongs to: the apps account's `home` when `dir` is
    /// below it, else `dir` itself. Writes hand what they create to `owner`.
    #[must_use]
    pub fn new(dir: &Path, home: Option<&Path>, owner: Option<Owner>) -> Self {
        match home {
            Some(home) if dir.starts_with(home) => Self {
                anchor: home.to_path_buf(),
                home: true,
                owner,
            },
            // Files are only ever handed to the account inside its home;
            // anywhere else (an administrator's override) root keeps them.
            _ => Self::trusted(dir),
        }
    }

    /// A tree anchored at `dir`, which root owns.
    #[must_use]
    pub fn trusted(dir: &Path) -> Self {
        Self {
            anchor: dir.to_path_buf(),
            home: false,
            owner: None,
        }
    }

    /// Create `dir` and its parents up to the anchor, each handed to the
    /// owner.
    ///
    /// # Errors
    /// Fails when `dir` is outside the tree, a component is a symlink or not
    /// a directory, or a directory cannot be created or given away.
    pub fn create_dir(&self, dir: &Path) -> Result<()> {
        let relative = self.relative(dir)?;
        self.open_dir(relative, true).map(drop)
    }

    /// Atomically replace `path` with `contents`, owned by the owner (if
    /// any) with `mode`, creating its directory. A symlink at `path` is
    /// replaced, not followed.
    ///
    /// # Errors
    /// Fails when the path is refused, or a step of the write fails.
    pub fn write(&self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        let (parent, name) = self.split(path)?;
        let dir = self
            .open_dir(parent, true)?
            .context("directory missing after creation")?;
        write_at(&dir, name, contents, mode, self.owner.as_ref(), path, true)
            .with_context(|| format!("failed to write `{}`", path.display()))
    }

    /// The contents of the regular file `path`, at most [`MAX_READ`] bytes.
    ///
    /// # Errors
    /// Fails when the path is refused or missing, is not a regular file with
    /// one link, or is larger than [`MAX_READ`].
    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let relative = self.relative(path)?;
        let missing = || {
            Err(io::Error::from(io::ErrorKind::NotFound))
                .with_context(|| format!("failed to read `{}`", path.display()))
        };
        let Some(anchor) = self.open_anchor(false)? else {
            return missing();
        };
        let flags = OFlags::RDONLY
            .union(OFlags::CLOEXEC)
            .union(OFlags::NOFOLLOW)
            .union(OFlags::NONBLOCK)
            .union(OFlags::NOCTTY);
        let fd = match rfs::openat2(&anchor, relative, flags, Mode::empty(), RESOLVE) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return missing(),
            Err(errno) => return Err(self.refused(errno, path)),
        };
        let stat = rfs::fstat(&fd)?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
            "`{}` is not a regular file",
            path.display()
        );
        ensure!(
            !self.home || stat.st_nlink == 1,
            "`{}` has other hard links; refusing to read it",
            path.display()
        );
        // The apps home belongs to the account that runs third-party
        // containers: a planted multi-gigabyte file must not exhaust memory.
        // Take one byte past the cap to tell "at the cap" from "over it".
        let mut contents = Vec::new();
        File::from(fd)
            .take(MAX_READ.saturating_add(1))
            .read_to_end(&mut contents)
            .with_context(|| format!("failed to read `{}`", path.display()))?;
        ensure!(
            u64::try_from(contents.len()).is_ok_and(|len| len <= MAX_READ),
            "`{}` is larger than {MAX_READ} bytes",
            path.display()
        );
        Ok(contents)
    }

    /// [`read`](Self::read) as UTF-8.
    ///
    /// # Errors
    /// See [`read`](Self::read); also fails on invalid UTF-8.
    pub fn read_to_string(&self, path: &Path) -> Result<String> {
        String::from_utf8(self.read(path)?)
            .with_context(|| format!("`{}` is not valid UTF-8", path.display()))
    }

    /// Whether anything (a symlink included) is at `path`.
    ///
    /// # Errors
    /// Fails when the path is refused or cannot be inspected.
    pub fn exists(&self, path: &Path) -> Result<bool> {
        if self.relative(path)?.as_os_str().is_empty() {
            return Ok(self.open_anchor(false)?.is_some());
        }
        let (parent, name) = self.split(path)?;
        let Some(dir) = self.open_dir(parent, false)? else {
            return Ok(false);
        };
        match rfs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(errno) => Err(io::Error::from(errno))
                .with_context(|| format!("failed to inspect `{}`", path.display())),
        }
    }

    /// Remove the file (or symlink) at `path`. Returns whether there was
    /// one.
    ///
    /// # Errors
    /// Fails when the path is refused, or names a directory, or the entry
    /// cannot be removed.
    pub fn remove_file(&self, path: &Path) -> Result<bool> {
        let (parent, name) = self.split(path)?;
        let Some(dir) = self.open_dir(parent, false)? else {
            return Ok(false);
        };
        match rfs::unlinkat(&dir, name, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(errno) => Err(io::Error::from(errno))
                .with_context(|| format!("failed to remove `{}`", path.display())),
        }
    }

    /// Remove the directory `dir` and everything in it, without following
    /// a symlink in it.
    ///
    /// # Errors
    /// Fails when `dir` is refused or missing, or an entry cannot be
    /// removed.
    pub fn remove_dir_all(&self, dir: &Path) -> Result<()> {
        let (parent, name) = self.split(dir)?;
        let context = || format!("failed to remove `{}`", dir.display());
        let parent = self
            .open_dir(parent, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
            .with_context(context)?;
        let target = rfs::openat2(&parent, name, DIRECTORY, Mode::empty(), RESOLVE)
            .map_err(|errno| self.refused(errno, dir))?;
        empty_dir(&target, dir)?;
        rfs::unlinkat(&parent, name, AtFlags::REMOVEDIR)
            .map_err(io::Error::from)
            .with_context(context)
    }

    /// The entries of `dir`, or `None` when it does not exist.
    ///
    /// # Errors
    /// Fails when `dir` is refused or cannot be read.
    pub fn read_dir(&self, dir: &Path) -> Result<Option<Vec<(OsString, Kind)>>> {
        let relative = self.relative(dir)?;
        let Some(fd) = self.open_dir(relative, false)? else {
            return Ok(None);
        };
        entries(&fd, dir).map(Some)
    }

    /// Regular files below `dir`, recursively, relative to it. Symlinks and
    /// special files are skipped; a missing `dir` has none.
    ///
    /// # Errors
    /// Fails when a directory is refused or cannot be read.
    pub fn files_below(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let relative = self.relative(dir)?;
        let Some(fd) = self.open_dir(relative, false)? else {
            return Ok(Vec::new());
        };
        let mut files = Vec::new();
        collect_files(&fd, dir, Path::new(""), &mut files)?;
        Ok(files)
    }

    /// `path` relative to the anchor: plain components only.
    fn relative<'a>(&self, path: &'a Path) -> Result<&'a Path> {
        let relative = path.strip_prefix(&self.anchor).with_context(|| {
            format!(
                "`{}` is outside `{}`",
                path.display(),
                self.anchor.display()
            )
        })?;
        ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_) | Component::CurDir)),
            "`{}` is not a plain path below `{}`",
            path.display(),
            self.anchor.display()
        );
        Ok(relative)
    }

    /// The directory and file name of `path`, which must be below the
    /// anchor.
    fn split<'a>(&self, path: &'a Path) -> Result<(&'a Path, &'a OsStr)> {
        let relative = self.relative(path)?;
        let name = relative
            .file_name()
            .with_context(|| format!("`{}` has no file name", path.display()))?;
        Ok((relative.parent().unwrap_or_else(|| Path::new("")), name))
    }

    /// Open the anchor, or `None` when it does not exist and `create` is
    /// not set. With `create`, a missing anchor is made, and the anchor is
    /// handed to the owner.
    fn open_anchor(&self, create: bool) -> Result<Option<OwnedFd>> {
        let anchor = &self.anchor;
        // The home's own entry is in a directory root owns, so the account
        // cannot swap it; `O_NOFOLLOW` refuses a symlink there anyway.
        let flags = if self.home {
            DIRECTORY.union(OFlags::NOFOLLOW)
        } else {
            DIRECTORY
        };
        let open = || rfs::open(anchor, flags, Mode::empty());
        let mut created = false;
        let fd = match open() {
            Ok(fd) => fd,
            Err(Errno::NOENT) if !create => return Ok(None),
            Err(Errno::NOENT) => {
                created = self.create_anchor()?;
                open().with_context(|| format!("failed to open `{}`", anchor.display()))?
            }
            // `O_DIRECTORY | O_NOFOLLOW` on a symlink is `ENOTDIR`.
            Err(Errno::LOOP | Errno::NOTDIR) if self.home => {
                bail!(
                    "`{}` is a symlink or not a directory; refusing to follow it",
                    anchor.display()
                )
            }
            Err(errno) => {
                return Err(io::Error::from(errno))
                    .with_context(|| format!("failed to open `{}`", anchor.display()));
            }
        };
        if created {
            // The umask may have narrowed the mode.
            rfs::fchmod(&fd, Mode::from_raw_mode(HOME_MODE))?;
        }
        if create && let Some(owner) = &self.owner {
            if self.home {
                let uid = rfs::fstat(&fd)?.st_uid;
                ensure!(
                    owner.may_own_home(uid),
                    "`{}` belongs to UID {uid}, not to `{}`; refusing to write to it",
                    anchor.display(),
                    crate::agent::apps_account::APPS_USER
                );
            }
            owner.claim(fd.as_fd(), anchor)?;
        }
        Ok(Some(fd))
    }

    /// Make the missing anchor: the home (`0700`, in a directory root owns),
    /// or a trusted directory and its parents. Returns whether this made the
    /// home.
    fn create_anchor(&self) -> Result<bool> {
        let anchor = &self.anchor;
        let context = || format!("failed to create `{}`", anchor.display());
        if !self.home {
            fs::create_dir_all(anchor).with_context(context)?;
            return Ok(false);
        }
        match fs::DirBuilder::new().mode(HOME_MODE).create(anchor) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error).with_context(context),
        }
    }

    /// Open the directory `relative` below the anchor, or `None` when it
    /// does not exist and `create` is not set. With `create`, missing
    /// directories are made, and every directory from the anchor down is
    /// handed to the owner.
    fn open_dir(&self, relative: &Path, create: bool) -> Result<Option<OwnedFd>> {
        let Some(mut fd) = self.open_anchor(create)? else {
            return Ok(None);
        };
        if relative.as_os_str().is_empty() {
            return Ok(Some(fd));
        }
        if !create {
            return match rfs::openat2(&fd, relative, DIRECTORY, Mode::empty(), RESOLVE) {
                Ok(fd) => Ok(Some(fd)),
                Err(Errno::NOENT) => Ok(None),
                Err(errno) => Err(self.refused(errno, &self.anchor.join(relative))),
            };
        }
        let mut current = self.anchor.clone();
        for component in relative.components() {
            current.push(component);
            let next = self.open_or_create(&fd, component.as_os_str(), &current)?;
            if let Some(owner) = &self.owner {
                owner.claim(next.as_fd(), &current)?;
            }
            fd = next;
        }
        Ok(Some(fd))
    }

    /// Open the directory `name` in `parent` (shown as `path`), making it
    /// (`0755`) when it is missing.
    fn open_or_create(&self, parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd> {
        let open = || rfs::openat2(parent, name, DIRECTORY, Mode::empty(), RESOLVE);
        match open() {
            Ok(fd) => return Ok(fd),
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(self.refused(errno, path)),
        }
        let created = match rfs::mkdirat(parent, name, Mode::from_raw_mode(DIR_MODE)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(errno) => {
                return Err(io::Error::from(errno))
                    .with_context(|| format!("failed to create `{}`", path.display()));
            }
        };
        let fd = open().map_err(|errno| self.refused(errno, path))?;
        if created {
            // The umask may have narrowed the mode.
            rfs::fchmod(&fd, Mode::from_raw_mode(DIR_MODE))?;
        }
        Ok(fd)
    }

    /// The error for an `openat2` below the anchor that failed.
    fn refused(&self, errno: Errno, path: &Path) -> anyhow::Error {
        match errno {
            Errno::LOOP => anyhow!(
                "`{}` contains a symlink; refusing to follow it",
                path.display()
            ),
            Errno::XDEV => anyhow!(
                "`{}` leaves `{}`; refusing to follow it",
                path.display(),
                self.anchor.display()
            ),
            Errno::NOTDIR => anyhow!("`{}` is not a directory", path.display()),
            errno => anyhow::Error::from(io::Error::from(errno))
                .context(format!("failed to open `{}`", path.display())),
        }
    }
}

/// Write `contents` to `name` in `dir` (see the [module docs](self)), in an
/// `O_TMPFILE` when `tmpfile` is set and the filesystem has them.
fn write_at(
    dir: &OwnedFd,
    name: &OsStr,
    contents: &[u8],
    mode: u32,
    owner: Option<&Owner>,
    path: &Path,
    tmpfile: bool,
) -> Result<()> {
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(
        ".tmp-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let private = Mode::from_raw_mode(0o600);
    let write = OFlags::WRONLY.union(OFlags::CLOEXEC);
    // Whether the file already has the temporary name.
    let anonymous = if tmpfile {
        rfs::openat(dir, ".", write.union(OFlags::TMPFILE), private)
    } else {
        Err(Errno::OPNOTSUPP)
    };
    let (fd, mut named) = match anonymous {
        Ok(fd) => (fd, false),
        // No `O_TMPFILE` on this filesystem (`EISDIR` before Linux 3.11).
        Err(Errno::OPNOTSUPP | Errno::ISDIR | Errno::INVAL) => {
            let exclusive = write
                .union(OFlags::CREATE)
                .union(OFlags::EXCL)
                .union(OFlags::NOFOLLOW);
            (rfs::openat(dir, &temporary, exclusive, private)?, true)
        }
        Err(errno) => return Err(errno.into()),
    };
    let mut file = File::from(fd);
    let result = (|| {
        if let Some(owner) = owner {
            owner.claim(file.as_fd(), path)?;
        }
        rfs::fchmod(&file, Mode::from_raw_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        if !named {
            link_tmpfile(file.as_fd(), dir, &temporary)?;
            named = true;
        }
        rfs::renameat(dir, &temporary, dir, name)?;
        named = false;
        rfs::fsync(dir)?;
        Ok(())
    })();
    if named {
        rfs::unlinkat(dir, &temporary, AtFlags::empty()).ok();
    }
    result
}

/// Give the `O_TMPFILE` `file` the name `name` in `dir`.
fn link_tmpfile(file: BorrowedFd<'_>, dir: &OwnedFd, name: &OsString) -> io::Result<()> {
    let proc = format!("/proc/self/fd/{}", file.as_raw_fd());
    rfs::linkat(rfs::CWD, proc.as_str(), dir, name, AtFlags::SYMLINK_FOLLOW).or_else(|error| {
        // Without `/proc`; needs `CAP_DAC_READ_SEARCH`.
        rfs::linkat(file, "", dir, name, AtFlags::EMPTY_PATH).map_err(|_| io::Error::from(error))
    })
}

/// The entries of the open directory `fd` (shown as `path`).
fn entries(fd: &OwnedFd, path: &Path) -> Result<Vec<(OsString, Kind)>> {
    let context = || format!("failed to read `{}`", path.display());
    let mut entries = Vec::new();
    for entry in rfs::Dir::read_from(fd).with_context(context)? {
        let entry = entry.map_err(io::Error::from).with_context(context)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = OsString::from_vec(name.to_vec());
        let kind = match entry.file_type() {
            FileType::Unknown => match rfs::statat(fd, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Kind::of(FileType::from_raw_mode(stat.st_mode)),
                // Removed meanwhile.
                Err(Errno::NOENT) => continue,
                Err(errno) => return Err(io::Error::from(errno)).with_context(context),
            },
            file_type => Kind::of(file_type),
        };
        entries.push((name, kind));
    }
    Ok(entries)
}

/// Remove everything in the open directory `fd` (shown as `path`).
fn empty_dir(fd: &OwnedFd, path: &Path) -> Result<()> {
    for (name, kind) in entries(fd, path)? {
        let child = path.join(&name);
        if kind == Kind::Dir {
            let dir =
                rfs::openat2(fd, &name, DIRECTORY, Mode::empty(), RESOLVE).map_err(|errno| {
                    anyhow::Error::from(io::Error::from(errno))
                        .context(format!("failed to open `{}`", child.display()))
                })?;
            empty_dir(&dir, &child)?;
        }
        let flags = if kind == Kind::Dir {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        match rfs::unlinkat(fd, &name, flags) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => {
                return Err(io::Error::from(errno))
                    .with_context(|| format!("failed to remove `{}`", child.display()));
            }
        }
    }
    Ok(())
}

/// Add the regular files below the open directory `fd` (shown as `path`,
/// `relative` to the listing's root) to `files`.
fn collect_files(
    fd: &OwnedFd,
    path: &Path,
    relative: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    for (name, kind) in entries(fd, path)? {
        match kind {
            Kind::File => files.push(relative.join(&name)),
            Kind::Dir => {
                let child = path.join(&name);
                let dir = rfs::openat2(fd, &name, DIRECTORY, Mode::empty(), RESOLVE).map_err(
                    |errno| {
                        anyhow::Error::from(io::Error::from(errno))
                            .context(format!("failed to open `{}`", child.display()))
                    },
                )?;
                collect_files(&dir, &child, &relative.join(&name), files)?;
            }
            Kind::Symlink | Kind::Other => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        sync::{Arc, Mutex},
    };

    use super::*;

    #[test]
    fn reads_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_READ.saturating_add(1)).unwrap();
        let tree = Tree::trusted(dir.path());
        let error = tree.read(&path).unwrap_err();
        assert!(error.to_string().contains("larger than"), "{error:#}");
        fs::File::create(&path).unwrap().set_len(MAX_READ).unwrap();
        assert_eq!(
            tree.read(&path).unwrap().len(),
            usize::try_from(MAX_READ).unwrap()
        );
    }
    use crate::agent::apps_account::AppsAccount;

    /// What the fake chown was handed: the path, relative to the home, and
    /// the inode of the descriptor it got.
    type Chowned = Arc<Mutex<Vec<(String, u64)>>>;

    /// A tree anchored at `home`, as the apps account's, whose owner
    /// records instead of changing ownership (which needs root).
    fn home_tree(home: &Path, dir: &Path) -> (Tree, Chowned) {
        let chowned: Chowned = Arc::default();
        let record = Arc::clone(&chowned);
        let base = home.to_path_buf();
        let account = AppsAccount {
            // Never the test's own IDs, so every entry is recorded.
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
            home: home.to_path_buf(),
        };
        let owner = Owner::with_chown(&account, move |fd, path, uid, gid| {
            assert_eq!((uid, gid), (u32::MAX - 1, u32::MAX - 1));
            let inode = rfs::fstat(fd).unwrap().st_ino;
            let relative = path.strip_prefix(&base).unwrap_or(path);
            record
                .lock()
                .unwrap()
                .push((relative.to_string_lossy().into_owned(), inode));
            Ok(())
        });
        (Tree::new(dir, Some(home), Some(owner)), chowned)
    }

    fn paths(chowned: &Chowned) -> Vec<String> {
        chowned
            .lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_and_hands_over_the_tree_below_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let quadlets = home.join(".config/containers/systemd");
        let (tree, chowned) = home_tree(&home, &quadlets);
        tree.create_dir(&quadlets).unwrap();
        assert!(quadlets.is_dir());
        assert_eq!(
            paths(&chowned),
            [
                "",
                ".config",
                ".config/containers",
                ".config/containers/systemd"
            ]
        );
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(&quadlets), 0o755);

        // The file is handed over through its descriptor: the inode the fake
        // chown saw is the one that ends up at the path.
        chowned.lock().unwrap().clear();
        let unit = quadlets.join("app.container");
        tree.write(&unit, b"[Container]\n", 0o600).unwrap();
        assert_eq!(fs::read(&unit).unwrap(), b"[Container]\n");
        assert_eq!(mode(&unit), 0o600);
        let (path, inode) = chowned.lock().unwrap().last().unwrap().clone();
        assert_eq!(path, ".config/containers/systemd/app.container");
        assert_eq!(inode, fs::metadata(&unit).unwrap().ino());

        // Replacing keeps the new mode, whatever the old file had.
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o666)).unwrap();
        tree.write(&unit, b"[Container]\nImage=x\n", 0o644).unwrap();
        assert_eq!(mode(&unit), 0o644);
        assert_eq!(
            tree.read_to_string(&unit).unwrap(),
            "[Container]\nImage=x\n"
        );
        // No temporary file is left behind.
        let names: Vec<_> = fs::read_dir(&quadlets)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["app.container"]);
    }

    #[test]
    fn writes_through_a_named_temporary_without_o_tmpfile() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let (tree, chowned) = home_tree(&home, &home);
        tree.create_dir(&home).unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "keep").unwrap();
        symlink(&target, home.join("app.json")).unwrap();
        let fd = rfs::open(&home, DIRECTORY, Mode::empty()).unwrap();
        let path = home.join("app.json");
        write_at(
            &fd,
            "app.json".as_ref(),
            b"{}",
            0o600,
            tree.owner.as_ref(),
            &path,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        let (_, inode) = chowned.lock().unwrap().last().unwrap().clone();
        assert_eq!(inode, fs::metadata(&path).unwrap().ino());
        let names: Vec<_> = fs::read_dir(&home)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["app.json"]);
    }

    #[test]
    fn nothing_is_given_away_without_an_owner() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("system");
        let tree = Tree::trusted(&base);
        tree.write(&base.join("a/b.container"), b"x", 0o600)
            .unwrap();
        assert_eq!(fs::read(base.join("a/b.container")).unwrap(), b"x");
        assert_eq!(mode(&base.join("a/b.container")), 0o600);
    }

    #[test]
    fn refuses_a_symlink_at_a_directory_component() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let elsewhere = dir.path().join("etc");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("passwd"), "root").unwrap();
        symlink(&elsewhere, home.join(".config")).unwrap();
        let quadlets = home.join(".config/containers/systemd");
        let (tree, chowned) = home_tree(&home, &quadlets);

        let error = tree.create_dir(&quadlets).unwrap_err().to_string();
        assert!(error.contains("contains a symlink"), "{error}");
        let error = tree
            .write(&quadlets.join("app.container"), b"x", 0o600)
            .unwrap_err()
            .to_string();
        assert!(error.contains("contains a symlink"), "{error}");
        let error = tree
            .read(&home.join(".config/passwd"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("contains a symlink"), "{error}");
        tree.remove_file(&home.join(".config/passwd")).unwrap_err();
        tree.remove_dir_all(&home.join(".config/x")).unwrap_err();
        tree.files_below(&home.join(".config")).unwrap_err();
        tree.read_dir(&home.join(".config")).unwrap_err();
        // Nothing happened on the other side of the link; only the home was
        // handed over.
        assert!(!elsewhere.join("containers").exists());
        assert_eq!(
            fs::read_to_string(elsewhere.join("passwd")).unwrap(),
            "root"
        );
        assert_eq!(paths(&chowned), ["", ""]);

        // A symlinked home is refused too.
        let linked = dir.path().join("linked-home");
        symlink(&home, &linked).unwrap();
        let (tree, _) = home_tree(&linked, &linked.join("x"));
        let error = tree.create_dir(&linked.join("x")).unwrap_err().to_string();
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn replaces_a_symlink_at_the_file_name_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let target = dir.path().join("shadow");
        fs::write(&target, "secret").unwrap();
        let (tree, chowned) = home_tree(&home, &home);
        tree.create_dir(&home.join("bundle")).unwrap();
        let manifest = home.join("bundle/app.json");
        symlink(&target, &manifest).unwrap();

        // Reading does not follow it.
        let error = tree.read(&manifest).unwrap_err().to_string();
        assert!(error.contains("contains a symlink"), "{error}");
        assert!(tree.exists(&manifest).unwrap());

        tree.write(&manifest, b"{}", 0o600).unwrap();
        assert!(!fs::symlink_metadata(&manifest).unwrap().is_symlink());
        assert_eq!(fs::read(&manifest).unwrap(), b"{}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "secret");
        assert_ne!(mode(&target), 0o600, "the target's mode was changed");
        let target_inode = fs::metadata(&target).unwrap().ino();
        assert!(
            chowned
                .lock()
                .unwrap()
                .iter()
                .all(|(_, inode)| *inode != target_inode),
            "the target was handed over"
        );
    }

    #[test]
    fn reads_only_regular_files_with_one_link() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let (tree, _) = home_tree(&home, &home);
        // A FIFO would block a plain open forever.
        nix::unistd::mkfifo(&home.join("fifo"), nix::sys::stat::Mode::S_IRWXU).unwrap();
        let error = tree.read(&home.join("fifo")).unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
        // A hard link to a file elsewhere.
        let outside = dir.path().join("outside");
        fs::write(&outside, "secret").unwrap();
        fs::hard_link(&outside, home.join("app.json")).unwrap();
        let error = tree.read(&home.join("app.json")).unwrap_err().to_string();
        assert!(error.contains("hard links"), "{error}");
        // Missing files say so.
        let error = format!("{:#}", tree.read(&home.join("missing")).unwrap_err());
        assert!(error.contains("failed to read"), "{error}");
        // Outside the anchor, or not a plain path below it.
        tree.read(&outside).unwrap_err();
        tree.read(&home.join("../outside")).unwrap_err();
    }

    #[test]
    fn removal_does_not_follow_links() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("keep"), "keep").unwrap();
        let (tree, _) = home_tree(&home, &home);
        let bundle = home.join("bundle");
        tree.write(&bundle.join("site/index.html"), b"hi", 0o644)
            .unwrap();
        symlink(&elsewhere, bundle.join("site/link")).unwrap();
        symlink(elsewhere.join("keep"), bundle.join("unit.container")).unwrap();

        // Removing a symlink removes the link.
        assert!(tree.remove_file(&bundle.join("unit.container")).unwrap());
        assert!(!tree.remove_file(&bundle.join("unit.container")).unwrap());
        assert!(elsewhere.join("keep").exists());
        // So does removing a tree with one inside.
        assert_eq!(
            tree.files_below(&bundle).unwrap(),
            [Path::new("site/index.html")]
        );
        tree.remove_dir_all(&bundle).unwrap();
        assert!(!bundle.exists());
        assert_eq!(fs::read_to_string(elsewhere.join("keep")).unwrap(), "keep");
        // A symlinked directory is refused, not emptied.
        symlink(&elsewhere, home.join("linked")).unwrap();
        tree.remove_dir_all(&home.join("linked")).unwrap_err();
        assert!(elsewhere.join("keep").exists());
        assert_eq!(
            tree.read_dir(&home).unwrap().unwrap(),
            [(OsString::from("linked"), Kind::Symlink)]
        );
        assert_eq!(tree.read_dir(&home.join("missing")).unwrap(), None);
    }

    #[test]
    fn a_home_owned_by_someone_else_is_refused() {
        let account = AppsAccount {
            uid: u32::MAX - 1,
            gid: u32::MAX - 1,
            home: PathBuf::from("/nonexistent"),
        };
        let owner = Owner::with_chown(&account, |_, _, _, _| Ok(()));
        assert!(owner.may_own_home(u32::MAX - 1));
        assert!(owner.may_own_home(nix::unistd::geteuid().as_raw()));
        let stranger = nix::unistd::geteuid().as_raw().wrapping_add(1);
        assert!(!owner.may_own_home(stranger) || stranger == u32::MAX - 1);
    }

    #[test]
    fn directories_outside_the_home_are_their_own_anchor() {
        let tree = Tree::new(
            Path::new("/etc/containers/systemd"),
            Some(Path::new("/var/lib/ultramarine-apps")),
            None,
        );
        assert_eq!(tree.anchor, Path::new("/etc/containers/systemd"));
        assert!(!tree.home);
        let tree = Tree::new(
            Path::new("/var/lib/ultramarine-apps/.config/containers/systemd"),
            Some(Path::new("/var/lib/ultramarine-apps")),
            None,
        );
        assert_eq!(tree.anchor, Path::new("/var/lib/ultramarine-apps"));
        assert!(tree.home);
        // Not a component-wise prefix.
        let tree = Tree::new(
            Path::new("/var/lib/ultramarine-apps2/x"),
            Some(Path::new("/var/lib/ultramarine-apps")),
            None,
        );
        assert!(!tree.home);
    }

    #[test]
    #[cfg(feature = "quadlets")]
    fn nothing_outside_the_home_is_given_away() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("apps");
        let (owner, chowned) = crate::agent::apps_account::tests::recording_owner(&home);
        let elsewhere = dir.path().join("override");
        let tree = Tree::new(&elsewhere, Some(&home), Some(owner));
        assert!(!tree.home);
        tree.create_dir(&elsewhere).unwrap();
        tree.write(&elsewhere.join("x.container"), b"[Container]\n", 0o600)
            .unwrap();
        assert!(chowned.lock().unwrap().is_empty());
    }
}
