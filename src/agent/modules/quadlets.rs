//! Quadlet file management for Podman-backed systemd services.
//!
//! Quadlets are systemd unit files (`.container`, `.volume`, `.network`,
//! `.pod`, `.kube`) that Podman scans to generate corresponding `.service`
//! units. This module owns their full lifecycle on behalf of the Ultramarine
//! Server control plane: `list`, `read`, `write`, `delete`, `validate`,
//! `install`, and `list_files`.
//!
//! Two distinct kinds of files are managed, and the distinction matters:
//!
//! - **Quadlet unit files** live in the directories Podman scans
//!   (`~ultramarine-apps/.config/containers/systemd` for apps scope,
//!   `/etc/containers/systemd` for system scope). They must have a supported
//!   extension and contain a matching Quadlet section header such as
//!   `[Container]`.
//!
//! - **Companion files** are arbitrary app content/config (an nginx site
//!   config, an `index.html`, ...) referenced by a Quadlet. They are *not*
//!   scanned by Podman and do not need a Quadlet extension. They live in a
//!   separate mutable data root (`~ultramarine-apps/.local/share/tetra/quadlets`
//!   for apps scope, `/var/lib/tetra/quadlets` for system scope), under a per-app
//!   bundle directory named after the primary Quadlet's stem — so
//!   `app.container`'s companions live under `.../quadlets/app/`.
//!
//! The split exists because on bootc-style image systems the Quadlet scan
//! directories may sit on an immutable image layer, while companion content
//! is mutable app data and must live in a writable data root. Keeping the
//! two roots separate also lets SELinux policy and config backups apply
//! independently to each.
//!
//! Scope is selected per request via `scope: "apps" | "system"` (default
//! `apps`, see [`AppScope`]). Apps-scope files are rootless Quadlets of the
//! `ultramarine-apps` account and are handed to it after each write; system
//! scope is rootful, for real system services. Every action also accepts
//! optional `base_dir` / `files_base_dir` overrides, which is what makes the
//! protocol testable without touching real system paths.
//!
//! This module only writes files. It deliberately does *not* run
//! `systemctl daemon-reload`; the caller does that through the separate
//! `services` module's `daemon_reload` action once writes are confirmed.

use serde_json::json;

use crate::actions;
use crate::agent::apps_account::{
    APPS_USER, AppsAccount, Owner, check_no_symlinks, create_dir_owned, write_owned,
};
use crate::agent::module_support::{
    ModuleInfo, ModuleStatus, SelinuxOptions, apply_selinux, resolve_under, safe_join,
};
use crate::agent::modules::Mod;
use crate::prelude::*;
use crate::types::AppScope;

/// Agent module backing the `quadlets` feature. See the module-level docs
/// for the unit-vs-companion distinction and the scope model.
#[derive(Clone, Copy, Debug)]
pub struct QuadletsModule;

/// Static module descriptor advertised to the control plane via
/// `capabilities`/`plan`. Marked `Available` because this module has no
/// optional host dependencies — it only touches the filesystem and shells
/// out for SELinux when explicitly requested.
const INFO: ModuleInfo = ModuleInfo {
    name: "quadlets",
    feature: "quadlets",
    description: "Manage Quadlet files separately from systemd unit service control.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "read",
        "write",
        "delete",
        "validate",
        "install",
        "list_files",
    ],
    privileged_actions: &["write", "delete", "install"],
};

/// File extensions Podman recognizes as Quadlet units. Used both to validate
/// incoming filenames and to classify listed files as Quadlet vs companion.
const QUADLET_EXTENSIONS: &[&str] = &["container", "image", "kube", "network", "pod", "volume"];

/// A single file within an `install` payload. The same shape is reused for
/// both Quadlet `resources` and companion `files`; the surrounding payload
/// decides which directory each one is written into. Per-resource `selinux`
/// lets one file be labeled differently from the rest, on top of any
/// payload-level labeling applied to the Quadlet base directory.
#[derive(Debug, Deserialize)]
struct InstallResource {
    filename: String,
    contents: String,
    #[serde(default)]
    selinux: Option<SelinuxOptions>,
}

/// Response entry for a discovered Quadlet unit file. `path` is absolute so
/// the control plane can address the file without reconstructing the base dir.
#[derive(Debug, Serialize)]
struct QuadletFile {
    filename: String,
    path: PathBuf,
}

/// Response entry for `list_files`, covering both Quadlet units and
/// companion files. `quadlet` flags which entries are Quadlet units so the
/// dashboard can route edits to the right surface without a second round-trip.
#[derive(Debug, Serialize)]
pub(crate) struct ManagedFile {
    filename: String,
    path: PathBuf,
    quadlet: bool,
}

impl ManagedFile {
    /// Filename relative to the scanned root (e.g. `app/index.html` for a
    /// companion inside a bundle directory).
    pub(crate) fn filename(&self) -> &str {
        &self.filename
    }
}

impl Mod for QuadletsModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List {
        base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
    } => {
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        Ok(json!({ "base_dir": base_dir, "files": QuadletFile::list(&base_dir)? }))
    },
    ListFiles {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
    } => {
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        let files_base_dir = quadlet_files_base_dir(payload.files_base_dir, payload.scope, None)?;
        let mut files = ManagedFile::list(&base_dir)?;
        files.extend(list_companion_files(&files_base_dir)?);
        // Quadlet entries first, then companions, each group sorted by filename.
        files.sort_by(|left, right| {
            left.quadlet
                .cmp(&right.quadlet)
                .reverse()
                .then_with(|| left.filename.cmp(&right.filename))
        });
        Ok(json!({ "base_dir": base_dir, "files_base_dir": files_base_dir, "files": files }))
    },
    Read {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
        filename: String,
        #[serde(default)]
        companion: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let (base_dir, path) = target(
            payload.base_dir,
            payload.files_base_dir,
            payload.scope,
            &payload.filename,
            payload.companion,
        )?;
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read `{}`", path.display()))?;
        Ok(json!({ "base_dir": base_dir, "filename": payload.filename, "contents": contents, "dry_run": payload.dry_run }))
    },
    Write {
        base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
        filename: String,
        contents: String,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        validate_quadlet(&payload.filename, &payload.contents)?;
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        let owner = scope_owner(payload.scope, payload.dry_run)?;
        let path = write_owned(
            &base_dir,
            &payload.filename,
            payload.contents.as_bytes(),
            UNIT_MODE,
            payload.dry_run,
            owner.as_ref(),
        )?;
        let selinux =
            apply_selinux(payload.selinux.as_ref(), Some(&path), payload.dry_run)?;
        Ok(json!({
            "base_dir": base_dir, "filename": payload.filename, "path": path,
            "owner": owner_name(payload.scope),
            "written": !payload.dry_run,
            "dry_run": payload.dry_run, "selinux": selinux,
        }))
    },
    Delete {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
        filename: String,
        #[serde(default)]
        companion: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let (base_dir, path) = target(
            payload.base_dir,
            payload.files_base_dir,
            payload.scope,
            &payload.filename,
            payload.companion,
        )?;
        if !payload.dry_run {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete `{}`", path.display()))?;
        }
        Ok(json!({
            "base_dir": base_dir, "filename": payload.filename, "path": path,
            "deleted": !payload.dry_run,
            "dry_run": payload.dry_run,
        }))
    },
    Validate {
        filename: String,
        contents: String,
    } => {
        validate_quadlet(&payload.filename, &payload.contents)?;
        Ok(json!({ "filename": payload.filename, "valid": true }))
    },
    Install {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: AppScope,
        resources: Vec<InstallResource>,
        #[serde(default)]
        files: Vec<InstallResource>,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        let owner = scope_owner(payload.scope, payload.dry_run)?;
        // The companion bundle is named after the first Quadlet
        // resource's stem (`site.container` -> `site`). Callers are
        // expected to put the primary unit first; with no Quadlets,
        // companions land directly under files_base_dir.
        let bundle_name = payload
            .resources
            .first()
            .map(|resource| quadlet_bundle_name(&resource.filename))
            .transpose()?;
        let files_base_dir = quadlet_files_base_dir(
            payload.files_base_dir,
            payload.scope,
            bundle_name.as_deref(),
        )?;
        // Create both roots up front so a permission or disk failure
        // surfaces before any file is written, rather than midway
        // through the bundle.
        create_dir_owned(&base_dir, payload.dry_run, owner.as_ref())?;
        create_dir_owned(&files_base_dir, payload.dry_run, owner.as_ref())?;

        let mut installed = Vec::new();
        let mut selinux_ops = Vec::new();
        for resource in payload.resources {
            validate_quadlet(&resource.filename, &resource.contents)?;
            let path = write_owned(&base_dir, &resource.filename, resource.contents.as_bytes(), UNIT_MODE, payload.dry_run, owner.as_ref())?;
            selinux_ops.extend(apply_selinux(
                resource.selinux.as_ref(),
                Some(&path),
                payload.dry_run,
            )?);
            installed.push(QuadletFile {
                filename: resource.filename,
                path,
            });
        }
        let mut files = Vec::new();
        for resource in payload.files {
            let path = write_owned(&files_base_dir, &resource.filename, resource.contents.as_bytes(), COMPANION_MODE, payload.dry_run, owner.as_ref())?;
            selinux_ops.extend(apply_selinux(
                resource.selinux.as_ref(),
                Some(&path),
                payload.dry_run,
            )?);
            files.push(ManagedFile {
                filename: resource.filename,
                path,
                quadlet: false,
            });
        }
        // Payload-level selinux labels the Quadlet scan directory
        // (typically with `recursive: true`), on top of any
        // per-resource labels above. Companion files under
        // files_base_dir are not labeled here — callers label them
        // per-resource when needed.
        selinux_ops.extend(apply_selinux(
            payload.selinux.as_ref(),
            Some(&base_dir),
            payload.dry_run,
        )?);

        Ok(json!({
            "base_dir": base_dir, "files_base_dir": files_base_dir, "installed": installed, "files": files,
            "owner": owner_name(payload.scope),
            "written": !payload.dry_run,
            "dry_run": payload.dry_run, "selinux": selinux_ops,
        }))
    },
});

impl QuadletFile {
    /// List Quadlet unit files directly under `base_dir` (non-recursive). Only
    /// flat files with a Quadlet extension are returned; subdirectories and
    /// non-Quadlet files are skipped, mirroring how Podman scans the directory.
    fn list(base_dir: &Path) -> Result<Vec<Self>> {
        if !base_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        for entry in fs::read_dir(base_dir)
            .with_context(|| format!("failed to read `{}`", base_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if is_quadlet_filename(filename) {
                files.push(Self {
                    filename: filename.to_owned(),
                    path,
                });
            }
        }
        files.sort_by(|left, right| left.filename.cmp(&right.filename));
        Ok(files)
    }
}

impl ManagedFile {
    /// Same scan as [`QuadletFile::list`] but returns [`ManagedFile`] entries tagged
    /// `quadlet: true`, so `list_files` can merge Quadlet and companion results
    /// into a single response.
    fn list(base_dir: &Path) -> Result<Vec<Self>> {
        Ok(QuadletFile::list(base_dir)?
            .into_iter()
            .map(|QuadletFile { filename, path }| Self {
                filename,
                path,
                quadlet: true,
            })
            .collect())
    }
}

/// Resolve the Quadlet scan directory for a request. An explicit `base_dir`
/// always wins — tests and custom deployments rely on this — otherwise the
/// scope picks the default Podman scan path.
///
/// The apps account's directories are refused when a directory on the way
/// is a symlink (see [`check_no_symlinks`]).
pub(crate) fn quadlet_base_dir(base_dir: Option<PathBuf>, scope: AppScope) -> Result<PathBuf> {
    if let Some(base_dir) = base_dir {
        return Ok(base_dir);
    }
    match scope {
        AppScope::Apps => apps_dir(AppsAccount::quadlet_dir),
        AppScope::System => Ok(PathBuf::from("/etc/containers/systemd")),
    }
}

/// One of the apps account's directories, checked for symlinks.
fn apps_dir(dir: fn(&AppsAccount) -> PathBuf) -> Result<PathBuf> {
    let account = AppsAccount::resolve();
    let dir = dir(&account);
    check_no_symlinks(&account.home, &dir)?;
    Ok(dir)
}

/// Resolve the companion-files data root, optionally nested under a bundle
/// name. Kept separate from `quadlet_base_dir` because the two roots serve
/// different mutability and labeling needs (see the module docs). The
/// `bundle_name` is joined via `safe_join` so a derived bundle path can
/// never escape the data root.
pub(crate) fn quadlet_files_base_dir(
    files_base_dir: Option<PathBuf>,
    scope: AppScope,
    bundle_name: Option<&str>,
) -> Result<PathBuf> {
    let base = match (files_base_dir, scope) {
        (Some(files_base_dir), _) => files_base_dir,
        (None, AppScope::Apps) => apps_dir(AppsAccount::data_dir)?,
        (None, AppScope::System) => PathBuf::from("/var/lib/tetra/quadlets"),
    };
    if let Some(bundle_name) = bundle_name {
        safe_join(&base, bundle_name)
    } else {
        Ok(base)
    }
}

/// Who files written in `scope` are handed to: the apps account in apps
/// scope (see [`Owner::for_apps`]), nobody (root keeps them) in system scope.
pub(crate) fn scope_owner(scope: AppScope, dry_run: bool) -> Result<Option<Owner>> {
    match scope {
        AppScope::Apps => Owner::for_apps(dry_run),
        AppScope::System => Ok(None),
    }
}

/// The account files written in `scope` belong to, for responses.
pub(crate) const fn owner_name(scope: AppScope) -> &'static str {
    match scope {
        AppScope::Apps => APPS_USER,
        AppScope::System => "root",
    }
}

/// Derive the companion bundle name from a Quadlet filename
/// (`app.container` -> `app`). This is also the first line of defense
/// against path-traversal in filenames: it rejects absolute paths and any
/// `..`/`Prefix` component before `safe_join` runs at write time.
fn quadlet_bundle_name(pathstr: &str) -> Result<String> {
    // Reject absolute paths and `..` up front so the derived bundle name
    // can't be used to escape the data root later.
    let path = safe_join(Path::new(""), pathstr)?;
    let base_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Quadlet filename must include a file name")?;
    let Some((stem, extension)) = base_name.rsplit_once('.') else {
        bail!("`{pathstr}` is not a supported Quadlet filename");
    };
    if !QUADLET_EXTENSIONS.contains(&extension) || stem.is_empty() {
        bail!("`{pathstr}` is not a supported Quadlet filename");
    }
    Ok(stem.to_owned())
}

/// Recursively list companion files under the data root. Recursive because,
/// unlike the Quadlet scan dir, the companion tree is ours to organize and
/// may hold nested paths like `app/nginx/default.conf`.
pub(crate) fn list_companion_files(base_dir: &Path) -> Result<Vec<ManagedFile>> {
    if !base_dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    collect_files(base_dir, base_dir, &mut files)?;
    files.sort_by(|left, right| left.filename.cmp(&right.filename));
    Ok(files)
}

/// Recursive worker for `list_companion_files`. `base_dir` is anchored at
/// the root so each entry's `filename` is reported relative to it (with
/// forward slashes regardless of platform), while `path` stays absolute for
/// filesystem access.
fn collect_files(base_dir: &Path, dir: &Path, files: &mut Vec<ManagedFile>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read `{}`", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_files(base_dir, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let filename = path
            .strip_prefix(base_dir)
            .with_context(|| format!("failed to make `{}` relative", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        // Classification is a suffix check only: a companion file that
        // happens to end in `.container` would be flagged `quadlet: true`.
        // This is fine because the flag is display-only and never gates a
        // write — real Quadlet files should not live under the companion root.
        files.push(ManagedFile {
            quadlet: is_quadlet_filename(&filename),
            filename,
            path,
        });
    }

    Ok(())
}

/// The directory and path of a Quadlet (`companion: false`) or companion
/// file named by a `read`/`delete` payload. Companion files are addressed by
/// their full relative path (e.g. `site/index.html`), so no bundle is
/// derived; Quadlets resolve against the flat scan directory. The path may
/// not leave the directory or pass through a symlink.
fn target(
    base_dir: Option<PathBuf>,
    files_base_dir: Option<PathBuf>,
    scope: AppScope,
    filename: &str,
    companion: bool,
) -> Result<(PathBuf, PathBuf)> {
    let base_dir = if companion {
        quadlet_files_base_dir(files_base_dir, scope, None)?
    } else {
        quadlet_bundle_name(filename)?;
        quadlet_base_dir(base_dir, scope)?
    };
    let path = resolve_under(&base_dir, filename)?;
    Ok((base_dir, path))
}

/// Mode of unit files, which can hold secrets (`Environment=...`).
const UNIT_MODE: u32 = 0o600;
/// Mode of companion files, which containers read through bind mounts.
const COMPANION_MODE: u32 = 0o644;

/// Cheap structural validation: supported extension, non-empty contents, and
/// at least one Quadlet section header. This is *not* a full `quadlet
/// -dryrun` lint — it just rejects obvious junk before anything is written
/// to a system directory. The section-header check is what stops a stray
/// `.service` or generic INI file from being installed as a Quadlet.
pub(crate) fn validate_quadlet(filename: &str, contents: &str) -> Result<()> {
    if !is_quadlet_filename(filename) {
        bail!("`{filename}` is not a supported Quadlet filename");
    }
    if contents.trim().is_empty() {
        bail!("Quadlet contents cannot be empty");
    }
    if !contents.lines().any(|line| {
        matches!(
            line.trim(),
            "[Container]" | "[Image]" | "[Kube]" | "[Network]" | "[Pod]" | "[Volume]"
        )
    }) {
        bail!("Quadlet contents must include a Quadlet section");
    }
    Ok(())
}

/// True if `filename` ends with a supported Quadlet extension. Used both to
/// reject non-Quadlet writes and to tag listed files as Quadlet vs companion.
pub(crate) fn is_quadlet_filename(filename: &str) -> bool {
    QUADLET_EXTENSIONS
        .iter()
        .any(|extension| filename.ends_with(&format!(".{extension}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::modules::Act;

    #[test]
    fn rejects_paths_outside_base_dir() {
        let base = Path::new("/tmp/quadlets");
        safe_join(base, "../unit.container").unwrap_err();
        safe_join(base, "/tmp/unit.container").unwrap_err();
        assert_eq!(
            safe_join(base, "unit.container").unwrap(),
            base.join("unit.container")
        );
    }

    #[test]
    fn validates_quadlet_sections_and_extensions() {
        validate_quadlet("app.container", "[Container]\nImage=example\n").unwrap();
        validate_quadlet("app.service", "[Container]\nImage=example\n").unwrap_err();
        validate_quadlet("app.container", "[Service]\nExecStart=true\n").unwrap_err();
    }

    #[test]
    fn system_scope_uses_system_quadlet_directory() {
        assert_eq!(
            quadlet_base_dir(None, AppScope::System).unwrap(),
            PathBuf::from("/etc/containers/systemd")
        );
    }

    #[test]
    fn system_scope_uses_var_lib_for_companion_files() {
        assert_eq!(
            quadlet_files_base_dir(None, AppScope::System, Some("app")).unwrap(),
            PathBuf::from("/var/lib/tetra/quadlets/app")
        );
    }

    #[test]
    fn apps_scope_is_the_default_and_lives_in_the_apps_home() {
        let list: List = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(list.scope, AppScope::Apps);
        let home = AppsAccount::resolve().home;
        assert_eq!(
            quadlet_base_dir(None, AppScope::Apps).unwrap(),
            home.join(".config/containers/systemd")
        );
        assert_eq!(
            quadlet_files_base_dir(None, AppScope::Apps, Some("app")).unwrap(),
            home.join(".local/share/tetra/quadlets/app")
        );
        // Overrides win in any scope.
        assert_eq!(
            quadlet_base_dir(Some("/srv/q".into()), AppScope::Apps).unwrap(),
            Path::new("/srv/q")
        );
        assert_eq!(owner_name(AppScope::Apps), "ultramarine-apps");
        assert_eq!(owner_name(AppScope::System), "root");
        // Nothing is given away on a dry run, or in system scope.
        assert!(scope_owner(AppScope::Apps, true).unwrap().is_none());
        assert!(scope_owner(AppScope::System, false).unwrap().is_none());
        serde_json::from_value::<List>(serde_json::json!({ "scope": "user" })).unwrap_err();
    }

    #[test]
    fn owned_writes_hand_units_and_companions_to_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("apps");
        let (owner, chowned) = crate::agent::apps_account::tests::recording_owner(&home);
        let base = home.join(".config/containers/systemd");
        let files = home.join(".local/share/tetra/quadlets/site");
        create_dir_owned(&base, false, Some(&owner)).unwrap();
        create_dir_owned(&files, false, Some(&owner)).unwrap();
        write_owned(&base, "site.container", b"[Container]\n", UNIT_MODE, false, Some(&owner))
            .unwrap();
        write_owned(&files, "nginx/default.conf", b"server {}\n", COMPANION_MODE, false, Some(&owner))
            .unwrap();
        let chowned = chowned.lock().unwrap().clone();
        for path in [
            ".config/containers/systemd",
            ".config/containers/systemd/site.container",
            ".local/share/tetra/quadlets/site",
            ".local/share/tetra/quadlets/site/nginx",
            ".local/share/tetra/quadlets/site/nginx/default.conf",
        ] {
            assert!(chowned.iter().any(|chowned| chowned == path), "{path}: {chowned:?}");
        }
        let mode = |path: &Path| {
            use std::os::unix::fs::PermissionsExt as _;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&base.join("site.container")), 0o600);
        assert_eq!(mode(&files.join("nginx/default.conf")), 0o644);

        // A dry run neither writes nor gives anything away.
        let before = chowned.len();
        let (dry_owner, dry_chowned) = crate::agent::apps_account::tests::recording_owner(&home);
        write_owned(&base, "other.container", b"[Container]\n", UNIT_MODE, true, Some(&dry_owner))
            .unwrap();
        assert!(!base.join("other.container").exists());
        assert!(dry_chowned.lock().unwrap().is_empty());
        assert!(before > 0);
    }

    #[test]
    fn dry_run_write_does_not_create_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.container");
        let response = Write {
            base_dir: Some(dir.path().to_path_buf()),
            scope: AppScope::Apps,
            filename: "app.container".into(),
            contents: "[Container]\nImage=example\n".into(),
            dry_run: true,
            selinux: None,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["dry_run"], true);
        assert_eq!(response["written"], false);
        assert!(!path.exists());
    }

    #[test]
    fn install_can_restore_quadlet_contexts() {
        let dir = tempfile::tempdir().unwrap();
        let response = Install {
            base_dir: Some(dir.path().to_path_buf()),
            files_base_dir: None,
            scope: AppScope::Apps,
            resources: vec![InstallResource {
                filename: "app.container".into(),
                contents: "[Container]\nImage=example\n".into(),
                selinux: None,
            }],
            files: vec![],
            dry_run: true,
            selinux: Some(SelinuxOptions {
                context_type: Some("container_unit_file_t".into()),
                recursive: true,
                ..SelinuxOptions::default()
            }),
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["selinux"].as_array().unwrap().len(), 2);
        assert!(
            response["selinux"][0]["command"]
                .as_str()
                .unwrap()
                .contains("semanage fcontext -a -t container_unit_file_t")
        );
        assert!(
            response["selinux"][1]["command"]
                .as_str()
                .unwrap()
                .contains("restorecon -R -v")
        );
    }

    #[test]
    fn install_writes_companion_files_under_mutable_files_base_dir() {
        let quadlet_dir = tempfile::tempdir().unwrap();
        let files_dir = tempfile::tempdir().unwrap();
        let response = Install {
            base_dir: Some(quadlet_dir.path().to_path_buf()),
            files_base_dir: Some(files_dir.path().to_path_buf()),
            scope: AppScope::Apps,
            resources: vec![InstallResource {
                filename: "site.container".into(),
                contents: "[Container]\nImage=nginx\n".into(),
                selinux: None,
            }],
            files: vec![
                InstallResource {
                    filename: "index.html".into(),
                    contents: "<h1>Hello</h1>\n".into(),
                    selinux: None,
                },
                InstallResource {
                    filename: "nginx/default.conf".into(),
                    contents: "server {}\n".into(),
                    selinux: None,
                },
            ],
            dry_run: false,
            selinux: None,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["written"], true);
        assert_eq!(
            response["base_dir"],
            quadlet_dir.path().to_string_lossy().as_ref()
        );
        assert_eq!(
            response["files_base_dir"],
            files_dir.path().join("site").to_string_lossy().as_ref()
        );
        assert_eq!(response["files"].as_array().unwrap().len(), 2);
        assert_eq!(
            fs::read_to_string(files_dir.path().join("site/index.html")).unwrap(),
            "<h1>Hello</h1>\n"
        );
        assert_eq!(
            fs::read_to_string(files_dir.path().join("site/nginx/default.conf")).unwrap(),
            "server {}\n"
        );
        assert!(!quadlet_dir.path().join("site/index.html").exists());
    }

    #[test]
    fn list_files_includes_quadlets_and_companion_files() {
        let quadlet_dir = tempfile::tempdir().unwrap();
        let files_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(files_dir.path().join("site")).unwrap();
        fs::write(
            quadlet_dir.path().join("site.container"),
            "[Container]\nImage=nginx\n",
        )
        .unwrap();
        fs::write(files_dir.path().join("site/index.html"), "<h1>Hello</h1>\n").unwrap();

        let response = ListFiles {
            base_dir: Some(quadlet_dir.path().to_path_buf()),
            files_base_dir: Some(files_dir.path().to_path_buf()),
            scope: AppScope::Apps,
        }
        .handle(None)
        .unwrap();
        let files = response["files"].as_array().unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["filename"], "site.container");
        assert_eq!(files[0]["quadlet"], true);
        assert_eq!(files[1]["filename"], "site/index.html");
        assert_eq!(files[1]["quadlet"], false);
    }

    #[test]
    fn read_can_load_companion_files_from_files_base_dir() {
        let files_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(files_dir.path().join("site")).unwrap();
        fs::write(files_dir.path().join("site/index.html"), "<h1>Hello</h1>\n").unwrap();

        let response = Read {
            base_dir: None,
            files_base_dir: Some(files_dir.path().to_path_buf()),
            scope: AppScope::Apps,
            filename: "site/index.html".into(),
            companion: true,
            dry_run: false,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["contents"], "<h1>Hello</h1>\n");
    }
}
