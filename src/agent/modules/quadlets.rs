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
//!   (`~/.config/containers/systemd` for user scope, `/etc/containers/systemd`
//!   for system scope). They must have a supported extension and contain a
//!   matching Quadlet section header such as `[Container]`.
//!
//! - **Companion files** are arbitrary app content/config (an nginx site
//!   config, an `index.html`, ...) referenced by a Quadlet. They are *not*
//!   scanned by Podman and do not need a Quadlet extension. They live in a
//!   separate mutable data root (`~/.local/share/tetra/quadlets` for user
//!   scope, `/var/lib/tetra/quadlets` for system scope), under a per-app
//!   bundle directory named after the primary Quadlet's stem — so
//!   `app.container`'s companions live under `.../quadlets/app/`.
//!
//! The split exists because on bootc-style image systems the Quadlet scan
//! directories may sit on an immutable image layer, while companion content
//! is mutable app data and must live in a writable data root. Keeping the
//! two roots separate also lets SELinux policy and config backups apply
//! independently to each.
//!
//! Scope is selected per request via `scope: "user" | "system"` (default
//! `user`). Every action also accepts optional `base_dir` / `files_base_dir`
//! overrides, which is what makes the protocol testable without touching
//! real system paths.
//!
//! This module only writes files. It deliberately does *not* run
//! `systemctl daemon-reload`; the caller does that through the separate
//! `services` module's `daemon_reload` action once writes are confirmed.

use crate::agent::module_support::{SelinuxOptions, apply_selinux, safe_join};
use crate::prelude::*;

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
const QUADLET_EXTENSIONS: &[&str] = &["container", "kube", "network", "pod", "volume"];

/// Which Podman/systemd tree a request targets. `User` resolves to the
/// invoking user's `~/.config/containers/systemd` and `~/.local/share/tetra`
/// data root; `System` resolves to `/etc/containers/systemd` and
/// `/var/lib/tetra/quadlets`. Defaults to `User` because the agent normally
/// runs under the owner's account rather than as root.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuadletScope {
    #[default]
    User,
    System,
}

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
        scope: QuadletScope,
    } => {
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        Ok(jsonf! { base_dir, "files": QuadletFile::list(&base_dir)? })
    },
    ListFiles {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: QuadletScope,
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
        Ok(jsonf! { base_dir, files_base_dir, files })
    },
    Read {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: QuadletScope,
        filename: String,
        #[serde(default)]
        companion: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        // Companion files are addressed by their full relative path
        // (e.g. `site/index.html`), so no bundle is derived. Quadlet
        // reads resolve against the flat scan directory instead.
        let bundle_name = if payload.companion {
            None
        } else {
            Some(quadlet_bundle_name(&payload.filename)?)
        };
        let base_dir = if payload.companion {
            quadlet_files_base_dir(
                payload.files_base_dir,
                payload.scope,
                bundle_name.as_deref(),
            )?
        } else {
            quadlet_base_dir(payload.base_dir, payload.scope)?
        };
        let path = safe_join(&base_dir, &payload.filename)?;
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read `{}`", path.display()))?;
        Ok(jsonf! { base_dir, payload.filename, contents, payload.dry_run })
    },
    Write {
        base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: QuadletScope,
        filename: String,
        contents: String,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        validate_quadlet(&payload.filename, &payload.contents)?;
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
        let path = safe_join(&base_dir, &payload.filename)?;
        if !payload.dry_run {
            fs::create_dir_all(&base_dir)
                .with_context(|| format!("failed to create `{}`", base_dir.display()))?;
            fs::write(&path, &payload.contents)
                .with_context(|| format!("failed to write `{}`", path.display()))?;
        }
        let selinux =
            apply_selinux(payload.selinux.as_ref(), Some(&path), payload.dry_run)?;
        Ok(jsonf! {
            base_dir, payload.filename, path,
            "written": !payload.dry_run,
            payload.dry_run, selinux,
        })
    },
    Delete {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: QuadletScope,
        filename: String,
        #[serde(default)]
        companion: bool,
        #[serde(default)]
        dry_run: bool,
    } => {
        let bundle_name = if payload.companion {
            None
        } else {
            Some(quadlet_bundle_name(&payload.filename)?)
        };
        let base_dir = if payload.companion {
            quadlet_files_base_dir(
                payload.files_base_dir,
                payload.scope,
                bundle_name.as_deref(),
            )?
        } else {
            quadlet_base_dir(payload.base_dir, payload.scope)?
        };
        let path = safe_join(&base_dir, &payload.filename)?;
        if !payload.dry_run {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete `{}`", path.display()))?;
        }
        Ok(jsonf! {
            base_dir, payload.filename, path,
            "deleted": !payload.dry_run,
            payload.dry_run,
        })
    },
    Validate {
        filename: String,
        contents: String,
    } => {
        validate_quadlet(&payload.filename, &payload.contents)?;
        Ok(jsonf! { payload.filename, "valid": true })
    },
    Install {
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        #[serde(default)]
        scope: QuadletScope,
        resources: Vec<InstallResource>,
        #[serde(default)]
        files: Vec<InstallResource>,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        let base_dir = quadlet_base_dir(payload.base_dir, payload.scope)?;
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
        if !payload.dry_run {
            fs::create_dir_all(&base_dir)
                .with_context(|| format!("failed to create `{}`", base_dir.display()))?;
            fs::create_dir_all(&files_base_dir).with_context(|| {
                format!("failed to create `{}`", files_base_dir.display())
            })?;
        }

        let mut installed = Vec::new();
        let mut selinux_ops = Vec::new();
        for resource in payload.resources {
            validate_quadlet(&resource.filename, &resource.contents)?;
            let path = write_resource(&base_dir, &resource, payload.dry_run)?;
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
            let path = write_resource(&files_base_dir, &resource, payload.dry_run)?;
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

        Ok(jsonf! {
            base_dir, files_base_dir, installed, files,
            "written": !payload.dry_run,
            payload.dry_run, "selinux": selinux_ops,
        })
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
pub(crate) fn quadlet_base_dir(base_dir: Option<PathBuf>, scope: QuadletScope) -> Result<PathBuf> {
    if let Some(base_dir) = base_dir {
        return Ok(base_dir);
    }

    match scope {
        QuadletScope::User => {
            let home =
                std::env::var_os("HOME").context("HOME is not set and no base_dir was provided")?;
            Ok(PathBuf::from(home).join(".config/containers/systemd"))
        }
        QuadletScope::System => Ok(PathBuf::from("/etc/containers/systemd")),
    }
}

/// Resolve the companion-files data root, optionally nested under a bundle
/// name. Kept separate from `quadlet_base_dir` because the two roots serve
/// different mutability and labeling needs (see the module docs). The
/// `bundle_name` is joined via `safe_join` so a derived bundle path can
/// never escape the data root.
pub(crate) fn quadlet_files_base_dir(
    files_base_dir: Option<PathBuf>,
    scope: QuadletScope,
    bundle_name: Option<&str>,
) -> Result<PathBuf> {
    let base = if let Some(files_base_dir) = files_base_dir {
        files_base_dir
    } else {
        match scope {
            QuadletScope::User => {
                // Honor XDG_DATA_HOME when set, falling back to the spec's
                // default of $HOME/.local/share. Never hardcode the latter so
                // environments that relocate data (snaps, flatpak-style
                // sandboxes) keep working.
                let xdg_data_home = std::env::var_os("XDG_DATA_HOME");
                let base = if let Some(xdg_data_home) = xdg_data_home {
                    PathBuf::from(xdg_data_home)
                } else {
                    let home = std::env::var_os("HOME")
                        .context("HOME is not set and no files_base_dir was provided")?;
                    PathBuf::from(home).join(".local/share")
                };
                base.join("tetra/quadlets")
            }
            QuadletScope::System => PathBuf::from("/var/lib/tetra/quadlets"),
        }
    };

    if let Some(bundle_name) = bundle_name {
        safe_join(&base, bundle_name)
    } else {
        Ok(base)
    }
}

/// Derive the companion bundle name from a Quadlet filename
/// (`app.container` -> `app`). This is also the first line of defense
/// against path-traversal in filenames: it rejects absolute paths and any
/// `..`/`Prefix` component before `safe_join` runs at write time.
fn quadlet_bundle_name(pathstr: &str) -> Result<String> {
    let path = Path::new(pathstr);
    // Reject absolute paths and `..`/`Prefix` components up front so the
    // derived bundle name can't be used to escape the data root later.
    // `Prefix` covers Windows drive roots and is harmless to reject on Linux.
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            )
        })
    {
        bail!("path `{pathstr}` must be relative and stay within the base directory");
    }

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

/// Write one `InstallResource` under `base_dir`, creating parent
/// directories as needed so nested companion paths such as
/// `nginx/default.conf` work. `safe_join` enforces that the resource path
/// stays within `base_dir`.
fn write_resource(base_dir: &Path, resource: &InstallResource, dry_run: bool) -> Result<PathBuf> {
    let path = safe_join(base_dir, &resource.filename)?;
    if !dry_run {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create `{}`", parent.display()))?;
        }
        fs::write(&path, &resource.contents)
            .with_context(|| format!("failed to write `{}`", path.display()))?;
    }
    Ok(path)
}

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
            "[Container]" | "[Kube]" | "[Network]" | "[Pod]" | "[Volume]"
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
            quadlet_base_dir(None, QuadletScope::System).unwrap(),
            PathBuf::from("/etc/containers/systemd")
        );
    }

    #[test]
    fn system_scope_uses_var_lib_for_companion_files() {
        assert_eq!(
            quadlet_files_base_dir(None, QuadletScope::System, Some("app")).unwrap(),
            PathBuf::from("/var/lib/tetra/quadlets/app")
        );
    }

    #[test]
    fn dry_run_write_does_not_create_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.container");
        let response = Write {
            base_dir: Some(dir.path().to_path_buf()),
            scope: QuadletScope::User,
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
            scope: QuadletScope::User,
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
            scope: QuadletScope::User,
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
            scope: QuadletScope::User,
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
            scope: QuadletScope::User,
            filename: "site/index.html".into(),
            companion: true,
            dry_run: false,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["contents"], "<h1>Hello</h1>\n");
    }
}
