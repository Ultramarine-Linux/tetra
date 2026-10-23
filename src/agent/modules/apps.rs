//! App lifecycle: cook recipes into installed, Quadlet-backed apps.
//!
//! Where the `quadlets` module manages individual files and the `recipes`
//! module renders recipe bodies, this module ties a cooked recipe to its
//! installed units and companion files as one lifecycle: `create` an app,
//! `get`/`list` what is installed, `update` it, and `remove` it.
//!
//! ## App bundle layout
//!
//! An installed app is two trees plus a manifest:
//!
//! - **Quadlet unit files** go to the directory Podman scans
//!   (`~ultramarine-apps/.config/containers/systemd` in apps scope, the
//!   default; `/etc/containers/systemd` in system scope), so a
//!   `daemon-reload` turns them into generated services.
//! - **Companion files** (reverse-proxy snippets, app config, content) go to
//!   a per-app bundle directory under the mutable data root:
//!   `~ultramarine-apps/.local/share/tetra/quadlets/<name>/` in apps scope,
//!   `/var/lib/tetra/quadlets/<name>/` in system scope. Keeping them out of
//!   the image-managed scan dir is what makes the layout bootc-friendly.
//!
//! Apps scope runs every user app rootless under the one `ultramarine-apps`
//! account (see [`crate::agent::apps_account`]): Tetra writes the files as
//! root and hands them to the account, prepares the account (subordinate
//! IDs, lingering, storage labels) when it converges, and talks to the
//! account's user manager. System scope is rootful, for real system
//! services; apps installed there by earlier releases keep working in it.
//! - **`<bundle>/app.json`** is the [`AppManifest`]: the recipe source and
//!   merged values the app was cooked from, plus the list of installed units
//!   and companions. It is what lets `update` re-render and `remove` tear
//!   down without guessing.
//!
//! ## The `create` / `update` pipeline
//!
//! 1. Render the recipe (inline bundle or on-disk paths) with the merged
//!    parameter values.
//! 2. Write companion files into the bundle directory and Quadlet units into
//!    the scan directory (`update` first deletes units/companions that the
//!    new render no longer produces).
//! 3. Write `<bundle>/app.json`.
//! 4. Optionally apply the shared `selinux` payload to the bundle directory.
//! 5. Unless `converge: false`, prepare the apps account (apps scope) and
//!    converge systemd: `daemon-reload`, then
//!    `start` (create) or `restart` (update) each service derived from the
//!    app's `.container`/`.kube`/`.pod` units. Quadlet services are
//!    generated, so `systemctl enable` refuses them; their `[Install]`
//!    section enables them at boot instead. `.network`/`.volume`
//!    units are not managed directly — Podman pulls them in as dependencies
//!    of the containers.
//!
//! All systemd interaction is delegated to the `services` module and all path
//! handling reuses the `quadlets` module's scope/traversal-safe helpers, so
//! every step stays representable as plain module actions. `remove` stops
//! the app's services, deletes its units, reloads systemd, and
//! removes the bundle directory; stop failures are tolerated (and
//! reported) so removal still cleans up after partial drift. Note that
//! Podman volumes created by `.volume` units are *not* deleted — app data
//! survives removal by design.
//!
//! Every mutating action honors `dry_run`, and the shared `plan` meta-action
//! echoes the request, so the dashboard can preview the exact pipeline —
//! rendered resources, target paths, and `systemctl` commands — before
//! committing.

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use serde_norway::Value as YamlValue;

use crate::actions;
use crate::agent::apps_account::{AppsAccount, HostPaths};
use crate::agent::module_support::{Commands, ModuleInfo, ModuleStatus, apply_selinux, safe_join};
use crate::agent::modules::Mod;
use crate::agent::modules::quadlets::{
    list_companion_files, owner_name, quadlet_base_dir, quadlet_files_base_dir, scope_owner,
    scope_tree, validate_quadlet,
};
use crate::agent::tree::{Kind, Tree};
use crate::catalog::{RenderedResource, ResourceKind, load_values};
use crate::prelude::*;
use crate::types::{
    AppCreateRequest, AppGetRequest, AppListRequest, AppManifest, AppRequest, AppScope,
    AppUpdateRequest, ServiceScope,
};

use super::ServicesModule;

/// Agent module backing the `apps` feature. Stateless; the lifecycle state
/// lives on the host in the bundle layout described in the module docs.
#[derive(Clone, Copy, Debug)]
pub struct AppsModule;

/// Static module descriptor advertised via `capabilities`/`plan`. `create`,
/// `update`, and `remove` are privileged: they write system directories and
/// drive `systemctl`.
const INFO: ModuleInfo = ModuleInfo {
    name: "apps",
    feature: "apps",
    description: "Cook recipes into installed Quadlet-backed apps and manage their lifecycle.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "get",
        "create",
        "update",
        "remove",
    ],
    privileged_actions: &["create", "update", "remove"],
};

/// Manifest filename inside every bundle directory. Chosen over `manifest.json`
/// so it sorts first and reads as the bundle's entry point.
const APP_MANIFEST: &str = "app.json";

/// Current manifest schema version written by `create`/`update`.
const MANIFEST_VERSION: u32 = 1;

impl Mod for AppsModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List: AppListRequest => {
        let mut apps = Vec::new();
        // Directories under the data root whose `app.json` cannot be read are
        // reported by name rather than failing the whole listing — they are
        // either corrupted bundles or stray unmanaged directories, both of
        // which the dashboard should surface.
        let mut invalid = Vec::new();
        let mut roots = Vec::new();
        for &scope in payload.scope.scopes() {
            let dirs = AppDirs::resolve(payload.base_dir.clone(), payload.files_base_dir.clone(), scope)?;
            list_scope(&dirs, scope, &mut apps, &mut invalid)?;
            roots.push(json!({ "scope": scope, "files_base_dir": dirs.files_root }));
        }
        apps.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        invalid.sort();
        let mut response = json!({ "apps": apps, "invalid": invalid, "roots": roots });
        // One scope: keep the single root at the top level, as before.
        if let [root] = roots.as_slice() {
            response["files_base_dir"] = root["files_base_dir"].clone();
        }
        Ok(response)
    },
    Get: AppGetRequest => {
        validate_app_name(&payload.name)?;
        let dirs = AppDirs::resolve(payload.base_dir, payload.files_base_dir, payload.scope)?;
        let bundle = dirs.bundle(&payload.name)?;
        let manifest = bundle.manifest()?;
        ensure!(
            manifest.name == payload.name && manifest.scope == payload.scope,
            "app manifest does not match requested app `{}` and scope",
            payload.name
        );
        // Report the on-disk state alongside the manifest so drift (a unit
        // deleted behind the agent's back) is visible to the dashboard.
        let units = manifest
            .units
            .iter()
            .map(|filename| {
                let path = dirs.base_dir.join(filename);
                let exists = dirs.units.exists(&path)?;
                Ok(json!({ "filename": filename, "path": path, "exists": exists }))
            })
            .collect::<Result<Vec<_>>>()?;
        let files = list_companion_files(&dirs.files, &bundle.dir)?
            .into_iter()
            .filter(|file| file.filename() != APP_MANIFEST)
            .collect::<Vec<_>>();
        let services = manifest.services();
        // `get` is open to the Apps page; secrets stay with administrators.
        let mut manifest = manifest;
        redact_secrets(&mut manifest);
        Ok(json!({
            "app": manifest,
            "base_dir": dirs.base_dir,
            "bundle_dir": bundle.dir,
            "units": units, "files": files, "services": services,
        }))
    },
    Create: AppCreateRequest => {
        validate_app_name(&payload.name)?;
        let dirs = AppDirs::resolve(payload.base_dir.clone(), payload.files_base_dir.clone(), payload.scope)?
            .owned(payload.scope, payload.dry_run)?;
        let bundle = dirs.bundle(&payload.name)?;
        ensure!(
            !bundle.exists()?,
            "app `{}` already exists; use `update` to modify it",
            payload.name
        );

        let source = payload.recipe_source()?.snapshot()?;
        let provenance = source.verify(payload.source.as_ref(), payload.allow_unpinned_images)?;
        // Inline values win over the optional values file, so a dashboard can
        // ship recipe defaults plus per-instance overrides in one call.
        let mut values = load_values(payload.values_path.as_ref())?;
        values.extend(payload.values);
        bundle.inject_dir(&mut values);
        let (recipe, resources) = source.render(&mut values)?;
        crate::catalog::verification::verify_images(&resources, payload.allow_unpinned_images)?;

        let outcome = bundle.install(&resources, None, payload.dry_run)?;
        let now = epoch_secs();
        let secret_keys = recipe.secret_keys().map(str::to_owned).collect();
        let manifest = AppManifest {
            source: Some(provenance),
            allow_unpinned_images: payload.allow_unpinned_images,
            version: MANIFEST_VERSION,
            name: payload.name,
            scope: payload.scope,
            recipe_id: recipe.recipe_id,
            recipe_version: recipe.version,
            recipe: source,
            values,
            secret_keys,
            units: outcome.units.clone(),
            files: outcome.files.clone(),
            created_at: now,
            updated_at: now,
        };
        let manifest_path = bundle.write_manifest(&manifest, payload.dry_run)?;
        let selinux = apply_selinux(payload.selinux.as_ref(), Some(&bundle.dir), payload.dry_run)?;
        let services = manifest.services();
        let (account, systemd) = if payload.converge {
            let account = prepare_account(payload.scope, payload.dry_run)?;
            let systemd = Systemd::new(payload.scope, payload.dry_run, user).converge(&services, "start")?;
            (account, systemd)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(json!({
            "app": manifest,
            "base_dir": dirs.base_dir,
            "bundle_dir": bundle.dir,
            "owner": owner_name(payload.scope),
            "manifest_path": manifest_path,
            "units": outcome.units, "files": outcome.files,
            "services": services, "account": account, "systemd": systemd, "selinux": selinux,
            "written": !payload.dry_run,
            "dry_run": payload.dry_run,
        }))
    },
    Update: AppUpdateRequest => {
        validate_app_name(&payload.name)?;
        let dirs = AppDirs::resolve(payload.base_dir.clone(), payload.files_base_dir.clone(), payload.scope)?
            .owned(payload.scope, payload.dry_run)?;
        let bundle = dirs.bundle(&payload.name)?;
        let mut manifest = bundle.manifest()?;
        ensure!(
            manifest.name == payload.name && manifest.scope == payload.scope,
            "app manifest does not match requested app `{}` and scope",
            payload.name
        );

        // A new recipe source replaces the stored one (recipe upgrade);
        // values merge per-key so secrets collected earlier are not resent.
        if let Some(source) = payload.recipe_source()? {
            manifest.recipe = source;
            // A replacement bundle without provenance is custom; never carry
            // an old official/community claim onto new bytes.
            manifest.source.clone_from(&payload.source);
            manifest.allow_unpinned_images = payload.allow_unpinned_images.unwrap_or(false);
        } else {
            if let Some(source) = &payload.source {
                manifest.source = Some(source.clone());
            }
            if let Some(allow) = payload.allow_unpinned_images {
                manifest.allow_unpinned_images = allow;
            }
        }
        manifest.recipe = manifest.recipe.snapshot()?;
        manifest.source = Some(manifest.recipe.verify(manifest.source.as_ref(), manifest.allow_unpinned_images)?);
        // `get` shows secrets as `REDACTED`; sent back unchanged, they keep
        // the stored value instead of replacing it.
        let is_secret = secrets(&manifest);
        let incoming: Vec<_> = payload
            .values
            .into_iter()
            .filter(|(key, value)| !(value.as_str() == Some(REDACTED) && is_secret(key)))
            .collect();
        manifest.values.extend(incoming);
        bundle.inject_dir(&mut manifest.values);
        let (recipe, resources) = manifest.recipe.render(&mut manifest.values)?;
        crate::catalog::verification::verify_images(&resources, manifest.allow_unpinned_images)?;
        manifest.secret_keys.extend(recipe.secret_keys().map(str::to_owned));
        manifest.recipe_id = recipe.recipe_id;
        manifest.recipe_version = recipe.version;

        let outcome = bundle.install(&resources, Some(&manifest), payload.dry_run)?;
        manifest.units.clone_from(&outcome.units);
        manifest.files.clone_from(&outcome.files);
        manifest.updated_at = epoch_secs();
        let manifest_path = bundle.write_manifest(&manifest, payload.dry_run)?;
        let selinux = apply_selinux(payload.selinux.as_ref(), Some(&bundle.dir), payload.dry_run)?;
        let services = manifest.services();
        let (account, systemd) = if payload.converge {
            let account = prepare_account(payload.scope, payload.dry_run)?;
            let systemd = Systemd::new(payload.scope, payload.dry_run, user).converge(&services, "restart")?;
            (account, systemd)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(json!({
            "app": manifest,
            "base_dir": dirs.base_dir,
            "bundle_dir": bundle.dir,
            "owner": owner_name(payload.scope),
            "manifest_path": manifest_path,
            "units": outcome.units, "files": outcome.files,
            "removed_units": outcome.removed_units, "removed_files": outcome.removed_files,
            "services": services, "account": account, "systemd": systemd, "selinux": selinux,
            "written": !payload.dry_run,
            "dry_run": payload.dry_run,
        }))
    },
    Remove: AppRequest => {
        validate_app_name(&payload.name)?;
        let dirs = AppDirs::resolve(payload.base_dir, payload.files_base_dir, payload.scope)?;
        let bundle = dirs.bundle(&payload.name)?;
        let manifest = bundle.manifest()?;
        ensure!(
            manifest.name == payload.name && manifest.scope == payload.scope,
            "app manifest does not match requested app `{}` and scope",
            payload.name
        );
        let services = manifest.services();

        // Stop before deleting anything so systemd can still resolve
        // the units.
        let phase = Systemd::new(payload.scope, payload.dry_run, user);
        let mut systemd = if payload.converge {
            phase.teardown(&services)
        } else {
            Vec::new()
        };
        let deleted_units = bundle.delete_units(&manifest.units, payload.dry_run)?;
        if payload.converge {
            systemd.push(phase.daemon_reload()?);
        }
        bundle.remove_bundle(payload.dry_run)?;
        Ok(json!({
            "name": payload.name,
            "bundle_dir": bundle.dir,
            "deleted_units": deleted_units, "services": services, "systemd": systemd,
            "bundle_removed": !payload.dry_run,
            "dry_run": payload.dry_run,
        }))
    },
});

/// Result of the file-install phase shared by `create` and `update`. Kept
/// separate from the systemd phase so hosts (and tests) can run a files-only
/// pass with `converge: false`.
#[derive(Debug, Default)]
struct InstallOutcome {
    /// Filenames of Quadlet units installed into the scan directory.
    units: Vec<String>,
    /// Companion file paths installed into the bundle, relative to it.
    files: Vec<String>,
    /// Units deleted because the new render no longer produces them.
    removed_units: Vec<String>,
    /// Companion files deleted for the same reason.
    removed_files: Vec<String>,
}

/// The two directory trees an app spans: the Quadlet scan directory its units
/// install into, and the companion-file data root its bundle lives under,
/// each with the [`Tree`] that resolves paths in it (handing what it writes
/// to the scope's owner). Apps default to apps scope; the request-level
/// overrides keep the protocol testable without touching real system paths.
#[derive(Debug)]
struct AppDirs {
    base_dir: PathBuf,
    files_root: PathBuf,
    units: Tree,
    files: Tree,
}

impl AppDirs {
    /// Resolve both roots for a request, honoring its directory overrides,
    /// for reading.
    fn resolve(
        base_dir: Option<PathBuf>,
        files_base_dir: Option<PathBuf>,
        scope: AppScope,
    ) -> Result<Self> {
        let base_dir = quadlet_base_dir(base_dir, scope);
        let files_root = quadlet_files_base_dir(files_base_dir, scope, None)?;
        Ok(Self {
            units: scope_tree(&base_dir, scope, None),
            files: scope_tree(&files_root, scope, None),
            base_dir,
            files_root,
        })
    }

    /// The same roots, for writes: files go to the scope's owner (see
    /// [`Owner::for_apps`](crate::agent::apps_account::Owner::for_apps)).
    fn owned(self, scope: AppScope, dry_run: bool) -> Result<Self> {
        let owner = scope_owner(scope, dry_run, &[&self.base_dir, &self.files_root])?;
        Ok(Self {
            units: scope_tree(&self.base_dir, scope, owner.clone()),
            files: scope_tree(&self.files_root, scope, owner),
            ..self
        })
    }

    /// Address an app's bundle directory inside the data root. `safe_join`
    /// keeps names with traversal components from escaping the root.
    fn bundle(&self, name: &str) -> Result<AppBundle> {
        Ok(AppBundle {
            base_dir: self.base_dir.clone(),
            dir: safe_join(&self.files_root, name)?,
            units: self.units.clone(),
            files: self.files.clone(),
        })
    }
}

/// Prepare the apps account to run apps (apps scope only), returning the
/// commands run (or planned, on a dry run). See [`AppsAccount::provision`].
fn prepare_account(scope: AppScope, dry_run: bool) -> Result<Vec<Value>> {
    if scope != AppScope::Apps {
        return Ok(Vec::new());
    }
    let account = if dry_run {
        AppsAccount::resolve()
    } else {
        AppsAccount::require()?
    };
    let mut commands = Commands::new(dry_run);
    account.provision(&HostPaths::system(), &mut commands)?;
    Ok(commands.done)
}

/// App names become directory and file names, so keep them to a single safe
/// path component. This is stricter than `safe_join` (which only rejects
/// traversal) because the name also shows up in systemd unit names.
fn validate_app_unit_filename(filename: &str) -> Result<()> {
    let path = Path::new(filename);
    ensure!(
        path.is_relative()
            && path.components().count() == 1
            && path.file_name().is_some_and(|name| name == filename),
        "Quadlet unit filename `{filename}` must be a single file name without directories"
    );
    Ok(())
}

fn validate_companion_filename(filename: &str) -> Result<()> {
    ensure!(
        !filename.ends_with('/')
            && !filename.ends_with("/.")
            && safe_join(Path::new(""), filename).is_ok_and(|path| path.file_name().is_some()),
        "companion filename `{filename}` must identify a relative file path"
    );
    Ok(())
}

fn validate_manifest_paths(manifest: &AppManifest) -> Result<()> {
    let mut units = HashSet::new();
    for unit in &manifest.units {
        validate_app_unit_filename(unit)?;
        ensure!(
            units.insert(unit.as_str()),
            "duplicate unit `{unit}` in app manifest"
        );
    }

    let mut files = HashSet::new();
    for file in &manifest.files {
        ensure!(
            file != APP_MANIFEST,
            "app manifest cannot own reserved file `{APP_MANIFEST}`"
        );
        validate_companion_filename(file)?;
        ensure!(
            files.insert(file.as_str()),
            "duplicate file `{file}` in app manifest"
        );
    }
    Ok(())
}

fn validate_app_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "app name cannot be empty");
    ensure!(
        !name.starts_with('.')
            && !name.starts_with('-')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
        "app name `{name}` must start with an alphanumeric and contain only alphanumerics, `.`, `_`, `-`"
    );
    Ok(())
}

/// The on-disk footprint of one installed app: rendered Quadlet units in the
/// scan directory plus a bundle directory holding companion files and the
/// `app.json` manifest. All bundle-level filesystem behavior hangs off this
/// type so the action handlers stay declarative.
#[derive(Debug)]
struct AppBundle {
    /// Scan directory the app's Quadlet units are installed into.
    base_dir: PathBuf,
    /// Per-app bundle directory under the companion-file data root.
    dir: PathBuf,
    /// Where the units are written.
    units: Tree,
    /// Where the bundle is written.
    files: Tree,
}

impl AppBundle {
    fn exists(&self) -> Result<bool> {
        self.files.exists(&self.dir)
    }

    /// Recipes that declare a `bundle_dir` parameter (typically for bind
    /// mounts) receive the real bundle directory unless the caller supplied
    /// one. Values for undeclared parameters are dropped by the renderer, so
    /// injecting unconditionally is safe for recipes without the parameter.
    fn inject_dir(&self, values: &mut BTreeMap<String, YamlValue>) {
        values
            .entry("bundle_dir".to_owned())
            .or_insert_with(|| YamlValue::String(self.dir.display().to_string()));
    }

    /// Read and parse `<dir>/app.json`.
    fn manifest(&self) -> Result<AppManifest> {
        let path = self.dir.join(APP_MANIFEST);
        let text = self
            .files
            .read_to_string(&path)
            .with_context(|| format!("failed to read app manifest `{}`", path.display()))?;
        let manifest: AppManifest = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse app manifest `{}`", path.display()))?;
        ensure!(
            manifest.version == MANIFEST_VERSION,
            "unsupported app manifest version {}; expected {}",
            manifest.version,
            MANIFEST_VERSION
        );
        validate_manifest_paths(&manifest)?;
        Ok(manifest)
    }

    /// Serialize the manifest into the bundle. Skipped on dry runs; returns
    /// the target path either way so previews show where it would land.
    fn write_manifest(&self, manifest: &AppManifest, dry_run: bool) -> Result<PathBuf> {
        let path = self.dir.join(APP_MANIFEST);
        if !dry_run {
            let contents =
                serde_json::to_vec_pretty(manifest).context("failed to serialize app manifest")?;
            // Holds the app's values, secrets included.
            self.files.write(&path, &contents, PRIVATE_MODE)?;
        }
        Ok(path)
    }

    /// Install a render: Quadlet resources into the scan directory, `file`
    /// resources into the bundle directory. When `previous` is given
    /// (update), units and companions the new render no longer produces are
    /// deleted. Directories are created up front so permission/disk failures
    /// surface before any file is written; Quadlet validation likewise
    /// happens before the first write.
    fn install(
        &self,
        resources: &[RenderedResource],
        previous: Option<&AppManifest>,
        dry_run: bool,
    ) -> Result<InstallOutcome> {
        let (units, companions): (Vec<&RenderedResource>, Vec<&RenderedResource>) = resources
            .iter()
            .partition(|resource| resource.kind != ResourceKind::File);
        let mut unit_names = HashSet::new();
        for unit in &units {
            ensure!(
                unit_names.insert(unit.filename.as_str()),
                "duplicate Quadlet unit filename `{}` in rendered app",
                unit.filename
            );
            validate_app_unit_filename(&unit.filename)?;
            validate_quadlet(&unit.filename, &unit.contents)?;
        }

        // App units live in a shared Quadlet scan directory. Never overwrite a
        // unit that is not recorded in this app's manifest; otherwise one app
        // could silently take ownership of another app's service.
        let mut companion_names = HashSet::new();
        for companion in &companions {
            ensure!(
                companion.filename != APP_MANIFEST,
                "companion filename `{APP_MANIFEST}` is reserved for the app manifest"
            );
            validate_companion_filename(&companion.filename)?;
            ensure!(
                companion_names.insert(companion.filename.as_str()),
                "duplicate companion filename `{}` in rendered app",
                companion.filename
            );
        }

        let previous_units: HashSet<&str> = previous
            .map(|manifest| manifest.units.iter().map(String::as_str).collect())
            .unwrap_or_default();
        for unit in &units {
            let path = safe_join(&self.base_dir, &unit.filename)?;
            if self.units.exists(&path)? && !previous_units.contains(unit.filename.as_str()) {
                bail!(
                    "Quadlet unit `{}` already exists and is not owned by this app",
                    unit.filename
                );
            }
        }

        if !dry_run {
            self.units.create_dir(&self.base_dir)?;
            self.files.create_dir(&self.dir)?;
        }

        let mut outcome = InstallOutcome::default();
        if let Some(previous) = previous {
            let desired_units: HashSet<&str> =
                units.iter().map(|unit| unit.filename.as_str()).collect();
            for unit in &previous.units {
                if desired_units.contains(unit.as_str()) {
                    continue;
                }
                remove_under(&self.units, &self.base_dir, unit, dry_run)?;
                outcome.removed_units.push(unit.clone());
            }
            let desired_files: HashSet<&str> = companions
                .iter()
                .map(|file| file.filename.as_str())
                .collect();
            for file in &previous.files {
                if desired_files.contains(file.as_str()) {
                    continue;
                }
                remove_under(&self.files, &self.dir, file, dry_run)?;
                outcome.removed_files.push(file.clone());
            }
        }

        for unit in units {
            // Units can carry secrets (`Environment=MYSQL_PASSWORD=...`).
            if !dry_run {
                let path = safe_join(&self.base_dir, &unit.filename)?;
                self.units
                    .write(&path, unit.contents.as_bytes(), unit.kind.mode())?;
            }
            outcome.units.push(unit.filename.clone());
        }
        for companion in companions {
            // Containers read companions through bind mounts.
            if !dry_run {
                let path = safe_join(&self.dir, &companion.filename)?;
                self.files
                    .write(&path, companion.contents.as_bytes(), companion.kind.mode())?;
            }
            outcome.files.push(companion.filename.clone());
        }
        Ok(outcome)
    }

    /// Delete the app's Quadlet units from the scan directory, returning the
    /// affected paths (deleted, or that would be on a dry run).
    fn delete_units(&self, units: &[String], dry_run: bool) -> Result<Vec<PathBuf>> {
        units
            .iter()
            .map(|unit| remove_under(&self.units, &self.base_dir, unit, dry_run))
            .collect()
    }

    /// Remove the bundle directory and everything in it.
    fn remove_bundle(&self, dry_run: bool) -> Result<()> {
        if !dry_run {
            self.files.remove_dir_all(&self.dir)?;
        }
        Ok(())
    }

    /// One-line summary of the installed app for the `list` action. Built
    /// from a borrow of the manifest; the manifest itself stays available
    /// for `get`.
    fn summary(&self, manifest: &AppManifest) -> Value {
        let AppManifest {
            name,
            recipe_id,
            recipe_version,
            scope,
            units,
            created_at,
            updated_at,
            ..
        } = manifest;
        json!({
            "name": name, "recipe_id": recipe_id, "recipe_version": recipe_version, "scope": scope, "units": units,
            "services": manifest.services(),
            "created_at": created_at, "updated_at": updated_at,
            "bundle_dir": self.dir,
        })
    }
}

/// Remove `relative` under `base` in `tree` unless `dry_run`; a missing
/// file is not an error. Returns its path.
fn remove_under(tree: &Tree, base: &Path, relative: &str, dry_run: bool) -> Result<PathBuf> {
    let path = safe_join(base, relative)?;
    if !dry_run {
        tree.remove_file(&path)?;
    }
    Ok(path)
}

/// Mode of `app.json`, which holds the app's values (secrets included).
const PRIVATE_MODE: u32 = 0o600;

/// What `get` shows in place of a secret.
const REDACTED: &str = "********";

/// Add the apps in `dirs` (of `scope`) to `apps`, and the names of bundles
/// that cannot be read to `invalid`.
fn list_scope(
    dirs: &AppDirs,
    scope: AppScope,
    apps: &mut Vec<Value>,
    invalid: &mut Vec<String>,
) -> Result<()> {
    for (name, kind) in dirs.files.read_dir(&dirs.files_root)?.unwrap_or_default() {
        let name = name.to_string_lossy().into_owned();
        if kind == Kind::Symlink {
            invalid.push(name);
            continue;
        }
        if kind != Kind::Dir {
            continue;
        }
        let Ok(bundle) = dirs.bundle(&name) else {
            invalid.push(name);
            continue;
        };
        match bundle.manifest() {
            Ok(manifest) if manifest.name == name && manifest.scope == scope => {
                apps.push(bundle.summary(&manifest));
            }
            Ok(_) | Err(_) => invalid.push(name),
        }
    }
    Ok(())
}

/// Whether a key holds a secret: it was a `Secret` parameter at some
/// render, is one in the current recipe, or the recipe cannot be read.
fn secrets(manifest: &AppManifest) -> impl Fn(&str) -> bool + use<> {
    let current: Option<std::collections::BTreeSet<String>> = manifest
        .recipe
        .load()
        .ok()
        .map(|recipe| recipe.secret_keys().map(str::to_owned).collect());
    let stored = manifest.secret_keys.clone();
    move |key| stored.contains(key) || current.as_ref().is_none_or(|current| current.contains(key))
}

/// Hide secrets in a manifest shown to the Apps page: the values of secret
/// parameters, and an inline recipe that spells out a secret's default.
fn redact_secrets(manifest: &mut AppManifest) {
    let is_secret = secrets(manifest);
    for (key, value) in &mut manifest.values {
        if is_secret(key) {
            *value = YamlValue::String(REDACTED.to_owned());
        }
    }
    if let crate::types::AppRecipeSource::Inline { recipe, .. } = &mut manifest.recipe {
        let secret_default = crate::catalog::AppRecipe::load_str(recipe).map_or(true, |parsed| {
            parsed
                .parameters
                .iter()
                .any(|p| p.kind == crate::catalog::ParameterKind::Secret && p.default.is_some())
        });
        if secret_default {
            REDACTED.clone_into(recipe);
        }
    }
}

/// Adapter that drives the systemd phase of the app lifecycle through the
/// services module, so the command shape, scope handling, and dry-run
/// behavior stay consistent with the rest of the agent. The per-action
/// results are returned so the dashboard can show exactly what ran.
#[derive(Clone, Copy, Debug)]
struct Systemd<'a> {
    scope: ServiceScope,
    dry_run: bool,
    user: Option<&'a str>,
}

impl<'a> Systemd<'a> {
    /// `systemctl` of the scope's manager: the apps account's user manager
    /// (`--user -M ultramarine-apps@`) or the system manager.
    fn new(scope: AppScope, dry_run: bool, user: Option<&'a str>) -> Self {
        Self {
            scope: scope.into(),
            dry_run,
            user,
        }
    }

    /// `systemctl daemon-reload` so Quadlet picks up the new unit set.
    fn daemon_reload(self) -> Result<Value> {
        ServicesModule.handle(
            "daemon_reload",
            json!({ "scope": self.scope, "dry_run": self.dry_run }),
            self.user,
        )
    }

    /// One single-service `systemctl` action (`start`/`stop`/`restart`/
    /// `enable`/`disable`).
    fn service_action(self, action: &str, service: &str) -> Result<Value> {
        ServicesModule.handle(
            action,
            json!({
                "service": service,
                "scope": self.scope,
                "dry_run": self.dry_run,
            }),
            self.user,
        )
    }

    /// The create/update phase: reload, then start (or restart, on update)
    /// each app service. No `enable`: systemd refuses it for generated
    /// units ("Unit ... is transient or generated"); the generator applies
    /// the unit's `[Install]` section on every reload instead.
    fn converge(self, services: &[String], service_action: &str) -> Result<Vec<Value>> {
        let mut ops = vec![self.daemon_reload()?];
        for service in services {
            ops.push(self.service_action(service_action, service)?);
        }
        Ok(ops)
    }

    /// The remove phase: stop each service before its unit is deleted
    /// (deleting the unit and reloading drops its `[Install]` links).
    /// Failures are reported inline but tolerated: the unit may already be
    /// gone, and removal should still clean up the bundle.
    fn teardown(self, services: &[String]) -> Vec<Value> {
        services
            .iter()
            .map(|service| {
                self.service_action("stop", service).unwrap_or_else(|error| {
                    json!({ "action": "stop", "service": service, "error": error.to_string() })
                })
            })
            .collect()
    }
}

/// Seconds since the Unix epoch for manifest timestamps. Falls back to 0 if
/// the system clock is before the epoch rather than failing the action.
fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DEMO_RECIPE: &str = r#"
recipe_id: demo-web
name: Demo Web
version: 0.1.0
parameters:
  - key: app_id
    label: App ID
    type: string
    default: demo-web
resources:
  - type: container
    filename: "{{ app_id }}.container"
    template: containers/demo.container.tera
  - type: file
    filename: site/index.html
    template: files/index.html.tera
"#;

    fn demo_templates() -> serde_json::Value {
        json!({
            "containers/demo.container.tera": "[Container]\nContainerName={{ app_id }}\nImage=example/demo:latest@sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
            "files/index.html.tera": "<h1>{{ app_id }}</h1>\n",
        })
    }

    /// A create payload rooted at two tempdirs with convergence disabled, so
    /// tests exercise the full file pipeline without touching systemctl.
    fn create_payload(base_dir: &Path, files_base_dir: &Path) -> Value {
        json!({
            "name": "demo",
            "base_dir": base_dir,
            "files_base_dir": files_base_dir,
            "recipe": DEMO_RECIPE,
            "templates": demo_templates(),
            "values": { "app_id": "demo-web" },
            "converge": false,
        })
    }

    fn dispatch(action: &str, payload: Value) -> Result<Value> {
        AppsModule.handle(action, payload, None)
    }

    #[test]
    fn rejects_nested_app_unit_filenames() {
        for filename in [
            "nested/demo.container",
            "../demo.container",
            "/demo.container",
        ] {
            assert!(
                validate_app_unit_filename(filename).is_err(),
                "accepted `{filename}`"
            );
        }
        validate_app_unit_filename("demo.container").unwrap();
    }

    #[test]
    fn rejects_invalid_companion_filenames() {
        for filename in ["", ".", "site/.", "site/"] {
            assert!(
                validate_companion_filename(filename).is_err(),
                "accepted `{filename}`"
            );
        }
        validate_companion_filename("site/index.html").unwrap();
    }

    #[test]
    fn lists_mismatched_manifests_as_invalid() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();
        let manifest_path = files.path().join("demo").join(APP_MANIFEST);
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["name"] = json!("other");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let response = dispatch(
            "list",
            json!({ "base_dir": base.path(), "files_base_dir": files.path() }),
        )
        .unwrap();
        assert_eq!(response["apps"], json!([]));
        assert_eq!(response["invalid"], json!(["demo"]));
    }

    #[test]
    fn rejects_unsupported_manifest_versions() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();
        let manifest_path = files.path().join("demo").join(APP_MANIFEST);
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["version"] = json!(999);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let error = dispatch(
            "remove",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "converge": false,
            }),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported app manifest version")
        );
    }

    #[test]
    fn lists_symlinked_bundles_as_invalid() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let files = tempfile::tempdir().unwrap();
            symlink("/tmp", files.path().join("linked")).unwrap();
            let response = dispatch(
                "list",
                json!({ "base_dir": files.path(), "files_base_dir": files.path() }),
            )
            .unwrap();
            assert_eq!(response["apps"].as_array().unwrap().len(), 0);
            assert_eq!(response["invalid"], json!(["linked"]));
        }
    }

    #[test]
    fn rejects_duplicate_rendered_resources() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let duplicate_recipe = DEMO_RECIPE.replace(
            "  - type: file\n    filename: site/index.html\n    template: files/index.html.tera\n",
            "  - type: file\n    filename: site/index.html\n    template: files/index.html.tera\n  - type: file\n    filename: site/index.html\n    template: files/index.html.tera\n",
        );
        let mut payload = create_payload(base.path(), files.path());
        payload["recipe"] = json!(duplicate_recipe);
        let error = dispatch("create", payload).unwrap_err();
        assert!(error.to_string().contains("duplicate companion filename"));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlinked_companion_path() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();
        let bundle = files.path().join("demo");
        fs::remove_dir_all(bundle.join("site")).unwrap();
        symlink("/tmp", bundle.join("site")).unwrap();

        let error = dispatch(
            "update",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "converge": false,
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("contains a symlink"));
    }

    #[test]
    fn rejects_manifest_reserved_companion() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let reserved_recipe = DEMO_RECIPE.replace("site/index.html", "app.json");
        let mut payload = create_payload(base.path(), files.path());
        payload["recipe"] = json!(reserved_recipe);
        let error = dispatch("create", payload).unwrap_err();
        assert!(error.to_string().contains("reserved for the app manifest"));
    }

    #[test]
    fn rejects_unit_collisions_between_apps() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();

        let mut second = create_payload(base.path(), files.path());
        second["name"] = json!("other");
        let error = dispatch("create", second).unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn rejects_update_overwriting_another_apps_unit() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();

        let mut other = create_payload(base.path(), files.path());
        other["name"] = json!("other");
        other["recipe"] = json!(DEMO_RECIPE.replace("{{ app_id }}.container", "other.container"));
        dispatch("create", other).unwrap();

        let error = dispatch(
            "update",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "recipe": DEMO_RECIPE.replace("{{ app_id }}.container", "other.container"),
                "templates": demo_templates(),
                "converge": false,
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn rejects_unsafe_app_names() {
        for name in [
            "",
            ".hidden",
            "-bad",
            "../escape",
            "a/b",
            "a b",
            "app.json/",
        ] {
            assert!(validate_app_name(name).is_err(), "accepted `{name}`");
        }
        for name in ["demo", "demo-web", "web_1", "my.app"] {
            assert!(validate_app_name(name).is_ok(), "rejected `{name}`");
        }
    }

    #[test]
    fn create_dry_run_previews_pipeline_without_writing() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut payload = create_payload(base.path(), files.path());
        payload["converge"] = json!(true);
        payload["dry_run"] = json!(true);

        let response = dispatch("create", payload).unwrap();

        assert_eq!(response["dry_run"], true);
        assert_eq!(response["written"], false);
        assert_eq!(response["units"], json!(["demo-web.container"]));
        assert_eq!(response["files"], json!(["site/index.html"]));
        assert_eq!(response["services"], json!(["demo-web.service"]));
        let commands = response["systemd"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["command"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        // Apps scope (the default): the apps account's user manager.
        assert_eq!(
            commands,
            [
                "systemctl --user -M ultramarine-apps@ daemon-reload",
                "systemctl --user -M ultramarine-apps@ start demo-web.service",
            ]
        );
        assert_eq!(response["app"]["scope"], "apps");
        assert_eq!(response["owner"], "ultramarine-apps");
        // The account is prepared before its manager is used.
        let account = response["account"].as_array().unwrap();
        assert!(
            account.iter().any(|op| op["command"]
                .as_str()
                .unwrap()
                .starts_with("systemctl start user@")),
            "{account:?}"
        );
        assert!(account.iter().all(|op| op["dry_run"] == true));
        assert_eq!(response["app"]["recipe_id"], "demo-web");
        // Nothing touched the filesystem.
        assert!(!base.path().join("demo-web.container").exists());
        assert!(!files.path().join("demo").exists());
    }

    #[test]
    fn system_scope_keeps_rootful_units_and_the_system_manager() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut payload = create_payload(base.path(), files.path());
        payload["scope"] = json!("system");
        payload["converge"] = json!(true);
        payload["dry_run"] = json!(true);
        let response = dispatch("create", payload).unwrap();
        let commands: Vec<_> = response["systemd"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["command"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            commands,
            [
                "systemctl daemon-reload",
                "systemctl start demo-web.service"
            ]
        );
        assert_eq!(response["account"], json!([]));
        assert_eq!(response["owner"], "root");
        assert_eq!(response["app"]["scope"], "system");

        // An app installed in system scope is found only there.
        let mut create = create_payload(base.path(), files.path());
        create["scope"] = json!("system");
        dispatch("create", create).unwrap();
        let listed = |scope: &str| {
            dispatch(
                "list",
                json!({ "scope": scope, "base_dir": base.path(), "files_base_dir": files.path() }),
            )
            .unwrap()
        };
        assert_eq!(listed("system")["apps"][0]["scope"], "system");
        assert_eq!(listed("apps")["apps"], json!([]));
        assert_eq!(listed("apps")["invalid"], json!(["demo"]));
        let get = |scope: &str| {
            dispatch(
                "get",
                json!({ "name": "demo", "scope": scope, "base_dir": base.path(), "files_base_dir": files.path() }),
            )
        };
        get("system").unwrap();
        get("apps").unwrap_err();
        // `user` scope is gone.
        get("user").unwrap_err();
    }

    #[test]
    fn apps_scope_bundles_are_handed_to_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("apps");
        let (owner, chowned) = crate::agent::apps_account::tests::recording_owner(&home);
        let base_dir = home.join(".config/containers/systemd");
        let files_root = home.join(".local/share/tetra/quadlets");
        let dirs = AppDirs {
            units: Tree::new(&base_dir, Some(&home), Some(owner.clone())),
            files: Tree::new(&files_root, Some(&home), Some(owner)),
            base_dir,
            files_root,
        };
        let bundle = dirs.bundle("demo").unwrap();
        let source = crate::types::AppRecipeSource::Inline {
            recipe: DEMO_RECIPE.to_owned(),
            templates: serde_json::from_value(demo_templates()).unwrap(),
        };
        let mut values = BTreeMap::new();
        let (_, resources) = source.render(&mut values).unwrap();
        let outcome = bundle.install(&resources, None, false).unwrap();
        assert_eq!(outcome.units, ["demo-web.container"]);
        let manifest = AppManifest {
            source: None,
            allow_unpinned_images: false,
            version: MANIFEST_VERSION,
            name: "demo".into(),
            scope: AppScope::Apps,
            recipe_id: "demo-web".into(),
            recipe_version: "0.1.0".into(),
            recipe: source,
            values,
            secret_keys: std::collections::BTreeSet::new(),
            units: outcome.units,
            files: outcome.files,
            created_at: 0,
            updated_at: 0,
        };
        bundle.write_manifest(&manifest, false).unwrap();

        let chowned = chowned.lock().unwrap().clone();
        for path in [
            "",
            ".config",
            ".config/containers/systemd",
            ".config/containers/systemd/demo-web.container",
            ".local/share/tetra/quadlets",
            ".local/share/tetra/quadlets/demo",
            ".local/share/tetra/quadlets/demo/site",
            ".local/share/tetra/quadlets/demo/site/index.html",
            ".local/share/tetra/quadlets/demo/app.json",
        ] {
            assert!(
                chowned.iter().any(|entry| entry == path),
                "{path}: {chowned:?}"
            );
        }
        let mode = |path: &Path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&dirs.base_dir.join("demo-web.container")), 0o600);
        assert_eq!(mode(&bundle.dir.join("app.json")), 0o600);
        assert_eq!(mode(&bundle.dir.join("site/index.html")), 0o644);
    }

    #[test]
    fn create_writes_bundle_then_get_and_list_read_it_back() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();

        let response = dispatch("create", create_payload(base.path(), files.path())).unwrap();
        assert_eq!(response["written"], true);
        assert_eq!(response["systemd"], json!([]));
        assert_eq!(
            fs::read_to_string(base.path().join("demo-web.container")).unwrap(),
            "[Container]\nContainerName=demo-web\nImage=example/demo:latest@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
        );
        let bundle = files.path().join("demo");
        assert_eq!(
            fs::read_to_string(bundle.join("site/index.html")).unwrap(),
            "<h1>demo-web</h1>\n"
        );
        let manifest: AppManifest =
            serde_json::from_str(&fs::read_to_string(bundle.join("app.json")).unwrap()).unwrap();
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.recipe_id, "demo-web");
        assert_eq!(manifest.units, ["demo-web.container"]);
        assert_eq!(manifest.files, ["site/index.html"]);
        assert_eq!(manifest.created_at, manifest.updated_at);

        let get = dispatch(
            "get",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
            }),
        )
        .unwrap();
        assert_eq!(get["app"]["name"], "demo");
        assert_eq!(get["units"][0]["exists"], true);
        assert_eq!(get["files"][0]["filename"], "site/index.html");

        let list = dispatch(
            "list",
            json!({
                "base_dir": base.path(),
                "files_base_dir": files.path(),
            }),
        )
        .unwrap();
        assert_eq!(list["apps"].as_array().unwrap().len(), 1);
        assert_eq!(list["apps"][0]["name"], "demo");
        assert_eq!(list["apps"][0]["services"], json!(["demo-web.service"]));
        assert_eq!(list["invalid"], json!([]));
    }

    /// Recipe that declares `bundle_dir`, so the agent can point templates at
    /// the real (agent-managed) bundle directory even when the caller leaves
    /// the value blank.
    const SITE_RECIPE: &str = "
recipe_id: static-site
name: Static Site
version: 1.0.0
parameters:
  - key: http_port
    label: HTTP port
    type: integer
    default: 8080
  - key: bundle_dir
    label: Bundle directory
    type: string
    required: false
resources:
  - type: container
    filename: site.container
    template: site.container.tera
";

    fn site_templates() -> serde_json::Value {
        json!({
            "site.container.tera": "[Container]\nImage=docker.io/library/nginx:alpine@sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417\nPublishPort={{ http_port }}:80\nVolume={{ bundle_dir }}/html:/usr/share/nginx/html:ro\n",
        })
    }

    fn site_payload(base_dir: &Path, files_base_dir: &Path, values: &serde_json::Value) -> Value {
        json!({
            "name": "site",
            "base_dir": base_dir,
            "files_base_dir": files_base_dir,
            "recipe": SITE_RECIPE,
            "templates": site_templates(),
            "values": values,
            "converge": false,
        })
    }

    #[test]
    fn create_injects_bundle_dir_for_recipes_that_declare_it() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let bundle_dir = files.path().join("site");
        let expected_volume = format!(
            "Volume={}/html:/usr/share/nginx/html:ro",
            bundle_dir.display()
        );

        let response = dispatch(
            "create",
            site_payload(base.path(), files.path(), &json!({ "http_port": 8080 })),
        )
        .unwrap();

        let rendered = fs::read_to_string(base.path().join("site.container")).unwrap();
        assert!(
            rendered.contains(&expected_volume),
            "rendered unit should bind the agent-managed bundle dir:\n{rendered}"
        );
        assert_eq!(
            response["app"]["values"]["bundle_dir"],
            json!(bundle_dir.display().to_string())
        );

        // An update on a bundle whose manifest predates the injection (no
        // `bundle_dir` in stored values) re-adds it, so old installs keep
        // rendering the right path. No recipe is resent: the stored one is used.
        let manifest_path = bundle_dir.join(APP_MANIFEST);
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["values"]
            .as_object_mut()
            .unwrap()
            .remove("bundle_dir");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        dispatch(
            "update",
            json!({
                "name": "site",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "values": { "http_port": 8081 },
                "converge": false,
            }),
        )
        .unwrap();

        let rendered = fs::read_to_string(base.path().join("site.container")).unwrap();
        assert!(rendered.contains(&expected_volume), "{rendered}");
        assert!(rendered.contains("PublishPort=8081:80"), "{rendered}");
    }

    #[test]
    fn caller_supplied_bundle_dir_wins_over_injection() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();

        dispatch(
            "create",
            site_payload(
                base.path(),
                files.path(),
                &json!({ "bundle_dir": "/opt/sites" }),
            ),
        )
        .unwrap();

        let rendered = fs::read_to_string(base.path().join("site.container")).unwrap();
        assert!(
            rendered.contains("Volume=/opt/sites/html:/usr/share/nginx/html:ro"),
            "{rendered}"
        );
    }

    #[test]
    fn create_refuses_an_existing_bundle() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();

        let again = dispatch("create", create_payload(base.path(), files.path()));
        let error = again.unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn update_merges_values_and_removes_stale_files() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut create = create_payload(base.path(), files.path());
        create["values"] = json!({ "app_id": "demo-web", "flavor": "vanilla" });
        dispatch("create", create).unwrap();

        // New render drops the companion file and renames the app (and thus
        // the unit filename); `flavor` is not resent and must survive.
        let updated_recipe = DEMO_RECIPE.replace(
            "  - type: file\n    filename: site/index.html\n    template: files/index.html.tera\n",
            "",
        );
        let response = dispatch(
            "update",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "recipe": updated_recipe,
                "templates": demo_templates(),
                "values": { "app_id": "demo-web-2" },
                "converge": false,
            }),
        )
        .unwrap();

        assert_eq!(response["units"], json!(["demo-web-2.container"]));
        assert_eq!(response["removed_units"], json!(["demo-web.container"]));
        assert_eq!(response["removed_files"], json!(["site/index.html"]));
        assert!(!base.path().join("demo-web.container").exists());
        assert!(base.path().join("demo-web-2.container").exists());
        assert!(!files.path().join("demo/site/index.html").exists());
        assert_eq!(response["app"]["values"]["flavor"], "vanilla");
        assert!(
            response["app"]["updated_at"].as_u64().unwrap()
                >= response["app"]["created_at"].as_u64().unwrap()
        );
    }

    #[test]
    fn generated_secrets_survive_updates_and_stay_private() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let recipe = DEMO_RECIPE.replace(
            "resources:",
            "  - key: db_password\n    label: Database password\n    type: secret\n    generate: random_32\nresources:",
        );
        let mut templates = demo_templates();
        templates["containers/demo.container.tera"] = json!(
            "[Container]\nImage=example/demo:latest@sha256:1111111111111111111111111111111111111111111111111111111111111111\nEnvironment=PW={{ db_password }}\n"
        );
        let mut create = create_payload(base.path(), files.path());
        create["recipe"] = json!(recipe);
        create["templates"] = templates;
        let created = dispatch("create", create).unwrap();
        let password = created["app"]["values"]["db_password"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(password.len(), 32);

        let unit = base.path().join("demo-web.container");
        let read = || fs::read_to_string(&unit).unwrap();
        assert!(read().contains(&password));
        let update = json!({
            "name": "demo",
            "base_dir": base.path(),
            "files_base_dir": files.path(),
            "converge": false,
        });
        dispatch("update", update).unwrap();
        assert!(read().contains(&password), "the secret was regenerated");

        let mode = |path: &Path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&unit), 0o600);
        assert_eq!(mode(&files.path().join("demo/app.json")), 0o600);
        assert_eq!(mode(&files.path().join("demo/site/index.html")), 0o644);

        let got = dispatch(
            "get",
            json!({ "name": "demo", "base_dir": base.path(), "files_base_dir": files.path() }),
        )
        .unwrap();
        assert_eq!(got["app"]["values"]["db_password"], "********");
        assert_eq!(got["app"]["values"]["app_id"], "demo-web");

        // Sending `get`'s values back keeps the secret.
        let mut update = json!({
            "name": "demo",
            "base_dir": base.path(),
            "files_base_dir": files.path(),
            "converge": false,
        });
        update["values"] = got["app"]["values"].clone();
        update["values"]["bundle_dir"] = json!(files.path().join("demo"));
        dispatch("update", update).unwrap();
        assert!(
            read().contains(&password),
            "the secret became the placeholder"
        );
    }

    #[test]
    fn get_keeps_secrets_hidden_even_after_the_recipe_declassifies_them() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let secret = DEMO_RECIPE.replace(
            "resources:",
            "  - key: token\n    label: Token\n    type: secret\n    default: hunter3\nresources:",
        );
        let mut create = create_payload(base.path(), files.path());
        create["recipe"] = json!(secret);
        create["values"]["token"] = json!("hunter2");
        dispatch("create", create).unwrap();
        let get = || {
            dispatch(
                "get",
                json!({ "name": "demo", "base_dir": base.path(), "files_base_dir": files.path() }),
            )
            .unwrap()
        };
        let shown = get();
        assert_eq!(shown["app"]["values"]["token"], "********");
        assert!(!shown.to_string().contains("hunter2"));
        assert!(
            !shown.to_string().contains("hunter3"),
            "the recipe's secret default"
        );

        // A later recipe calls it a plain string; the stored value stays hidden.
        dispatch(
            "update",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "recipe": secret.replace("type: secret\n    default: hunter3", "type: string"),
                "templates": demo_templates(),
                "converge": false,
            }),
        )
        .unwrap();
        let shown = get();
        assert_eq!(shown["app"]["values"]["token"], "********");
        assert!(!shown.to_string().contains("hunter2"));
    }

    #[test]
    fn list_filters_by_scope() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();
        let list = |scope: Option<&str>| {
            let mut payload = json!({ "base_dir": base.path(), "files_base_dir": files.path() });
            if let Some(scope) = scope {
                payload["scope"] = json!(scope);
            }
            dispatch("list", payload).unwrap()
        };
        let names = |response: &Value| {
            response["apps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|app| app["name"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let default = list(None);
        assert_eq!(names(&default), ["demo"]);
        assert_eq!(default["files_base_dir"], json!(files.path()));
        // The demo app is apps scope; with shared overrides, system scope
        // sees its manifest and refuses it as another scope's.
        assert!(names(&list(Some("system"))).is_empty());
        let all = list(Some("all"));
        assert_eq!(names(&all), ["demo"]);
        assert_eq!(all["roots"].as_array().unwrap().len(), 2);
        assert!(all.get("files_base_dir").is_none());
    }

    #[test]
    fn remove_deletes_units_and_bundle() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();

        let response = dispatch(
            "remove",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "converge": false,
            }),
        )
        .unwrap();

        assert_eq!(response["bundle_removed"], true);
        assert_eq!(response["deleted_units"].as_array().unwrap().len(), 1);
        assert!(!base.path().join("demo-web.container").exists());
        assert!(!files.path().join("demo").exists());

        // Removing again reports the app as gone instead of succeeding.
        let missing = dispatch(
            "remove",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "converge": false,
            }),
        );
        missing.unwrap_err();
    }

    #[test]
    fn remove_dry_run_shows_teardown_commands() {
        let base = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        dispatch("create", create_payload(base.path(), files.path())).unwrap();

        let response = dispatch(
            "remove",
            json!({
                "name": "demo",
                "base_dir": base.path(),
                "files_base_dir": files.path(),
                "dry_run": true,
            }),
        )
        .unwrap();

        let commands = response["systemd"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["command"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                "systemctl --user -M ultramarine-apps@ stop demo-web.service",
                "systemctl --user -M ultramarine-apps@ daemon-reload",
            ]
        );
        assert_eq!(response["bundle_removed"], false);
        // Dry run deleted nothing.
        assert!(base.path().join("demo-web.container").exists());
        assert!(files.path().join("demo/app.json").exists());
    }
}
