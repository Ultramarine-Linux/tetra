//! `apps` module payloads and the installed-app manifest.

use std::collections::BTreeMap;

use serde_norway::Value as YamlValue;

use crate::agent::module_support::SelinuxOptions;
use crate::catalog::{AppRecipe, RenderedResource};
use crate::prelude::*;

use super::{ServiceScope, default_true};

/// Where an app, or a Quadlet of the `quadlets` module, is installed.
///
/// There is no per-user scope: every user app is a rootless Quadlet of the
/// one `ultramarine-apps` account, whoever installed it. A payload or stored
/// manifest that still says `user` is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppScope {
    /// Rootless, under the `ultramarine-apps` account: units in its
    /// `~/.config/containers/systemd`, companion files and manifests in its
    /// `~/.local/share/tetra/quadlets`, services in its user manager.
    #[default]
    Apps,
    /// Rootful, for real system services: `/etc/containers/systemd`,
    /// `/var/lib/tetra/quadlets` and the system manager.
    System,
}

/// Which apps `apps.list` shows.
///
/// The apps account's (the default), the rootful system services, or both.
/// Anything but `apps` needs the
/// `system_services` grant (`auth::authz`), since system scope belongs to the
/// system services page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppListScope {
    #[default]
    Apps,
    System,
    All,
}

impl AppListScope {
    /// The scopes listed, in order.
    #[must_use]
    pub const fn scopes(self) -> &'static [AppScope] {
        match self {
            Self::Apps => &[AppScope::Apps],
            Self::System => &[AppScope::System],
            Self::All => &[AppScope::Apps, AppScope::System],
        }
    }
}

impl From<AppScope> for ServiceScope {
    fn from(scope: AppScope) -> Self {
        match scope {
            AppScope::Apps => Self::Apps,
            AppScope::System => Self::System,
        }
    }
}

/// Target of an `apps.remove` action.
///
/// Identifies which installed app to remove, in which scope, and whether to
/// converge systemd (stop/disable + daemon-reload) while removing it. The
/// directory overrides exist so tests and custom deployments can redirect the
/// Quadlet scan dir and the companion data root.
#[derive(Debug, Deserialize)]
pub struct AppRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

/// Where an app's recipe comes from.
///
/// A recipe is either shipped inline (`recipe` + `templates`) or referenced
/// on disk (`recipe_path` + `templates_dir`); exactly one form must be given.
///
/// Only [`snapshot`](Self::snapshot) reads the paths of the `File` form;
/// everything else works on the inline snapshot it returns. Manifests store
/// snapshots, so a `File` source in a stored manifest is from an older
/// release, and only system scope (whose manifests root owns) accepts one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AppRecipeSource {
    Inline {
        recipe: String,
        #[serde(default)]
        templates: BTreeMap<String, String>,
    },
    File {
        recipe_path: PathBuf,
        templates_dir: PathBuf,
    },
}

impl AppRecipeSource {
    /// Snapshot disk bytes once, including all resource templates (even conditional
    /// ones), so verification and rendering cannot observe different versions.
    /// Inline bundles retain every supplied template, including unused entries.
    ///
    /// The paths are root's (a payload's, or a system-scope manifest's): the
    /// recipe is read without blocking on a FIFO, and only if it is a regular
    /// file; templates are resolved below `templates_dir` without following
    /// a symlink.
    pub fn snapshot(&self) -> Result<Self> {
        match self {
            Self::Inline { .. } => Ok(self.clone()),
            Self::File {
                recipe_path,
                templates_dir,
            } => {
                let recipe = read_recipe(recipe_path)?;
                let parsed = AppRecipe::load_str(&recipe)?;
                let mut templates = BTreeMap::new();
                for resource in parsed.resources {
                    // Resolved without following a symlink below the
                    // templates directory.
                    let path =
                        crate::agent::module_support::safe_join(templates_dir, &resource.template)?;
                    let template =
                        crate::agent::tree::Tree::trusted(templates_dir).read_to_string(&path)?;
                    templates.insert(resource.template, template);
                }
                Ok(Self::Inline { recipe, templates })
            }
        }
    }

    /// Verify the exact snapshot and return provenance for the manifest.
    pub fn verify(
        &self,
        source: Option<&crate::catalog::verification::RecipeSource>,
        allow_unpinned: bool,
    ) -> Result<crate::catalog::verification::RecipeSource> {
        let Self::Inline { recipe, templates } = self else {
            bail!("recipe verification requires a snapshot");
        };
        crate::catalog::verification::verify_source(recipe, templates, source, allow_unpinned)
    }

    /// Parse the recipe of a snapshot. A `File` source is refused: reading
    /// its paths is [`snapshot`](Self::snapshot)'s job alone.
    pub fn load(&self) -> Result<AppRecipe> {
        match self {
            Self::Inline { recipe, .. } => AppRecipe::load_str(recipe),
            Self::File { .. } => bail!("an on-disk recipe must be snapshotted first"),
        }
    }

    /// Render a snapshot with `values`, returning the parsed recipe alongside
    /// the rendered resources so callers can record `recipe_id`/`version`.
    /// Generated values are added to `values` first, so callers store them.
    pub fn render(
        &self,
        values: &mut BTreeMap<String, YamlValue>,
    ) -> Result<(AppRecipe, Vec<RenderedResource>)> {
        let recipe = self.load()?;
        let Self::Inline { templates, .. } = self else {
            unreachable!("`load` refuses on-disk recipes");
        };
        recipe.fill_generated(values);
        let resources = recipe.render_with_templates(values, templates)?;
        Ok((recipe, resources))
    }
}

/// Read the recipe file at `path`: a regular file of at most
/// [`MAX_READ`](crate::agent::tree::MAX_READ) bytes, opened with
/// `O_NONBLOCK` so a FIFO cannot hang the dispatch worker.
fn read_recipe(path: &Path) -> Result<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let context = || format!("failed to read recipe `{}`", path.display());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .with_context(context)?;
    ensure!(
        file.metadata().with_context(context)?.is_file(),
        "recipe `{}` is not a regular file",
        path.display()
    );
    let max = crate::agent::tree::MAX_READ;
    let mut contents = String::new();
    file.take(max.saturating_add(1))
        .read_to_string(&mut contents)
        .with_context(context)?;
    ensure!(
        u64::try_from(contents.len()).is_ok_and(|len| len <= max),
        "recipe `{}` is larger than {max} bytes",
        path.display()
    );
    Ok(contents)
}

/// Payload for `apps.create`: cook a recipe into an installed app bundle.
///
/// `values` are merged over `values_path` (inline wins), so a dashboard can
/// ship a defaults file plus per-instance overrides. `converge` controls the
/// systemd phase; when `false` only files are written and systemd is left
/// untouched (no daemon-reload, no enable/start), letting a controller run
/// that phase itself through the `services` module.
#[derive(Debug, Deserialize)]
pub struct AppCreateRequest {
    pub source: Option<crate::catalog::verification::RecipeSource>,
    #[serde(default)]
    pub allow_unpinned_images: bool,
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    pub recipe: Option<String>,
    #[serde(default)]
    pub templates: BTreeMap<String, String>,
    pub recipe_path: Option<PathBuf>,
    pub templates_dir: Option<PathBuf>,
    pub values_path: Option<PathBuf>,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

impl AppCreateRequest {
    /// Build the recipe source for a `create`: exactly one of the inline
    /// bundle or the on-disk paths must be given.
    pub fn recipe_source(&self) -> Result<AppRecipeSource> {
        match (&self.recipe, &self.recipe_path) {
            (Some(recipe), None) => Ok(AppRecipeSource::Inline {
                recipe: recipe.clone(),
                templates: self.templates.clone(),
            }),
            (None, Some(recipe_path)) => Ok(AppRecipeSource::File {
                recipe_path: recipe_path.clone(),
                templates_dir: self
                    .templates_dir
                    .clone()
                    .context("`templates_dir` is required with `recipe_path`")?,
            }),
            (Some(_), Some(_)) => bail!("pass either `recipe` or `recipe_path`, not both"),
            (None, None) => {
                bail!("`create` requires either `recipe` (inline) or `recipe_path` (file)")
            }
        }
    }
}

/// Payload for `apps.update`: re-cook an installed app.
///
/// `values` are merged per-key over the stored values from `create` (or the
/// last `update`), so secrets do not have to be re-sent on every edit.
/// Passing a new `recipe` / `recipe_path` swaps the recipe source (e.g. a
/// recipe upgrade).
#[derive(Debug, Deserialize)]
pub struct AppUpdateRequest {
    pub source: Option<crate::catalog::verification::RecipeSource>,
    pub allow_unpinned_images: Option<bool>,
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
    pub recipe: Option<String>,
    pub templates: Option<BTreeMap<String, String>>,
    pub recipe_path: Option<PathBuf>,
    pub templates_dir: Option<PathBuf>,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
    #[serde(default = "default_true")]
    pub converge: bool,
    #[serde(default)]
    pub dry_run: bool,
}

impl AppUpdateRequest {
    /// Build the replacement recipe source for an `update`, or `None` to keep
    /// the stored one. An inline recipe with no `templates` replaces the
    /// template bundle with an empty one; callers keeping the same templates
    /// can omit the field only when the stored source is reused unchanged.
    pub fn recipe_source(&self) -> Result<Option<AppRecipeSource>> {
        match (&self.recipe, &self.recipe_path) {
            (Some(recipe), None) => Ok(Some(AppRecipeSource::Inline {
                recipe: recipe.clone(),
                templates: self.templates.clone().unwrap_or_default(),
            })),
            (None, Some(recipe_path)) => Ok(Some(AppRecipeSource::File {
                recipe_path: recipe_path.clone(),
                templates_dir: self
                    .templates_dir
                    .clone()
                    .context("`templates_dir` is required with `recipe_path`")?,
            })),
            (Some(_), Some(_)) => bail!("pass either `recipe` or `recipe_path`, not both"),
            (None, None) => Ok(None),
        }
    }
}

/// Payload for `apps.get`: read one installed app's manifest and on-disk
/// state. Read-only, so there is no `dry_run`.
#[derive(Debug, Deserialize)]
pub struct AppGetRequest {
    pub name: String,
    #[serde(default)]
    pub scope: AppScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
}

/// Payload for `apps.list`: enumerate installed app bundles under the
/// companion data root. Read-only.
#[derive(Debug, Deserialize)]
pub struct AppListRequest {
    #[serde(default)]
    pub scope: AppListScope,
    pub base_dir: Option<PathBuf>,
    pub files_base_dir: Option<PathBuf>,
}

/// The on-disk record of one installed app.
///
/// Serialized as `<bundle>/app.json` under the companion data root
/// (`~ultramarine-apps/.local/share/tetra/quadlets/<name>/app.json` in apps
/// scope, `/var/lib/tetra/quadlets/<name>/app.json` in system scope), tying
/// the app to the recipe and values it was cooked from.
///
/// The manifest is what makes the bundle self-contained: `update` re-renders
/// from the stored recipe source and merged values, `remove` derives the
/// units/services to tear down, and config backups can snapshot one directory
/// per app. `values` may contain secrets, so the manifest is private (`0600`,
/// root's or the apps account's) and is excluded from secret-free backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Verified catalog claim and computed recipe/template digest. Old manifests
    /// have no provenance until their next update (implicit custom policy).
    #[serde(default)]
    pub source: Option<crate::catalog::verification::RecipeSource>,
    #[serde(default)]
    pub allow_unpinned_images: bool,
    /// Manifest schema version; currently 1.
    pub version: u32,
    pub name: String,
    pub scope: AppScope,
    pub recipe_id: String,
    pub recipe_version: String,
    pub recipe: AppRecipeSource,
    #[serde(default)]
    pub values: BTreeMap<String, YamlValue>,
    /// Keys that were `Secret` parameters at any render. Redaction uses this
    /// snapshot, so editing a recipe file cannot declassify a stored value.
    #[serde(default)]
    pub secret_keys: std::collections::BTreeSet<String>,
    /// Quadlet unit filenames installed into the scan directory.
    #[serde(default)]
    pub units: Vec<String>,
    /// Companion file paths, relative to the bundle directory.
    #[serde(default)]
    pub files: Vec<String>,
    /// Seconds since the Unix epoch.
    pub created_at: u64,
    pub updated_at: u64,
}

impl AppManifest {
    /// The systemd services Quadlet generates for the app's units.
    /// `.network`/`.volume` units have no service of their own — Podman pulls
    /// them in as dependencies of the containers that use them.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        self.units
            .iter()
            .filter_map(|unit| unit_service_name(unit))
            .collect()
    }
}

/// Derive the systemd service Quadlet generates for a unit filename, or
/// `None` for units that are not directly started (`.network`, `.volume`).
/// `.container`/`.kube` produce `<stem>.service`; `.pod` produces
/// `<stem>-pod.service`.
fn unit_service_name(filename: &str) -> Option<String> {
    let (stem, extension) = filename.rsplit_once('.')?;
    match extension {
        "container" | "kube" => Some(format!("{stem}.service")),
        "pod" => Some(format!("{stem}-pod.service")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn apps_default_to_the_apps_account_and_user_scope_is_gone() {
        let list: AppListRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(list.scope, AppListScope::Apps);
        let system: AppListRequest = serde_json::from_value(json!({ "scope": "system" })).unwrap();
        assert_eq!(system.scope, AppListScope::System);
        let error = serde_json::from_value::<AppListRequest>(json!({ "scope": "user" }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown variant `user`"), "{error}");
        assert_eq!(ServiceScope::from(AppScope::Apps), ServiceScope::Apps);
        assert_eq!(ServiceScope::from(AppScope::System), ServiceScope::System);
    }

    #[test]
    fn manifest_derives_service_names_from_unit_filenames() {
        let manifest = AppManifest {
            source: None,
            allow_unpinned_images: false,
            version: 1,
            name: "demo".into(),
            scope: AppScope::System,
            recipe_id: "demo-web".into(),
            recipe_version: "0.1.0".into(),
            recipe: AppRecipeSource::Inline {
                recipe: String::new(),
                templates: BTreeMap::new(),
            },
            values: BTreeMap::new(),
            secret_keys: std::collections::BTreeSet::new(),
            units: [
                "demo-web.container",
                "site.kube",
                "pair.pod",
                "demo-net.network",
                "demo-data.volume",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            files: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };

        assert_eq!(
            manifest.services(),
            ["demo-web.service", "site.service", "pair-pod.service"]
        );
    }
}
