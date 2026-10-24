//! Recipes agent module.
//!
//! Exposes Tetra's recipe catalog over the agent protocol so the
//! Ultramarine Server dashboard can render recipes on a remote host without
//! baking the recipe files into the agent. Recipes are YAML documents that
//! declare metadata, parameters, requirements, and Tera-templated resources
//! (Quadlet units plus companion files); see `crate::catalog` for the schema
//! and rendering engine.
//!
//! Actions come in two flavors:
//! - File-based (`render`, `context`): the recipe and templates already live
//!   on the host filesystem, addressed by path.
//! - Inline (`render_inline`, `context_inline`): the dashboard ships the
//!   recipe body, templates, and values in the command itself. This lets a
//!   remote catalog publish new recipes without bumping the installed Tetra
//!   version, as long as the recipe schema is one the agent understands.

use serde_yaml::Value as YamlValue;

use crate::{
    catalog::{AppRecipe, RenderOptions, RenderedResource},
    prelude::*,
};

/// Agent module that wraps the recipe catalog for remote rendering.
///
/// Registered behind the `recipes` cargo feature. The module holds no state;
/// all parsing and rendering is delegated to `crate::catalog`.
#[derive(Clone, Copy, Debug)]
pub struct RecipesModule;

/// Static descriptor published via the shared `capabilities` and `plan`
/// actions. Kept as a `const` so the dispatcher and callers share one source
/// of truth for the module's name, feature gate, and supported actions.
const INFO: ModuleInfo = ModuleInfo {
    name: "recipes",
    feature: "recipes",
    description: "Render app recipes into Quadlet resources and expose template context.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "render",
        "render_inline",
        "context",
        "context_inline",
    ],
    privileged_actions: &[],
};

impl Mod for RecipesModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    Render {
        recipe_path: PathBuf,
        templates_dir: PathBuf,
        values_path: Option<PathBuf>,
        output_dir: Option<PathBuf>,
        #[serde(default)]
        dry_run: bool,
    } => {
        let resources = RenderedResource::from_files(&RenderOptions {
            recipe_path: payload.recipe_path,
            values_path: payload.values_path,
            templates_dir: payload.templates_dir,
            output_dir: payload.output_dir,
            dry_run: payload.dry_run,
        })?;
        Ok(jsonf! { resources })
    },
    RenderInline {
        recipe: String,
        #[serde(default)]
        templates: BTreeMap<String, String>,
        #[serde(default)]
        values: BTreeMap<String, YamlValue>,
    } => {
        let recipe = AppRecipe::load_str(&payload.recipe)?;
        let resources =
            recipe.render_with_templates(&payload.values, &payload.templates)?;
        // Echo the parsed recipe alongside the rendered resources so
        // the dashboard can display normalized metadata (id, version,
        // parameters) without re-parsing the YAML it just sent.
        Ok(jsonf! { recipe, resources })
    },
    Context {
        recipe_path: PathBuf,
        #[serde(default)]
        values: BTreeMap<String, YamlValue>,
    } => {
        let recipe = AppRecipe::load(payload.recipe_path)?;
        let context = recipe.context_for_agent(&payload.values)?;
        Ok(jsonf! { context })
    },
    ContextInline {
        recipe: String,
        #[serde(default)]
        values: BTreeMap<String, YamlValue>,
    } => {
        let recipe = AppRecipe::load_str(&payload.recipe)?;
        let context = recipe.context_for_agent(&payload.values)?;
        Ok(jsonf! { recipe, context })
    },
});
