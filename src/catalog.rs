//! Recipe catalog and rendering engine.
//!
//! A *recipe* is a YAML document that declares an installable application in a
//! host-neutral way: human-readable metadata, a list of UI parameters the
//! operator must supply, optional host requirements, and a list of *resources*
//! to materialize. Each resource points at a [Tera] template and is rendered
//! into a concrete file — typically a Podman Quadlet systemd unit
//! (`.container`, `.network`, `.volume`, `.pod`, `.kube`) or a plain companion
//! `file` shipped alongside the units.
//!
//! This module is pure rendering: it does not install units, reload systemd,
//! or enforce the recipe's `requires` list. Those concerns belong to the
//! `quadlets` and `selinux` agent modules. The catalog is exposed to the
//! control plane through the agent `recipes` module (see
//! `agent/modules/recipes.rs` and `docs/agent-protocol.md`), which supports
//! both a file-backed `render` action (templates on disk) and a `render_inline`
//! action that accepts a template bundle fetched from a remote catalog, so new
//! recipes can be published without shipping a new Tetra build.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use tera::{Context as TeraContext, Tera};

/// A parsed recipe: metadata plus the parameter and resource declarations that
/// drive rendering. This is the top-level schema deserialized from recipe YAML.
///
/// `recipe_id` is the stable key the catalog indexes recipes by; `name`,
/// `description`, `category`, `icon`, and `version` are UI metadata surfaced
/// to the dashboard. `parameters` become keys in the Tera render context, and
/// `resources` are the files to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecipe {
    /// Stable identifier the catalog indexes recipes by and templates can
    /// reference via `{{ recipe_id }}`.
    pub recipe_id: String,
    /// Human-readable name shown in the dashboard.
    pub name: String,
    /// Optional long-form description for the dashboard listing.
    pub description: Option<String>,
    /// Optional grouping label used by the dashboard to organize recipes.
    pub category: Option<String>,
    /// Optional icon asset name/URL for the dashboard.
    pub icon: Option<String>,
    /// Recipe version, surfaced as metadata; not used to gate rendering.
    pub version: String,
    /// Host capabilities the recipe expects (e.g. `podman`, `quadlets`).
    /// Declarative only — this module does not verify them; the operator or
    /// controller is expected to check before rendering.
    #[serde(default)]
    pub requires: Vec<Requirement>,
    /// User-facing parameters. Each `key` becomes a Tera context key, so
    /// parameter keys must be unique (enforced in [`AppRecipe::validate`]).
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    /// Files to render. Ordering is preserved; see [`Resource::depends_on`]
    /// for ordering hints that are not enforced here.
    #[serde(default)]
    pub resources: Vec<Resource>,
}

/// A host requirement declared by a recipe.
///
/// Serialized with `untagged` so YAML authors may write either a bare string
/// (`requires: [podman]`) or a detailed form
/// (`requires: [{ key: podman, version: ">=5" }]`). Only metadata — the
/// renderer does not check whether the host actually satisfies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Requirement {
    /// Bare requirement name with no version constraint.
    Named(String),
    /// Requirement name with an optional version specifier. The version
    /// format is opaque to this module; the controller interprets it.
    Detailed {
        key: String,
        version: Option<String>,
    },
}

/// A single user-facing parameter declared by a recipe.
///
/// The `key` is what templates reference (e.g. `{{ domain }}`); the remaining
/// fields describe how the dashboard should prompt for and constrain the
/// value. Validation in [`validate_parameter_value`] mirrors `kind` so that a
/// malformed `values.yaml` fails fast with a clear error instead of producing
/// a broken unit file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// Context key the template references. Must be unique within a recipe.
    pub key: String,
    /// Human-readable label for the dashboard input field.
    pub label: String,
    /// Value type. Renamed from the YAML `type` field because `type` is a
    /// Rust reserved word.
    #[serde(rename = "type")]
    pub kind: ParameterKind,
    /// Whether the operator must supply a value. Checked during context
    /// building, before any template is rendered.
    #[serde(default)]
    pub required: bool,
    /// Optional placeholder text for the dashboard input field.
    pub placeholder: Option<String>,
    /// Default value used when the operator omits the parameter. Kept as a
    /// `YamlValue` so any scalar (string/bool/int) can serve as a default
    /// without a separate per-type field.
    #[serde(default)]
    pub default: Option<YamlValue>,
    /// Inclusive lower bound for `Integer` parameters.
    pub min: Option<i64>,
    /// Inclusive upper bound for `Integer` parameters.
    pub max: Option<i64>,
    /// Optional auto-generation strategy used when no value and no default
    /// are provided. Currently only [`Generator::Random32`] is supported,
    /// which is useful for secrets that should differ per install.
    pub generate: Option<Generator>,
    /// Allowed values for `Choice` parameters. Must be non-empty when
    /// `kind == Choice` (enforced in [`AppRecipe::validate`]).
    #[serde(default)]
    pub options: Vec<String>,
}

impl Parameter {
    pub fn yaml_value(&self, values: &BTreeMap<String, YamlValue>) -> Result<YamlValue> {
        let value = values.get(&self.key).or(self.default.as_ref()).cloned();
        let value = value.or_else(|| self.generate.map(Into::into).map(YamlValue::String));
        if value.is_none() && self.required {
            bail!("missing required parameter `{}`", self.key);
        }
        Ok(value.unwrap_or(YamlValue::Null))
    }
    pub fn json_value(&self, values: &BTreeMap<String, YamlValue>) -> Result<JsonValue> {
        let value = values.get(&self.key).or(self.default.as_ref()).cloned();
        let value = value.map(yaml_to_json).transpose()?;
        let value = value.or_else(|| self.generate.map(Into::into).map(JsonValue::String));
        let value = if value.is_none() && self.required {
            bail!("missing required parameter `{}`", self.key);
        } else {
            value.unwrap_or(JsonValue::Null)
        };
        self.validate_json(&value)?;
        Ok(value)
    }
    pub fn validate_json(&self, value: &JsonValue) -> Result<()> {
        match self.kind {
            // `Secret` validates exactly like `String`: the distinction is a UI
            // hint, not a separate value type.
            ParameterKind::String | ParameterKind::Secret => {
                if !matches!(value, JsonValue::String(_)) {
                    bail!("parameter `{}` must be a string", self.key);
                }
            }
            ParameterKind::Integer => {
                let Some(number) = value.as_i64() else {
                    bail!("parameter `{}` must be an integer", self.key);
                };
                if self.min.is_some_and(|min| number < min) {
                    bail!("parameter `{}` is below its minimum", self.key);
                }
                if self.max.is_some_and(|max| number > max) {
                    bail!("parameter `{}` is above its maximum", self.key);
                }
            }
            ParameterKind::Boolean => {
                if !matches!(value, JsonValue::Bool(_)) {
                    bail!("parameter `{}` must be a boolean", self.key);
                }
            }
            ParameterKind::Choice => {
                let Some(choice) = value.as_str() else {
                    bail!("parameter `{}` must be a choice string", self.key);
                };
                if !self.options.iter().any(|option| option == choice) {
                    bail!("parameter `{}` has an unsupported choice", self.key);
                }
            }
        }
        Ok(())
    }
}

/// The type of value a [`Parameter`] holds, which drives both dashboard input
/// rendering and runtime validation in [`validate_parameter_value`].
///
/// `Secret` validates identically to `String` but signals to the dashboard
/// that the input should be masked and not logged; it is not a cryptographic
/// guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterKind {
    String,
    Secret,
    Integer,
    Boolean,
    Choice,
}

/// Strategy for auto-generating a parameter value when the operator supplies
/// neither a value nor a default. See [`generate_value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Generator {
    /// Generate a 32-character alphanumeric string. Intended for per-install
    /// secrets (e.g. random database passwords) so two hosts don't share one.
    #[serde(rename = "random_32")]
    Random32,
}
impl From<Generator> for String {
    fn from(value: Generator) -> Self {
        match value {
            Generator::Random32 => rand::rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect(),
        }
    }
}

/// A single output file declared by a recipe.
///
/// Both `filename` and `template` are run through Tera, so a filename like
/// `{{ app_id }}.container` is resolved using the same context as the template
/// body. `condition` allows optional resources (e.g. a Redis sidecar) to be
/// skipped based on parameter values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// What kind of unit/file this is. Renamed from the YAML `type` field.
    /// Determines the Quadlet extension appended in [`resource_extension`].
    #[serde(rename = "type")]
    pub kind: ResourceKind,
    /// Output filename, rendered through Tera so it can embed parameter
    /// values (e.g. `{{ app_id }}.container`).
    pub filename: String,
    /// Template name/path passed to the template loader. For the file-backed
    /// renderer this is a path under `templates_dir`; for `render_inline` it
    /// is a key in the in-memory template bundle.
    pub template: String,
    /// Optional predicate controlling whether this resource is rendered.
    /// Uses the tiny DSL parsed by [`condition_matches`].
    #[serde(default)]
    pub condition: Option<String>,
    /// Other resource filenames this one conceptually depends on. Declared
    /// as metadata for callers/templates; the renderer itself processes
    /// resources in declared order and does not topologically sort.
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// The kind of file a [`Resource`] produces.
///
/// The Quadlet variants map 1:1 to Podman Quadlet systemd unit extensions
/// (see [`resource_extension`]). `File` is the escape hatch for companion
/// content (e.g. an `index.html`) that ships alongside the units and is
/// installed separately via the `quadlets.install.files` agent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Container,
    Network,
    Volume,
    Pod,
    Kube,
    File,
}
impl ResourceKind {
    /// Map a resource kind to the Quadlet systemd unit extension it produces.
    ///
    /// Pitfall: this includes the `.` prefix for the extension.
    ///
    /// `File` returns an empty extension because companion files keep their own
    /// names (e.g. `index.html`) rather than following the Quadlet naming scheme.
    #[must_use]
    pub const fn ext(&self) -> &'static str {
        match self {
            Self::Container => ".container",
            Self::Network => ".network",
            Self::Volume => ".volume",
            Self::Pod => ".pod",
            Self::Kube => ".kube",
            Self::File => "",
        }
    }
}

/// A fully rendered resource returned to the caller or agent.
///
/// `Serialize` only — these values flow out to the dashboard or to disk and
/// are never parsed back into this module, so `Deserialize` is intentionally
/// omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedResource {
    pub kind: ResourceKind,
    pub filename: String,
    pub contents: String,
}

impl RenderedResource {
    /// Full file-backed pipeline: load recipe + values, render all resources, and
    /// optionally write them to `output_dir`.
    ///
    /// This is the entry point used by the CLI `render` command and the agent
    /// `recipes.render` action. Disk writes are skipped on `dry_run` or when
    /// `output_dir` is `None`, but the rendered resources are always returned so
    /// the caller can preview them.
    pub fn from_files(options: &RenderOptions) -> Result<Vec<Self>> {
        let recipe = AppRecipe::load(&options.recipe_path)?;
        let values = load_values(options.values_path.as_deref())?;
        let rendered = recipe.render(&values, &options.templates_dir)?;

        // Only touch the filesystem when explicitly asked to: dry-run previews and
        // agent calls that just want the rendered bytes both rely on this skip.
        if let Some(output_dir) = &options.output_dir
            && !options.dry_run
        {
            fs::create_dir_all(output_dir).with_context(|| {
                format!(
                    "failed to create output directory `{}`",
                    output_dir.display()
                )
            })?;
            for resource in &rendered {
                let path = output_dir.join(&resource.filename);
                fs::write(&path, &resource.contents)
                    .with_context(|| format!("failed to write `{}`", path.display()))?;
            }
        }

        Ok(rendered)
    }
}

/// Options for the file-backed render pipeline ([`render_from_files`]).
///
/// Writing to disk is skipped when `dry_run` is set *or* when `output_dir` is
/// `None`; in both cases the rendered resources are still returned so callers
/// can preview them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOptions {
    pub recipe_path: PathBuf,
    pub values_path: Option<PathBuf>,
    pub templates_dir: PathBuf,
    pub output_dir: Option<PathBuf>,
    pub dry_run: bool,
}

/// Load the operator-supplied parameter values from a YAML file.
///
/// Returns an empty map when `path` is `None` so callers can uniformly rely on
/// recipe defaults and generators for any un-supplied parameters.
pub fn load_values<P: AsRef<Path>>(path: Option<P>) -> Result<BTreeMap<String, YamlValue>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read values `{}`", path.display()))?;
    serde_yaml::from_str(&text)
        .with_context(|| format!("failed to parse values YAML `{}`", path.display()))
}

/// Bridge a `serde_yaml::Value` into a `serde_json::Value`.
///
/// Tera's context expects JSON values, while recipe defaults and operator
/// values arrive as YAML. Going through `serde_json::to_value` round-trips
/// scalars/maps/sequences losslessly for the types this module handles.
#[inline]
fn yaml_to_json(value: YamlValue) -> Result<JsonValue> {
    serde_json::to_value(value).context("failed to convert YAML value to template value")
}

/// Evaluate a resource's `condition` predicate against the render context.
///
/// This is a deliberately tiny DSL — not a full expression evaluator — to
/// keep recipes auditable. It supports three forms:
/// - `key == literal` / `key != literal` for equality against a literal
///   parsed by [`parse_condition_literal`];
/// - a bare `key`, interpreted as truthiness: a boolean value wins, `null`
///   or a missing key is false, and any other type is an error.
///
/// An empty or missing condition is treated as always-true so unconditional
/// resources (the common case) require no extra YAML.
fn condition_matches(
    condition: Option<&str>,
    context: &BTreeMap<String, JsonValue>,
) -> Result<bool> {
    let Some(condition) = condition
        .map(str::trim)
        .filter(|condition| !condition.is_empty())
    else {
        return Ok(true);
    };

    let eq = condition.split_once("==");
    if let Some((key, expected)) = eq.or_else(|| condition.split_once("!=")) {
        let key = key.trim();
        let expected = parse_condition_literal(expected.trim());
        return Ok((context.get(key) == Some(&expected)) ^ eq.is_none());
    }

    match context.get(condition) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        // Missing or null keys default to false so an unset optional
        // parameter doesn't accidentally enable a conditional resource.
        Some(JsonValue::Null) | None => Ok(false),
        Some(_) => bail!("condition `{condition}` does not resolve to a boolean"),
    }
}

#[must_use]
fn unquote_str<'s>(value: &'s str) -> &'s str {
    let unquote_str_inner = |value: &'s str| value.strip_prefix('"')?.strip_suffix('"');
    unquote_str_inner(value).unwrap_or(value)
}

/// Parse the right-hand side of a `==` / `!=` condition into a comparable
/// JSON value.
///
/// Surrounding double quotes are stripped so quoted strings compare as
/// strings (`domain == "cloud.example.test"`); `true`/`false` and integers
/// are recognized as their native types; anything else is treated as a bare
/// string literal. There is no null/float/list syntax — by design.
fn parse_condition_literal(value: &str) -> JsonValue {
    match unquote_str(value) {
        "true" => JsonValue::Bool(true),
        "false" => JsonValue::Bool(false),
        other => other.parse::<i64>().map_or_else(
            |_| JsonValue::String(other.to_owned()),
            |i| JsonValue::Number(i.into()),
        ),
    }
}

macro_rules! assert_not_empty {
    ($value:expr => $msg:literal) => {
        if $value.is_empty() {
            bail!($msg);
        }
    };
}

impl AppRecipe {
    /// Parse and validate a recipe from an in-memory YAML string.
    ///
    /// Used by the agent `render_inline` / `context_inline` actions, where the
    /// recipe body arrives over the wire rather than from the local filesystem.
    pub fn load_str(text: &str) -> Result<Self> {
        let recipe: Self = serde_yaml::from_str(text).context("failed to parse recipe YAML")?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Read, parse, and validate a recipe from a YAML file on disk.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let recipe: Self = serde_yaml::from_reader(fs::File::open(path.as_ref())?)
            .with_context(|| format!("failed to load recipe YAML `{}`", path.as_ref().display()))?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Validate recipe-level invariants that deserialization alone can't enforce.
    ///
    /// Called from both load paths ([`load_recipe`] / [`load_recipe_from_str`])
    /// and again at the top of rendering, so inline bundles arriving over the
    /// wire get the same scrutiny as on-disk recipes. The checks are kept
    /// intentionally cheap: they catch schema mistakes that would otherwise
    /// surface as confusing Tera or filesystem errors later.
    pub fn validate(&self) -> Result<()> {
        assert_not_empty!(self.recipe_id.trim() => "recipe_id is required");
        assert_not_empty!(self.name.trim() => "name is required");
        assert_not_empty!(self.version.trim() => "version is required");
        assert_not_empty!(self.resources => "at least one resource is required");

        // Parameter keys become Tera context keys, so duplicates would silently
        // shadow each other. Reject them up front with a precise error.
        let mut parameters = BTreeSet::new();
        for parameter in &self.parameters {
            let key = parameter.key.trim();
            assert_not_empty!(key => "parameter key is required");
            if !parameters.insert(key) {
                bail!("duplicate parameter `{key}`");
            }
            // A Choice parameter with no options can never validate, so catch
            // it here rather than failing at first render time.
            if parameter.kind == ParameterKind::Choice && parameter.options.is_empty() {
                bail!("choice parameter `{key}` must define options");
            }
        }

        Ok(())
    }

    /// Render a recipe using templates loaded from a directory on disk.
    ///
    /// Each resource's `template` field is interpreted as a path relative to
    /// `templates_dir`. Used by the CLI and the agent `recipes.render` action.
    pub fn render<P: AsRef<Path>>(
        &self,
        values: &BTreeMap<String, YamlValue>,
        templates_dir: P,
    ) -> Result<Vec<RenderedResource>> {
        self.render_with_loader(values, |template| {
            let templates_dir = templates_dir.as_ref();
            let template_path = templates_dir.join(template);
            fs::read_to_string(&template_path)
                .with_context(|| format!("failed to read template `{}`", template_path.display()))
        })
    }

    /// Render a recipe using an in-memory template bundle keyed by template name.
    ///
    /// This is the path used by the agent `recipes.render_inline` action: the
    /// dashboard ships a remote catalog bundle (recipe YAML + named templates) to
    /// the host, so new recipes can be published without a Tetra upgrade as long
    /// as this module understands the recipe schema.
    pub fn render_with_templates(
        &self,
        values: &BTreeMap<String, YamlValue>,
        templates: &BTreeMap<String, String>,
    ) -> Result<Vec<RenderedResource>> {
        self.render_with_loader(values, |template| {
            templates
                .get(template)
                .with_context(|| format!("template `{template}` is missing from bundle"))
        })
    }

    /// Shared core of [`render_recipe`] and [`render_recipe_with_templates`].
    ///
    /// `load_template` abstracts over the two ways templates can arrive (disk
    /// vs. in-memory bundle) so the rendering logic only exists once.
    ///
    /// Rendering is two-pass per resource: the *filename* is rendered first (so
    /// it can embed parameter values like `{{ app_id }}.container`), and then the
    /// template body is rendered with three extra context keys injected —
    /// `resource` (the full resource declaration), `resource_filename` (the
    /// rendered filename), and `resource_name` (the Quadlet unit basename, see
    /// [`resource_name`]). This lets a template reference its own unit name, which
    /// is useful for cross-unit references such as `Volume=` mounts.
    fn render_with_loader<S: AsRef<str>>(
        &self,
        values: &BTreeMap<String, YamlValue>,
        load_template: impl Fn(&str) -> Result<S>,
    ) -> Result<Vec<RenderedResource>> {
        let mut context = self.build_context(values)?;
        let mut rendered = Vec::new();

        for resource in &self.resources {
            // Skip optional resources whose declared predicate does not hold.
            if !condition_matches(resource.condition.as_deref(), &context)? {
                continue;
            }

            // First pass: resolve the filename with the base context only.
            let tera_context =
                TeraContext::from_serialize(&context).context("failed to build context")?;
            let filename = Tera::one_off(&resource.filename, &tera_context, false)
                .with_context(|| format!("failed to render filename `{}`", resource.filename))?;
            // Second pass: build an enriched context so the template body can see
            // its own rendered filename and unit name, then render the body.
            // Overwrite previous records of `context`.
            context.extend([
                (
                    "resource".into(),
                    serde_json::to_value(resource).context("failed to serialize resource")?,
                ),
                (
                    "resource_filename".into(),
                    JsonValue::String(filename.clone()),
                ),
                (
                    "resource_name".into(),
                    JsonValue::String(filename.trim_end_matches(resource.kind.ext()).to_owned()),
                ),
            ]);
            let tera_context =
                TeraContext::from_serialize(&context).context("failed to build context")?;
            let template = load_template(&resource.template)?;
            let contents = Tera::one_off(template.as_ref(), &tera_context, false)
                .with_context(|| format!("failed to render template `{}`", resource.template))?;

            rendered.push(RenderedResource {
                kind: resource.kind,
                filename,
                contents,
            });
        }

        Ok(rendered)
    }

    /// Resolve a recipe's parameter context and return it as a JSON object for
    /// the agent protocol.
    ///
    /// Backs the `recipes.context` and `recipes.context_inline` actions, which let
    /// the dashboard preview what values a render *would* use (after defaults,
    /// generators, and validation) without actually rendering any templates.
    pub fn context_for_agent(&self, values: &BTreeMap<String, YamlValue>) -> Result<JsonValue> {
        let context = self.build_context(values)?;
        let object: JsonMap<String, JsonValue> = context.into_iter().collect();
        Ok(JsonValue::Object(object))
    }

    /// Build the Tera render context for a recipe.
    ///
    /// The context always exposes `recipe_id`, `name`, `version`, and the full
    /// `recipe` object (so templates can introspect metadata or iterate
    /// parameters). Each declared parameter is then resolved and inserted under
    /// its own key.
    ///
    /// Parameter resolution priority (first match wins):
    /// 1. An explicit operator-supplied value from `values`;
    /// 2. the recipe's declared `default`;
    /// 3. a value produced by the parameter's `generate` strategy;
    /// 4. for `required` parameters, a hard error (we must not silently render
    ///    with a missing value);
    /// 5. otherwise `Null`, which optional parameters can handle in-template via
    ///    Tera's `default` filter.
    ///
    /// Every resolved value is type-checked by [`validate_parameter_value`] before
    /// being inserted, so a bad `values.yaml` fails before any template runs.
    fn build_context(
        &self,
        values: &BTreeMap<String, YamlValue>,
    ) -> Result<BTreeMap<String, JsonValue>> {
        let ctx = [
            (
                "recipe_id".into(),
                JsonValue::String(self.recipe_id.clone()),
            ),
            ("name".into(), JsonValue::String(self.name.clone())),
            ("version".into(), JsonValue::String(self.version.clone())),
            (
                "recipe".into(),
                serde_json::to_value(self).context("failed to serialize recipe metadata")?,
            ),
        ];
        let ctx = ctx.into_iter().map(Ok);
        ctx.chain(
            (self.parameters.iter())
                .map(|parameter| Ok((parameter.key.clone(), parameter.json_value(values)?))),
        )
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nextcloud_recipe() -> AppRecipe {
        serde_yaml::from_str(
            r#"
recipe_id: nextcloud
name: Nextcloud
description: Self-hosted file sharing and collaboration
category: productivity
icon: nextcloud.svg
version: 1.0.0
parameters:
  - key: domain
    label: Domain name
    type: string
    required: true
  - key: enable_redis
    label: Enable Redis
    type: boolean
    default: true
resources:
  - type: container
    filename: "{{ recipe_id }}-app.container"
    template: app.container.tera
  - type: container
    filename: "{{ recipe_id }}-redis.container"
    template: redis.container.tera
    condition: "enable_redis == true"
"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_new_recipe_schema() {
        let recipe = nextcloud_recipe();

        assert_eq!(recipe.recipe_id, "nextcloud");
        assert_eq!(recipe.parameters.len(), 2);
        assert_eq!(recipe.resources.len(), 2);
    }

    #[test]
    fn filters_conditional_resources() {
        let recipe = nextcloud_recipe();
        let values = BTreeMap::from([
            (
                "domain".into(),
                YamlValue::String("cloud.example.com".into()),
            ),
            ("enable_redis".into(), YamlValue::Bool(false)),
        ]);

        let context = recipe.build_context(&values).unwrap();

        assert!(!condition_matches(Some("enable_redis == true"), &context).unwrap());
        assert!(condition_matches(Some("enable_redis != true"), &context).unwrap());
    }

    #[test]
    fn renders_resource_templates() {
        let templates = tempfile::tempdir().unwrap();
        fs::write(
            templates.path().join("app.container.tera"),
            "[Container]\nContainerName={{ recipe_id }}\nEnvironment=DOMAIN={{ domain }}\n",
        )
        .unwrap();
        fs::write(
            templates.path().join("redis.container.tera"),
            "[Container]\nContainerName={{ recipe_id }}-redis\n",
        )
        .unwrap();

        let values = BTreeMap::from([(
            "domain".into(),
            YamlValue::String("cloud.example.com".into()),
        )]);

        let rendered = nextcloud_recipe()
            .render(&values, templates.path())
            .unwrap();

        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0].filename, "nextcloud-app.container");
        assert!(rendered[0].contents.contains("DOMAIN=cloud.example.com"));
        assert_eq!(rendered[1].filename, "nextcloud-redis.container");
    }

    #[test]
    fn renders_file_resources_without_quadlet_extension() {
        let templates = tempfile::tempdir().unwrap();
        fs::write(
            templates.path().join("site.container.tera"),
            "[Container]\nContainerName={{ app_id }}\nVolume={{ bundle_dir }}:/usr/share/nginx/html:ro\n",
        )
        .unwrap();
        fs::write(
            templates.path().join("index.html.tera"),
            "<h1>{{ site_title }}</h1>\n",
        )
        .unwrap();
        let recipe: AppRecipe = serde_yaml::from_str(
            r#"
recipe_id: nginx-site
name: Nginx static site
version: 0.1.0
parameters:
  - key: app_id
    label: App ID
    type: string
    default: demo-web
  - key: bundle_dir
    label: Bundle directory
    type: string
    default: /var/lib/tetra/quadlets/demo-web
  - key: site_title
    label: Site title
    type: string
    default: Demo Web
resources:
  - type: container
    filename: "{{ app_id }}.container"
    template: site.container.tera
  - type: file
    filename: index.html
    template: index.html.tera
"#,
        )
        .unwrap();

        let rendered = recipe.render(&BTreeMap::new(), templates.path()).unwrap();

        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0].filename, "demo-web.container");
        assert!(
            rendered[0]
                .contents
                .contains("/var/lib/tetra/quadlets/demo-web")
        );
        assert_eq!(rendered[1].kind, ResourceKind::File);
        assert_eq!(rendered[1].filename, "index.html");
        assert_eq!(rendered[1].contents, "<h1>Demo Web</h1>\n");
    }

    #[test]
    fn renders_recipe_with_inline_template_bundle() {
        let recipe: AppRecipe = serde_yaml::from_str(
            r#"
recipe_id: nginx-site
name: Nginx static site
version: 0.1.0
parameters:
  - key: app_id
    label: App ID
    type: string
    default: demo-web
resources:
  - type: container
    filename: "{{ app_id }}.container"
    template: containers/nginx.container.tera
"#,
        )
        .unwrap();
        let templates = BTreeMap::from([(
            "containers/nginx.container.tera".into(),
            "[Container]\nContainerName={{ app_id }}\n".into(),
        )]);

        let rendered = recipe
            .render_with_templates(&BTreeMap::new(), &templates)
            .unwrap();

        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].filename, "demo-web.container");
        assert_eq!(
            rendered[0].contents,
            "[Container]\nContainerName=demo-web\n"
        );
    }
}
