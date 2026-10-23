//! Install-time recipe integrity and rendered image policy (no catalog I/O).
use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::RenderedResource;

/// Caller-supplied catalog classification; not proof of publisher identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogKind {
    Official,
    Community,
    #[default]
    Custom,
}

/// Expected digest of the exact recipe and template bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSource {
    pub catalog: CatalogKind,
    pub url: Option<String>,
    pub sha256: String,
}

/// SHA-256 of `tetra-recipe-bundle-v1\0`, length-prefixed recipe bytes,
/// template count, then sorted length-prefixed names and bodies.
///
/// All lengths
/// are unsigned 64-bit big-endian byte counts. UTF-8 bytes are not normalized.
#[must_use]
pub fn bundle_sha256(recipe: &str, templates: &BTreeMap<String, String>) -> String {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    hash.update(b"tetra-recipe-bundle-v1\0");
    field(&mut hash, recipe.as_bytes());
    hash.update((templates.len() as u64).to_be_bytes());
    for (name, body) in templates {
        field(&mut hash, name.as_bytes());
        field(&mut hash, body.as_bytes());
    }
    hash.finalize()
        .iter()
        .flat_map(|byte| {
            let digits = b"0123456789abcdef";
            [
                char::from(digits[(byte >> 4) as usize]),
                char::from(digits[(byte & 15) as usize]),
            ]
        })
        .collect()
}

/// Verify supplied integrity metadata, or record implicit custom provenance.
pub fn verify_source(
    recipe: &str,
    templates: &BTreeMap<String, String>,
    source: Option<&RecipeSource>,
    allow_unpinned: bool,
) -> Result<RecipeSource> {
    let digest = bundle_sha256(recipe, templates);
    if let Some(source) = source {
        ensure!(
            hex_digest(&source.sha256) && source.sha256.eq_ignore_ascii_case(&digest),
            "recipe source sha256 mismatch"
        );
        ensure!(
            !allow_unpinned || source.catalog == CatalogKind::Custom,
            "allow_unpinned_images is only permitted for custom recipes"
        );
        let mut verified = source.clone();
        verified.sha256 = digest;
        Ok(verified)
    } else {
        Ok(RecipeSource {
            catalog: CatalogKind::Custom,
            url: None,
            sha256: digest,
        })
    }
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn pinned(image: &str) -> bool {
    image.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && !name.chars().any(char::is_whitespace)
            && !name.contains(['@', '%', '$', '\\', '"', '\''])
            && hex_digest(digest)
    })
}

fn check_image(image: &str) -> Result<()> {
    ensure!(pinned(image), "image `{image}` must use @sha256:<64 hex>");
    Ok(())
}

/// Fail closed on image-bearing Quadlet directives and companion kube YAML.
///
/// Raw argument overrides and image mounts are deliberately unsupported by
/// the pinned policy: they can hide extra image pulls from Quadlet's parser.
pub fn verify_images(resources: &[RenderedResource], allow_unpinned: bool) -> Result<()> {
    if allow_unpinned {
        return Ok(());
    }
    for resource in resources {
        let extension = resource
            .filename
            .rsplit_once('.')
            .map_or("", |(_, ext)| ext);
        if !matches!(
            extension,
            "container" | "image" | "volume" | "pod" | "kube" | "build"
        ) {
            continue;
        }
        ensure!(
            extension != "pod",
            "pod units are unsupported by the pinned policy (implicit infra image)"
        );
        ensure!(
            extension != "build",
            "build units are unsupported by the pinned image policy"
        );
        let mut section = "";
        let mut continuation = String::new();
        let mut image_seen = false;
        let mut yaml_seen = false;
        for line in resource.contents.lines() {
            let line = line.trim();
            if line.starts_with(['#', ';']) {
                continue;
            }
            if let Some(part) = line.strip_suffix('\\') {
                continuation.push_str(part);
                continuation.push(' ');
                continue;
            }
            continuation.push_str(line);
            let logical = std::mem::take(&mut continuation);
            let line = logical.trim();
            if line.starts_with('[') && line.ends_with(']') {
                section = resource_section(line);
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if section.is_empty() {
                continue;
            }
            let key = key.trim();
            let value = value.trim();
            match key {
                "Image" | "InfraImage" => {
                    check_image(value)?;
                    image_seen = true;
                }
                "PodmanArgs" | "GlobalArgs" if !value.is_empty() => {
                    bail!("raw Podman arguments are unsupported by the pinned image policy")
                }
                // Only `type=image` mounts pull an image; bind mounts of a
                // path that happens to contain "image" are fine.
                "Mount" if value.split(',').any(|option| option.trim() == "type=image") => {
                    bail!("image mounts are unsupported by the pinned image policy")
                }
                "Yaml" if section == "Kube" => {
                    let path = std::path::Path::new(value);
                    ensure!(
                        !path.is_absolute()
                            && path
                                .components()
                                .all(|part| matches!(part, std::path::Component::Normal(_))),
                        "pinned kube Yaml must be a relative bundle path"
                    );
                    yaml_seen = true;
                    let yaml = resources.iter().find(|r| r.filename == value)
                        .context("pinned kube units require a bundled relative Yaml file (no external paths)")?;
                    for document in serde_norway::Deserializer::from_str(&yaml.contents) {
                        let value = serde_norway::Value::deserialize(document)?;
                        check_yaml(&value)?;
                    }
                }
                _ => {}
            }
        }
        ensure!(continuation.is_empty(), "unterminated Quadlet continuation");
        ensure!(
            !matches!(extension, "container" | "image") || image_seen,
            "{} requires a pinned Image directive",
            resource.filename
        );
        ensure!(
            extension != "kube" || yaml_seen,
            "kube unit requires bundled Yaml"
        );
    }
    Ok(())
}

fn resource_section(line: &str) -> &'static str {
    match line {
        "[Container]" => "Container",
        "[Image]" => "Image",
        "[Volume]" => "Volume",
        "[Pod]" => "Pod",
        "[Kube]" => "Kube",
        _ => "",
    }
}

fn check_yaml(value: &serde_norway::Value) -> Result<()> {
    use serde_norway::Value;
    match value {
        Value::Mapping(map) => {
            for (key, value) in map {
                if key.as_str() == Some("image") {
                    check_image(value.as_str().context("kube image must be a string")?)?;
                } else {
                    check_yaml(value)?;
                }
            }
        }
        Value::Sequence(items) => {
            for item in items {
                check_yaml(item)?;
            }
        }
        Value::Tagged(tagged) => check_yaml(&tagged.value)?,
        _ => {}
    }
    Ok(())
}
