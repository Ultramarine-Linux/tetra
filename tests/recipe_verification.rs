use std::collections::BTreeMap;

use tetra::{
    catalog::{AppRecipe, RenderedResource, ResourceKind, verification::*},
    types::{AppManifest, AppRecipeSource},
};

const RECIPE: &str = "recipe_id: demo\nname: Demo\nversion: '1'\nresources:\n  - type: container\n    filename: demo.container\n    template: demo.tera\n";
const PIN: &str = "docker.io/library/nginx:alpine@sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417";

fn bundle(image: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("demo.tera".into(), format!("[Container]\nImage={image}\n"))])
}

#[test]
fn catalog_integrity_and_opt_out_matrix() {
    for catalog in [
        CatalogKind::Official,
        CatalogKind::Community,
        CatalogKind::Custom,
    ] {
        for image in [PIN, "nginx:latest"] {
            let templates = bundle(image);
            let source = RecipeSource {
                catalog,
                url: Some("https://example.test/recipe".into()),
                sha256: bundle_sha256(RECIPE, &templates),
            };
            let resources = AppRecipe::load_str(RECIPE)
                .unwrap()
                .render_with_templates(&BTreeMap::new(), &templates)
                .unwrap();
            for allow in [false, true] {
                let result = verify_source(RECIPE, &templates, Some(&source), allow)
                    .and_then(|_| verify_images(&resources, allow));
                assert_eq!(
                    result.is_ok(),
                    (image == PIN || allow) && (!allow || catalog == CatalogKind::Custom)
                );
            }
            let mut bad = source.clone();
            bad.sha256 = "0".repeat(64);
            verify_source(RECIPE, &templates, Some(&bad), false).unwrap_err();
            verify_source(
                &(RECIPE.to_owned() + "\n"),
                &templates,
                Some(&source),
                false,
            )
            .unwrap_err();
        }
    }
    let templates = bundle("nginx:latest");
    let source = verify_source(RECIPE, &templates, None, false).unwrap();
    assert_eq!(source.catalog, CatalogKind::Custom);
    let resources = AppRecipe::load_str(RECIPE)
        .unwrap()
        .render_with_templates(&BTreeMap::new(), &templates)
        .unwrap();
    verify_images(&resources, false).unwrap_err();
}

#[test]
fn canonical_digest_is_unambiguous_and_stable() {
    assert_eq!(
        bundle_sha256("", &BTreeMap::new()),
        "daa263c4011e48aef28bad521f6a2cf5120dcd148fd57de9a5ebff1af83d4e50"
    );
    assert_ne!(
        bundle_sha256("a", &BTreeMap::from([("bc".into(), "d".into())])),
        bundle_sha256("ab", &BTreeMap::from([("c".into(), "d".into())]))
    );
    assert_ne!(
        bundle_sha256("a", &BTreeMap::from([("b".into(), "cd".into())])),
        bundle_sha256("a", &BTreeMap::from([("bc".into(), "d".into())]))
    );
}

fn resource(filename: &str, contents: &str) -> RenderedResource {
    RenderedResource {
        kind: ResourceKind::File,
        filename: filename.into(),
        contents: contents.into(),
    }
}

#[test]
fn covers_quadlet_images_continuations_and_kube_yaml() {
    for (filename, section) in [
        ("a.container", "Container"),
        ("a.image", "Image"),
        ("a.volume", "Volume"),
    ] {
        verify_images(
            &[resource(filename, &format!("[{section}]\nImage={PIN}\n"))],
            false,
        )
        .unwrap();
        for image in [
            "nginx",
            "nginx@sha256:123",
            "nginx@sha256:zzzz",
            "nginx.image",
            "nginx.build",
        ] {
            verify_images(
                &[resource(filename, &format!("[{section}]\nImage={image}\n"))],
                false,
            )
            .unwrap_err();
        }
    }
    verify_images(
        &[resource(
            "a.container",
            &format!("[Container]\nImage=\\\n{PIN}\n"),
        )],
        false,
    )
    .unwrap();
    for directive in [
        "PodmanArgs=--mount=type=image,source=nginx",
        "GlobalArgs=--config=/tmp/config",
        "Mount=type=image,source=nginx",
        "Image=nginx",
    ] {
        verify_images(
            &[resource(
                "a.container",
                &format!("[Container]\nImage={PIN}\n{directive}\n"),
            )],
            false,
        )
        .unwrap_err();
    }
    let kube = resource("a.kube", "[Kube]\nYaml=pod.yaml\n");
    let yaml = resource(
        "pod.yaml",
        &format!(
            "spec:\n  containers:\n    - image: {PIN}\n  initContainers:\n    - image: {PIN}\n"
        ),
    );
    verify_images(&[kube.clone(), yaml], false).unwrap();
    verify_images(
        &[
            kube.clone(),
            resource("pod.yaml", "spec:\n  initContainers:\n    - image: nginx\n"),
        ],
        false,
    )
    .unwrap_err();
    verify_images(&[kube], false).unwrap_err();
    verify_images(&[resource("a.pod", "[Pod]\n")], false).unwrap_err();
}

#[test]
fn disk_snapshot_and_bundled_templates_pass() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("recipe.yaml"), RECIPE).unwrap();
    std::fs::write(dir.path().join("demo.tera"), &bundle(PIN)["demo.tera"]).unwrap();
    let source = AppRecipeSource::File {
        recipe_path: dir.path().join("recipe.yaml"),
        templates_dir: dir.path().into(),
    }
    .snapshot()
    .unwrap();
    let provenance = source.verify(None, false).unwrap();
    std::fs::write(
        dir.path().join("demo.tera"),
        "[Container]\nImage=nginx:latest\n",
    )
    .unwrap();
    // Rendering uses the verified snapshot, not later changes to disk.
    assert_eq!(source.verify(Some(&provenance), false).unwrap(), provenance);
    let (_, resources) = source
        .render(&mut BTreeMap::from([(
            "domain".into(),
            "cloud.example.test".into(),
        )]))
        .unwrap();
    verify_images(&resources, false).unwrap();
    assert_eq!(provenance.catalog, CatalogKind::Custom);
    for (filename, contents) in [
        (
            "nginx.container",
            include_str!("../templates/containers/nginx-site.container.tera"),
        ),
        (
            "mariadb.container",
            include_str!("../templates/containers/mariadb.container.tera"),
        ),
        (
            "nextcloud.container",
            include_str!("../templates/containers/nextcloud.container.tera"),
        ),
        (
            "redis.container",
            include_str!("../templates/containers/redis.container.tera"),
        ),
    ] {
        verify_images(&[resource(filename, contents)], false).unwrap();
    }
}

#[test]
fn old_manifest_loads_without_provenance() {
    let manifest: AppManifest = serde_json::from_value(serde_json::json!({
        "version": 1, "name": "old", "scope": "system", "recipe_id": "demo", "recipe_version": "1",
        "recipe": {"source": "inline", "recipe": RECIPE}, "created_at": 0, "updated_at": 0
    }))
    .unwrap();
    assert!(manifest.source.is_none());
    assert!(!manifest.allow_unpinned_images);
}

#[cfg(feature = "recipes")]
#[test]
fn file_render_checks_before_any_output_writes() {
    use tetra::agent::modules::{Mod, RecipesModule};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("recipe.yaml"), RECIPE).unwrap();
    let templates = bundle(PIN);
    std::fs::write(dir.path().join("demo.tera"), &templates["demo.tera"]).unwrap();
    let output = dir.path().join("out");
    let mut payload = serde_json::json!({
        "recipe_path": dir.path().join("recipe.yaml"), "templates_dir": dir.path(),
        "output_dir": output, "source": {"catalog": "community", "sha256": "0".repeat(64)}
    });
    RecipesModule
        .handle("render", payload.clone(), None)
        .unwrap_err();
    assert!(!output.exists());
    let digest = bundle_sha256(RECIPE, &templates);
    payload["source"]["sha256"] = serde_json::json!(digest);
    let response = RecipesModule
        .handle("render", payload.clone(), None)
        .unwrap();
    assert_eq!(response["source"]["sha256"], digest);
    assert_eq!(
        std::fs::read_to_string(output.join("demo.container")).unwrap(),
        templates["demo.tera"]
    );
    std::fs::write(dir.path().join("demo.tera"), "[Container]\nImage=nginx\n").unwrap();
    payload["source"] = serde_json::Value::Null;
    RecipesModule.handle("render", payload, None).unwrap_err();
    assert_eq!(
        std::fs::read_to_string(output.join("demo.container")).unwrap(),
        templates["demo.tera"]
    );
}

#[cfg(all(feature = "apps", feature = "recipes"))]
#[test]
fn install_records_provenance_updates_and_rejects_before_writing() {
    use tetra::agent::modules::{AppsModule, Mod, RecipesModule};
    let units = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let templates = bundle(PIN);
    let digest = bundle_sha256(RECIPE, &templates);
    let mut payload = serde_json::json!({
        "name": "demo", "recipe": RECIPE, "templates": templates,
        "source": {"catalog": "official", "sha256": digest, "url": "https://example.test/recipe"},
        "base_dir": units.path(), "files_base_dir": files.path(), "converge": false
    });
    payload["source"]["sha256"] = serde_json::json!("0".repeat(64));
    AppsModule
        .handle("create", payload.clone(), None)
        .unwrap_err();
    assert!(std::fs::read_dir(units.path()).unwrap().next().is_none());
    RecipesModule
        .handle("render_inline", payload.clone(), None)
        .unwrap_err();
    payload["source"]["sha256"] = serde_json::json!(digest);
    let response = AppsModule.handle("create", payload, None).unwrap();
    assert_eq!(response["app"]["source"]["catalog"], "official");
    assert_eq!(response["app"]["source"]["sha256"], digest);
    let mut update = serde_json::json!({ "name": "demo", "base_dir": units.path(), "files_base_dir": files.path(), "converge": false });
    let response = AppsModule.handle("update", update.clone(), None).unwrap();
    assert_eq!(response["app"]["source"]["sha256"], digest);
    update["allow_unpinned_images"] = serde_json::json!(true);
    AppsModule
        .handle("update", update.clone(), None)
        .unwrap_err();
    update["recipe"] = serde_json::json!(RECIPE);
    update["templates"] = serde_json::json!(bundle("nginx:latest"));
    let response = AppsModule.handle("update", update, None).unwrap();
    assert_eq!(response["app"]["source"]["catalog"], "custom");
    assert_eq!(response["app"]["allow_unpinned_images"], true);
}
