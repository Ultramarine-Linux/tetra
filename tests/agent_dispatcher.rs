#![allow(clippy::tests_outside_test_module)]

use serde_json::{Value, json};
use tempfile::tempdir;
use tetra::agent::{AgentCommand, Dispatcher, backend};

fn dispatch(module: &str, action: &str, payload: Value) -> tetra::agent::AgentResponse {
    Dispatcher::full().dispatch(AgentCommand {
        id: format!("{module}-{action}"),
        module: module.into(),
        action: action.into(),
        payload,
        signature: None,
        user: None,
    })
}

#[test]
fn dispatcher_reports_enabled_modules() {
    let response = dispatch("agent", "capabilities", json!({}));

    assert!(response.ok, "{response:?}");
    let modules = response.payload.unwrap()["modules"]
        .as_array()
        .unwrap()
        .clone();
    let names = modules
        .iter()
        .map(|module| module["name"].as_str().unwrap())
        .collect::<Vec<_>>();

    assert!(names.contains(&"settings"));
    #[cfg(feature = "apps")]
    assert!(names.contains(&"apps"));
    #[cfg(feature = "files")]
    assert!(names.contains(&"files"));
    #[cfg(feature = "recipes")]
    assert!(names.contains(&"recipes"));
    #[cfg(feature = "services")]
    assert!(names.contains(&"services"));
    #[cfg(feature = "selinux")]
    assert!(names.contains(&"selinux"));
    #[cfg(feature = "quadlets")]
    assert!(names.contains(&"quadlets"));
}

#[tokio::test]
async fn kameo_backend_dispatches_commands() {
    let response = backend::dispatch_with_default_backend(AgentCommand {
        id: "backend-settings".into(),
        module: "settings".into(),
        action: "get_system".into(),
        payload: Value::Null,
        signature: None,
        user: None,
    })
    .await
    .unwrap();

    assert!(response.ok, "{response:?}");
    let payload = response.payload.unwrap();
    assert!(payload["os"].is_string());
    assert!(payload["arch"].is_string());
}

#[test]
fn dispatcher_rejects_unknown_modules_and_empty_signatures() {
    let unknown = dispatch("missing", "capabilities", json!({}));
    assert!(!unknown.ok);
    assert!(unknown.error.as_deref().unwrap().contains("unknown module"));

    let empty_signature = Dispatcher::full().dispatch(AgentCommand {
        id: "empty-signature".into(),
        module: "settings".into(),
        action: "get_system".into(),
        payload: Value::Null,
        signature: Some(String::new()),
        user: None,
    });
    assert!(!empty_signature.ok);
    assert!(
        empty_signature
            .error
            .as_deref()
            .unwrap()
            .contains("signature cannot be empty")
    );
}

#[test]
fn settings_module_returns_host_shape() {
    let response = dispatch("settings", "get_system", Value::Null);

    assert!(response.ok, "{response:?}");
    let payload = response.payload.unwrap();
    assert!(payload["os"].is_string());
    assert!(payload["arch"].is_string());
    assert!(payload["family"].is_string());
}

#[cfg(feature = "files")]
#[test]
fn files_module_reads_and_writes_files() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("managed.conf");

    let write = dispatch(
        "files",
        "write",
        tetra::jsonf! { path, "contents": "enabled=true\n" },
    );
    assert!(write.ok, "{write:?}");

    let read = dispatch("files", "read", json!({ "path": path }));
    assert!(read.ok, "{read:?}");
    assert_eq!(read.payload.unwrap()["contents"], "enabled=true\n");
}

#[cfg(feature = "quadlets")]
#[test]
fn quadlets_module_installs_lists_reads_and_deletes_files() {
    let dir = tempdir().unwrap();
    let files_dir = tempdir().unwrap();
    let base_dir = dir.path();
    let files_base_dir = files_dir.path();

    let install = dispatch(
        "quadlets",
        "install",
        tetra::jsonf! {
            base_dir, files_base_dir,
            "resources": [
                {
                    "filename": "app.container",
                    "contents": "[Container]\nImage=example/app:latest\n",
                },
                {
                    "filename": "app.network",
                    "contents": "[Network]\nDriver=bridge\n",
                },
            ],
            "files": [
                {
                    "filename": "index.html",
                    "contents": "<h1>Hello</h1>\n",
                },
            ],
        },
    );
    assert!(install.ok, "{install:?}");
    assert_eq!(
        install.payload.unwrap()["installed"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let list = dispatch("quadlets", "list", json!({ "base_dir": base_dir }));
    assert!(list.ok, "{list:?}");
    let files = list.payload.unwrap()["files"].as_array().unwrap().clone();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["filename"], "app.container");
    assert_eq!(files[1]["filename"], "app.network");

    let list_files = dispatch(
        "quadlets",
        "list_files",
        json!({ "base_dir": base_dir, "files_base_dir": files_base_dir }),
    );
    assert!(list_files.ok, "{list_files:?}");
    let managed_files = list_files.payload.unwrap()["files"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(managed_files.len(), 3);
    assert_eq!(managed_files[0]["filename"], "app.container");
    assert_eq!(managed_files[1]["filename"], "app.network");
    assert_eq!(managed_files[2]["filename"], "app/index.html");

    let read = dispatch(
        "quadlets",
        "read",
        json!({ "base_dir": base_dir, "filename": "app.container" }),
    );
    assert!(read.ok, "{read:?}");
    assert_eq!(
        read.payload.unwrap()["contents"],
        "[Container]\nImage=example/app:latest\n"
    );

    let read_companion = dispatch(
        "quadlets",
        "read",
        json!({
            "files_base_dir": files_base_dir,
            "filename": "app/index.html",
            "companion": true
        }),
    );
    assert!(read_companion.ok, "{read_companion:?}");
    assert_eq!(
        read_companion.payload.unwrap()["contents"],
        "<h1>Hello</h1>\n"
    );

    let delete = dispatch(
        "quadlets",
        "delete",
        json!({ "base_dir": base_dir, "filename": "app.network" }),
    );
    assert!(delete.ok, "{delete:?}");
}

#[cfg(feature = "quadlets")]
#[test]
fn quadlets_module_rejects_invalid_or_unsafe_files() {
    let dir = tempdir().unwrap();
    let base_dir = dir.path();

    let wrong_extension = dispatch(
        "quadlets",
        "validate",
        json!({
            "base_dir": base_dir,
            "filename": "app.service",
            "contents": "[Container]\nImage=example\n"
        }),
    );
    assert!(!wrong_extension.ok);

    let unsafe_path = dispatch(
        "quadlets",
        "write",
        json!({
            "base_dir": base_dir,
            "filename": "../app.container",
            "contents": "[Container]\nImage=example\n"
        }),
    );
    assert!(!unsafe_path.ok);
}

#[cfg(feature = "quadlets")]
#[test]
fn quadlets_module_supports_dry_run_and_system_scope() {
    let dir = tempdir().unwrap();
    let base_dir = dir.path();

    let dry_run = dispatch(
        "quadlets",
        "install",
        json!({
            "base_dir": base_dir,
            "scope": "system",
            "dry_run": true,
            "resources": [
                {
                    "filename": "app.container",
                    "contents": "[Container]\nImage=example/app:latest\n"
                }
            ]
        }),
    );
    assert!(dry_run.ok, "{dry_run:?}");
    let payload = dry_run.payload.unwrap();
    assert_eq!(payload["dry_run"], true);
    assert_eq!(payload["written"], false);
    assert!(!base_dir.join("app.container").exists());

    let system_scope = dispatch("quadlets", "list", json!({ "scope": "system" }));
    assert!(system_scope.ok, "{system_scope:?}");
    assert_eq!(
        system_scope.payload.unwrap()["base_dir"],
        "/etc/containers/systemd"
    );
}

#[cfg(feature = "apps")]
#[test]
fn apps_module_cooks_lists_and_removes_apps() {
    let dir = tempdir().unwrap();
    let files_dir = tempdir().unwrap();
    let base_dir = dir.path();
    let files_base_dir = files_dir.path();

    let create = dispatch(
        "apps",
        "create",
        json!({
            "name": "demo",
            "base_dir": base_dir,
            "files_base_dir": files_base_dir,
            "converge": false,
            "recipe": r#"
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
  - type: file
    filename: site/index.html
    template: files/index.html.tera
"#,
            "templates": {
                "containers/nginx.container.tera": "[Container]\nContainerName={{ app_id }}\nImage=docker.io/library/nginx:alpine\n",
                "files/index.html.tera": "<h1>{{ app_id }}</h1>\n",
            },
            "values": { "app_id": "demo-web" },
        }),
    );
    assert!(create.ok, "{create:?}");
    let payload = create.payload.unwrap();
    assert_eq!(payload["units"], json!(["demo-web.container"]));
    assert_eq!(payload["files"], json!(["site/index.html"]));
    assert!(base_dir.join("demo-web.container").exists());
    assert!(files_base_dir.join("demo/app.json").exists());

    let list = dispatch(
        "apps",
        "list",
        json!({ "base_dir": base_dir, "files_base_dir": files_base_dir }),
    );
    assert!(list.ok, "{list:?}");
    let apps = list.payload.unwrap()["apps"].as_array().unwrap().clone();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0]["name"], "demo");
    assert_eq!(apps[0]["recipe_id"], "nginx-site");

    let get = dispatch(
        "apps",
        "get",
        json!({
            "name": "demo",
            "base_dir": base_dir,
            "files_base_dir": files_base_dir,
        }),
    );
    assert!(get.ok, "{get:?}");
    let payload = get.payload.unwrap();
    assert_eq!(payload["app"]["values"]["app_id"], "demo-web");
    assert_eq!(payload["services"], json!(["demo-web.service"]));

    let remove = dispatch(
        "apps",
        "remove",
        json!({
            "name": "demo",
            "base_dir": base_dir,
            "files_base_dir": files_base_dir,
            "converge": false,
        }),
    );
    assert!(remove.ok, "{remove:?}");
    assert!(!base_dir.join("demo-web.container").exists());
    assert!(!files_base_dir.join("demo").exists());
}

#[cfg(feature = "apps")]
#[test]
fn apps_create_dry_run_previews_systemd_commands() {
    let dir = tempdir().unwrap();
    let files_dir = tempdir().unwrap();

    let create = dispatch(
        "apps",
        "create",
        json!({
            "name": "demo",
            "base_dir": dir.path(),
            "files_base_dir": files_dir.path(),
            "dry_run": true,
            "recipe": "recipe_id: nginx-site\nname: Nginx static site\nversion: 0.1.0\nparameters:\n  - key: app_id\n    label: App ID\n    type: string\n    default: demo-web\nresources:\n  - type: container\n    filename: \"{{ app_id }}.container\"\n    template: containers/nginx.container.tera\n",
            "templates": {
                "containers/nginx.container.tera": "[Container]\nContainerName={{ app_id }}\n",
            },
            "values": { "app_id": "demo-web" },
        }),
    );
    assert!(create.ok, "{create:?}");
    let payload = create.payload.unwrap();
    assert_eq!(payload["dry_run"], true);
    assert_eq!(payload["written"], false);
    let commands = payload["systemd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op["command"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "systemctl daemon-reload",
            "systemctl enable demo-web.service",
            "systemctl start demo-web.service",
        ]
    );
    assert!(!dir.path().join("demo-web.container").exists());
}

#[cfg(feature = "services")]
#[test]
fn services_mutations_support_dry_run() {
    let response = dispatch(
        "services",
        "restart",
        json!({ "service": "example.service", "dry_run": true }),
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.unwrap();
    assert_eq!(payload["command"], "systemctl restart example.service");
    assert_eq!(payload["dry_run"], true);
    assert!(payload["status"].is_null());
}

#[cfg(feature = "selinux")]
#[test]
fn selinux_mutations_support_dry_run() {
    let set_boolean = dispatch(
        "selinux",
        "set_boolean",
        json!({ "name": "virt_use_nfs", "value": true, "dry_run": true }),
    );

    assert!(set_boolean.ok, "{set_boolean:?}");
    let payload = set_boolean.payload.unwrap();
    assert_eq!(payload["command"], "setsebool -P virt_use_nfs on");
    assert_eq!(payload["dry_run"], true);
    assert!(payload["status"].is_null());

    let restore = dispatch(
        "selinux",
        "restore_context",
        json!({ "path": "/srv/tetra", "recursive": true, "dry_run": true }),
    );
    assert!(restore.ok, "{restore:?}");
    assert_eq!(
        restore.payload.unwrap()["command"],
        "restorecon -R -v /srv/tetra"
    );
}

#[cfg(feature = "recipes")]
#[test]
fn recipes_module_builds_template_context() {
    let response = dispatch(
        "recipes",
        "context",
        json!({
            "recipe_path": "schema.yaml",
            "values": {
                "domain": "cloud.example.test"
            }
        }),
    );

    assert!(response.ok, "{response:?}");
    let context = &response.payload.unwrap()["context"];
    assert_eq!(context["recipe_id"], "nextcloud");
    assert_eq!(context["domain"], "cloud.example.test");
    assert_eq!(context["admin_password"].as_str().unwrap().len(), 32);
    assert_eq!(context["db_password"].as_str().unwrap().len(), 32);
}

#[cfg(feature = "recipes")]
#[test]
fn recipes_module_renders_inline_recipe_bundles() {
    let response = dispatch(
        "recipes",
        "render_inline",
        json!({
            "recipe": r#"
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
            "templates": {
                "containers/nginx.container.tera": "[Container]\nContainerName={{ app_id }}\n"
            }
        }),
    );

    assert!(response.ok, "{response:?}");
    let payload = response.payload.unwrap();
    let resources = payload["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["filename"], "demo-web.container");
    assert_eq!(
        resources[0]["contents"],
        "[Container]\nContainerName=demo-web\n"
    );
}
