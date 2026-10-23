//! Authorization of module actions: admins, default permissions, grants and
//! the action log.

mod common;

use common::{Dashboard, call, fails, host, login, ok};
use serde_json::json;
use tetra::auth::{
    api::ErrorCode,
    audit::{AuditLog, Origin},
};

/// Whether `module.action` got past authorization (it may still fail on this
/// test machine for other reasons).
async fn allowed(
    service: &tetra::auth::AuthService,
    token: &str,
    module: &str,
    action: &str,
) -> bool {
    let response = call(
        service,
        Dashboard,
        Some(token),
        "module.dispatch",
        json!({"module": module, "action": action, "payload": {"dry_run": true}}),
    )
    .await;
    response
        .error
        .is_none_or(|error| error.code != ErrorCode::Forbidden)
}

#[tokio::test]
async fn non_admins_only_get_the_launcher_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    assert!(allowed(&host.service, &alice, "settings", "get_system").await);
    assert!(allowed(&host.service, &alice, "storage", "capabilities").await);
    assert!(allowed(&host.service, &alice, "services", "capabilities").await);
    for (module, action) in [
        // System units and the journal are administrator-only by default.
        ("services", "list"),
        ("services", "status"),
        ("services", "logs"),
        ("services", "restart"),
        ("storage", "list"),
        ("users", "create"),
        ("files", "write"),
        ("settings", "set_hostname"),
        ("made_up", "action"),
    ] {
        assert!(
            !allowed(&host.service, &alice, module, action).await,
            "{module}.{action}"
        );
    }
}

#[tokio::test]
async fn admins_may_run_privileged_actions_and_lose_that_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    let result = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        json!({"module": "settings", "action": "set_hostname", "payload": {"hostname": "box", "dry_run": true}}),
    )
    .await;
    assert_eq!(result["dry_run"], true);

    // Membership is checked on every action, not at login.
    host.accounts.update("admin", |account| {
        account.groups.retain(|group| group != "wheel");
    });
    assert!(!allowed(&host.service, &admin, "settings", "set_hostname").await);
    host.accounts.update("admin", |account| {
        account.groups.push("ultramarine-admin".into());
    });
    assert!(allowed(&host.service, &admin, "settings", "set_hostname").await);
}

#[tokio::test]
async fn admins_grant_page_permissions_per_uid() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;

    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"storage": "view"}}),
        ErrorCode::Forbidden,
    )
    .await;
    let set = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"storage": "view", "network": "manage"}}),
    )
    .await;
    assert_eq!(
        set["effective"],
        json!({"launcher": "view", "storage": "view", "network": "manage"})
    );

    // Grants apply to existing sessions right away.
    assert!(allowed(&host.service, &alice, "storage", "list").await);
    assert!(!allowed(&host.service, &alice, "storage", "mount").await);
    assert!(allowed(&host.service, &alice, "network", "status").await);
    assert!(allowed(&host.service, &alice, "reverse_proxy", "write").await);
    assert!(!allowed(&host.service, &alice, "network", "set_config").await);

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"storage": null}}),
    )
    .await;
    assert!(!allowed(&host.service, &alice, "storage", "list").await);

    let all = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_get",
        json!({}),
    )
    .await;
    assert_eq!(all["grants"], json!({"1000": {"network": "manage"}}));
}

#[tokio::test]
async fn root_equivalent_permissions_cannot_be_granted() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    for page in [
        "users",
        "files",
        "settings",
        "system_services",
        "launcher",
        "apps",
        "containers",
        "storage",
    ] {
        fails(
            &host.service,
            Dashboard,
            Some(&admin),
            "admin.grants_set",
            json!({"uid": 1000, "grants": {page: "manage"}}),
            ErrorCode::BadRequest,
        )
        .await;
    }
    let catalog = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "authz.catalog",
        json!({}),
    )
    .await;
    let users = catalog["pages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|page| page["page"] == "users")
        .unwrap();
    assert_eq!(users["grantable"], json!(["view"]));
    let system_services = catalog["pages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|page| page["page"] == "system_services")
        .unwrap();
    assert_eq!(system_services["label"], "System services");
    assert_eq!(system_services["grantable"], json!(["view"]));
    assert_eq!(system_services["default"], json!(null));
}

#[tokio::test]
async fn system_services_view_can_be_granted() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    let denied = call(
        &host.service,
        Dashboard,
        Some(&alice),
        "module.dispatch",
        json!({"module": "services", "action": "logs", "payload": {"unit": "sshd.service"}}),
    )
    .await
    .error
    .unwrap();
    assert_eq!(denied.code, ErrorCode::Forbidden);
    assert!(
        denied.message.contains("system_services"),
        "{}",
        denied.message
    );

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"system_services": "view"}}),
    )
    .await;
    assert!(allowed(&host.service, &alice, "services", "logs").await);
    assert!(!allowed(&host.service, &alice, "services", "restart").await);
}

#[tokio::test]
async fn module_actions_run_as_the_user_and_are_logged() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        json!({"module": "settings", "action": "get_system"}),
    )
    .await;
    let log = AuditLog::new(host.config.state_dir.join("audit"));
    let entries = log.recent(10, Some(Origin::Local)).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].username.as_deref(), Some("admin"));
    assert_eq!(entries[0].module, "settings");

    let actions = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.actions",
        json!({"origin": "remote"}),
    )
    .await;
    assert_eq!(actions["actions"], json!([]));
    let alice = login(&host.service, "alice").await;
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "admin.actions",
        json!({}),
        ErrorCode::Forbidden,
    )
    .await;
}

#[tokio::test]
async fn failed_actions_report_action_failed() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        json!({"module": "no_such_module", "action": "x"}),
        ErrorCode::ActionFailed,
    )
    .await;
}

#[tokio::test]
async fn files_cannot_be_granted_and_config_dir_is_admin_only() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    // The files module reads any path as root.
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"files": "view"}}),
        ErrorCode::BadRequest,
    )
    .await;

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"network": "manage"}}),
    )
    .await;
    let write = |config_dir: Option<&str>| {
        let mut payload = json!({
            "domain": "app.example.com",
            "upstream": "127.0.0.1:8080",
            "dry_run": true,
        });
        if let Some(config_dir) = config_dir {
            payload["config_dir"] = json!(config_dir);
        }
        json!({"module": "reverse_proxy", "action": "write", "payload": payload})
    };
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "module.dispatch",
        write(Some("/etc/systemd/system")),
        ErrorCode::Forbidden,
    )
    .await;
    for token in [&alice, &admin] {
        let config_dir = (token == &admin).then_some("/tmp/caddy");
        let response = call(
            &host.service,
            Dashboard,
            Some(token),
            "module.dispatch",
            write(config_dir),
        )
        .await;
        assert!(
            response
                .error
                .is_none_or(|error| error.code != ErrorCode::Forbidden)
        );
    }
}

/// A `users` module that succeeds without touching the host.
struct StubUsers;

impl tetra::agent::modules::Mod for StubUsers {
    fn info(&self) -> tetra::agent::module_support::ModuleInfo {
        tetra::agent::module_support::ModuleInfo {
            name: "users",
            feature: "users",
            description: "Stub users module",
            status: tetra::agent::module_support::ModuleStatus::Available,
            actions: &["set_password", "delete"],
            privileged_actions: &[],
        }
    }

    fn handle(
        &self,
        action: &str,
        _payload: serde_json::Value,
        _user: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(json!({ "action": action }))
    }
}

#[tokio::test]
async fn a_new_password_ends_the_accounts_other_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let host = tetra::auth::testing::TestHost::with_dispatcher(dir.path(), |dispatcher| {
        dispatcher.with_module(StubUsers)
    })
    .unwrap();
    host.accounts.add("alice", 1000, &[]);
    host.accounts.add("admin", 1001, &["wheel"]);
    host.passwords.set("alice", "hunter2");
    host.passwords.set("admin", "hunter2");
    let admin = login(&host.service, "admin").await;
    let other_admin = login(&host.service, "admin").await;
    let alice = login(&host.service, "alice").await;
    let set_password = |name: &str, dry_run: bool| {
        json!({"module": "users", "action": "set_password",
               "payload": {"name": name, "password_hash": "$6$x", "dry_run": dry_run}})
    };

    // A dry run changes nothing.
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        set_password("alice", true),
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "session.info",
        json!({}),
    )
    .await;

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        set_password("alice", false),
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&other_admin),
        "session.info",
        json!({}),
    )
    .await;

    // Changing one's own password keeps the session it was changed from.
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        set_password("admin", false),
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "session.info",
        json!({}),
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&other_admin),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
}

#[tokio::test]
async fn grant_changes_are_in_the_action_log() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"storage": "view"}}),
    )
    .await;
    let actions = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.actions",
        json!({}),
    )
    .await;
    let logged = &actions["actions"][0];
    assert_eq!(logged["module"], "admin");
    assert_eq!(logged["action"], "grants_set");
    assert_eq!(logged["username"], "admin");
    assert_eq!(logged["ok"], true);
}

/// A `podman` module that reports who it ran as, defaulting to the apps
/// account like the real one.
struct StubPodman;

impl tetra::agent::modules::Mod for StubPodman {
    fn info(&self) -> tetra::agent::module_support::ModuleInfo {
        tetra::agent::module_support::ModuleInfo {
            name: "podman",
            feature: "podman",
            description: "Stub podman module",
            status: tetra::agent::module_support::ModuleStatus::Available,
            actions: &["containers", "inspect"],
            privileged_actions: &[],
        }
    }

    fn default_run_as(&self) -> tetra::agent::dispatcher::RunAs {
        tetra::agent::dispatcher::RunAs::Apps
    }

    fn handle(
        &self,
        _action: &str,
        payload: serde_json::Value,
        user: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(json!({ "user": user, "payload": payload }))
    }
}

#[tokio::test]
async fn container_views_default_to_the_apps_account() {
    let dir = tempfile::tempdir().unwrap();
    let host = tetra::auth::testing::TestHost::with_dispatcher(dir.path(), |dispatcher| {
        dispatcher.with_module(StubPodman)
    })
    .unwrap();
    host.accounts.add("alice", 1000, &[]);
    host.accounts.add("admin", 1001, &["wheel"]);
    host.passwords.set("alice", "hunter2");
    host.passwords.set("admin", "hunter2");
    let admin = login(&host.service, "admin").await;
    let alice = login(&host.service, "alice").await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.grants_set",
        json!({"uid": 1000, "grants": {"containers": "view"}}),
    )
    .await;
    let containers = |payload: serde_json::Value| json!({"module": "podman", "action": "containers", "payload": payload});
    let ran_as = |result: serde_json::Value| result["user"].clone();

    let default = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "module.dispatch",
        containers(json!({})),
    )
    .await;
    assert_eq!(ran_as(default), "ultramarine-apps");
    for (run_as, expected) in [
        ("apps", json!("ultramarine-apps")),
        ("user", json!("alice")),
    ] {
        let result = ok(
            &host.service,
            Dashboard,
            Some(&alice),
            "module.dispatch",
            containers(json!({ "run_as": run_as })),
        )
        .await;
        assert_eq!(ran_as(result), expected, "{run_as}");
    }
    for payload in [json!({ "run_as": "root" }), json!({ "run_as": "both" })] {
        fails(
            &host.service,
            Dashboard,
            Some(&alice),
            "module.dispatch",
            containers(payload),
            ErrorCode::Forbidden,
        )
        .await;
    }
    // Environments (app secrets) are for administrators.
    let inspect = |show_env: bool| {
        json!({"module": "podman", "action": "inspect",
               "payload": {"name": "db", "show_env": show_env}})
    };
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "module.dispatch",
        inspect(true),
        ErrorCode::Forbidden,
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "module.dispatch",
        inspect(false),
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        inspect(true),
    )
    .await;
    let root = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "module.dispatch",
        containers(json!({ "run_as": "root" })),
    )
    .await;
    assert!(ran_as(root).is_null());
}
