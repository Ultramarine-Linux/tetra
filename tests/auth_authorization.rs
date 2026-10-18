//! Authorization of module actions: admins, default permissions, grants and
//! the action log.
#![allow(clippy::tests_outside_test_module)]

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
async fn non_admins_only_view_services_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    assert!(allowed(&host.service, &alice, "services", "list").await);
    assert!(allowed(&host.service, &alice, "settings", "get_system").await);
    assert!(allowed(&host.service, &alice, "storage", "capabilities").await);
    for (module, action) in [
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
        json!({"services": "view", "storage": "view", "network": "manage"})
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
        "services",
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
