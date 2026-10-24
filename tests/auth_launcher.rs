//! The launcher: per-entry visibility, administrator-only changes, the access
//! check for apps and the public page.

mod common;

use common::{Dashboard, Oobe, call, fails, host, login, ok};
use serde_json::{Value, json};
use tetra::auth::{AuthService, accounts::ShadowState, api::ErrorCode, testing::TestHost};

/// `common::host` plus `bob` (in `media`) and `carol` (no groups).
fn launcher_host(dir: &std::path::Path) -> TestHost {
    let host = host(dir);
    host.accounts.add("bob", 1002, &["media"]);
    host.accounts.add("carol", 1003, &[]);
    host.passwords.set("bob", "hunter2");
    host.passwords.set("carol", "hunter2");
    host
}

async fn add(
    service: &AuthService,
    admin: &str,
    name: &str,
    visibility: Value,
    public: bool,
) -> String {
    let result = ok(
        service,
        Dashboard,
        Some(admin),
        "launcher.set",
        json!({"entry": {
            "name": name,
            "icon": null,
            "url": format!("https://{}.example.com/", name.to_ascii_lowercase()),
            "visibility": visibility,
            "public": public,
        }}),
    )
    .await;
    result["entry"]["id"].as_str().unwrap().to_owned()
}

async fn names(service: &AuthService, token: &str) -> Vec<String> {
    let result = ok(service, Dashboard, Some(token), "launcher.list", json!({})).await;
    result["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn can_access(service: &AuthService, uid: u32, id: &str) -> bool {
    let result = ok(
        service,
        Dashboard,
        None,
        "launcher.can_access",
        json!({"uid": uid, "id": id}),
    )
    .await;
    result["allowed"].as_bool().unwrap()
}

/// Entries named after who can see them.
async fn sample_entries(host: &TestHost, admin: &str) -> [String; 4] {
    [
        add(
            &host.service,
            admin,
            "Everyone",
            json!({"kind": "everyone"}),
            false,
        )
        .await,
        add(
            &host.service,
            admin,
            "Admins",
            json!({"kind": "admins"}),
            false,
        )
        .await,
        add(
            &host.service,
            admin,
            "Alice",
            json!({"kind": "members", "users": ["alice"], "groups": []}),
            false,
        )
        .await,
        add(
            &host.service,
            admin,
            "Media",
            json!({"kind": "members", "users": [], "groups": ["media"]}),
            false,
        )
        .await,
    ]
}

#[tokio::test]
async fn each_user_lists_only_the_entries_shared_with_them() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    sample_entries(&host, &admin).await;

    let alice = login(&host.service, "alice").await;
    let bob = login(&host.service, "bob").await;
    let carol = login(&host.service, "carol").await;
    assert_eq!(
        names(&host.service, &admin).await,
        ["Everyone", "Admins", "Alice", "Media"]
    );
    assert_eq!(names(&host.service, &alice).await, ["Everyone", "Alice"]);
    assert_eq!(names(&host.service, &bob).await, ["Everyone", "Media"]);
    assert_eq!(names(&host.service, &carol).await, ["Everyone"]);

    // Non-administrators get only what they need to open an app.
    let listed = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "launcher.list",
        json!({}),
    )
    .await;
    let mut keys: Vec<&str> = listed["entries"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["icon", "id", "name", "url"]);
    let full = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.list",
        json!({}),
    )
    .await;
    assert_eq!(full["entries"][1]["visibility"], json!({"kind": "admins"}));
    assert_eq!(full["entries"][1]["public"], false);

    // Group membership is read on every request.
    host.accounts
        .update("carol", |account| account.groups.push("media".into()));
    assert_eq!(names(&host.service, &carol).await, ["Everyone", "Media"]);
}

#[tokio::test]
async fn get_hides_entries_the_caller_cannot_see() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    let [everyone, admins, alice_only, _] = sample_entries(&host, &admin).await;
    let alice = login(&host.service, "alice").await;
    let carol = login(&host.service, "carol").await;

    let got = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "launcher.get",
        json!({"id": alice_only}),
    )
    .await;
    assert_eq!(
        got["entry"],
        json!({"id": alice_only, "name": "Alice", "icon": null, "url": "https://alice.example.com/"})
    );
    ok(
        &host.service,
        Dashboard,
        Some(&carol),
        "launcher.get",
        json!({"id": everyone}),
    )
    .await;

    // A hidden entry answers exactly like a missing one.
    let error = |id: &str| {
        let service = host.service.clone();
        let carol = carol.clone();
        let id = id.to_owned();
        async move {
            call(
                &service,
                Dashboard,
                Some(&carol),
                "launcher.get",
                json!({"id": id}),
            )
            .await
            .error
            .unwrap()
        }
    };
    let hidden = error(&admins).await;
    let shared_with_someone_else = error(&alice_only).await;
    let missing = error("no-such-entry").await;
    assert_eq!(hidden.code, ErrorCode::NotFound);
    assert_eq!(hidden, missing);
    assert_eq!(shared_with_someone_else, missing);
}

#[tokio::test]
async fn only_administrators_change_entries() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    let alice = login(&host.service, "alice").await;
    let id = add(
        &host.service,
        &admin,
        "Wiki",
        json!({"kind": "everyone"}),
        false,
    )
    .await;
    let entry = json!({
        "name": "Docs", "icon": "book", "url": "http://192.0.2.1:8080/docs",
        "visibility": {"kind": "everyone"}, "public": false,
    });

    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "launcher.set",
        json!({"entry": entry}),
        ErrorCode::Forbidden,
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "launcher.remove",
        json!({"id": id}),
        ErrorCode::Forbidden,
    )
    .await;

    let replaced = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.set",
        json!({"id": id, "entry": entry}),
    )
    .await;
    assert_eq!(replaced["entry"]["id"], id);
    assert_eq!(replaced["entry"]["url"], "http://192.0.2.1:8080/docs");
    assert_eq!(replaced["entry"]["icon"], "book");
    assert_eq!(replaced["entry"]["source"], "manual");
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.set",
        json!({"id": "missing", "entry": entry}),
        ErrorCode::NotFound,
    )
    .await;
    let mut bad = entry.clone();
    bad["url"] = json!("javascript:alert(1)");
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.set",
        json!({"entry": bad}),
        ErrorCode::BadRequest,
    )
    .await;

    let removed = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.remove",
        json!({"id": id}),
    )
    .await;
    assert_eq!(removed, json!({"removed": id}));
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.remove",
        json!({"id": id}),
        ErrorCode::NotFound,
    )
    .await;
    assert_eq!(names(&host.service, &admin).await, Vec::<String>::new());
}

#[tokio::test]
async fn changes_are_in_the_action_log() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    let id = add(
        &host.service,
        &admin,
        "Wiki",
        json!({"kind": "everyone"}),
        false,
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.public_set",
        json!({"enabled": true}),
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.remove",
        json!({"id": id}),
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
    let logged: Vec<&str> = actions["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|action| action["module"] == "launcher")
        .map(|action| action["action"].as_str().unwrap())
        .collect();
    assert_eq!(logged, ["remove", "public_set", "set"]);
}

#[tokio::test]
async fn entries_are_stored_with_a_versioned_header_and_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    add(
        &host.service,
        &admin,
        "Wiki",
        json!({"kind": "everyone"}),
        false,
    )
    .await;
    let path = host.config.state_dir.join("launcher.json");
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored["schema"], 1);
    assert_eq!(stored["compat"], 1);
    assert_eq!(stored["public_page"], false);
    assert_eq!(stored["entries"][0]["name"], "Wiki");

    let restarted = host.restart().unwrap();
    let admin = login(&restarted, "admin").await;
    assert_eq!(names(&restarted, &admin).await, ["Wiki"]);
}

#[tokio::test]
async fn the_setup_session_has_no_launcher() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let setup = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
    let token = setup["token"].as_str().unwrap();
    fails(
        &host.service,
        Oobe,
        Some(token),
        "launcher.list",
        json!({}),
        ErrorCode::Forbidden,
    )
    .await;
}

#[tokio::test]
async fn can_access_follows_the_same_visibility() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    let [everyone, admins, alice_only, media] = sample_entries(&host, &admin).await;
    let (alice, admin_uid, bob, carol) = (1000, 1001, 1002, 1003);

    for id in [&everyone, &admins, &alice_only, &media] {
        assert!(can_access(&host.service, admin_uid, id).await);
    }
    assert!(can_access(&host.service, alice, &everyone).await);
    assert!(can_access(&host.service, alice, &alice_only).await);
    assert!(!can_access(&host.service, alice, &admins).await);
    assert!(!can_access(&host.service, alice, &media).await);
    assert!(can_access(&host.service, bob, &media).await);
    assert!(!can_access(&host.service, bob, &alice_only).await);
    assert!(can_access(&host.service, carol, &everyone).await);
    assert!(!can_access(&host.service, carol, &media).await);
    assert!(!can_access(&host.service, carol, "no-such-entry").await);

    // Accounts that cannot log in get into nothing.
    assert!(!can_access(&host.service, 4242, &everyone).await);
    host.accounts
        .update("carol", |account| account.shadow = ShadowState::Locked);
    assert!(!can_access(&host.service, carol, &everyone).await);
    host.accounts.add("ultramarine-apps", 1500, &[]);
    assert!(!can_access(&host.service, 1500, &everyone).await);

    // Only the dashboard asks.
    fails(
        &host.service,
        Oobe,
        None,
        "launcher.can_access",
        json!({"uid": alice, "id": everyone}),
        ErrorCode::WrongClient,
    )
    .await;
}

#[tokio::test]
async fn the_public_page_is_off_by_default_and_lists_only_public_entries() {
    let dir = tempfile::tempdir().unwrap();
    let host = launcher_host(dir.path());
    let admin = login(&host.service, "admin").await;
    let alice = login(&host.service, "alice").await;
    let page = host.config.public_dir.join("index.html");
    add(
        &host.service,
        &admin,
        "Photos",
        json!({"kind": "admins"}),
        true,
    )
    .await;
    add(
        &host.service,
        &admin,
        "Private",
        json!({"kind": "everyone"}),
        false,
    )
    .await;
    assert!(!page.exists());
    let status = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.public_get",
        json!({}),
    )
    .await;
    assert_eq!(status["enabled"], false);

    for op in ["launcher.public_get", "launcher.public_set"] {
        fails(
            &host.service,
            Dashboard,
            Some(&alice),
            op,
            json!(if op.ends_with("set") {
                json!({"enabled": true})
            } else {
                json!({})
            }),
            ErrorCode::Forbidden,
        )
        .await;
    }

    let enabled = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.public_set",
        json!({"enabled": true}),
    )
    .await;
    assert_eq!(enabled["enabled"], true);
    let html = std::fs::read_to_string(&page).unwrap();
    assert!(html.contains("Photos"));
    assert!(html.contains("https://photos.example.com/"));
    assert!(!html.contains("Private"));
    assert!(!html.contains("private.example.com"));
    // No visibility, ids or other details.
    assert!(!html.contains("admins"));

    // Regenerated when entries change, and after a restart.
    let id = add(
        &host.service,
        &admin,
        "Status",
        json!({"kind": "everyone"}),
        true,
    )
    .await;
    assert!(std::fs::read_to_string(&page).unwrap().contains("Status"));
    assert!(!std::fs::read_to_string(&page).unwrap().contains(&id));
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.remove",
        json!({"id": id}),
    )
    .await;
    assert!(!std::fs::read_to_string(&page).unwrap().contains("Status"));
    std::fs::remove_file(&page).unwrap();
    host.restart().unwrap();
    assert!(std::fs::read_to_string(&page).unwrap().contains("Photos"));

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "launcher.public_set",
        json!({"enabled": false}),
    )
    .await;
    assert!(!page.exists());
}
