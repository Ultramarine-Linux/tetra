//! First-boot setup: the setup code, the setup session and completion.

mod common;

use common::{Dashboard, Oobe, access_set, call, fails, fresh, login, ok};
use serde_json::json;
use tetra::auth::{api::ErrorCode, testing::TestHost};

fn published_code(host: &TestHost) -> String {
    std::fs::read_to_string(host.config.run_dir.join("setup-code"))
        .unwrap()
        .trim()
        .to_owned()
}

#[tokio::test]
async fn the_oobe_redeems_the_published_code_for_a_limited_session() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    assert_eq!(host.service.hello()["setup_required"], true);
    let code = host.service.publish_setup_code().unwrap().unwrap();
    assert_eq!(published_code(&host), code);
    let banner =
        std::fs::read_to_string(host.config.issue_dir.join("50-tetra-setup.issue")).unwrap();
    assert!(banner.contains(&code));
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(host.config.issue_dir.join("50-tetra-setup.issue"))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600, "local users must not read the code");

    // Only the OOBE may redeem it.
    fails(
        &host.service,
        Dashboard,
        None,
        "setup.redeem",
        json!({"code": code}),
        ErrorCode::WrongClient,
    )
    .await;
    fails(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": "0000-0000"}),
        ErrorCode::InvalidCredentials,
    )
    .await;

    let redeemed = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
    assert_eq!(redeemed["admin_exists"], false);
    let token = redeemed["token"].as_str().unwrap().to_owned();
    let info = ok(&host.service, Oobe, Some(&token), "session.info", json!({})).await;
    assert_eq!(info["session"]["kind"], "setup");

    // OOBE operations are allowed...
    #[cfg(feature = "users")]
    let created = ok(
        &host.service,
        Oobe,
        Some(&token),
        "module.dispatch",
        json!({"module": "users", "action": "create", "payload": {"name": "admin", "dry_run": true}}),
    )
    .await;
    #[cfg(feature = "users")]
    assert_eq!(created["dry_run"], true);
    let response = access_set(
        &host,
        &token,
        json!({"mode": "ip", "hostname": "192.0.2.10"}),
    )
    .await;
    assert!(response.ok, "{:?}", response.error);
    // ...everything else is not.
    for (module, action) in [
        ("files", "write"),
        ("services", "start"),
        ("users", "delete"),
    ] {
        fails(
            &host.service,
            Oobe,
            Some(&token),
            "module.dispatch",
            json!({"module": module, "action": action, "payload": {"dry_run": true}}),
            ErrorCode::Forbidden,
        )
        .await;
    }
    for op in ["account.totp_begin", "admin.grants_get"] {
        fails(
            &host.service,
            Oobe,
            Some(&token),
            op,
            json!({}),
            ErrorCode::Forbidden,
        )
        .await;
    }
}

#[tokio::test]
async fn wrong_codes_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    for _ in 0..3 {
        fails(
            &host.service,
            Oobe,
            None,
            "setup.redeem",
            json!({"code": "WRONG"}),
            ErrorCode::InvalidCredentials,
        )
        .await;
    }
    let response = call(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
    let error = response.error.unwrap();
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(error.retry_after, Some(1));
    host.clock.advance(1);
    ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
}

#[tokio::test]
async fn the_code_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let restarted = host.restart().unwrap();
    assert_eq!(restarted.publish_setup_code().unwrap().unwrap(), code);
    ok(
        &restarted,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
}

#[tokio::test]
async fn completing_setup_needs_an_admin_and_disables_the_code_for_good() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let token = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_owned();

    fails(
        &host.service,
        Oobe,
        Some(&token),
        "setup.complete",
        json!({}),
        ErrorCode::SetupIncomplete,
    )
    .await;
    // A non-admin account is not enough.
    host.accounts.add("alice", 1000, &[]);
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "setup.complete",
        json!({}),
        ErrorCode::SetupIncomplete,
    )
    .await;
    host.accounts.add("admin", 1001, &["ultramarine-admin"]);
    let status = ok(&host.service, Oobe, Some(&token), "setup.status", json!({})).await;
    assert_eq!(status["admin_exists"], true);
    ok(
        &host.service,
        Oobe,
        Some(&token),
        "setup.complete",
        json!({}),
    )
    .await;

    assert!(host.config.state_dir.join("setup-complete").exists());
    assert!(!host.config.run_dir.join("setup-code").exists());
    assert!(!host.config.issue_dir.join("50-tetra-setup.issue").exists());
    assert_eq!(host.service.hello()["setup_required"], false);
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    fails(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
        ErrorCode::SetupComplete,
    )
    .await;
    assert_eq!(host.service.publish_setup_code().unwrap(), None);
    // Also after a restart.
    let restarted = host.restart().unwrap();
    fails(
        &restarted,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
        ErrorCode::SetupComplete,
    )
    .await;
}

#[tokio::test]
async fn setup_mode_applies_even_when_an_admin_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let host = common::host(dir.path());
    assert_eq!(host.service.hello()["setup_required"], true);
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let redeemed = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
    assert_eq!(redeemed["admin_exists"], true);

    // An administrator may also finish setup, from the dashboard.
    let admin = login(&host.service, "admin").await;
    let alice = login(&host.service, "alice").await;
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "setup.complete",
        json!({}),
        ErrorCode::Forbidden,
    )
    .await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "setup.complete",
        json!({}),
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "setup.complete",
        json!({}),
        ErrorCode::SetupComplete,
    )
    .await;
}

#[tokio::test]
async fn the_setup_code_is_stored_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let stored = std::fs::read_to_string(host.config.auth_dir().join("setup-code.json")).unwrap();
    assert!(!stored.contains(&code));
}

#[tokio::test]
async fn the_console_can_complete_setup_when_an_admin_exists() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let token = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Same rule as setup.complete: an eligible administrator must exist.
    host.service.complete_setup_from_console().unwrap_err();
    host.accounts.add("admin", 1001, &["wheel"]);
    // Run it as a separate process would: a second service over the same state.
    host.restart()
        .unwrap()
        .complete_setup_from_console()
        .unwrap();

    assert!(host.config.state_dir.join("setup-complete").exists());
    assert!(!host.config.issue_dir.join("50-tetra-setup.issue").exists());
    // The running service sees the marker on the next request.
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    fails(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
        ErrorCode::SetupComplete,
    )
    .await;
    host.service.complete_setup_from_console().unwrap_err();
}
