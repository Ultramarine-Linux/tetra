//! Password, TOTP, recovery code and session behavior of the auth service,
//! with PAM, accounts and `systemd-creds` replaced by fakes.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Dashboard, Oobe, call, fails, host, login, ok};
use serde_json::{Value, json};
use tetra::auth::{accounts::ShadowState, api::ErrorCode, service::reset_second_factor, totp};
use totp_rs::Secret;

/// Enroll TOTP for the holder of `token`, returning the secret and the
/// recovery codes.
async fn enroll_totp(
    service: &tetra::auth::AuthService,
    token: &str,
    now: i64,
) -> (Vec<u8>, Vec<String>) {
    let begin = ok(
        service,
        Dashboard,
        Some(token),
        "account.totp_begin",
        json!({}),
    )
    .await;
    assert!(
        begin["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    let secret = Secret::try_from_base32(begin["secret"].as_str().unwrap())
        .unwrap()
        .as_ref()
        .to_vec();
    let confirmed = ok(
        service,
        Dashboard,
        Some(token),
        "account.totp_confirm",
        json!({"enrollment": begin["enrollment"], "code": totp::code_at(&secret, now).unwrap()}),
    )
    .await;
    let codes = confirmed["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    (secret, codes)
}

async fn password_step(service: &tetra::auth::AuthService, username: &str) -> Value {
    ok(
        service,
        Dashboard,
        None,
        "auth.password",
        json!({"username": username, "password": "hunter2"}),
    )
    .await
}

#[tokio::test]
async fn password_login_issues_a_working_session() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    assert!(token.starts_with("tts_"));
    let info = ok(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
    )
    .await;
    assert_eq!(info["user"]["username"], "alice");
    assert_eq!(info["user"]["admin"], false);
    assert_eq!(info["session"]["method"], "password");
    assert_eq!(info["permissions"], json!({"services": "view"}));
}

#[tokio::test]
async fn wrong_passwords_and_unknown_users_look_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    for (username, password) in [("alice", "wrong"), ("nobody", "hunter2"), ("alice", "")] {
        fails(
            &host.service,
            Dashboard,
            None,
            "auth.password",
            json!({"username": username, "password": password}),
            ErrorCode::InvalidCredentials,
        )
        .await;
    }
}

#[tokio::test]
async fn ineligible_accounts_cannot_log_in_even_with_the_right_password() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    host.accounts.add("daemon", 2, &[]);
    host.accounts.add("svc", 1002, &[]);
    host.accounts
        .update("svc", |account| account.shell = "/sbin/nologin".into());
    host.accounts.add("locked", 1003, &[]);
    host.accounts
        .update("locked", |account| account.shadow = ShadowState::Locked);
    host.accounts.add("expired", 1004, &[]);
    host.accounts
        .update("expired", |account| account.shadow = ShadowState::Expired);
    host.accounts.add("ultramarine-apps", 1005, &[]);
    for name in ["daemon", "svc", "locked", "expired", "ultramarine-apps"] {
        host.passwords.set(name, "hunter2");
        fails(
            &host.service,
            Dashboard,
            None,
            "auth.password",
            json!({"username": name, "password": "hunter2"}),
            ErrorCode::InvalidCredentials,
        )
        .await;
    }
}

#[tokio::test]
async fn expired_passwords_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    host.passwords.expire("alice");
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.password",
        json!({"username": "alice", "password": "hunter2"}),
        ErrorCode::PasswordExpired,
    )
    .await;
}

#[tokio::test]
async fn every_operation_but_login_needs_a_token() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    for op in [
        "session.info",
        "module.dispatch",
        "account.totp_begin",
        "admin.grants_get",
    ] {
        fails(
            &host.service,
            Dashboard,
            None,
            op,
            json!({}),
            ErrorCode::Unauthenticated,
        )
        .await;
        fails(
            &host.service,
            Dashboard,
            Some("tts_forged"),
            op,
            json!({}),
            ErrorCode::Unauthenticated,
        )
        .await;
    }
}

#[tokio::test]
async fn totp_is_required_once_enrolled_and_codes_are_single_use() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let now = host.clock_now();
    let (secret, _) = enroll_totp(&host.service, &token, now).await;

    // The password alone no longer issues a session.
    host.clock.advance(30);
    let step = password_step(&host.service, "alice").await;
    assert_eq!(step["status"], "second_factor_required");
    assert!(step.get("token").is_none());
    let code = totp::code_at(&secret, host.clock_now()).unwrap();
    let done = ok(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": step["pending"], "code": code}),
    )
    .await;
    assert_eq!(done["session"]["method"], "password_totp");

    // Replaying the same code fails.
    let again = password_step(&host.service, "alice").await;
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": again["pending"], "code": code}),
        ErrorCode::InvalidCredentials,
    )
    .await;
}

#[tokio::test]
async fn second_factor_attempts_are_limited_and_pending_logins_expire() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let (secret, _) = enroll_totp(&host.service, &token, host.clock_now()).await;
    host.clock.advance(30);

    let step = password_step(&host.service, "alice").await;
    for _ in 0..5 {
        fails(
            &host.service,
            Dashboard,
            None,
            "auth.second_factor",
            json!({"pending": step["pending"], "code": "000000"}),
            ErrorCode::InvalidCredentials,
        )
        .await;
    }
    // After five wrong codes the pending login is gone, even with a right code.
    let code = totp::code_at(&secret, host.clock_now()).unwrap();
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": step["pending"], "code": code}),
        ErrorCode::InvalidCredentials,
    )
    .await;

    let step = password_step(&host.service, "alice").await;
    host.clock.advance(301);
    let code = totp::code_at(&secret, host.clock_now()).unwrap();
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": step["pending"], "code": code}),
        ErrorCode::InvalidCredentials,
    )
    .await;
}

#[tokio::test]
async fn recovery_codes_work_once() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let (_, codes) = enroll_totp(&host.service, &token, host.clock_now()).await;
    assert_eq!(codes.len(), 10);

    let step = password_step(&host.service, "alice").await;
    let done = ok(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": step["pending"], "recovery_code": codes[0]}),
    )
    .await;
    assert_eq!(done["session"]["method"], "password_recovery_code");
    let status = ok(
        &host.service,
        Dashboard,
        Some(done["token"].as_str().unwrap()),
        "account.status",
        json!({}),
    )
    .await;
    assert_eq!(status["recovery_codes_left"], 9);

    let step = password_step(&host.service, "alice").await;
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.second_factor",
        json!({"pending": step["pending"], "recovery_code": codes[0]}),
        ErrorCode::InvalidCredentials,
    )
    .await;
}

#[tokio::test]
async fn totp_secrets_are_encrypted_and_files_are_root_only() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let (secret, codes) = enroll_totp(&host.service, &token, host.clock_now()).await;

    let record_path = host.config.auth_dir().join("users/1000.json");
    let record = std::fs::read_to_string(&record_path).unwrap();
    let base32 = Secret::from(secret).to_base32();
    assert!(!record.contains(&base32), "TOTP secret stored in clear");
    assert!(
        !record.contains(&codes[0].replace('-', "")),
        "recovery code stored in clear"
    );
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&record_path), 0o600);
    assert_eq!(mode(&host.config.auth_dir()), 0o700);
    assert_eq!(mode(&host.config.state_dir), 0o700);
    assert_eq!(mode(&host.config.store_key_path()), 0o600);
}

#[tokio::test]
async fn disabling_totp_needs_a_current_code() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let (secret, _) = enroll_totp(&host.service, &token, host.clock_now()).await;
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "account.totp_disable",
        json!({"code": "000000"}),
        ErrorCode::InvalidCredentials,
    )
    .await;
    host.clock.advance(30);
    let code = totp::code_at(&secret, host.clock_now()).unwrap();
    ok(
        &host.service,
        Dashboard,
        Some(&token),
        "account.totp_disable",
        json!({"code": code}),
    )
    .await;
    assert_eq!(
        password_step(&host.service, "alice").await["status"],
        "authenticated"
    );
}

#[tokio::test]
async fn sessions_expire_and_can_be_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    ok(
        &host.service,
        Dashboard,
        Some(&token),
        "session.logout",
        json!({}),
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;

    let idle = login(&host.service, "alice").await;
    host.clock.advance(3600);
    fails(
        &host.service,
        Dashboard,
        Some(&idle),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;

    // An admin can revoke everything a user has.
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    let revoked = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.sessions_revoke",
        json!({"uid": 1000}),
    )
    .await;
    assert_eq!(revoked["revoked"], 1);
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
}

#[tokio::test]
async fn users_see_and_revoke_only_their_own_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let first = login(&host.service, "alice").await;
    let second = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    let list = ok(
        &host.service,
        Dashboard,
        Some(&first),
        "session.list",
        json!({}),
    )
    .await;
    let sessions = list["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    let other = sessions.iter().find(|s| s["current"] == false).unwrap();
    ok(
        &host.service,
        Dashboard,
        Some(&first),
        "session.revoke",
        json!({"id": other["id"]}),
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&second),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;

    let admin_sessions = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "session.list",
        json!({}),
    )
    .await;
    let admin_id = admin_sessions["sessions"][0]["id"].clone();
    fails(
        &host.service,
        Dashboard,
        Some(&first),
        "session.revoke",
        json!({"id": admin_id}),
        ErrorCode::NotFound,
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&first),
        "session.list",
        json!({"uid": 1001}),
        ErrorCode::Forbidden,
    )
    .await;
}

#[tokio::test]
async fn tokens_only_work_for_the_client_they_were_issued_to() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::WrongClient,
    )
    .await;
}

#[tokio::test]
async fn locking_or_deleting_an_account_ends_its_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    host.accounts
        .update("alice", |account| account.shadow = ShadowState::Locked);
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    host.accounts
        .update("alice", |account| account.shadow = ShadowState::Active);
    // Revoked for good, not just while locked.
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;

    let token = login(&host.service, "alice").await;
    host.accounts.remove("alice");
    host.accounts.add("mallory", 1000, &[]);
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
}

#[tokio::test]
async fn sessions_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    host.service.flush_sessions().unwrap();
    let restarted = host.restart().unwrap();
    ok(
        &restarted,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
    )
    .await;
}

#[tokio::test]
async fn console_reset_removes_the_second_factor_and_logs_the_user_out() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    enroll_totp(&host.service, &token, host.clock_now()).await;

    let result = reset_second_factor(
        &host.config.state_dir,
        host.accounts.as_ref(),
        "alice",
        false,
    )
    .unwrap();
    assert_eq!(result["totp_removed"], true);
    assert_eq!(result["recovery_codes_removed"], 10);
    fails(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    // The password alone works again.
    assert_eq!(
        password_step(&host.service, "alice").await["status"],
        "authenticated"
    );

    reset_second_factor(
        &host.config.state_dir,
        host.accounts.as_ref(),
        "nobody",
        false,
    )
    .unwrap_err();
}

#[tokio::test]
async fn stored_records_keep_fields_from_a_newer_release() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let path = host.config.auth_dir().join("users/1000.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        json!({"schema": 2, "compat": 1, "uid": 1000, "username": "alice", "future_field": [1, 2]})
            .to_string(),
    )
    .unwrap();
    enroll_totp(&host.service, &token, host.clock_now()).await;
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored["future_field"], json!([1, 2]));
    assert!(stored["totp"].is_object());
}

#[tokio::test]
async fn unknown_operations_and_bad_params_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let response = call(&host.service, Dashboard, Some(&token), "nope", json!({})).await;
    assert_eq!(response.error.unwrap().code, ErrorCode::UnknownOperation);
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.password",
        json!({"username": "alice"}),
        ErrorCode::BadRequest,
    )
    .await;
}

trait ClockNow {
    fn clock_now(&self) -> i64;
}

impl ClockNow for tetra::auth::testing::TestHost {
    fn clock_now(&self) -> i64 {
        use tetra::auth::clock::Clock;
        self.clock.now()
    }
}
