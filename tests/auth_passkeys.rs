//! Passkey registration and login against a software authenticator, and the
//! access configuration that decides whether passkeys are available.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::{Dashboard, fails, host, login, ok};
use serde_json::{Value, json};
use tetra::auth::{AuthService, accounts::ShadowState, api::ErrorCode};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::Url;

const ORIGIN: &str = "https://server.example.com";

fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    // `true`: report user verification, which Tetra requires.
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

async fn set_domain(service: &AuthService, admin: &str) -> Value {
    ok(
        service,
        Dashboard,
        Some(admin),
        "access.set",
        json!({"mode": "domain", "hostname": "server.example.com"}),
    )
    .await
}

async fn register(
    service: &AuthService,
    token: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &str,
) -> Result<Value, ErrorCode> {
    let begin = ok(
        service,
        Dashboard,
        Some(token),
        "account.passkey_register_begin",
        json!({"name": "Laptop"}),
    )
    .await;
    let options = serde_json::from_value(begin["options"].clone()).unwrap();
    let Ok(credential) = authenticator.do_registration(Url::parse(origin).unwrap(), options) else {
        return Err(ErrorCode::InvalidCredentials);
    };
    let response = common::call(
        service,
        Dashboard,
        Some(token),
        "account.passkey_register_finish",
        json!({"ceremony": begin["ceremony"], "credential": credential}),
    )
    .await;
    match response.error {
        None => Ok(response.result.unwrap()),
        Some(error) => Err(error.code),
    }
}

async fn passkey_login(
    service: &AuthService,
    username: Option<&str>,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> Result<Value, ErrorCode> {
    let begin = ok(
        service,
        Dashboard,
        None,
        "auth.passkey_begin",
        json!({"username": username}),
    )
    .await;
    let options = serde_json::from_value(begin["options"].clone()).unwrap();
    let Ok(credential) = authenticator.do_authentication(Url::parse(ORIGIN).unwrap(), options)
    else {
        return Err(ErrorCode::InvalidCredentials);
    };
    let response = common::call(
        service,
        Dashboard,
        None,
        "auth.passkey_finish",
        json!({"ceremony": begin["ceremony"], "credential": credential}),
    )
    .await;
    match response.error {
        None => Ok(response.result.unwrap()),
        Some(error) => Err(error.code),
    }
}

#[tokio::test]
async fn passkeys_are_unavailable_without_a_domain() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    for op in ["auth.passkey_begin"] {
        fails(
            &host.service,
            Dashboard,
            None,
            op,
            json!({}),
            ErrorCode::PasskeysUnavailable,
        )
        .await;
    }
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "account.passkey_register_begin",
        json!({}),
        ErrorCode::PasskeysUnavailable,
    )
    .await;

    let set = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "access.set",
        json!({"mode": "ip", "hostname": "192.0.2.10"}),
    )
    .await;
    assert_eq!(set["passkeys_available"], false);
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.passkey_begin",
        json!({}),
        ErrorCode::PasskeysUnavailable,
    )
    .await;
    assert_eq!(host.service.hello()["passkeys_available"], false);
}

#[cfg(feature = "reverse-proxy")]
#[tokio::test]
async fn access_set_writes_the_dashboard_site_and_needs_an_admin() {
    use tetra::agent::modules::reverse_proxy::DASHBOARD_SITE_FILE;
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let alice = login(&host.service, "alice").await;
    let admin = login(&host.service, "admin").await;
    fails(
        &host.service,
        Dashboard,
        Some(&alice),
        "access.set",
        json!({"mode": "domain", "hostname": "server.example.com"}),
        ErrorCode::Forbidden,
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&admin),
        "access.set",
        json!({"mode": "domain", "hostname": "192.0.2.10"}),
        ErrorCode::BadRequest,
    )
    .await;

    let set = set_domain(&host.service, &admin).await;
    assert_eq!(set["passkeys_available"], true);
    let site = host.config.caddy_sites_dir.join(DASHBOARD_SITE_FILE);
    let contents = std::fs::read_to_string(&site).unwrap();
    assert!(contents.contains("server.example.com {"), "{contents}");
    assert!(contents.contains("reverse_proxy 127.0.0.1:3000"));

    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "access.set",
        json!({"mode": "ip", "hostname": "192.0.2.10"}),
    )
    .await;
    let contents = std::fs::read_to_string(&site).unwrap();
    assert!(contents.contains("https://192.0.2.10 {"), "{contents}");
    assert!(contents.contains("tls internal"));
    let access = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "access.get",
        json!({}),
    )
    .await;
    assert_eq!(access["access"]["mode"], "ip");
}

#[tokio::test]
async fn a_passkey_alone_logs_in() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    let registered = register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();
    assert_eq!(registered["name"], "Laptop");

    let session = passkey_login(&host.service, Some("alice"), &mut key)
        .await
        .unwrap();
    assert_eq!(session["status"], "authenticated");
    assert_eq!(session["session"]["method"], "passkey");
    assert_eq!(session["user"]["username"], "alice");
    // The account stack ran even though no password was used.
    assert!(host.passwords.calls().contains(&"account:alice".to_owned()));

    let list = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "account.passkey_list",
        json!({}),
    )
    .await;
    assert!(list["passkeys"][0]["last_used_at"].is_number());
}

#[tokio::test]
async fn passkey_logins_check_account_state() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();

    host.accounts
        .update("alice", |account| account.shell = "/sbin/nologin".into());
    assert_eq!(
        passkey_login(&host.service, Some("alice"), &mut key)
            .await
            .unwrap_err(),
        ErrorCode::InvalidCredentials
    );
    host.accounts
        .update("alice", |account| account.shell = "/bin/bash".into());
    host.accounts
        .update("alice", |account| account.shadow = ShadowState::Locked);
    // A locked account is not even offered its credentials.
    assert_eq!(
        passkey_login(&host.service, Some("alice"), &mut key)
            .await
            .unwrap_err(),
        ErrorCode::InvalidCredentials
    );
    host.accounts
        .update("alice", |account| account.shadow = ShadowState::Active);
    host.passwords.deny_account("alice");
    assert_eq!(
        passkey_login(&host.service, Some("alice"), &mut key)
            .await
            .unwrap_err(),
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test]
async fn registration_from_the_wrong_origin_fails() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    assert_eq!(
        register(
            &host.service,
            &alice,
            &mut authenticator(),
            "https://evil.example.net"
        )
        .await
        .unwrap_err(),
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test]
async fn removed_passkeys_no_longer_log_in() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    let registered = register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();
    ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "account.passkey_remove",
        json!({"id": registered["id"]}),
    )
    .await;
    assert_eq!(
        passkey_login(&host.service, Some("alice"), &mut key)
            .await
            .unwrap_err(),
        ErrorCode::InvalidCredentials
    );
}

#[tokio::test]
async fn usernameless_and_unknown_users_get_a_discoverable_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    for params in [json!({}), json!({"username": "nobody"})] {
        let begin = ok(&host.service, Dashboard, None, "auth.passkey_begin", params).await;
        let public_key = &begin["options"]["publicKey"];
        assert_eq!(public_key["rpId"], "server.example.com");
        assert!(
            public_key["allowCredentials"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        assert!(begin["options"].get("mediation").is_none_or(Value::is_null));
    }
    // Conditional mediation (autofill UI) is kept only on request.
    let conditional = ok(
        &host.service,
        Dashboard,
        None,
        "auth.passkey_begin",
        json!({"conditional": true}),
    )
    .await;
    assert_eq!(conditional["options"]["mediation"], "conditional");
    // The software authenticator used here cannot answer a discoverable
    // challenge (it returns no user handle), so the discoverable finish path
    // is not exercised end to end.
}
