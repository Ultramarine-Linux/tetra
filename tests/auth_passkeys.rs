//! Passkey registration and login against a software authenticator, and the
//! access configuration that decides whether passkeys are available.

mod common;

use common::{Dashboard, fails, host, login, ok};
use serde_json::{Value, json};
use tetra::auth::{AuthService, accounts::ShadowState, api::ErrorCode};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{Base64UrlSafeData, Url, Uuid};

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

/// Usernameless login with conditional mediation, as the dashboard's
/// autofill does. The software authenticator cannot pick a discoverable
/// credential itself or return a user handle, so the test plays the browser:
/// it points the authenticator at the user's stored credential and adds the
/// handle (which the assertion signature does not cover).
async fn discoverable_login(
    host: &tetra::auth::testing::TestHost,
    token: &str,
    uid: u32,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> Result<Value, ErrorCode> {
    let list = ok(
        &host.service,
        Dashboard,
        Some(token),
        "account.passkey_list",
        json!({}),
    )
    .await;
    let record: Value = serde_json::from_str(
        &std::fs::read_to_string(host.config.auth_dir().join(format!("users/{uid}.json"))).unwrap(),
    )
    .unwrap();
    let handle: Uuid = record["webauthn_id"].as_str().unwrap().parse().unwrap();

    let begin = ok(
        &host.service,
        Dashboard,
        None,
        "auth.passkey_begin",
        json!({"conditional": true, "remote_addr": "192.0.2.10"}),
    )
    .await;
    assert_eq!(begin["options"]["mediation"], "conditional");
    let mut options = begin["options"].clone();
    assert!(
        options["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    options["publicKey"]["allowCredentials"] =
        json!([{"type": "public-key", "id": list["passkeys"][0]["id"]}]);
    let options = serde_json::from_value(options).unwrap();
    let Ok(credential) = authenticator.do_authentication(Url::parse(ORIGIN).unwrap(), options)
    else {
        return Err(ErrorCode::InvalidCredentials);
    };
    let mut credential = serde_json::to_value(credential).unwrap();
    credential["response"]["userHandle"] =
        serde_json::to_value(Base64UrlSafeData::from(handle.as_bytes().to_vec())).unwrap();
    let response = common::call(
        &host.service,
        Dashboard,
        None,
        "auth.passkey_finish",
        json!({"ceremony": begin["ceremony"], "credential": credential, "remote_addr": "192.0.2.10"}),
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
    assert!(contents.contains("reverse_proxy 127.0.0.1:3972"));
    // The launcher's public page is routed even while it is disabled; Tetra
    // only writes the file once an administrator turns it on.
    assert!(contents.contains("handle_path /public/*"), "{contents}");

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
    let begin = ok(
        &host.service,
        Dashboard,
        None,
        "auth.passkey_begin",
        json!({}),
    )
    .await;
    let public_key = &begin["options"]["publicKey"];
    assert_eq!(public_key["rpId"], "server.example.com");
    assert!(
        public_key["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert!(begin["options"].get("mediation").is_none_or(Value::is_null));
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
    // `discoverable_login_is_the_primary_path` completes such a challenge.
}

#[tokio::test]
async fn passkey_begin_does_not_reveal_which_users_have_passkeys() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    register(&host.service, &alice, &mut authenticator(), ORIGIN)
        .await
        .unwrap();
    let allowed = |service: AuthService, username: &'static str| async move {
        let begin = ok(
            &service,
            Dashboard,
            None,
            "auth.passkey_begin",
            json!({"username": username}),
        )
        .await;
        assert!(begin["options"].get("mediation").is_none_or(Value::is_null));
        begin["options"]["publicKey"]["allowCredentials"].clone()
    };

    // A user with a passkey, one without (`admin`) and one that does not
    // exist all get one credential to try.
    for username in ["alice", "admin", "nobody", "root"] {
        let credentials = allowed(host.service.clone(), username).await;
        assert_eq!(credentials.as_array().unwrap().len(), 1, "{username}");
        assert_eq!(credentials[0]["type"], "public-key", "{username}");
    }
    // Decoys are stable across requests and restarts, and differ per name.
    let nobody = allowed(host.service.clone(), "nobody").await;
    assert_eq!(allowed(host.service.clone(), "nobody").await, nobody);
    assert_eq!(allowed(host.restart().unwrap(), "nobody").await, nobody);
    assert_ne!(allowed(host.service.clone(), "admin").await, nobody);
    // A decoy challenge cannot be completed.
    passkey_login(&host.service, Some("nobody"), &mut authenticator())
        .await
        .unwrap_err();
}

#[tokio::test]
async fn one_address_cannot_block_passkey_logins_for_others() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();
    for _ in 0..tetra::auth::passkey::MAX_PENDING {
        ok(
            &host.service,
            Dashboard,
            None,
            "auth.passkey_begin",
            json!({"remote_addr": "203.0.113.9"}),
        )
        .await;
    }
    let session = passkey_login(&host.service, Some("alice"), &mut key)
        .await
        .unwrap();
    assert_eq!(session["status"], "authenticated");
}

#[tokio::test]
async fn registration_asks_for_a_discoverable_credential() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let begin = ok(
        &host.service,
        Dashboard,
        Some(&alice),
        "account.passkey_register_begin",
        json!({"name": "Laptop"}),
    )
    .await;
    let selection = &begin["options"]["publicKey"]["authenticatorSelection"];
    assert_eq!(selection["residentKey"], "preferred");
    // Preferred, not required: keys without room for one still register.
    assert_ne!(selection["requireResidentKey"], true);
}

#[tokio::test]
async fn discoverable_login_is_the_primary_path() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();

    let session = discoverable_login(&host, &alice, 1000, &mut key)
        .await
        .unwrap();
    assert_eq!(session["status"], "authenticated");
    assert_eq!(session["session"]["method"], "passkey");
    assert_eq!(session["user"]["username"], "alice");
    assert!(host.passwords.calls().contains(&"account:alice".to_owned()));

    // Username-first still works for keys without a discoverable credential.
    let session = passkey_login(&host.service, Some("alice"), &mut key)
        .await
        .unwrap();
    assert_eq!(session["user"]["username"], "alice");
}

#[tokio::test]
async fn a_password_lockout_does_not_block_passkey_logins() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let admin = login(&host.service, "admin").await;
    set_domain(&host.service, &admin).await;
    let alice = login(&host.service, "alice").await;
    let mut key = authenticator();
    register(&host.service, &alice, &mut key, ORIGIN)
        .await
        .unwrap();

    // Five wrong passwords and pam_faillock locks the password login, even
    // for the right password.
    for _ in 0..5 {
        fails(
            &host.service,
            Dashboard,
            None,
            "auth.password",
            json!({"username": "alice", "password": "wrong"}),
            ErrorCode::InvalidCredentials,
        )
        .await;
    }
    host.passwords.lock_out("alice");
    fails(
        &host.service,
        Dashboard,
        None,
        "auth.password",
        json!({"username": "alice", "password": "hunter2"}),
        ErrorCode::InvalidCredentials,
    )
    .await;

    // The passkey still logs in, by either path; only the account stack ran.
    let session = discoverable_login(&host, &alice, 1000, &mut key)
        .await
        .unwrap();
    assert_eq!(session["status"], "authenticated");
    let session = passkey_login(&host.service, Some("alice"), &mut key)
        .await
        .unwrap();
    assert_eq!(session["status"], "authenticated");
}
