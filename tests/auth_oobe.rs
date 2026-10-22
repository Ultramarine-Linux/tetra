//! What the server OOBE does through Tetra with a setup session: the setup
//! allowlist, `access.set` (DNS-01, the dashboard's `ORIGIN`), the setup-code
//! throttle and the handoff to the dashboard.
#![allow(clippy::tests_outside_test_module)]
#![cfg(all(
    feature = "network",
    feature = "reverse-proxy",
    feature = "users",
    feature = "power",
    feature = "updates",
    feature = "remote-access"
))]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Oobe, call, fails, ok};
use serde_json::{Value, json};
use tetra::{
    agent::Dispatcher,
    auth::{
        api::{ErrorCode, Response},
        authz,
        testing::TestHost,
    },
};

const DNS_TOKEN: &str = "cf-api-token-S3CRET-value";

fn fresh(dir: &std::path::Path) -> TestHost {
    TestHost::new(dir).unwrap()
}

async fn setup_token(host: &TestHost) -> String {
    setup_session(host).await.0
}

/// A setup session's token and public ID.
async fn setup_session(host: &TestHost) -> (String, String) {
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let session = ok(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code, "remote_addr": "192.0.2.50"}),
    )
    .await;
    (
        session["token"].as_str().unwrap().to_owned(),
        session["session"]["id"].as_str().unwrap().to_owned(),
    )
}

async fn dispatch(
    host: &TestHost,
    token: &str,
    module: &str,
    action: &str,
    payload: Value,
) -> Response {
    call(
        &host.service,
        Oobe,
        Some(token),
        "module.dispatch",
        json!({"module": module, "action": action, "payload": payload}),
    )
    .await
}

#[tokio::test]
async fn the_setup_session_is_denied_every_action_not_on_the_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;

    let mut actions: Vec<(String, String)> = Dispatcher::full()
        .capabilities()
        .iter()
        .flat_map(|module| {
            module
                .actions
                .iter()
                .map(|action| (module.name.to_owned(), (*action).to_owned()))
        })
        .collect();
    actions.push(("nope".into(), "nope".into()));
    let mut denied = 0;
    for (module, action) in &actions {
        if authz::setup_allows(module, action) {
            continue;
        }
        let response = dispatch(&host, &token, module, action, json!({"dry_run": true})).await;
        assert!(!response.ok, "{module}.{action} was allowed");
        assert_eq!(
            response.error.unwrap().code,
            ErrorCode::Forbidden,
            "{module}.{action}"
        );
        denied += 1;
    }
    assert!(denied > 50, "only {denied} actions checked");

    for op in [
        "session.list",
        "session.revoke",
        "account.status",
        "account.totp_begin",
        "account.passkey_list",
        "authz.catalog",
        "admin.grants_get",
        "admin.grants_set",
        "admin.sessions_revoke",
        "admin.actions",
        "launcher.list",
        "launcher.get",
        "launcher.set",
        "launcher.remove",
        "launcher.public_get",
        "launcher.public_set",
        "no.such_operation",
    ] {
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
    let info = ok(&host.service, Oobe, Some(&token), "session.info", json!({})).await;
    let allowed = info["permissions"]["setup"].as_array().unwrap();
    assert!(allowed.contains(&json!("users.add_admin")));
    assert!(
        !allowed
            .iter()
            .any(|action| action.as_str().unwrap().ends_with(".*"))
    );
    assert!(
        info["permissions"]["operations"]
            .as_array()
            .unwrap()
            .contains(&json!("access.set"))
    );
}

#[tokio::test]
async fn the_setup_session_may_run_the_new_oobe_actions() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    for (module, action, payload) in [
        (
            "settings",
            "set_keymap",
            json!({"layout": "de", "variant": "nodeadkeys", "dry_run": true}),
        ),
        (
            "settings",
            "set_locale",
            json!({"locale": "de_DE.UTF-8", "dry_run": true}),
        ),
        (
            "settings",
            "set_timezone",
            json!({"timezone": "Europe/Berlin", "dry_run": true}),
        ),
        (
            "users",
            "add_admin",
            json!({"name": "admin", "dry_run": true}),
        ),
        (
            "network",
            "connect_wifi",
            json!({
                "interface": "wlan0",
                "ssid": "Home",
                "security": {"type": "wpa-personal", "password": "wifi-SECRET-pass"},
                "dry_run": true,
            }),
        ),
        ("power", "reboot", json!({"dry_run": true})),
        ("power", "poweroff", json!({"dry_run": true})),
        (
            "updates",
            "set_policy",
            json!({"policy": "automatic", "dry_run": true}),
        ),
        (
            "remote_access",
            "tailscale_up",
            json!({"auth_key": "tskey-auth-SECRET", "dry_run": true}),
        ),
        (
            "remote_access",
            "cloudflared_set_token",
            json!({"token": "eyJTOKEN", "dry_run": true}),
        ),
    ] {
        let response = dispatch(&host, &token, module, action, payload).await;
        assert!(response.ok, "{module}.{action}: {:?}", response.error);
        let result = response.result.unwrap();
        assert!(
            !result.to_string().contains("SECRET"),
            "{module}.{action}: {result}"
        );
        assert!(
            !result.to_string().contains("eyJTOKEN"),
            "{module}.{action}: {result}"
        );
    }
    // The action log records the actions, never their payloads.
    let log = read_tree(&host.config.state_dir.join("audit"));
    assert!(log.contains("tailscale_up"));
    assert!(!log.contains("SECRET") && !log.contains("eyJTOKEN"));
}

#[tokio::test]
async fn add_admin_is_only_for_the_first_administrator() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    let add_admin = || {
        dispatch(
            &host,
            &token,
            "users",
            "add_admin",
            json!({"name": "admin", "dry_run": true}),
        )
    };
    assert!(add_admin().await.ok);
    // Once an eligible administrator exists (made by the OOBE or Readymade),
    // the setup code cannot make more.
    host.accounts.add("admin", 1001, &["ultramarine-admin"]);
    let response = add_admin().await;
    assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden);
    // users.update could change group memberships, so it is not on the list.
    let response = dispatch(
        &host,
        &token,
        "users",
        "update",
        json!({"name": "alice", "groups": ["wheel"], "dry_run": true}),
    )
    .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn the_setup_session_only_sets_up_accounts_it_created() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let (token, session) = setup_session(&host).await;
    // An administrator Readymade created, and root.
    host.accounts.add("admin", 1001, &["ultramarine-admin"]);
    host.accounts.add("root", 0, &["root"]);
    let set_password = |name: &'static str| {
        dispatch(
            &host,
            &token,
            "users",
            "set_password",
            json!({"name": name, "password_hash": "$y$j9T$hash", "dry_run": true}),
        )
    };
    let set_keys = |name: &'static str| {
        dispatch(
            &host,
            &token,
            "users",
            "set_authorized_keys",
            json!({"name": name, "keys": ["ssh-ed25519 AAAAC3Nza attacker"], "dry_run": true}),
        )
    };

    // A dry-run users.create does not make the account the session's.
    let response = dispatch(
        &host,
        &token,
        "users",
        "create",
        json!({"name": "alice", "dry_run": true}),
    )
    .await;
    assert!(response.ok, "{:?}", response.error);
    assert_eq!(
        set_password("alice").await.error.unwrap().code,
        ErrorCode::Forbidden
    );

    host.record_setup_account(&session, "alice").unwrap();
    let response = set_password("alice").await;
    assert!(response.ok, "{:?}", response.error);
    // Not forbidden; it only fails because the test host has no `alice`.
    let response = set_keys("alice").await;
    assert_ne!(response.error.unwrap().code, ErrorCode::Forbidden);

    for name in ["admin", "root", "nobody-here"] {
        for response in [set_password(name).await, set_keys(name).await] {
            assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden, "{name}");
        }
    }
    // Root stays off limits even if the session somehow recorded it.
    host.record_setup_account(&session, "root").unwrap();
    for response in [set_password("root").await, set_keys("root").await] {
        assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden);
    }

    // The record is kept with the session, across a Tetra restart.
    let service = host.restart().unwrap();
    let response = call(
        &service,
        Oobe,
        Some(&token),
        "module.dispatch",
        json!({
            "module": "users",
            "action": "set_password",
            "payload": {"name": "alice", "password_hash": "$y$j9T$hash", "dry_run": true},
        }),
    )
    .await;
    assert!(response.ok, "{:?}", response.error);

    // A new setup session starts with no accounts of its own.
    let (token, _) = setup_session(&host).await;
    let response = dispatch(
        &host,
        &token,
        "users",
        "set_password",
        json!({"name": "alice", "password_hash": "$y$j9T$hash", "dry_run": true}),
    )
    .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn the_setup_session_may_not_choose_a_home_directory() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    let response = dispatch(
        &host,
        &token,
        "users",
        "create",
        json!({"name": "alice", "home": "/root", "dry_run": true}),
    )
    .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn one_noisy_address_is_throttled_before_the_global_counter() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let code = host.service.publish_setup_code().unwrap().unwrap();
    let redeem = |code: &str, addr: &str| {
        call(
            &host.service,
            Oobe,
            None,
            "setup.redeem",
            json!({"code": code, "remote_addr": addr}),
        )
    };
    for _ in 0..3 {
        let response = redeem("WRONG", "198.51.100.7").await;
        assert_eq!(response.error.unwrap().code, ErrorCode::InvalidCredentials);
    }
    host.clock.advance(1);
    // The noisy address now waits on its own, and its attempts no longer
    // count against the code.
    for _ in 0..20 {
        let error = redeem("WRONG", "198.51.100.7").await.error.unwrap();
        assert_eq!(error.code, ErrorCode::RateLimited);
        assert!(error.retry_after.unwrap() >= 29, "{error:?}");
    }
    // So the code was not rotated and another browser can still use it.
    let response = redeem(&code, "2001:db8:7::5").await;
    assert!(response.ok, "{:?}", response.error);
    assert_eq!(host.service.publish_setup_code().unwrap().unwrap(), code);
    // Without an address only the global counter applies.
    let response = call(
        &host.service,
        Oobe,
        None,
        "setup.redeem",
        json!({"code": code}),
    )
    .await;
    assert!(response.ok, "{:?}", response.error);
}

#[tokio::test]
async fn the_oobe_is_served_through_caddy_until_setup_completes() {
    use tetra::agent::modules::reverse_proxy::SETUP_SITE_FILE;
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    host.service.publish_setup_code().unwrap();
    let site = std::fs::read_to_string(host.config.caddy_sites_dir.join(SETUP_SITE_FILE)).unwrap();
    assert!(site.contains(
        "https://:6623 {\n\ttls internal {\n\t\ton_demand\n\t}\n\treverse_proxy 127.0.0.1:6624\n}"
    ));
    assert_eq!(
        host.host.calls(),
        ["systemctl --no-block try-reload-or-restart caddy.service"]
    );
    // Publishing again changes nothing, so Caddy is not reloaded again.
    host.service.publish_setup_code().unwrap();
    assert_eq!(host.host.calls().len(), 1);
}

#[tokio::test]
async fn setup_code_output_can_show_the_internal_ca_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    assert_eq!(host.service.internal_ca_fingerprint(), None);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["Caddy Local Authority".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let path = &host.config.caddy_root_ca;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, cert.pem()).unwrap();
    let fingerprint = host.service.internal_ca_fingerprint().unwrap();
    let expected: String = {
        use sha2::Digest as _;
        sha2::Sha256::digest(cert.der())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    assert_eq!(fingerprint, expected);
    assert_eq!(fingerprint.len(), 32 * 3 - 1);
}

#[tokio::test]
async fn setup_complete_hands_over_to_the_dashboard() {
    use tetra::agent::modules::reverse_proxy::SETUP_SITE_FILE;
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        json!({"mode": "ip", "hostname": "2001:db8::10"}),
    )
    .await;
    host.accounts.add("admin", 1001, &["ultramarine-admin"]);
    // The handoff only runs once setup is complete.
    host.service.finish_handoff().unwrap_err();
    host.host.clear();

    let result = ok(
        &host.service,
        Oobe,
        Some(&token),
        "setup.complete",
        json!({}),
    )
    .await;
    assert_eq!(result["complete"], true);
    assert_eq!(result["dashboard_url"], "https://[2001:db8::10]");
    assert_eq!(result["handoff_in_seconds"], 5);
    assert_eq!(result["handoff"]["dashboard_started"], true);
    assert_eq!(result["handoff"]["oobe_stop_scheduled"], true);
    // The dashboard is started now; the OOBE is stopped by a timer, after
    // this response has reached it.
    assert_eq!(
        host.host.calls(),
        [
            "systemctl start ultramarine-dashboard.service".to_owned(),
            "systemd-run --on-active=5 --unit=tetra-setup-handoff \
             --description=Hand over from the Ultramarine Server setup to the dashboard \
             --collect /usr/bin/tetra setup finish-handoff"
                .to_owned(),
        ]
    );
    assert!(host.config.caddy_sites_dir.join(SETUP_SITE_FILE).exists());

    // What the timer runs (`tetra setup finish-handoff`).
    host.host.clear();
    let finished = host.restart().unwrap().finish_handoff().unwrap();
    assert_eq!(finished["oobe_stopped"], true);
    assert_eq!(
        host.host.calls(),
        [
            "systemctl disable --now ultramarine-server-oobe.service tetra-setup-code.service",
            "systemctl try-reload-or-restart caddy.service",
        ]
    );
    assert!(!host.config.caddy_sites_dir.join(SETUP_SITE_FILE).exists());
    // The setup session is over.
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "session.info",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
}

#[tokio::test]
async fn a_failed_dashboard_start_is_reported_but_setup_stays_complete() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    host.accounts.add("admin", 1001, &["wheel"]);
    host.host
        .fail("systemctl start ultramarine-dashboard.service");
    let result = ok(
        &host.service,
        Oobe,
        Some(&token),
        "setup.complete",
        json!({}),
    )
    .await;
    assert_eq!(result["complete"], true);
    assert_eq!(result["dashboard_url"], Value::Null);
    assert_eq!(result["handoff"]["dashboard_started"], false);
    assert!(
        result["handoff"]["dashboard_error"]
            .as_str()
            .unwrap()
            .contains("failed")
    );
    assert!(host.config.state_dir.join("setup-complete").exists());
}

#[tokio::test]
async fn completing_setup_from_the_console_stops_the_oobe_right_away() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    host.service.publish_setup_code().unwrap();
    host.accounts.add("admin", 1001, &["wheel"]);
    host.host.clear();
    let handoff = host.service.complete_setup_from_console().unwrap();
    assert_eq!(handoff["dashboard_started"], true);
    assert_eq!(
        host.host.calls(),
        [
            "systemctl start ultramarine-dashboard.service",
            "systemctl disable --now ultramarine-server-oobe.service tetra-setup-code.service",
            "systemctl try-reload-or-restart caddy.service",
        ]
    );
}

/// The Caddy-related commands the service ran.
fn caddy_calls(host: &TestHost) -> Vec<String> {
    host.host
        .calls()
        .into_iter()
        .filter(|call| call.contains("caddy") || call.contains("daemon-reload"))
        .collect()
}

fn read_tree(path: &std::path::Path) -> String {
    let mut out = String::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.push_str(&read_tree(&path));
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    out
}

fn dns_request() -> Value {
    json!({
        "mode": "domain",
        "hostname": "server.example.com",
        "challenge": "dns-01",
        "dns_provider": "cloudflare",
        "dns_credentials": {"api_token": DNS_TOKEN}
    })
}

#[tokio::test]
async fn dns_01_credentials_reach_caddy_only_through_its_environment() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    host.host.clear();
    let request = dns_request();
    let result = ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        request.clone(),
    )
    .await;
    assert!(!result.to_string().contains(DNS_TOKEN), "{result}");
    assert_eq!(result["access"]["challenge"], "dns-01");
    assert_eq!(result["access"]["dns_provider"], "cloudflare");
    assert_eq!(result["dashboard_url"], "https://server.example.com");

    // The site names the variable, never the token.
    let sites = read_tree(&host.config.caddy_sites_dir);
    assert!(sites.contains(
        "\ttls {\n\t\tdns cloudflare {\n\t\t\tapi_token {env.TETRA_DNS_API_TOKEN}\n\t\t}\n\t}\n"
    ));
    assert!(!sites.contains(DNS_TOKEN));
    // Caddy gets it from a group-readable environment file.
    let env = std::fs::read_to_string(&host.config.caddy_env_file).unwrap();
    assert!(env.contains(&format!("TETRA_DNS_API_TOKEN=\"{DNS_TOKEN}\"\n")));
    // As root (as in CI) it belongs to `root:caddy`, or is root-only when
    // there is no `caddy` group.
    let metadata = std::fs::metadata(&host.config.caddy_env_file).unwrap();
    let caddy = nix::unistd::Group::from_name("caddy").unwrap();
    let mode = if nix::unistd::geteuid().is_root() && caddy.is_none() {
        0o600
    } else {
        0o640
    };
    assert_eq!(metadata.permissions().mode() & 0o777, mode);
    if nix::unistd::geteuid().is_root()
        && let Some(caddy) = caddy
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!((metadata.uid(), metadata.gid()), (0, caddy.gid.as_raw()));
    }
    let drop_in = std::fs::read_to_string(
        host.config
            .systemd_dir
            .join("caddy.service.d/50-tetra.conf"),
    )
    .unwrap();
    assert!(drop_in.contains(&format!(
        "EnvironmentFile=-{}\n",
        host.config.caddy_env_file.display()
    )));
    // Sealed in Tetra's store; not in access.json or the action log.
    assert!(
        host.config
            .secrets_dir()
            .join("tetra-dns-credentials.cred")
            .exists()
    );
    assert!(
        !std::fs::read_to_string(host.config.access_path())
            .unwrap()
            .contains(DNS_TOKEN)
    );
    assert!(!read_tree(&host.config.state_dir.join("audit")).contains(DNS_TOKEN));
    // A new environment needs a restart, without waiting on this request.
    assert_eq!(
        caddy_calls(&host),
        [
            "systemctl daemon-reload",
            "systemctl --no-block try-restart caddy.service",
        ]
    );
}

#[tokio::test]
async fn stored_dns_credentials_are_reused_and_forgotten_with_dns_01() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    let request = dns_request();
    ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        request.clone(),
    )
    .await;

    // The same settings again only reload, and the stored credentials are
    // reused when left out.
    host.host.clear();
    let mut again = request.clone();
    again.as_object_mut().unwrap().remove("dns_credentials");
    again["port"] = json!(8443);
    ok(&host.service, Oobe, Some(&token), "access.set", again).await;
    assert_eq!(
        caddy_calls(&host),
        ["systemctl try-reload-or-restart caddy.service"]
    );
    assert!(read_tree(&host.config.caddy_sites_dir).contains("server.example.com:8443 {"));

    // Another provider needs its own credentials.
    let mut other = request.clone();
    other["dns_provider"] = json!("desec");
    other.as_object_mut().unwrap().remove("dns_credentials");
    fails(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        other,
        ErrorCode::BadRequest,
    )
    .await;

    // Switching to HTTP-01 forgets them.
    host.host.clear();
    ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        json!({"mode": "domain", "hostname": "server.example.com", "challenge": "http-01"}),
    )
    .await;
    assert!(!host.config.caddy_env_file.exists());
    assert!(
        !host
            .config
            .systemd_dir
            .join("caddy.service.d/50-tetra.conf")
            .exists()
    );
    assert!(
        !host
            .config
            .secrets_dir()
            .join("tetra-dns-credentials.cred")
            .exists()
    );
    assert!(!read_tree(&host.config.caddy_sites_dir).contains("dns cloudflare"));
    assert_eq!(
        caddy_calls(&host),
        [
            "systemctl daemon-reload",
            "systemctl --no-block try-restart caddy.service",
        ]
    );
}

#[tokio::test]
async fn access_set_writes_the_dashboard_origin() {
    let dir = tempfile::tempdir().unwrap();
    let host = fresh(dir.path());
    let token = setup_token(&host).await;
    let env = &host.config.dashboard_env_file;
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(env, "BODY_SIZE_LIMIT=10M\nORIGIN=https://old.example.com\n").unwrap();
    host.host.clear();

    let result = ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        json!({"mode": "ip", "hostname": "[2001:db8::10]", "port": 8443}),
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(env).unwrap(),
        "BODY_SIZE_LIMIT=10M\nORIGIN=https://[2001:db8::10]:8443\n"
    );
    assert_eq!(result["dashboard_env"]["changed"], true);
    assert_eq!(result["dashboard_url"], "https://[2001:db8::10]:8443");
    // The dashboard is restarted only if it is running, without waiting (it
    // may be the caller).
    assert!(
        host.host
            .calls()
            .contains(&"systemctl --no-block try-restart ultramarine-dashboard.service".to_owned())
    );

    // Unchanged: no restart.
    host.host.clear();
    ok(
        &host.service,
        Oobe,
        Some(&token),
        "access.set",
        json!({"mode": "ip", "hostname": "2001:db8::10", "port": 8443}),
    )
    .await;
    assert!(
        !host
            .host
            .calls()
            .iter()
            .any(|call| call.contains("ultramarine-dashboard"))
    );
}
