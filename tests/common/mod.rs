//! Shared helpers for the auth integration tests.
#![allow(dead_code, unused_imports, clippy::missing_panics_doc)]

use serde_json::{Value, json};
use tetra::auth::{
    AuthService,
    api::{ErrorCode, Request, Response},
    sessions::ClientKind,
    testing::TestHost,
};

pub use tetra::auth::sessions::ClientKind::{Dashboard, Oobe};

pub async fn call(
    service: &AuthService,
    client: ClientKind,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> Response {
    service
        .handle(
            client,
            Request {
                id: format!("test-{op}"),
                token: token.map(str::to_owned),
                op: op.into(),
                params,
            },
        )
        .await
}

/// Call and expect success, returning the result.
pub async fn ok(
    service: &AuthService,
    client: ClientKind,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> Value {
    let response = call(service, client, token, op, params).await;
    assert!(response.ok, "{op} failed: {:?}", response.error);
    response.result.unwrap()
}

/// Call and expect failure with `code`.
pub async fn fails(
    service: &AuthService,
    client: ClientKind,
    token: Option<&str>,
    op: &str,
    params: Value,
    code: ErrorCode,
) {
    let response = call(service, client, token, op, params).await;
    assert!(
        !response.ok,
        "{op} unexpectedly succeeded: {:?}",
        response.result
    );
    assert_eq!(response.error.unwrap().code, code, "{op}");
}

/// A host with `alice` (regular user) and `root-admin` (`admin`, in wheel),
/// both with password `hunter2`.
pub fn host(dir: &std::path::Path) -> TestHost {
    let host = TestHost::new(dir).unwrap();
    host.accounts.add("alice", 1000, &[]);
    host.accounts.add("admin", 1001, &["wheel"]);
    host.passwords.set("alice", "hunter2");
    host.passwords.set("admin", "hunter2");
    host
}

/// Log in with a password (no second factor) and return the token.
pub async fn login(service: &AuthService, username: &str) -> String {
    let result = ok(
        service,
        Dashboard,
        None,
        "auth.password",
        json!({"username": username, "password": "hunter2"}),
    )
    .await;
    assert_eq!(result["status"], "authenticated", "{result}");
    result["token"].as_str().unwrap().to_owned()
}
