//! Web shell tickets: `shell.ticket`, redeeming a ticket for `shell.open`,
//! and the session checks a running shell makes, with the fakes of
//! `tetra::auth::testing`. The shell stream itself is tested in
//! `src/agent/shell.rs`.

mod common;

use common::{Dashboard, Oobe, call, fails, host, login, ok, setup_token};
use serde_json::{Value, json};
use tetra::auth::{
    AuthService,
    api::ErrorCode,
    sessions::SessionPolicy,
    shell::{ShellGrant, TICKET_TTL},
    testing::TEST_EPOCH,
};

async fn ticket(service: &AuthService, token: &str) -> Value {
    ok(service, Dashboard, Some(token), "shell.ticket", json!({})).await
}

fn ticket_id(ticket: &Value) -> &str {
    ticket["ticket"].as_str().unwrap()
}

fn redeem(service: &AuthService, ticket: &str) -> Result<ShellGrant, ErrorCode> {
    service
        .redeem_shell_ticket(Dashboard, ticket)
        .map_err(|error| error.code)
}

#[tokio::test]
async fn a_ticket_opens_the_users_own_shell_once() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    assert_eq!(issued["expires_at"], TEST_EPOCH + TICKET_TTL);

    let grant = redeem(&host.service, ticket_id(&issued)).unwrap();
    assert_eq!(grant.uid, 1000);
    assert_eq!(grant.username, "alice");
    assert_eq!(grant.shell, "/bin/bash");
    let session = ok(
        &host.service,
        Dashboard,
        Some(&token),
        "session.info",
        json!({}),
    )
    .await;
    assert_eq!(grant.session_id, session["session"]["id"].as_str().unwrap());

    // Single use.
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::InvalidCredentials)
    );
    assert_eq!(
        redeem(&host.service, "made-up"),
        Err(ErrorCode::InvalidCredentials)
    );
    // Administrators get their own shell too, never someone else's.
    let admin = login(&host.service, "admin").await;
    let grant = redeem(
        &host.service,
        ticket_id(&ticket(&host.service, &admin).await),
    )
    .unwrap();
    assert_eq!((grant.uid, grant.username.as_str()), (1001, "admin"));
}

#[tokio::test]
async fn tickets_expire() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    host.clock.advance(TICKET_TTL);
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::InvalidCredentials)
    );
}

#[tokio::test]
async fn tickets_die_with_their_session() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());

    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    ok(
        &host.service,
        Dashboard,
        Some(&token),
        "session.logout",
        json!({}),
    )
    .await;
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::Unauthenticated)
    );

    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    let admin = login(&host.service, "admin").await;
    ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.sessions_revoke",
        json!({"uid": 1000}),
    )
    .await;
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::Unauthenticated)
    );

    // An idle session expires, and its tickets with it.
    let token = login(&host.service, "alice").await;
    host.clock.advance(SessionPolicy::default().idle - 1);
    let issued = ticket(&host.service, &token).await;
    host.clock.advance(TICKET_TTL - 1);
    redeem(&host.service, ticket_id(&issued)).unwrap();
}

#[tokio::test]
async fn tickets_are_bound_to_the_account() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());

    // Renamed: the session (and its ticket) belonged to `alice`.
    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    host.accounts
        .update("alice", |account| account.name = "mallory".into());
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::Unauthenticated)
    );
    host.accounts
        .update("mallory", |account| account.name = "alice".into());

    // Locked.
    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    host.accounts.update("alice", |account| {
        account.shadow = tetra::auth::accounts::ShadowState::Locked;
    });
    assert_eq!(
        redeem(&host.service, ticket_id(&issued)),
        Err(ErrorCode::Unauthenticated)
    );
}

#[tokio::test]
async fn only_the_dashboards_user_sessions_get_tickets() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    // The setup session never gets a shell.
    let setup = setup_token(&host).await;
    fails(
        &host.service,
        Oobe,
        Some(&setup),
        "shell.ticket",
        json!({}),
        ErrorCode::Forbidden,
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        None,
        "shell.ticket",
        json!({}),
        ErrorCode::Unauthenticated,
    )
    .await;
    fails(
        &host.service,
        Dashboard,
        Some(&login(&host.service, "alice").await),
        "shell.ticket",
        json!({"uid": 0}),
        ErrorCode::BadRequest,
    )
    .await;

    // Tickets are redeemed on the dashboard's connections only.
    let token = login(&host.service, "alice").await;
    let issued = ticket(&host.service, &token).await;
    assert_eq!(
        host.service
            .redeem_shell_ticket(Oobe, ticket_id(&issued))
            .unwrap_err()
            .code,
        ErrorCode::WrongClient
    );
    // `shell.open` is not a request/response operation.
    let response = call(
        &host.service,
        Dashboard,
        Some(&token),
        "shell.open",
        json!({"ticket": ticket_id(&ticket(&host.service, &token).await)}),
    )
    .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::BadRequest);
}

#[tokio::test]
async fn pending_tickets_are_bounded_per_user() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let first = ticket(&host.service, &token).await;
    let mut last = Value::Null;
    for _ in 0..tetra::auth::passkey::MAX_PER_OWNER {
        last = ticket(&host.service, &token).await;
    }
    assert_eq!(
        redeem(&host.service, ticket_id(&first)),
        Err(ErrorCode::InvalidCredentials)
    );
    redeem(&host.service, ticket_id(&last)).unwrap();
}

#[tokio::test]
async fn a_running_shell_keeps_its_session_alive_while_used() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let idle = SessionPolicy::default().idle;
    let token = login(&host.service, "alice").await;
    let grant = redeem(
        &host.service,
        ticket_id(&ticket(&host.service, &token).await),
    )
    .unwrap();

    host.clock.advance(idle - 1);
    host.service.check_shell_session(&grant, true).unwrap();
    host.clock.advance(idle - 1);
    host.service.check_shell_session(&grant, false).unwrap();
    host.clock.advance(1);
    assert_eq!(
        host.service
            .check_shell_session(&grant, false)
            .unwrap_err()
            .code,
        ErrorCode::Unauthenticated
    );
}

#[tokio::test]
async fn shells_are_recorded_in_the_action_log() {
    let dir = tempfile::tempdir().unwrap();
    let host = host(dir.path());
    let token = login(&host.service, "alice").await;
    let grant = redeem(
        &host.service,
        ticket_id(&ticket(&host.service, &token).await),
    )
    .unwrap();
    host.service
        .record_shell(&grant, "req\n{\"forged\":1}", "open", Ok(()), None);
    let admin = login(&host.service, "admin").await;
    let actions = ok(
        &host.service,
        Dashboard,
        Some(&admin),
        "admin.actions",
        json!({}),
    )
    .await;
    let entry = &actions["actions"][0];
    assert_eq!(entry["module"], "shell");
    assert_eq!(entry["action"], "open");
    assert_eq!(entry["username"], "alice");
    // A client-chosen id stays one JSON string on one line.
    assert_eq!(entry["command_id"], "req\n{\"forged\":1}");
    assert_eq!(actions["actions"].as_array().unwrap().len(), 1);
}
