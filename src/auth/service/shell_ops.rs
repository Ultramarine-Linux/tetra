//! The web shell: `shell.ticket`, and the checks the shell transport
//! ([`crate::agent::shell`]) asks for when it opens a shell and while the
//! shell runs. See [`crate::auth::shell`].

use serde_json::json;

use crate::{
    auth::{
        accounts::Account,
        api::{ApiError, ApiResult, ErrorCode},
        audit::{self, Origin},
        sessions::{ClientKind, SessionKind},
        shell::{ShellGrant, ShellTicket, TICKET_TTL},
    },
    prelude::*,
};

use super::{AuthService, Caller, require_client, session_error, user_owner};

impl AuthService {
    pub(super) fn shell_ticket(&self, caller: &Caller, _: TicketParams) -> ApiResult {
        require_client(caller.client, ClientKind::Dashboard)?;
        // Refuses the setup session.
        let (uid, username) = caller.user()?;
        caller.authorize("shell", "open")?;
        let now = self.now();
        let expires_at = now.saturating_add(TICKET_TTL);
        let ticket = self
            .inner
            .shell_tickets
            .insert(
                Some(&user_owner(uid)),
                ShellTicket {
                    client: caller.client,
                    session_id: caller.session.id.clone(),
                    uid,
                    username: username.to_owned(),
                },
                expires_at,
                now,
            )
            .ok_or_else(|| ApiError::rate_limited(TICKET_TTL))?;
        Ok(json!({ "ticket": ticket, "expires_at": expires_at }))
    }

    /// Redeem a `shell.ticket` for `shell.open` on a connection from
    /// `client`. The ticket is used up whatever the outcome.
    ///
    /// # Errors
    /// `wrong_client` from the OOBE; `invalid_credentials` for an unknown,
    /// expired or used ticket; `unauthenticated` when its session has ended
    /// (or its account may no longer log in); `forbidden` when the account
    /// may no longer open a shell.
    pub fn redeem_shell_ticket(
        &self,
        client: ClientKind,
        ticket: &str,
    ) -> Result<ShellGrant, ApiError> {
        require_client(client, ClientKind::Dashboard)?;
        let ticket = self
            .inner
            .shell_tickets
            .take(ticket, self.now())
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidCredentials,
                    "unknown, expired or already used shell ticket; ask for a new one",
                )
            })?;
        require_client(ticket.client, client)?;
        let mut grant = ShellGrant {
            client,
            session_id: ticket.session_id,
            uid: ticket.uid,
            username: ticket.username,
            shell: String::new(),
        };
        let account = self.shell_account(&grant, false)?;
        grant.shell = account.shell;
        Ok(grant)
    }

    /// Check that the shell of `grant` may keep running: its session is
    /// live, the account may still log in, and it may still open a shell.
    /// With `touch`, count it as a use of the session (the user typed in
    /// the shell), which keeps the session from expiring while idle.
    ///
    /// # Errors
    /// Like [`Self::redeem_shell_ticket`] once the ticket is accepted.
    pub fn check_shell_session(&self, grant: &ShellGrant, touch: bool) -> Result<(), ApiError> {
        self.shell_account(grant, touch).map(drop)
    }

    fn shell_account(&self, grant: &ShellGrant, touch: bool) -> Result<Account, ApiError> {
        let session = self
            .inner
            .sessions
            .by_id(&grant.session_id, grant.client, touch, self.now())
            .map_err(session_error)?;
        if session.kind != SessionKind::User
            || session.uid != Some(grant.uid)
            || session.username.as_deref() != Some(grant.username.as_str())
        {
            return Err(ApiError::unauthenticated());
        }
        let (principal, account) = self.user_principal(&session)?;
        if !principal.allows("shell", "open") {
            return Err(ApiError::forbidden("this account may not open a shell"));
        }
        // The login policy already refuses system accounts (UID_MIN); a
        // shell is never root's.
        if account.uid == 0 {
            return Err(ApiError::forbidden("root never gets a web shell"));
        }
        Ok(account)
    }

    /// Record a shell's `open` or `close` in the action log, as module
    /// `shell` with the `shell.open` request's id.
    pub fn record_shell(
        &self,
        grant: &ShellGrant,
        command_id: &str,
        action: &str,
        outcome: Result<(), &str>,
        detail: Option<String>,
    ) {
        self.inner.audit.record(&audit::Entry {
            at: self.now(),
            origin: Origin::Local,
            client: Some(grant.client),
            uid: Some(grant.uid),
            username: Some(grant.username.clone()),
            host_id: None,
            command_id: command_id.to_owned(),
            module: "shell".to_owned(),
            action: action.to_owned(),
            ok: outcome.is_ok(),
            error: outcome.err().map(str::to_owned),
            detail,
        });
    }
}

/// `shell.ticket` takes no parameters; a ticket is always for the caller's
/// own account.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "serde reads `{}` only into a braced struct"
)]
pub(super) struct TicketParams {}
