//! Web shell tickets.
//!
//! A signed-in dashboard user asks for a ticket with `shell.ticket` on the
//! dashboard's normal connection, then opens a second connection to the
//! socket and redeems it with `shell.open`, which turns that connection into
//! the shell's byte stream ([`crate::agent::shell`]).
//!
//! A ticket is a random, single-use bearer string bound to the session that
//! asked for it (its public id, UID and username). It lives in memory only,
//! expires after [`TICKET_TTL`] seconds, and is gone once used. Redeeming it
//! checks the session again (still live, same account, account may still log
//! in, still allowed to open a shell), so a ticket of a session that has
//! ended is worthless. Pending tickets are bounded like passkey ceremonies
//! ([`super::passkey::Pending`]): 16 per user, 4096 in all.
//!
//! Remote controllers never get a shell (they do not use the socket's
//! operations), and neither does the setup session.

use super::sessions::ClientKind;

/// Seconds a ticket may wait before `shell.open`.
pub const TICKET_TTL: i64 = 30;

/// A pending ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTicket {
    pub client: ClientKind,
    pub session_id: String,
    pub uid: u32,
    pub username: String,
}

/// What a redeemed ticket lets the transport start: the account's own login
/// shell, as that account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellGrant {
    pub client: ClientKind,
    /// Public id of the session the shell belongs to; the shell ends with it.
    pub session_id: String,
    pub uid: u32,
    pub username: String,
    /// Login shell from the account database (listed in `/etc/shells`).
    pub shell: String,
}
