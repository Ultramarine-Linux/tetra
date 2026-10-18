//! Identify which local client is on the other end of the Unix socket.
//!
//! The kernel reports the connecting process's credentials (`SO_PEERCRED`),
//! which the client cannot forge. The dashboard container runs as the fixed
//! host UID of the `ultramarine-dashboard` account (rootful Quadlet, no user
//! namespace) and the OOBE service as `ultramarine-oobe`. Any other peer,
//! root included, is refused. The token on each request then identifies the
//! user; the peer identifies the client the token must belong to.
//!
//! Account names are resolved on every connection, so accounts created by
//! `systemd-sysusers` after Tetra started are picked up.

use nix::unistd::{Group, User};

use crate::auth::sessions::ClientKind;

pub const DEFAULT_DASHBOARD_USER: &str = "ultramarine-dashboard";
pub const DEFAULT_OOBE_USER: &str = "ultramarine-oobe";
/// Group that owns the local socket (`systemd/tetra.socket`).
pub const SOCKET_GROUP: &str = "tetra";
/// Fixed GID of [`SOCKET_GROUP`] (`systemd/tetra.sysusers.conf`). The
/// dashboard's rootful Quadlet adds the group by this number.
pub const SOCKET_GID: u32 = 241;

/// Warn when the socket group does not have its fixed GID.
///
/// That happens on a host where the group was created dynamically before the
/// GID was fixed; the dashboard container would then be unable to open the
/// socket.
pub fn check_socket_group() {
    match Group::from_name(SOCKET_GROUP) {
        Ok(Some(group)) if group.gid.as_raw() == SOCKET_GID => {}
        Ok(Some(group)) => eprintln!(
            "warning: group `{SOCKET_GROUP}` has GID {}, expected {SOCKET_GID}; \
             the dashboard container adds GID {SOCKET_GID} and cannot reach the socket",
            group.gid
        ),
        Ok(None) => eprintln!("warning: group `{SOCKET_GROUP}` does not exist"),
        Err(error) => eprintln!("warning: cannot look up group `{SOCKET_GROUP}`: {error}"),
    }
}

/// How to recognize one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMatch {
    /// The UID of this account.
    User(String),
    /// A fixed UID (tests).
    Uid(u32),
}

impl PeerMatch {
    fn uid(&self) -> Option<u32> {
        match self {
            Self::Uid(uid) => Some(*uid),
            Self::User(name) => User::from_name(name)
                .ok()
                .flatten()
                .map(|user| user.uid.as_raw()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    pub dashboard: PeerMatch,
    pub oobe: PeerMatch,
}

impl PeerPolicy {
    #[must_use]
    pub fn from_users(dashboard: &str, oobe: &str) -> Self {
        Self {
            dashboard: PeerMatch::User(dashboard.to_owned()),
            oobe: PeerMatch::User(oobe.to_owned()),
        }
    }

    /// The client a peer UID belongs to, or `None` to refuse it. If both
    /// clients resolve to the same UID neither is accepted, since Tetra could
    /// not tell them apart.
    #[must_use]
    pub fn classify(&self, uid: u32) -> Option<ClientKind> {
        let dashboard = self.dashboard.uid();
        let oobe = self.oobe.uid();
        if dashboard.is_some() && dashboard == oobe {
            eprintln!("the dashboard and OOBE accounts share UID {uid}; refusing both");
            return None;
        }
        if dashboard == Some(uid) {
            Some(ClientKind::Dashboard)
        } else if oobe == Some(uid) {
            Some(ClientKind::Oobe)
        } else {
            None
        }
    }
}

impl Default for PeerPolicy {
    fn default() -> Self {
        Self::from_users(DEFAULT_DASHBOARD_USER, DEFAULT_OOBE_USER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_uid_and_refuses_everyone_else() {
        let policy = PeerPolicy {
            dashboard: PeerMatch::Uid(970),
            oobe: PeerMatch::Uid(971),
        };
        assert_eq!(policy.classify(970), Some(ClientKind::Dashboard));
        assert_eq!(policy.classify(971), Some(ClientKind::Oobe));
        assert_eq!(policy.classify(0), None);
        assert_eq!(policy.classify(1000), None);
    }

    #[test]
    fn missing_accounts_match_nobody() {
        let policy = PeerPolicy::from_users("tetra-test-no-such-user", "tetra-test-no-such-oobe");
        assert_eq!(policy.classify(0), None);
    }

    #[test]
    fn sysusers_declares_the_fixed_socket_gid() {
        let sysusers = include_str!("../../systemd/tetra.sysusers.conf");
        let line = sysusers
            .lines()
            .find(|line| line.starts_with("g "))
            .unwrap();
        assert_eq!(line, format!("g {SOCKET_GROUP} {SOCKET_GID}"));
        let socket = include_str!("../../systemd/tetra.socket");
        assert!(socket.contains(&format!("SocketGroup={SOCKET_GROUP}")));
    }

    #[test]
    fn a_shared_uid_is_refused() {
        let policy = PeerPolicy {
            dashboard: PeerMatch::Uid(970),
            oobe: PeerMatch::Uid(970),
        };
        assert_eq!(policy.classify(970), None);
    }
}
