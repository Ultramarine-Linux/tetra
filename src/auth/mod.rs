//! Login and authorization.
//!
//! Tetra is the single authority for both: it verifies passwords (PAM), TOTP
//! codes and passkeys, issues session tokens, and checks every request
//! against the caller's role and grants. The dashboard only ever holds
//! Tetra-issued tokens.
//!
//! See `docs/auth-protocol.md` for the socket API and
//! `docs/dashboard-auth-guide.md` for how the dashboard should call it.

pub mod access;
pub mod accounts;
pub mod api;
pub mod audit;
pub mod authz;
pub mod clock;
pub mod dns;
pub mod host;
pub mod launcher;
pub mod pam;
pub mod passkey;
pub mod recovery;
pub mod seal;
pub mod secrets;
pub mod service;
pub mod sessions;
pub mod setup;
pub mod store;
pub mod testing;
pub mod totp;
pub mod users;

pub use service::{AuthConfig, AuthService, Backends};
