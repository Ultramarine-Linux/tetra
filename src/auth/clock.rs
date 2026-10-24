//! Wall-clock source, injectable so expiry and TOTP logic can be tested.

use crate::agent::protocol::unix_timestamp;

/// Seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        unix_timestamp()
    }
}
