//! Wall-clock source, injectable so expiry and TOTP logic can be tested.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds since the epoch.
///
/// # Panics
/// Panics if the system clock is before the Unix epoch.
#[must_use]
pub fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
        .try_into()
        .expect("unix_timestamp overflow when casting u64 → i64")
}

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
