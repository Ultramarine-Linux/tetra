//! First-boot setup code.
//!
//! Until setup completes, a one-time code lets the OOBE in: it submits the
//! code with `setup.redeem` and gets a setup session limited to OOBE
//! operations. The code is generated once, sealed with the store key and kept
//! in `/var/lib/tetra/auth/setup-code.json` until setup completes, so it stays
//! the same across reboots and Tetra restarts (Tetra is socket-activated and
//! may not be running). It only changes when the wrong-code limit rotates it.
//!
//! `tetra-setup-code.service`, a boot-time oneshot, runs
//! `tetra setup code --publish` to write the code where the console can show
//! it: `/run/tetra/setup-code` (root-only, for the console screen) and
//! `/run/issue.d/50-tetra-setup.issue` (the getty login banner). It is never
//! put in the SSH banner. The daemon republishes after a rotation and removes
//! both files when setup completes.
//!
//! Wrong codes are rate-limited: after [`FREE_ATTEMPTS`] failures each attempt
//! waits twice as long as the last (capped at [`MAX_BACKOFF`] seconds), and
//! after [`ROTATE_AFTER`] failures the code is replaced. The failure count is
//! stored, so restarting Tetra does not reset it. This global counter is what
//! stops guessing from many addresses.
//!
//! In front of it, [`AddressThrottle`] slows down one noisy browser address
//! (as reported by the OOBE in `remote_addr`) much sooner and harder: after
//! [`ADDRESS_FREE_ATTEMPTS`] failures its waits start at
//! [`ADDRESS_BASE_BACKOFF`] seconds and double up to [`ADDRESS_MAX_BACKOFF`].
//! Attempts it refuses never reach the global counter, so a single address
//! needs hours rather than minutes to force a rotation that the console then
//! has to catch up with. It cannot stop many addresses, or a client that
//! changes its address; that is the global counter's job. Each attempt holds
//! the throttle's lock from the check to recording its outcome, so
//! concurrent attempts from one address are counted one after another.
//!
//! `setup.complete` writes the `/var/lib/tetra/setup-complete` marker, which
//! disables this path permanently.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use subtle::ConstantTimeEq;

use crate::prelude::*;

use super::{
    seal::{Sealed, StoreKey},
    store::{self, Extra, Header, Record, StoreLock},
};

pub const MARKER_FILE: &str = "setup-complete";
const CODE_FILE: &str = "setup-code.json";
const RUN_CODE_FILE: &str = "setup-code";
const ISSUE_FILE: &str = "50-tetra-setup.issue";
const CODE_PURPOSE: &str = "setup-code";
const CODE_CHARS: usize = 8;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Wrong codes allowed before backoff starts.
pub const FREE_ATTEMPTS: u32 = 3;
/// Wrong codes after which the code is replaced.
pub const ROTATE_AFTER: u32 = 20;
/// Longest wait between attempts, in seconds.
pub const MAX_BACKOFF: i64 = 300;

/// Wrong codes allowed per address before its own backoff starts.
pub const ADDRESS_FREE_ATTEMPTS: u32 = 3;
/// First per-address wait, in seconds; it doubles with every further failure.
pub const ADDRESS_BASE_BACKOFF: i64 = 30;
/// Longest per-address wait, in seconds.
pub const ADDRESS_MAX_BACKOFF: i64 = 3600;
/// Addresses remembered at most; the least recently seen are forgotten first.
const ADDRESS_MAX_TRACKED: usize = 4096;

/// Where setup state lives.
#[derive(Debug, Clone)]
pub struct SetupPaths {
    /// `/var/lib/tetra`, holding the completion marker.
    pub state_dir: PathBuf,
    /// `/var/lib/tetra/auth`, holding the sealed code.
    pub auth_dir: PathBuf,
    /// `/run/tetra`, for the console screen.
    pub run_dir: PathBuf,
    /// `/run/issue.d`, for the getty banner.
    pub issue_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct CodeFile {
    #[serde(flatten)]
    header: Header,
    code: Sealed,
    created_at: i64,
    #[serde(default)]
    failures: u32,
    #[serde(default)]
    retry_at: i64,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for CodeFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MarkerFile {
    #[serde(flatten)]
    header: Header,
    completed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_by: Option<String>,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for MarkerFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// Setup already completed.
    Complete,
    /// Too many wrong codes; retry after this many seconds.
    RateLimited {
        retry_after: i64,
    },
    Invalid,
}

#[derive(Debug, Clone)]
pub struct Setup {
    paths: SetupPaths,
}

impl Setup {
    #[must_use]
    pub const fn new(paths: SetupPaths) -> Self {
        Self { paths }
    }

    fn code_path(&self) -> PathBuf {
        self.paths.auth_dir.join(CODE_FILE)
    }

    fn marker_path(&self) -> PathBuf {
        self.paths.state_dir.join(MARKER_FILE)
    }

    /// Whether setup has completed. Checked on every use, never cached.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.marker_path().exists()
    }

    /// The current code, generating and storing one if needed. `None` once
    /// setup has completed.
    ///
    /// # Errors
    /// Fails when the code cannot be read, decrypted or written.
    pub fn ensure_code(&self, key: &StoreKey, now: i64) -> Result<Option<String>> {
        let _lock = StoreLock::acquire(&self.paths.auth_dir)?;
        if self.is_complete() {
            return Ok(None);
        }
        self.load_or_create(key, now).map(|(code, _)| Some(code))
    }

    fn load_or_create(&self, key: &StoreKey, now: i64) -> Result<(String, CodeFile)> {
        if let Some(file) = store::read::<CodeFile>(&self.code_path())? {
            let code = key.decrypt(CODE_PURPOSE, &file.code)?;
            return Ok((String::from_utf8(code)?, file));
        }
        self.create(key, now)
    }

    fn create(&self, key: &StoreKey, now: i64) -> Result<(String, CodeFile)> {
        let code = generate_code();
        let mut file = CodeFile {
            header: Header::default(),
            code: key.encrypt(CODE_PURPOSE, code.as_bytes())?,
            created_at: now,
            failures: 0,
            retry_at: 0,
            extra: Extra::new(),
        };
        store::write(&self.code_path(), &mut file)?;
        Ok((code, file))
    }

    /// Write the code for the console screen and the getty banner.
    ///
    /// # Errors
    /// Fails when either file cannot be written.
    pub fn publish(&self, code: &str) -> Result<()> {
        // `/run/tetra` also holds the socket the OOBE connects to, so it must
        // stay traversable: only the code file itself is private.
        fs::create_dir_all(&self.paths.run_dir)
            .with_context(|| format!("failed to create `{}`", self.paths.run_dir.display()))?;
        store::replace(
            &self.paths.run_dir.join(RUN_CODE_FILE),
            format!("{code}\n").as_bytes(),
            0o600,
        )?;
        fs::create_dir_all(&self.paths.issue_dir)
            .with_context(|| format!("failed to create `{}`", self.paths.issue_dir.display()))?;
        let banner = format!(
            "Ultramarine Server setup code: {code}\n\
             Open this server's address (\\4) in a web browser and enter the code to finish setup.\n\n"
        );
        let issue = self.paths.issue_dir.join(ISSUE_FILE);
        fs::write(&issue, banner).with_context(|| format!("failed to write `{}`", issue.display()))
    }

    /// Remove the published code.
    ///
    /// # Errors
    /// Fails when a file exists but cannot be removed.
    pub fn unpublish(&self) -> Result<()> {
        store::remove(&self.paths.run_dir.join(RUN_CODE_FILE))?;
        store::remove(&self.paths.issue_dir.join(ISSUE_FILE))
    }

    /// Check a submitted code.
    ///
    /// # Errors
    /// The outer error is an I/O or decryption failure; the inner one is the
    /// caller's mistake.
    pub fn redeem(&self, key: &StoreKey, input: &str, now: i64) -> Result<Result<(), RedeemError>> {
        let _lock = StoreLock::acquire(&self.paths.auth_dir)?;
        if self.is_complete() {
            return Ok(Err(RedeemError::Complete));
        }
        let (code, mut file) = self.load_or_create(key, now)?;
        if now < file.retry_at {
            return Ok(Err(RedeemError::RateLimited {
                retry_after: file.retry_at.saturating_sub(now),
            }));
        }
        let matches: bool = normalize(input)
            .as_bytes()
            .ct_eq(normalize(&code).as_bytes())
            .into();
        if matches {
            if file.failures > 0 {
                file.failures = 0;
                file.retry_at = 0;
                store::write(&self.code_path(), &mut file)?;
            }
            return Ok(Ok(()));
        }

        file.failures = file.failures.saturating_add(1);
        if file.failures >= ROTATE_AFTER {
            eprintln!("setup code: {ROTATE_AFTER} wrong codes, rotating the code");
            let (code, mut rotated) = self.create(key, now)?;
            rotated.retry_at = now.saturating_add(MAX_BACKOFF);
            store::write(&self.code_path(), &mut rotated)?;
            if let Err(error) = self.publish(&code) {
                eprintln!("failed to publish the rotated setup code: {error:#}");
            }
        } else {
            if let Some(excess) = file.failures.checked_sub(FREE_ATTEMPTS) {
                file.retry_at = now.saturating_add(doubling_backoff(excess, 1, MAX_BACKOFF));
            }
            store::write(&self.code_path(), &mut file)?;
        }
        Ok(Err(RedeemError::Invalid))
    }

    /// Finish setup: write the marker, delete the code and unpublish it.
    ///
    /// # Errors
    /// Fails when the marker cannot be written.
    pub fn complete(&self, completed_by: Option<&str>, now: i64) -> Result<()> {
        let _lock = StoreLock::acquire(&self.paths.auth_dir)?;
        store::write(
            &self.marker_path(),
            &mut MarkerFile {
                header: Header::default(),
                completed_at: now,
                completed_by: completed_by.map(str::to_owned),
                extra: Extra::new(),
            },
        )?;
        store::remove(&self.code_path())?;
        self.unpublish()
    }
}

/// Per-address throttle for `setup.redeem`, in memory.
#[derive(Debug, Default)]
pub struct AddressThrottle {
    addresses: Mutex<Addresses>,
}

/// The throttle's state, locked for one attempt by [`AddressThrottle::lock`].
#[derive(Debug, Default)]
pub struct Addresses {
    entries: HashMap<String, AddressEntry>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AddressEntry {
    failures: u32,
    retry_at: i64,
    last_seen: i64,
}

impl AddressThrottle {
    /// Lock the throttle for one attempt. Hold the guard from
    /// [`Addresses::check`] until the outcome is recorded, so concurrent
    /// attempts from one address cannot all pass the check before the first
    /// failure is counted.
    pub fn lock(&self) -> MutexGuard<'_, Addresses> {
        self.addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Addresses {
    /// `Err(retry_after)` while `key` must wait.
    ///
    /// # Errors
    /// Returns the seconds `key` still has to wait.
    pub fn check(&self, key: &str, now: i64) -> Result<(), i64> {
        match self.entries.get(key) {
            Some(entry) if now < entry.retry_at => Err(entry.retry_at.saturating_sub(now)),
            _ => Ok(()),
        }
    }

    /// Record a wrong code from `key`.
    pub fn failed(&mut self, key: &str, now: i64) {
        let entries = &mut self.entries;
        if !entries.contains_key(key) && entries.len() >= ADDRESS_MAX_TRACKED {
            // Forget the address seen longest ago.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        let entry = entries.entry(key.to_owned()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_seen = now;
        if let Some(excess) = entry.failures.checked_sub(ADDRESS_FREE_ATTEMPTS) {
            entry.retry_at = now.saturating_add(doubling_backoff(
                excess,
                ADDRESS_BASE_BACKOFF,
                ADDRESS_MAX_BACKOFF,
            ));
        }
    }

    /// Forget `key` after it redeemed the code.
    pub fn succeeded(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

/// Seconds to wait after `excess` failures beyond the free attempts: `base`,
/// doubled for each further failure, at most `max`.
fn doubling_backoff(excess: u32, base: i64, max: i64) -> i64 {
    2_i64
        .checked_pow(excess)
        .and_then(|factor| factor.checked_mul(base))
        .map_or(max, |wait| wait.min(max))
}

fn generate_code() -> String {
    let mut bytes = [0_u8; CODE_CHARS];
    rand::fill(&mut bytes);
    let raw: String = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte % 32)]))
        .collect();
    format!("{}-{}", &raw[..4], &raw[4..])
}

fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| match ch.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::FakeSealer;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _dir: tempfile::TempDir,
        setup: Setup,
        key: StoreKey,
        paths: SetupPaths,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            state_dir: dir.path().join("lib"),
            auth_dir: dir.path().join("lib/auth"),
            run_dir: dir.path().join("run/tetra"),
            issue_dir: dir.path().join("run/issue.d"),
        };
        let key = StoreKey::load_or_create(&paths.auth_dir.join("key"), &FakeSealer).unwrap();
        Fixture {
            _dir: dir,
            setup: Setup::new(paths.clone()),
            key,
            paths,
        }
    }

    #[test]
    fn the_code_is_persistent_until_setup_completes() {
        let f = fixture();
        let code = f.setup.ensure_code(&f.key, 0).unwrap().unwrap();
        assert_eq!(code.len(), 9);
        assert_eq!(f.setup.ensure_code(&f.key, 100).unwrap().unwrap(), code);
        // Stored sealed, not in plain text.
        let stored = fs::read_to_string(f.paths.auth_dir.join(CODE_FILE)).unwrap();
        assert!(!stored.contains(&code));

        f.setup
            .redeem(&f.key, &code.to_lowercase(), 1)
            .unwrap()
            .unwrap();
        f.setup.complete(Some("alice"), 2).unwrap();
        assert!(f.setup.is_complete());
        assert_eq!(f.setup.ensure_code(&f.key, 3).unwrap(), None);
        assert_eq!(
            f.setup.redeem(&f.key, &code, 4).unwrap(),
            Err(RedeemError::Complete)
        );
        assert!(!f.paths.auth_dir.join(CODE_FILE).exists());
    }

    #[test]
    fn publishes_to_the_console_and_unpublishes_on_completion() {
        let f = fixture();
        let code = f.setup.ensure_code(&f.key, 0).unwrap().unwrap();
        // `/run/tetra` holds the socket too: publishing must not restrict it.
        fs::create_dir_all(&f.paths.run_dir).unwrap();
        fs::set_permissions(&f.paths.run_dir, fs::Permissions::from_mode(0o755)).unwrap();
        f.setup.publish(&code).unwrap();
        assert_eq!(
            fs::metadata(&f.paths.run_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let banner = fs::read_to_string(f.paths.issue_dir.join(ISSUE_FILE)).unwrap();
        assert!(banner.contains(&code));
        let run = f.paths.run_dir.join(RUN_CODE_FILE);
        assert_eq!(fs::read_to_string(&run).unwrap().trim(), code);
        assert_eq!(
            fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o600
        );

        f.setup.complete(None, 1).unwrap();
        assert!(!run.exists());
        assert!(!f.paths.issue_dir.join(ISSUE_FILE).exists());
    }

    #[test]
    fn wrong_codes_back_off_then_rotate() {
        let f = fixture();
        let code = f.setup.ensure_code(&f.key, 0).unwrap().unwrap();
        let mut now = 0;
        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(
                f.setup.redeem(&f.key, "WRONG-CODE", now).unwrap(),
                Err(RedeemError::Invalid)
            );
        }
        // The free attempts are used up: even the right code must wait.
        assert_eq!(
            f.setup.redeem(&f.key, &code, now).unwrap(),
            Err(RedeemError::RateLimited { retry_after: 1 })
        );
        // Keep failing, waiting out each backoff, until the code rotates.
        let mut rotated = false;
        for _ in 0..ROTATE_AFTER {
            now += MAX_BACKOFF;
            f.setup
                .redeem(&f.key, "WRONG-CODE", now)
                .unwrap()
                .unwrap_err();
            if f.setup.ensure_code(&f.key, now).unwrap().unwrap() != code {
                rotated = true;
                break;
            }
        }
        assert!(rotated, "code was not rotated");
        now += MAX_BACKOFF;
        assert_eq!(
            f.setup.redeem(&f.key, &code, now).unwrap(),
            Err(RedeemError::Invalid)
        );
        let fresh = f.setup.ensure_code(&f.key, now).unwrap().unwrap();
        // The rotated code was published for the console.
        let banner = fs::read_to_string(f.paths.issue_dir.join(ISSUE_FILE)).unwrap();
        assert!(banner.contains(&fresh));
        now += MAX_BACKOFF;
        f.setup.redeem(&f.key, &fresh, now).unwrap().unwrap();
    }

    #[test]
    fn one_address_is_throttled_before_the_global_counter() {
        let throttle = AddressThrottle::default();
        let mut throttle = throttle.lock();
        let mut now = 0;
        for _ in 0..ADDRESS_FREE_ATTEMPTS {
            throttle.check("192.0.2.1", now).unwrap();
            throttle.failed("192.0.2.1", now);
        }
        // Waits start well before the global counter's free attempts run
        // out, and only for this address.
        assert_eq!(throttle.check("192.0.2.1", now), Err(ADDRESS_BASE_BACKOFF));
        throttle.check("192.0.2.2", now).unwrap();
        now += ADDRESS_BASE_BACKOFF;
        throttle.check("192.0.2.1", now).unwrap();
        throttle.failed("192.0.2.1", now);
        assert_eq!(
            throttle.check("192.0.2.1", now),
            Err(2 * ADDRESS_BASE_BACKOFF)
        );
        throttle.succeeded("192.0.2.1");
        throttle.check("192.0.2.1", now).unwrap();
    }

    #[test]
    fn the_throttle_forgets_the_oldest_address_when_full() {
        let throttle = AddressThrottle::default();
        let mut throttle = throttle.lock();
        for i in 0..ADDRESS_MAX_TRACKED {
            for _ in 0..=ADDRESS_FREE_ATTEMPTS {
                throttle.failed(&format!("a{i}"), i64::try_from(i).unwrap());
            }
        }
        throttle.check("a0", 0).unwrap_err();
        throttle.failed("new", 0);
        assert_eq!(throttle.entries.len(), ADDRESS_MAX_TRACKED);
        throttle.check("a0", 0).unwrap();
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        assert_eq!(doubling_backoff(0, 1, MAX_BACKOFF), 1);
        assert_eq!(doubling_backoff(3, 1, MAX_BACKOFF), 8);
        assert_eq!(doubling_backoff(30, 1, MAX_BACKOFF), MAX_BACKOFF);
        assert_eq!(doubling_backoff(u32::MAX, 1, MAX_BACKOFF), MAX_BACKOFF);
        let address = |excess| doubling_backoff(excess, ADDRESS_BASE_BACKOFF, ADDRESS_MAX_BACKOFF);
        assert_eq!(address(0), ADDRESS_BASE_BACKOFF);
        assert_eq!(address(2), 4 * ADDRESS_BASE_BACKOFF);
        assert_eq!(address(20), ADDRESS_MAX_BACKOFF);
        // 2^62 fits, times the base does not.
        assert_eq!(address(62), ADDRESS_MAX_BACKOFF);
        assert_eq!(address(u32::MAX), ADDRESS_MAX_BACKOFF);
    }
}
