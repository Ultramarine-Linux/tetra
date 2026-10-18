//! Safe apply for `network.configure`: write, activate, and roll back if the
//! change cut the host off.
//!
//! Before activating a new profile Tetra records the interface's routable
//! addresses (global, private IPv4, and ULA). After activation it waits
//! briefly for any of them to reappear. If none does, the change may have
//! locked a remote administrator out, so Tetra arms a rollback: unless the
//! caller sends `network.confirm` with the returned token within
//! [`ROLLBACK_AFTER`], the previous keyfile is restored (or the new one
//! removed if there was none) and the previously active profile is brought
//! back up. A caller that can still reach Tetra after the change confirms
//! it; one that cannot, gets its old network back.
//!
//! Only one change can await confirmation at a time. The pending rollback
//! lives in memory, so it does not survive a Tetra restart or reboot; after
//! either, the new profile stays in place.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;

use super::paths::{read_keyfile, remove_keyfile, write_keyfile};
use crate::prelude::*;

/// How long a change that dropped every routable address waits for
/// `network.confirm` before it is rolled back.
pub const ROLLBACK_AFTER: Duration = Duration::from_secs(60);

/// How long to wait after activation for a previous address to come back
/// (a re-acquired DHCP lease or re-added static address).
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE_POLL: Duration = Duration::from_millis(500);

/// The host operations safe apply needs, so the logic can be tested
/// without NetworkManager.
pub trait NetworkHost: Send + Sync {
    /// Routable addresses currently assigned to `interface`.
    fn routable_addresses(&self, interface: &str) -> Result<Vec<IpAddr>>;
    /// UUID of the profile active on `interface`, if any.
    fn active_connection(&self, interface: &str) -> Option<String>;
    /// Apply the default SELinux label to a freshly written keyfile.
    fn relabel(&self, path: &Path) -> Result<()>;
    /// Make NetworkManager (re)read the keyfile at `path`.
    fn load(&self, path: &Path) -> Result<()>;
    /// Activate profile `uuid`.
    fn activate(&self, uuid: &str) -> Result<()>;
    /// Deactivate profile `uuid`.
    fn deactivate(&self, uuid: &str) -> Result<()>;
    /// Remove profile `uuid` (and its keyfile) from NetworkManager.
    fn delete(&self, uuid: &str) -> Result<()>;
}

/// What a rollback needs to undo one change.
#[derive(Debug, Clone)]
struct Pending {
    token: String,
    interface: String,
    path: PathBuf,
    uuid: String,
    /// The keyfile's previous contents, or `None` if it was new.
    previous: Option<Vec<u8>>,
    /// The profile that was active on the interface before the change.
    previously_active: Option<String>,
}

/// One change to apply.
#[derive(Debug, Clone)]
pub struct Change<'a> {
    pub interface: &'a str,
    pub path: &'a Path,
    pub uuid: &'a str,
    pub contents: &'a [u8],
}

/// Applies changes and owns the (at most one) pending rollback.
pub struct SafeApply {
    host: Arc<dyn NetworkHost>,
    pending: Arc<Mutex<Option<Pending>>>,
    rollback_after: Duration,
    settle_timeout: Duration,
}

impl SafeApply {
    #[must_use]
    pub fn new(host: Arc<dyn NetworkHost>) -> Self {
        Self::with_timing(host, ROLLBACK_AFTER, SETTLE_TIMEOUT)
    }

    fn with_timing(
        host: Arc<dyn NetworkHost>,
        rollback_after: Duration,
        settle_timeout: Duration,
    ) -> Self {
        Self {
            host,
            pending: Arc::default(),
            rollback_after,
            settle_timeout,
        }
    }

    /// Write and activate `change`, arming a rollback if the interface lost
    /// every routable address it had before.
    ///
    /// # Errors
    /// Errs when another change is awaiting confirmation or the keyfile
    /// cannot be written. Activation failures do not error: they are
    /// reported in the response and covered by the rollback.
    pub fn apply(&self, change: &Change<'_>) -> Result<Value> {
        let mut pending = lock(&self.pending);
        ensure!(
            pending.is_none(),
            "another network change is awaiting confirmation; confirm it or wait for it to roll back"
        );

        let before = self.host.routable_addresses(change.interface)?;
        let previously_active = self.host.active_connection(change.interface);
        let previous = read_keyfile(change.path)?;

        write_keyfile(change.path, change.contents)?;
        self.host.relabel(change.path)?;
        let activation = self
            .host
            .load(change.path)
            .and_then(|()| self.host.activate(change.uuid));

        let kept = self.wait_for_any(change.interface, &before);
        let activation_error = activation.err().map(|error| format!("{error:#}"));

        if kept.is_some() || before.is_empty() {
            return Ok(jsonf! {
                "path": change.path,
                "applied": true,
                "activation_error": activation_error,
                "confirmation_required": false,
                "addresses_before": before,
                "addresses_after": kept.unwrap_or_default(),
            });
        }

        let token = random_token();
        *pending = Some(Pending {
            token: token.clone(),
            interface: change.interface.to_owned(),
            path: change.path.to_path_buf(),
            uuid: change.uuid.to_owned(),
            previous,
            previously_active,
        });
        drop(pending);
        self.arm_rollback(token.clone());

        Ok(jsonf! {
            "path": change.path,
            "applied": true,
            "activation_error": activation_error,
            "confirmation_required": true,
            "confirmation_token": token,
            "rollback_in_seconds": self.rollback_after.as_secs(),
            "addresses_before": before,
            "addresses_after": Vec::<IpAddr>::new(),
        })
    }

    /// Keep the change identified by `token`, cancelling its rollback.
    ///
    /// # Errors
    /// Errs when no change with that token is pending (it was already
    /// confirmed or rolled back).
    pub fn confirm(&self, token: &str) -> Result<Value> {
        let change = {
            let mut pending = lock(&self.pending);
            pending
                .take_if(|change| change.token == token)
                .context("no network change is awaiting confirmation with that token")?
        };
        Ok(jsonf! { "confirmed": true, "path": change.path })
    }

    /// Poll until any address in `before` is on `interface` again, returning
    /// the current routable addresses, or `None` on timeout.
    fn wait_for_any(&self, interface: &str, before: &[IpAddr]) -> Option<Vec<IpAddr>> {
        if before.is_empty() {
            return self.host.routable_addresses(interface).ok();
        }
        let deadline = Instant::now().checked_add(self.settle_timeout)?;
        loop {
            if let Ok(now) = self.host.routable_addresses(interface)
                && now.iter().any(|address| before.contains(address))
            {
                return Some(now);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(SETTLE_POLL.min(self.settle_timeout));
        }
    }

    fn arm_rollback(&self, token: String) {
        let host = Arc::clone(&self.host);
        let pending = Arc::clone(&self.pending);
        let delay = self.rollback_after;
        thread::spawn(move || {
            thread::sleep(delay);
            // Hold the lock for the whole rollback so a racing `confirm` or
            // `configure` sees a consistent state.
            let mut guard = lock(&pending);
            if let Some(change) = guard.take_if(|change| change.token == token)
                && let Err(error) = roll_back(host.as_ref(), &change)
            {
                eprintln!(
                    "network rollback of `{}` on {} failed: {error:#}",
                    change.path.display(),
                    change.interface
                );
            }
            drop(guard);
        });
    }
}

fn roll_back(host: &dyn NetworkHost, change: &Pending) -> Result<()> {
    eprintln!(
        "network change to `{}` was not confirmed; rolling back",
        change.path.display()
    );
    if let Some(previous) = &change.previous {
        write_keyfile(&change.path, previous)?;
        host.relabel(&change.path)?;
        host.load(&change.path)?;
    } else {
        if let Err(error) = host.delete(&change.uuid) {
            eprintln!("failed to delete profile {}: {error:#}", change.uuid);
        }
        remove_keyfile(&change.path)?;
    }
    // Return the interface to the profile it was running before; reloading a
    // keyfile alone does not reapply it to an active device.
    match &change.previously_active {
        Some(uuid) => host.activate(uuid),
        None if change.previous.is_some() => host.deactivate(&change.uuid),
        None => Ok(()),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn random_token() -> String {
    let mut value = [0_u8; 24];
    rand::rng().fill(&mut value[..]);
    URL_SAFE_NO_PAD.encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake host whose addresses after activation are scripted.
    #[derive(Default)]
    struct FakeHost {
        addresses: Mutex<Vec<IpAddr>>,
        after_activate: Mutex<Option<Vec<IpAddr>>>,
        active: Mutex<Option<String>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeHost {
        fn with(addresses: &[&str], active: Option<&str>) -> Arc<Self> {
            let host = Self::default();
            *lock(&host.addresses) = addresses.iter().map(|a| a.parse().unwrap()).collect();
            *lock(&host.active) = active.map(str::to_owned);
            Arc::new(host)
        }

        fn after_activate(&self, addresses: &[&str]) {
            *lock(&self.after_activate) =
                Some(addresses.iter().map(|a| a.parse().unwrap()).collect());
        }

        fn calls(&self) -> Vec<String> {
            lock(&self.calls).clone()
        }
    }

    impl NetworkHost for FakeHost {
        fn routable_addresses(&self, _interface: &str) -> Result<Vec<IpAddr>> {
            Ok(lock(&self.addresses).clone())
        }

        fn active_connection(&self, _interface: &str) -> Option<String> {
            lock(&self.active).clone()
        }

        fn relabel(&self, _path: &Path) -> Result<()> {
            Ok(())
        }

        fn load(&self, _path: &Path) -> Result<()> {
            lock(&self.calls).push("load".to_owned());
            Ok(())
        }

        fn activate(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("up {uuid}"));
            let after = lock(&self.after_activate).take();
            if let Some(after) = after {
                *lock(&self.addresses) = after;
            }
            Ok(())
        }

        fn deactivate(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("down {uuid}"));
            Ok(())
        }

        fn delete(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("delete {uuid}"));
            Ok(())
        }
    }

    fn safe_apply(host: &Arc<FakeHost>, rollback_after: Duration) -> SafeApply {
        SafeApply::with_timing(
            Arc::clone(host) as Arc<dyn NetworkHost>,
            rollback_after,
            Duration::from_millis(50),
        )
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
        while !condition() {
            assert!(Instant::now() < deadline, "timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn keeping_an_address_needs_no_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&["2001:db8::2"], None);
        host.after_activate(&["2001:db8::2", "192.0.2.10"]);

        let response = safe_apply(&host, Duration::from_secs(60))
            .apply(&Change { interface: "eth0", path: &path, uuid: "new", contents: b"new" })
            .unwrap();

        assert_eq!(response["confirmation_required"], false);
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn host_without_routable_addresses_needs_no_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&[], None);

        let response = safe_apply(&host, Duration::from_secs(60))
            .apply(&Change { interface: "eth0", path: &path, uuid: "new", contents: b"new" })
            .unwrap();

        assert_eq!(response["confirmation_required"], false);
    }

    #[test]
    fn losing_every_address_rolls_back_to_the_previous_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10", "2001:db8::2"], Some("same"));
        host.after_activate(&["198.51.100.4"]);
        let apply = safe_apply(&host, Duration::from_millis(100));

        let response = apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "same", contents: b"new" })
            .unwrap();
        assert_eq!(response["confirmation_required"], true);
        assert!(response["confirmation_token"].as_str().is_some());
        assert_eq!(fs::read(&path).unwrap(), b"new");

        // A second change is refused while this one is pending.
        apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "same", contents: b"x" })
            .unwrap_err();

        wait_until(|| fs::read(&path).unwrap() == b"old");
        wait_until(|| lock(&apply.pending).is_none());
        assert_eq!(host.calls(), ["load", "up same", "load", "up same"]);
    }

    #[test]
    fn rolling_back_a_new_profile_deletes_it_and_reactivates_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&["192.0.2.10"], Some("cloud-init"));
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_millis(50));

        let response = apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "new", contents: b"new" })
            .unwrap();
        assert_eq!(response["confirmation_required"], true);

        wait_until(|| !path.exists());
        wait_until(|| host.calls().len() == 4);
        assert_eq!(host.calls(), ["load", "up new", "delete new", "up cloud-init"]);
    }

    #[test]
    fn rolling_back_with_nothing_previously_active_deactivates_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_millis(20));

        apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "u", contents: b"new" })
            .unwrap();

        wait_until(|| host.calls().len() == 4);
        assert_eq!(host.calls(), ["load", "up u", "load", "down u"]);
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn confirming_keeps_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.after_activate(&["192.0.2.99"]);
        let apply = safe_apply(&host, Duration::from_millis(200));

        let response = apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "u", contents: b"new" })
            .unwrap();
        let token = response["confirmation_token"].as_str().unwrap();

        apply.confirm("wrong").unwrap_err();
        assert_eq!(apply.confirm(token).unwrap()["confirmed"], true);
        apply.confirm(token).unwrap_err();

        thread::sleep(Duration::from_millis(400));
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(host.calls(), ["load", "up u"]);
    }

    #[test]
    fn confirming_after_rollback_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_millis(20));

        let response = apply
            .apply(&Change { interface: "eth0", path: &path, uuid: "u", contents: b"new" })
            .unwrap();
        let token = response["confirmation_token"].as_str().unwrap().to_owned();

        wait_until(|| lock(&apply.pending).is_none());
        apply.confirm(&token).unwrap_err();
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }
}
