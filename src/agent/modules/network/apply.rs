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

use super::{
    certs,
    paths::{read_keyfile, remove_keyfile, write_keyfile},
};
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
    /// Apply the default SELinux label to a freshly written keyfile or
    /// certificate.
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
    certs: Option<PathBuf>,
}

/// One change to apply.
#[derive(Debug, Clone)]
pub struct Change<'a> {
    pub interface: &'a str,
    pub path: &'a Path,
    pub uuid: &'a str,
    pub contents: &'a [u8],
    /// The profile's certificate directory ([`super::certs`]), pruned to
    /// what the profile on disk names once the change settles.
    pub certs: Option<&'a Path>,
    /// PEM files (in `certs`) the new keyfile names, written just before
    /// it.
    pub pem_files: &'a [certs::PemFile],
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
        self.apply_with(change, false)
    }

    /// [`apply`](Self::apply), but a profile that fails to activate is
    /// undone right away (the previous keyfile and profile come back) and
    /// the failure is returned as an error.
    ///
    /// # Errors
    /// As [`apply`](Self::apply), and when activation fails.
    pub fn apply_or_revert(&self, change: &Change<'_>) -> Result<Value> {
        self.apply_with(change, true)
    }

    fn apply_with(&self, change: &Change<'_>, revert_on_failure: bool) -> Result<Value> {
        // Held until the change is applied: certificates are only written
        // and pruned under this lock, so a rollback or confirmation settling
        // meanwhile cannot remove files a new keyfile is about to name.
        let mut pending = lock(&self.pending);
        ensure!(
            pending.is_none(),
            "another network change is awaiting confirmation; confirm it or wait for it to roll back"
        );

        let before = self.host.routable_addresses(change.interface)?;
        let mut undo = Pending {
            token: String::new(),
            interface: change.interface.to_owned(),
            path: change.path.to_path_buf(),
            uuid: change.uuid.to_owned(),
            previous: read_keyfile(change.path)?,
            previously_active: self.host.active_connection(change.interface),
            certs: change.certs.map(Path::to_path_buf),
        };

        if let Err(error) = self.store(change) {
            // The new keyfile may be in place (its relabel failed, say). Put
            // the previous one back before pruning, so the certificates the
            // still-loaded profile names are kept.
            if let Err(restore_error) = restore_keyfile(self.host.as_ref(), &undo) {
                eprintln!(
                    "failed to restore `{}` after a failed write: {restore_error:#}",
                    change.path.display()
                );
            }
            prune_certs(change.path, change.certs);
            return Err(error);
        }
        let activation = self
            .host
            .load(change.path)
            .and_then(|()| self.host.activate(change.uuid));

        if revert_on_failure && let Err(error) = activation {
            let undone = roll_back(self.host.as_ref(), &undo);
            prune_certs(change.path, change.certs);
            return Err(match undone {
                Ok(()) => error.context("activation failed; the change was undone"),
                Err(undo_error) => error.context(format!(
                    "activation failed, and undoing the change failed too ({undo_error:#})"
                )),
            });
        }

        let kept = self.wait_for_any(change.interface, &before);
        let activation_error = activation.err().map(|error| format!("{error:#}"));

        if kept.is_some() || before.is_empty() {
            prune_certs(change.path, change.certs);
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
        undo.token.clone_from(&token);
        *pending = Some(undo);
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

    /// Write `change`'s certificates and keyfile, with their default
    /// SELinux labels.
    fn store(&self, change: &Change<'_>) -> Result<()> {
        for path in certs::write(change.pem_files)? {
            self.host.relabel(&path)?;
        }
        write_keyfile(change.path, change.contents)?;
        self.host.relabel(change.path)
    }

    /// Keep the change identified by `token`, cancelling its rollback.
    ///
    /// # Errors
    /// Errs when no change with that token is pending (it was already
    /// confirmed or rolled back).
    pub fn confirm(&self, token: &str) -> Result<Value> {
        let mut pending = lock(&self.pending);
        let change = pending
            .take_if(|change| change.token == token)
            .context("no network change is awaiting confirmation with that token")?;
        prune_certs(&change.path, change.certs.as_deref());
        drop(pending);
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
            if let Some(change) = guard.take_if(|change| change.token == token) {
                eprintln!(
                    "network change to `{}` was not confirmed; rolling back",
                    change.path.display()
                );
                if let Err(error) = roll_back(host.as_ref(), &change) {
                    eprintln!(
                        "network rollback of `{}` on {} failed: {error:#}",
                        change.path.display(),
                        change.interface
                    );
                }
                prune_certs(&change.path, change.certs.as_deref());
            }
            drop(guard);
        });
    }
}

/// Put the previous keyfile back on disk (or remove the new one if there
/// was none), without telling NetworkManager.
fn restore_keyfile(host: &dyn NetworkHost, change: &Pending) -> Result<()> {
    match &change.previous {
        Some(previous) => {
            write_keyfile(&change.path, previous)?;
            host.relabel(&change.path)
        }
        None => remove_keyfile(&change.path),
    }
}

fn roll_back(host: &dyn NetworkHost, change: &Pending) -> Result<()> {
    if change.previous.is_some() {
        restore_keyfile(host, change)?;
        host.load(&change.path)?;
    } else {
        if let Err(error) = host.delete(&change.uuid) {
            eprintln!("failed to delete profile {}: {error:#}", change.uuid);
        }
        restore_keyfile(host, change)?;
    }
    // Return the interface to the profile it was running before; reloading a
    // keyfile alone does not reapply it to an active device.
    if let Some(uuid) = &change.previously_active {
        return host.activate(uuid);
    }
    // Nothing was: take the restored profile down, unless it is down
    // already (it failed to activate, say).
    if change.previous.is_some()
        && host.active_connection(&change.interface).as_deref() == Some(change.uuid.as_str())
    {
        host.deactivate(&change.uuid)?;
    }
    Ok(())
}

/// Once a change has settled, drop the certificates its profile on disk no
/// longer names. When the profile cannot be read, nothing is pruned: it
/// may still name any of them.
fn prune_certs(path: &Path, dir: Option<&Path>) {
    let Some(dir) = dir else { return };
    match read_keyfile(path) {
        Ok(keyfile) => certs::prune(dir, keyfile.as_deref()),
        Err(error) => eprintln!(
            "not pruning `{}`: failed to read `{}`: {error:#}",
            dir.display(),
            path.display()
        ),
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

/// A NetworkManager stand-in for tests, shared with the parent module's.
#[cfg(test)]
pub(super) mod fake {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// Tracks which profile is active like NetworkManager does; addresses
    /// after activation are scripted, and activations can be made to fail.
    #[derive(Default)]
    pub struct FakeHost {
        addresses: Mutex<Vec<IpAddr>>,
        after_activate: Mutex<Option<Vec<IpAddr>>>,
        active: Mutex<Option<String>>,
        calls: Mutex<Vec<String>>,
        fail_uuid: Mutex<Option<String>>,
        fail_every_activation: AtomicBool,
        fail_relabel: Mutex<Option<PathBuf>>,
    }

    impl FakeHost {
        pub fn with(addresses: &[&str], active: Option<&str>) -> Arc<Self> {
            let host = Self::default();
            *lock(&host.addresses) = addresses.iter().map(|a| a.parse().unwrap()).collect();
            *lock(&host.active) = active.map(str::to_owned);
            Arc::new(host)
        }

        pub fn after_activate(&self, addresses: &[&str]) {
            *lock(&self.after_activate) =
                Some(addresses.iter().map(|a| a.parse().unwrap()).collect());
        }

        /// Activating `uuid` fails from now on.
        pub fn fail_activation_of(&self, uuid: &str) {
            *lock(&self.fail_uuid) = Some(uuid.to_owned());
        }

        /// Relabelling `path` fails from now on.
        pub fn fail_relabel_of(&self, path: &Path) {
            *lock(&self.fail_relabel) = Some(path.to_path_buf());
        }

        pub fn fail_every_activation(&self) {
            self.fail_every_activation.store(true, Ordering::Relaxed);
        }

        pub fn calls(&self) -> Vec<String> {
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

        fn relabel(&self, path: &Path) -> Result<()> {
            ensure!(
                lock(&self.fail_relabel).as_deref() != Some(path),
                "restorecon: could not set the context of `{}`",
                path.display()
            );
            Ok(())
        }

        fn load(&self, _path: &Path) -> Result<()> {
            lock(&self.calls).push("load".to_owned());
            Ok(())
        }

        fn activate(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("up {uuid}"));
            // Like NetworkManager, activating a profile takes down the one
            // that was active, even when the new one then fails.
            *lock(&self.active) = None;
            if self.fail_every_activation.load(Ordering::Relaxed)
                || lock(&self.fail_uuid).as_deref() == Some(uuid)
            {
                bail!("Error: Connection activation failed: Secrets were required, but not provided");
            }
            *lock(&self.active) = Some(uuid.to_owned());
            let after = lock(&self.after_activate).take();
            if let Some(after) = after {
                *lock(&self.addresses) = after;
            }
            Ok(())
        }

        fn deactivate(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("down {uuid}"));
            ensure!(
                lock(&self.active).take_if(|active| active == uuid).is_some(),
                "Error: '{uuid}' is not an active connection"
            );
            Ok(())
        }

        fn delete(&self, uuid: &str) -> Result<()> {
            lock(&self.calls).push(format!("delete {uuid}"));
            lock(&self.active).take_if(|active| active == uuid);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeHost;
    use super::*;

    fn safe_apply(host: &Arc<FakeHost>, rollback_after: Duration) -> SafeApply {
        SafeApply::with_timing(
            Arc::clone(host) as Arc<dyn NetworkHost>,
            rollback_after,
            Duration::from_millis(50),
        )
    }

    fn change<'a>(interface: &'a str, path: &'a Path, uuid: &'a str, contents: &'a [u8]) -> Change<'a> {
        Change { interface, path, uuid, contents, certs: None, pem_files: &[] }
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
            .apply(&change("eth0", &path, "new", b"new"))
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
            .apply(&change("eth0", &path, "new", b"new"))
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
            .apply(&change("eth0", &path, "same", b"new"))
            .unwrap();
        assert_eq!(response["confirmation_required"], true);
        assert!(response["confirmation_token"].as_str().is_some());
        assert_eq!(fs::read(&path).unwrap(), b"new");

        // A second change is refused while this one is pending.
        apply
            .apply(&change("eth0", &path, "same", b"x"))
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
            .apply(&change("eth0", &path, "new", b"new"))
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
            .apply(&change("eth0", &path, "u", b"new"))
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
            .apply(&change("eth0", &path, "u", b"new"))
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
            .apply(&change("eth0", &path, "u", b"new"))
            .unwrap();
        let token = response["confirmation_token"].as_str().unwrap().to_owned();

        wait_until(|| lock(&apply.pending).is_none());
        apply.confirm(&token).unwrap_err();
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn a_failed_activation_is_undone_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        let host = FakeHost::with(&[], Some("ethernet"));
        host.fail_activation_of("new");
        let apply = safe_apply(&host, Duration::from_secs(60));

        let error = apply
            .apply_or_revert(&change("wlan0", &path, "new", b"new"))
            .unwrap_err();

        assert!(format!("{error:#}").contains("Secrets were required"), "{error:#}");
        assert!(!path.exists());
        assert_eq!(host.calls(), ["load", "up new", "delete new", "up ethernet"]);
        assert!(lock(&apply.pending).is_none());
    }

    #[test]
    fn a_failed_activation_restores_the_previous_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], Some("same"));
        host.fail_activation_of("same");

        let error = safe_apply(&host, Duration::from_secs(60))
            .apply_or_revert(&change("wlan0", &path, "same", b"new"))
            .unwrap_err();

        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(host.calls(), ["load", "up same", "load", "up same"]);
        // Bringing the old profile back failed too; both are reported.
        let message = format!("{error:#}");
        assert!(message.contains("undoing the change failed too"), "{message}");
        assert!(message.contains("Secrets were required"), "{message}");
    }

    /// PEM files for a TLS profile, in `dir`.
    fn pem_files(dir: &Path) -> Vec<certs::PemFile> {
        let mut settings: crate::types::Wired8021x = serde_json::from_value(serde_json::json!({
            "eap": "tls",
            "identity": "host",
            "client_cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        }))
        .unwrap();
        certs::externalize(&mut settings, dir)
    }

    #[test]
    fn a_failed_activation_of_an_inactive_profile_is_undone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let certs = dir.path().join("certs");
        let pem_files = pem_files(&certs);
        let host = FakeHost::with(&[], None);
        host.fail_activation_of("u");

        let error = safe_apply(&host, Duration::from_secs(60))
            .apply_or_revert(&Change {
                certs: Some(&certs),
                pem_files: &pem_files,
                ..change("wlan0", &path, "u", b"new")
            })
            .unwrap_err();

        // The profile never came up, so there is nothing to take down.
        let message = format!("{error:#}");
        assert!(message.contains("the change was undone"), "{message}");
        assert!(message.contains("Secrets were required"), "{message}");
        assert_eq!(host.calls(), ["load", "up u", "load"]);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(!certs.exists());
    }

    #[test]
    fn a_refused_change_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let certs = dir.path().join("certs");
        let pem_files = pem_files(&certs);
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_secs(60));
        let response = apply.apply(&change("eth0", &path, "u", b"first")).unwrap();
        assert_eq!(response["confirmation_required"], true);

        apply
            .apply(&Change {
                certs: Some(&certs),
                pem_files: &pem_files,
                ..change("eth0", &path, "u", b"second")
            })
            .unwrap_err();

        assert!(!certs.exists());
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn a_failed_write_keeps_the_previous_keyfile_and_its_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let certs = dir.path().join("certs");
        let old_certs = certs::write(&pem_files(&certs)).unwrap();
        let old = old_certs.iter().map(|cert| cert.display().to_string()).join("\n");
        fs::write(&path, &old).unwrap();
        let host = FakeHost::with(&["192.0.2.10"], Some("u"));
        host.fail_relabel_of(&path);

        let error = safe_apply(&host, Duration::from_secs(60))
            .apply(&Change { certs: Some(&certs), ..change("eth0", &path, "u", b"new") })
            .unwrap_err();

        assert!(format!("{error:#}").contains("restorecon"), "{error:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), old);
        assert!(old_certs.iter().all(|cert| cert.exists()));
        assert!(host.calls().is_empty());
    }

    #[test]
    fn certificates_are_kept_when_the_profile_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        certs::write(&pem_files(&certs)).unwrap();
        // A keyfile that is a symlink is refused, not taken as missing.
        let path = dir.path().join("eth0.nmconnection");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &path).unwrap();

        prune_certs(&path, Some(&certs));
        assert_eq!(fs::read_dir(&certs).unwrap().count(), 2);

        // With no profile at all, they go.
        fs::remove_file(&path).unwrap();
        prune_certs(&path, Some(&certs));
        assert!(!certs.exists());
    }
}
