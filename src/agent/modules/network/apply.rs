//! Safe apply for `network.configure`: write, activate, and roll back if the
//! change cut the host off.
//!
//! Before activating a new profile Tetra records the interface's routable
//! addresses (global, private IPv4, and ULA) and default gateways, and asks
//! NetworkManager for a checkpoint of the interface's device
//! ([`super::checkpoint`]). After activation it waits briefly for one of
//! those addresses (and gateways) to reappear. If one does, the checkpoint
//! is destroyed and the change stays. If none does, the change may have
//! locked a remote administrator out: the checkpoint is kept, and unless the
//! caller sends `network.confirm` with the returned token within
//! [`ROLLBACK_AFTER`], NetworkManager itself restores the previously active
//! profile and deletes a profile the change added. That happens in the
//! NetworkManager daemon, so it does not depend on Tetra still running.
//!
//! Tetra then finishes the rollback: it puts the previous keyfile back byte
//! for byte (a profile that was not active is not covered by the
//! checkpoint), removes a new one NetworkManager did not, and reactivates
//! the previous profile if NetworkManager did not (it drops checkpoints
//! when it restarts). The change awaiting confirmation is recorded, root
//! only, in [`PENDING_STATE`], so after a Tetra restart `network.pending`
//! still returns its token and the rollback still completes; a change Tetra
//! was in the middle of applying when it stopped is rolled back.
//!
//! When NetworkManager cannot create a checkpoint (D-Bus is unavailable, or
//! another checkpoint already covers the device), Tetra rolls back by
//! itself, from a timer and the same state file.
//!
//! Only one change can await confirmation at a time.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

use super::{
    certs,
    paths::{read_keyfile, remove_keyfile, write_keyfile},
};
use serde_json::json;

use crate::auth::store::{self, Extra, Header, Record};
use crate::prelude::*;

/// How long a change that dropped every routable address waits for
/// `network.confirm` before it is rolled back.
pub const ROLLBACK_AFTER: Duration = Duration::from_secs(60);

/// Where the change awaiting confirmation is recorded, so it survives a
/// Tetra restart.
pub const PENDING_STATE: &str = "/var/lib/tetra/network/pending.json";

/// How long after NetworkManager's rollback Tetra finishes it, so the two
/// do not race.
const ROLLBACK_GRACE: Duration = Duration::from_secs(5);

/// How long to wait after activation for a previous address to come back
/// (a re-acquired DHCP lease or re-added static address).
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE_POLL: Duration = Duration::from_millis(500);

/// The host operations safe apply needs, so the logic can be tested
/// without NetworkManager.
pub trait NetworkHost: Send + Sync {
    /// Routable addresses currently assigned to `interface`.
    fn routable_addresses(&self, interface: &str) -> Result<Vec<IpAddr>>;
    /// Gateways of `interface`'s default routes, IPv4 and IPv6.
    fn default_gateways(&self, interface: &str) -> Result<Vec<IpAddr>>;
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
    /// Create a NetworkManager checkpoint of `interface`'s device that
    /// rolls back after `timeout` unless destroyed, and deletes profiles
    /// added meanwhile when it does. Returns its object path.
    fn checkpoint_create(&self, interface: &str, timeout: Duration) -> Result<String>;
    /// Make `checkpoint` roll back `timeout` from now instead.
    fn checkpoint_adjust(&self, checkpoint: &str, timeout: Duration) -> Result<()>;
    /// Drop `checkpoint`, keeping the current configuration.
    fn checkpoint_destroy(&self, checkpoint: &str) -> Result<()>;
    /// Roll back to `checkpoint` now, which also drops it.
    fn checkpoint_rollback(&self, checkpoint: &str) -> Result<()>;
    /// Every checkpoint NetworkManager holds.
    fn checkpoints(&self) -> Result<Vec<String>>;
}

/// How a remote administrator may be reaching an interface: its routable
/// addresses and the gateways of its default routes.
#[derive(Debug, Clone, Default)]
struct Reach {
    addresses: Vec<IpAddr>,
    gateways: Vec<IpAddr>,
}

impl Reach {
    /// Whether `now` still has one of these addresses and, if there were
    /// default routes, one of their gateways: a kept address alone does not
    /// help a remote administrator whose packets go through a gateway the
    /// change dropped (a manual profile without one, or a mistyped one).
    fn kept_in(&self, now: &Self) -> bool {
        now.addresses.iter().any(|address| self.addresses.contains(address))
            && (self.gateways.is_empty()
                || now.gateways.iter().any(|gateway| self.gateways.contains(gateway)))
    }
}

/// What a rollback needs to undo one change.
#[derive(Debug, Clone)]
struct Pending {
    token: String,
    /// When the rollback is due.
    rollback_at: Instant,
    /// The NetworkManager checkpoint that rolls the change back, or `None`
    /// when Tetra does.
    checkpoint: Option<String>,
    interface: String,
    path: PathBuf,
    uuid: String,
    /// The keyfile's previous contents, or `None` if it was new.
    previous: Option<Vec<u8>>,
    /// The profile that was active on the interface before the change.
    previously_active: Option<String>,
    certs: Option<PathBuf>,
    /// [`digest`] of the keyfile the change wrote, to tell whether
    /// NetworkManager's rollback rewrote it.
    written: String,
}

impl Pending {
    const fn rollback_by(&self) -> &'static str {
        if self.checkpoint.is_some() { "networkmanager" } else { "tetra" }
    }

    fn shown(&self) -> Value {
        json!({
            "confirmation_token": self.token,
            "interface": self.interface,
            "path": self.path,
            "rollback_in_seconds": self.rollback_at.saturating_duration_since(Instant::now()).as_secs(),
            "rollback_by": self.rollback_by(),
            "checkpoint": self.checkpoint,
        })
    }
}

/// [`Pending`] as stored in [`PENDING_STATE`] (`0600`, root only). It holds
/// the previous keyfile, secrets included, as the keyfile itself does.
#[derive(Debug, Serialize, Deserialize)]
struct Saved {
    #[serde(flatten)]
    header: Header,
    token: String,
    /// Unix time, in seconds, the rollback is due.
    rollback_at: u64,
    #[serde(default)]
    checkpoint: Option<String>,
    interface: String,
    path: PathBuf,
    uuid: String,
    /// The previous keyfile, base64-encoded.
    #[serde(default)]
    previous: Option<String>,
    #[serde(default)]
    previously_active: Option<String>,
    #[serde(default)]
    certs: Option<PathBuf>,
    written: String,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for Saved {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl From<&Pending> for Saved {
    fn from(change: &Pending) -> Self {
        let remaining = change.rollback_at.saturating_duration_since(Instant::now());
        Self {
            header: Header::default(),
            token: change.token.clone(),
            rollback_at: unix_now().saturating_add(remaining.as_secs()),
            checkpoint: change.checkpoint.clone(),
            interface: change.interface.clone(),
            path: change.path.clone(),
            uuid: change.uuid.clone(),
            previous: change.previous.as_ref().map(|previous| STANDARD.encode(previous)),
            previously_active: change.previously_active.clone(),
            certs: change.certs.clone(),
            written: change.written.clone(),
            extra: Extra::new(),
        }
    }
}

impl TryFrom<Saved> for Pending {
    type Error = anyhow::Error;

    fn try_from(saved: Saved) -> Result<Self> {
        let remaining = Duration::from_secs(saved.rollback_at.saturating_sub(unix_now()));
        Ok(Self {
            token: saved.token,
            rollback_at: Instant::now().checked_add(remaining).unwrap_or_else(Instant::now),
            checkpoint: saved.checkpoint,
            interface: saved.interface,
            path: saved.path,
            uuid: saved.uuid,
            previous: saved
                .previous
                .map(|previous| STANDARD.decode(previous))
                .transpose()
                .context("the previous keyfile is not valid base64")?,
            previously_active: saved.previously_active,
            certs: saved.certs,
            written: saved.written,
        })
    }
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

/// What the rollback timer shares with [`SafeApply`].
struct Shared {
    host: Arc<dyn NetworkHost>,
    pending: Mutex<Option<Pending>>,
    /// The state file ([`PENDING_STATE`] outside tests).
    state: PathBuf,
}

impl Shared {
    /// Record `change` in the state file. A failure only costs the
    /// recovery after a restart, so it is logged rather than returned.
    fn save(&self, change: &Pending) {
        if let Err(error) = store::write(&self.state, &mut Saved::from(change)) {
            eprintln!(
                "warning: failed to record the pending network change in `{}`; a Tetra restart \
                 will lose its token: {error:#}",
                self.state.display()
            );
        }
    }

    /// Remove the state file: the change settled.
    fn forget(&self) {
        if let Err(error) = store::remove(&self.state) {
            eprintln!("failed to remove `{}`: {error:#}", self.state.display());
        }
    }

    /// The change recorded in the state file, if any. One that cannot be
    /// read is logged and removed: NetworkManager still holds its
    /// checkpoint, if it had one.
    fn load(&self) -> Option<Pending> {
        let loaded = store::read::<Saved>(&self.state).and_then(|saved| saved.map(Pending::try_from).transpose());
        loaded.unwrap_or_else(|error| {
            eprintln!(
                "discarding the pending network change in `{}`: {error:#}",
                self.state.display()
            );
            self.forget();
            None
        })
    }

    /// Undo `change` (see [`roll_back`]), then prune its certificates and
    /// forget it, whether or not undoing it worked: a stale record would
    /// roll back a later change after a restart.
    fn roll_back(&self, change: &Pending) -> Result<()> {
        let result = roll_back(self.host.as_ref(), change);
        prune_certs(&change.path, change.certs.as_deref());
        self.forget();
        result
    }
}

/// Applies changes and owns the (at most one) pending rollback.
pub struct SafeApply {
    shared: Arc<Shared>,
    /// Whether the state file was read: on first use rather than on
    /// construction, which must not touch the host.
    recovered: AtomicBool,
    rollback_after: Duration,
    settle_timeout: Duration,
    grace: Duration,
}

impl SafeApply {
    /// Safe apply on `host`, recording pending changes in
    /// [`PENDING_STATE`].
    #[must_use]
    pub fn new(host: Arc<dyn NetworkHost>) -> Self {
        Self::with_state(host, PathBuf::from(PENDING_STATE))
    }

    /// Safe apply on `host`, recording pending changes in `state`.
    #[must_use]
    pub fn with_state(host: Arc<dyn NetworkHost>, state: PathBuf) -> Self {
        Self::with_timing(host, state, ROLLBACK_AFTER, SETTLE_TIMEOUT, ROLLBACK_GRACE)
    }

    fn with_timing(
        host: Arc<dyn NetworkHost>,
        state: PathBuf,
        rollback_after: Duration,
        settle_timeout: Duration,
        grace: Duration,
    ) -> Self {
        Self {
            shared: Arc::new(Shared { host, pending: Mutex::default(), state }),
            recovered: AtomicBool::new(false),
            rollback_after,
            settle_timeout,
            grace,
        }
    }

    fn host(&self) -> &dyn NetworkHost {
        self.shared.host.as_ref()
    }

    /// Lock the pending change, first picking up one a previous Tetra
    /// recorded: its rollback timer is armed again, and a change whose
    /// time is up is rolled back right away.
    fn lock_pending(&self) -> MutexGuard<'_, Option<Pending>> {
        let mut pending = lock(&self.shared.pending);
        if !self.recovered.swap(true, Ordering::AcqRel)
            && pending.is_none()
            && let Some(change) = self.shared.load()
        {
            eprintln!(
                "recovered the network change to `{}` awaiting confirmation",
                change.path.display()
            );
            self.arm_rollback(change.token.clone(), self.timer_delay(&change));
            *pending = Some(change);
        }
        pending
    }

    /// Recover a change a previous Tetra left awaiting confirmation (see
    /// [`lock_pending`](Self::lock_pending)). Meant for startup; every other
    /// method does this too.
    pub fn recover(&self) {
        drop(self.lock_pending());
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
        let mut pending = self.lock_pending();
        ensure!(
            pending.is_none(),
            "another network change is awaiting confirmation; confirm it or wait for it to roll back"
        );

        let before = self.reach(change.interface)?;
        let mut undo = Pending {
            token: random_token(),
            rollback_at: after(self.rollback_after),
            checkpoint: None,
            interface: change.interface.to_owned(),
            path: change.path.to_path_buf(),
            uuid: change.uuid.to_owned(),
            previous: read_keyfile(change.path)?,
            previously_active: self.host().active_connection(change.interface),
            certs: change.certs.map(Path::to_path_buf),
            written: digest(change.contents),
        };

        let created = Instant::now();
        self.arm_checkpoint(&mut undo);

        if let Err(error) = self.store(change) {
            // The new keyfile may be in place (its relabel failed, say). Put
            // the previous one back before pruning, so the certificates the
            // still-loaded profile names are kept.
            if let Err(restore_error) = restore_keyfile(self.host(), &undo) {
                eprintln!(
                    "failed to restore `{}` after a failed write: {restore_error:#}",
                    change.path.display()
                );
            }
            prune_certs(change.path, change.certs);
            // Nothing was loaded, so there is nothing to roll back.
            self.discard_checkpoint(&undo);
            self.shared.forget();
            return Err(error);
        }
        let activation = self
            .host()
            .load(change.path)
            .and_then(|()| self.host().activate(change.uuid));

        let kept = if revert_on_failure && activation.is_err() {
            None
        } else {
            self.wait_for_any(change.interface, &before)
        };
        let cut_off = kept.is_none() && !before.addresses.is_empty();

        // A profile that failed to activate and cut the host off has nothing
        // to confirm: undo it now rather than after `rollback_after`.
        if (revert_on_failure || cut_off)
            && let Err(error) = activation
        {
            let undone = self.shared.roll_back(&undo);
            return Err(match undone {
                Ok(()) => error.context("activation failed; the change was undone"),
                Err(undo_error) => error.context(format!(
                    "activation failed, and undoing the change failed too ({undo_error:#})"
                )),
            });
        }
        let activation_error = activation.err().map(|error| format!("{error:#}"));
        let after_change = kept.unwrap_or_default();

        if !cut_off && self.commit(&undo, created)? {
            self.shared.forget();
            prune_certs(change.path, change.certs);
            return Ok(json!({
                "path": change.path,
                "applied": true,
                "activation_error": activation_error,
                "confirmation_required": false,
                "addresses_before": before.addresses,
                "addresses_after": after_change.addresses,
                "gateways_before": before.gateways,
                "gateways_after": after_change.gateways,
            }));
        }

        // Give the caller the full time to confirm, counted from now.
        undo.rollback_at = after(self.rollback_after);
        if let Some(checkpoint) = &undo.checkpoint
            && let Err(error) = self.host().checkpoint_adjust(checkpoint, self.rollback_after)
        {
            eprintln!("failed to extend NetworkManager checkpoint {checkpoint}: {error:#}");
            undo.rollback_at = created.checked_add(self.rollback_after).unwrap_or(undo.rollback_at);
        }
        self.shared.save(&undo);
        let response = json!({
            "path": change.path,
            "applied": true,
            "activation_error": activation_error,
            "confirmation_required": true,
            "confirmation_token": undo.token,
            "rollback_in_seconds": undo.rollback_at.saturating_duration_since(Instant::now()).as_secs(),
            "rollback_by": undo.rollback_by(),
            "checkpoint": undo.checkpoint,
            "addresses_before": before.addresses,
            "addresses_after": after_change.addresses,
            "gateways_before": before.gateways,
            "gateways_after": after_change.gateways,
        });
        self.arm_rollback(undo.token.clone(), self.timer_delay(&undo));
        *pending = Some(undo);
        drop(pending);
        crate::agent::websocket::NETWORK_CHANGED.notify_one();
        Ok(response)
    }

    /// Arm NetworkManager's own rollback of `change` before anything
    /// changes, and record it: if Tetra dies from here on, NetworkManager
    /// still undoes the change, and the next Tetra finishes that. Applying
    /// takes well under `rollback_after` (activation waits 30 seconds at
    /// most, settling 10), and a change that needs confirmation gets the
    /// full time again once applied.
    fn arm_checkpoint(&self, change: &mut Pending) {
        match self.host().checkpoint_create(&change.interface, self.rollback_after) {
            Ok(checkpoint) => change.checkpoint = Some(checkpoint),
            Err(error) => eprintln!(
                "warning: no NetworkManager checkpoint for {} ({error:#}); Tetra will roll the \
                 change back by itself if needed, which a NetworkManager or Tetra failure can \
                 interrupt",
                change.interface
            ),
        }
        self.shared.save(change);
    }

    /// Keep a change that did not cut the host off by destroying its
    /// checkpoint. `Ok(false)` when the checkpoint could not be destroyed
    /// and may still roll the change back, so it needs confirmation after
    /// all.
    ///
    /// # Errors
    /// Errs, after finishing the rollback, when NetworkManager already
    /// rolled the change back (applying it outlasted the checkpoint).
    fn commit(&self, change: &Pending, created: Instant) -> Result<bool> {
        let Some(checkpoint) = &change.checkpoint else { return Ok(true) };
        let Err(error) = self.host().checkpoint_destroy(checkpoint) else { return Ok(true) };
        if !self.checkpoint_gone(checkpoint) {
            eprintln!(
                "failed to destroy NetworkManager checkpoint {checkpoint}; the change needs \
                 confirmation: {error:#}"
            );
            return Ok(false);
        }
        if created.elapsed() < self.rollback_after {
            // NetworkManager restarted, or another tool destroyed it: nothing
            // will roll the change back.
            eprintln!("NetworkManager checkpoint {checkpoint} is gone; keeping the change");
            return Ok(true);
        }
        let undone = self.shared.roll_back(change);
        let error = error.context("NetworkManager rolled the change back before it settled");
        Err(match undone {
            Ok(()) => error,
            Err(undo_error) => error.context(format!("and undoing it failed ({undo_error:#})")),
        })
    }

    /// Whether NetworkManager no longer holds `checkpoint` (it rolled back,
    /// was destroyed, or NetworkManager restarted). `false` when that
    /// cannot be told.
    fn checkpoint_gone(&self, checkpoint: &str) -> bool {
        self.host()
            .checkpoints()
            .is_ok_and(|checkpoints| !checkpoints.iter().any(|held| held == checkpoint))
    }

    /// Drop `change`'s checkpoint, if it has one, without rolling back.
    fn discard_checkpoint(&self, change: &Pending) {
        if let Some(checkpoint) = &change.checkpoint
            && let Err(error) = self.host().checkpoint_destroy(checkpoint)
        {
            eprintln!("failed to destroy NetworkManager checkpoint {checkpoint}: {error:#}");
        }
    }

    fn reach(&self, interface: &str) -> Result<Reach> {
        Ok(Reach {
            addresses: self.host().routable_addresses(interface)?,
            gateways: self.host().default_gateways(interface)?,
        })
    }

    /// The change awaiting confirmation, if any, with its token: the
    /// response that carried the token is often lost, since the change cut
    /// the connection it was sent on.
    #[must_use]
    pub fn pending(&self) -> Value {
        json!({ "pending": self.lock_pending().as_ref().map(Pending::shown) })
    }

    /// Write `change`'s certificates and keyfile, with their default
    /// SELinux labels.
    fn store(&self, change: &Change<'_>) -> Result<()> {
        for path in certs::write(change.pem_files)? {
            self.host().relabel(&path)?;
        }
        write_keyfile(change.path, change.contents)?;
        self.host().relabel(change.path)
    }

    /// Refuse to edit `path` behind a pending change's back: its rollback
    /// would overwrite the edit with the keyfile from before that change.
    ///
    /// # Errors
    /// Errs when a change to `path` awaits confirmation.
    pub fn ensure_settled(&self, path: &Path) -> Result<()> {
        ensure!(
            self.lock_pending().as_ref().is_none_or(|change| change.path != path),
            "`{}` has a network change awaiting confirmation; confirm it or wait for it to roll back",
            path.display()
        );
        Ok(())
    }

    /// Keep the change identified by `token`, cancelling its rollback.
    ///
    /// # Errors
    /// Errs when no change with that token is pending (it was already
    /// confirmed or rolled back), when NetworkManager rolled it back just
    /// now, or when its checkpoint cannot be destroyed (the change then
    /// stays pending).
    pub fn confirm(&self, token: &str) -> Result<Value> {
        let mut pending = self.lock_pending();
        let change = pending
            .take_if(|change| change.token == token)
            .context("no network change is awaiting confirmation with that token")?;
        if let Some(checkpoint) = change.checkpoint.clone()
            && let Err(error) = self.host().checkpoint_destroy(&checkpoint)
        {
            if !self.checkpoint_gone(&checkpoint) {
                *pending = Some(change);
                return Err(error.context(
                    "could not keep the network change: NetworkManager still holds its checkpoint",
                ));
            }
            if Instant::now() >= change.rollback_at {
                // Too late: NetworkManager rolled it back; finish that now
                // rather than when the timer fires.
                if let Err(undo_error) = self.shared.roll_back(&change) {
                    eprintln!(
                        "network rollback of `{}` on {} failed: {undo_error:#}",
                        change.path.display(),
                        change.interface
                    );
                }
                drop(pending);
                bail!("the network change was already rolled back");
            }
            // Gone before its time: NetworkManager restarted, so nothing
            // rolls the change back any more.
            eprintln!("NetworkManager checkpoint {checkpoint} is gone; keeping the change");
        }
        self.shared.forget();
        prune_certs(&change.path, change.certs.as_deref());
        drop(pending);
        Ok(json!({ "confirmed": true, "path": change.path }))
    }

    /// Poll until `interface` is reachable as in `before` again
    /// ([`Reach::kept_in`]), returning how, or `None` on timeout.
    fn wait_for_any(&self, interface: &str, before: &Reach) -> Option<Reach> {
        if before.addresses.is_empty() {
            return self.reach(interface).ok();
        }
        let deadline = Instant::now().checked_add(self.settle_timeout)?;
        loop {
            if let Ok(now) = self.reach(interface)
                && before.kept_in(&now)
            {
                return Some(now);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(SETTLE_POLL.min(self.settle_timeout));
        }
    }

    /// When Tetra's timer for `change` fires: at its deadline, or a little
    /// later when NetworkManager rolls it back, to finish that.
    fn timer_delay(&self, change: &Pending) -> Duration {
        let remaining = change.rollback_at.saturating_duration_since(Instant::now());
        if change.checkpoint.is_some() { remaining.saturating_add(self.grace) } else { remaining }
    }

    fn arm_rollback(&self, token: String, delay: Duration) {
        let shared = Arc::clone(&self.shared);
        thread::spawn(move || {
            thread::sleep(delay);
            // Hold the lock for the whole rollback so a racing `confirm` or
            // `configure` sees a consistent state.
            let mut guard = lock(&shared.pending);
            if let Some(change) = guard.take_if(|change| change.token == token) {
                eprintln!(
                    "network change to `{}` was not confirmed; rolling back",
                    change.path.display()
                );
                if let Err(error) = shared.roll_back(&change) {
                    eprintln!(
                        "network rollback of `{}` on {} failed: {error:#}",
                        change.path.display(),
                        change.interface
                    );
                }
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

/// Undo `change`: roll back its checkpoint, if NetworkManager still holds
/// it, then [`finish_rollback`].
fn roll_back(host: &dyn NetworkHost, change: &Pending) -> Result<()> {
    if let Some(checkpoint) = &change.checkpoint
        && let Err(error) = host.checkpoint_rollback(checkpoint)
    {
        // Usually because NetworkManager rolled it back at its deadline
        // already, or dropped it when it restarted.
        eprintln!(
            "NetworkManager checkpoint {checkpoint} was not rolled back ({error:#}); restoring \
             the previous profile directly"
        );
    }
    finish_rollback(host, change)
}

/// Bring back what `change` replaced, as far as NetworkManager has not:
/// its checkpoint restores (on disk too) and reactivates the profile that
/// was active on the device, and deletes a profile the change added, but
/// not a changed profile that was not active, and none of it when
/// NetworkManager restarted in between or there was no checkpoint.
fn finish_rollback(host: &dyn NetworkHost, change: &Pending) -> Result<()> {
    let on_disk = read_keyfile(&change.path)?;
    // NetworkManager rewrites a profile it restores, so the change's own
    // keyfile still being there means it was not restored.
    let untouched = on_disk.as_deref().is_some_and(|keyfile| digest(keyfile) == change.written);
    match &change.previous {
        // Byte for byte, so the certificates it names are kept when pruning.
        Some(previous) if on_disk.as_ref() != Some(previous) => {
            restore_keyfile(host, change)?;
            // When another profile was active, bring it back even if
            // reloading this one failed; re-upping this one would reapply
            // the broken in-memory settings, so then the error stands.
            if let Err(error) = host.load(&change.path) {
                match &change.previously_active {
                    Some(uuid) if *uuid != change.uuid => {
                        eprintln!("failed to reload `{}`: {error:#}", change.path.display());
                    }
                    _ => return Err(error),
                }
            }
        }
        None if on_disk.is_some() => {
            if let Err(error) = host.delete(&change.uuid) {
                eprintln!("failed to delete profile {}: {error:#}", change.uuid);
            }
            restore_keyfile(host, change)?;
        }
        _ => {}
    }
    let active = host.active_connection(&change.interface);
    match &change.previously_active {
        // Return the interface to the profile it was running before; reloading
        // a keyfile alone does not reapply it to an active device.
        Some(uuid) => {
            if active.as_ref() != Some(uuid) || (untouched && *uuid == change.uuid) {
                host.activate(uuid)?;
            }
        }
        // Nothing was: take the restored profile down, unless it is down
        // already (it failed to activate, say).
        None => {
            if active.as_deref() == Some(change.uuid.as_str()) {
                host.deactivate(&change.uuid)?;
            }
        }
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

/// SHA-256 of a keyfile, base64-encoded.
fn digest(keyfile: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(keyfile))
}

/// `duration` from now.
fn after(duration: Duration) -> Instant {
    Instant::now().checked_add(duration).unwrap_or_else(Instant::now)
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// A NetworkManager stand-in for tests, shared with the parent module's.
#[cfg(test)]
pub(super) mod fake {
    use std::sync::atomic::AtomicBool;

    use super::*;

    /// What a checkpoint restores: the device's profile and, since that
    /// brings back its addresses and routes, those.
    struct Checkpoint {
        path: String,
        active: Option<String>,
        addresses: Vec<IpAddr>,
        gateways: Vec<IpAddr>,
    }

    /// Tracks which profile is active like NetworkManager does; addresses
    /// after activation are scripted, and activations can be made to fail.
    /// Checkpoints restore the active profile, addresses and gateways, and
    /// whatever keyfile writes a test scripts with
    /// [`FakeHost::rollback_writes`].
    #[derive(Default)]
    pub struct FakeHost {
        addresses: Mutex<Vec<IpAddr>>,
        after_activate: Mutex<Option<Vec<IpAddr>>>,
        gateways: Mutex<Vec<IpAddr>>,
        gateways_after_activate: Mutex<Option<Vec<IpAddr>>>,
        active: Mutex<Option<String>>,
        calls: Mutex<Vec<String>>,
        fail_uuid: Mutex<Option<String>>,
        fail_every_activation: AtomicBool,
        fail_relabel: Mutex<Option<PathBuf>>,
        checkpoints: Mutex<Vec<Checkpoint>>,
        created: std::sync::atomic::AtomicUsize,
        checkpoint_calls: Mutex<Vec<String>>,
        no_checkpoints: AtomicBool,
        rollback_writes: Mutex<Vec<(PathBuf, Option<Vec<u8>>)>>,
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

        /// Default route gateways now, and after the next activation.
        pub fn gateways(&self, now: &[&str], after_activate: &[&str]) {
            *lock(&self.gateways) = now.iter().map(|a| a.parse().unwrap()).collect();
            *lock(&self.gateways_after_activate) =
                Some(after_activate.iter().map(|a| a.parse().unwrap()).collect());
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

        /// Creating checkpoints fails from now on, as on a host without
        /// NetworkManager's D-Bus API.
        pub fn without_checkpoints(&self) {
            self.no_checkpoints.store(true, Ordering::Relaxed);
        }

        /// A rollback writes `contents` to `path`, or removes it: how
        /// NetworkManager restores a profile, or deletes a new one.
        pub fn rollback_writes(&self, path: &Path, contents: Option<&[u8]>) {
            lock(&self.rollback_writes).push((path.to_path_buf(), contents.map(<[u8]>::to_vec)));
        }

        /// NetworkManager's timeouts fire: every checkpoint rolls back.
        pub fn expire_checkpoints(&self) {
            let paths: Vec<_> = lock(&self.checkpoints).iter().map(|cp| cp.path.clone()).collect();
            for path in paths {
                // Tetra's timer may have rolled it back meanwhile.
                self.restore(&path).ok();
            }
        }

        /// NetworkManager restarts, dropping every checkpoint.
        pub fn restart(&self) {
            lock(&self.checkpoints).clear();
        }

        pub fn calls(&self) -> Vec<String> {
            lock(&self.calls).clone()
        }

        /// Checkpoint operations, as `create`, `adjust`, `destroy` and
        /// `rollback`.
        pub fn checkpoint_calls(&self) -> Vec<String> {
            lock(&self.checkpoint_calls).clone()
        }

        pub fn held_checkpoints(&self) -> usize {
            lock(&self.checkpoints).len()
        }

        fn take(&self, checkpoint: &str) -> Result<Checkpoint> {
            let mut checkpoints = lock(&self.checkpoints);
            let index = checkpoints
                .iter()
                .position(|cp| cp.path == checkpoint)
                .with_context(|| format!("checkpoint {checkpoint} does not exist"))?;
            Ok(checkpoints.remove(index))
        }

        fn restore(&self, checkpoint: &str) -> Result<()> {
            let checkpoint = self.take(checkpoint)?;
            *lock(&self.active) = checkpoint.active;
            *lock(&self.addresses) = checkpoint.addresses;
            *lock(&self.gateways) = checkpoint.gateways;
            let writes = std::mem::take(&mut *lock(&self.rollback_writes));
            for (path, contents) in writes {
                match contents {
                    Some(contents) => fs::write(&path, contents)?,
                    None => fs::remove_file(&path)?,
                }
            }
            Ok(())
        }
    }

    impl NetworkHost for FakeHost {
        fn routable_addresses(&self, _interface: &str) -> Result<Vec<IpAddr>> {
            Ok(lock(&self.addresses).clone())
        }

        fn default_gateways(&self, _interface: &str) -> Result<Vec<IpAddr>> {
            Ok(lock(&self.gateways).clone())
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
            // Scripted addresses change either way: the old profile went down.
            let after = lock(&self.after_activate).take();
            if let Some(after) = after {
                *lock(&self.addresses) = after;
            }
            let gateways = lock(&self.gateways_after_activate).take();
            if let Some(gateways) = gateways {
                *lock(&self.gateways) = gateways;
            }
            if self.fail_every_activation.load(Ordering::Relaxed)
                || lock(&self.fail_uuid).as_deref() == Some(uuid)
            {
                bail!("Error: Connection activation failed: Secrets were required, but not provided");
            }
            *lock(&self.active) = Some(uuid.to_owned());
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

        fn checkpoint_create(&self, _interface: &str, _timeout: Duration) -> Result<String> {
            ensure!(
                !self.no_checkpoints.load(Ordering::Relaxed),
                "`busctl` failed: Unknown method CheckpointCreate"
            );
            lock(&self.checkpoint_calls).push("create".to_owned());
            let id = self.created.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            let path = format!("/org/freedesktop/NetworkManager/Checkpoint/{id}");
            lock(&self.checkpoints).push(Checkpoint {
                path: path.clone(),
                active: lock(&self.active).clone(),
                addresses: lock(&self.addresses).clone(),
                gateways: lock(&self.gateways).clone(),
            });
            Ok(path)
        }

        fn checkpoint_adjust(&self, checkpoint: &str, _timeout: Duration) -> Result<()> {
            lock(&self.checkpoint_calls).push("adjust".to_owned());
            ensure!(
                lock(&self.checkpoints).iter().any(|cp| cp.path == checkpoint),
                "checkpoint {checkpoint} does not exist"
            );
            Ok(())
        }

        fn checkpoint_destroy(&self, checkpoint: &str) -> Result<()> {
            lock(&self.checkpoint_calls).push("destroy".to_owned());
            self.take(checkpoint).map(drop)
        }

        fn checkpoint_rollback(&self, checkpoint: &str) -> Result<()> {
            lock(&self.checkpoint_calls).push("rollback".to_owned());
            self.restore(checkpoint)
        }

        fn checkpoints(&self) -> Result<Vec<String>> {
            Ok(lock(&self.checkpoints).iter().map(|cp| cp.path.clone()).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeHost;
    use super::*;

    /// Where tests in `dir` keep the pending change.
    fn state(dir: &Path) -> PathBuf {
        dir.join("state/pending.json")
    }

    fn safe_apply(host: &Arc<FakeHost>, rollback_after: Duration, dir: &Path) -> SafeApply {
        SafeApply::with_timing(
            Arc::clone(host) as Arc<dyn NetworkHost>,
            state(dir),
            rollback_after,
            Duration::from_millis(50),
            Duration::ZERO,
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

        let response = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&change("eth0", &path, "new", b"new"))
            .unwrap();

        assert_eq!(response["confirmation_required"], false);
        assert_eq!(fs::read(&path).unwrap(), b"new");
        // The checkpoint was destroyed, so NetworkManager keeps the change.
        assert_eq!(host.checkpoint_calls(), ["create", "destroy"]);
        assert_eq!(host.held_checkpoints(), 0);
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn host_without_routable_addresses_needs_no_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&[], None);

        let response = safe_apply(&host, Duration::from_secs(60), dir.path())
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
        host.without_checkpoints();
        host.after_activate(&["198.51.100.4"]);
        let apply = safe_apply(&host, Duration::from_millis(100), dir.path());

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
        wait_until(|| lock(&apply.shared.pending).is_none());
        assert_eq!(host.calls(), ["load", "up same", "load", "up same"]);
    }

    #[test]
    fn rolling_back_a_new_profile_deletes_it_and_reactivates_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&["192.0.2.10"], Some("cloud-init"));
        host.without_checkpoints();
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_millis(50), dir.path());

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
        host.without_checkpoints();
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_millis(20), dir.path());

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
        let apply = safe_apply(&host, Duration::from_millis(200), dir.path());

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
        let apply = safe_apply(&host, Duration::from_millis(20), dir.path());

        let response = apply
            .apply(&change("eth0", &path, "u", b"new"))
            .unwrap();
        let token = response["confirmation_token"].as_str().unwrap().to_owned();

        wait_until(|| lock(&apply.shared.pending).is_none());
        apply.confirm(&token).unwrap_err();
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn a_failed_activation_is_undone_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        let host = FakeHost::with(&[], Some("ethernet"));
        host.without_checkpoints();
        host.fail_activation_of("new");
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());

        let error = apply
            .apply_or_revert(&change("wlan0", &path, "new", b"new"))
            .unwrap_err();

        assert!(format!("{error:#}").contains("Secrets were required"), "{error:#}");
        assert!(!path.exists());
        assert_eq!(host.calls(), ["load", "up new", "delete new", "up ethernet"]);
        assert!(lock(&apply.shared.pending).is_none());
    }

    #[test]
    fn a_failed_activation_restores_the_previous_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], Some("same"));
        host.fail_activation_of("same");

        let error = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply_or_revert(&change("wlan0", &path, "same", b"new"))
            .unwrap_err();

        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(host.calls(), ["load", "up same", "load", "up same"]);
        // Bringing the old profile back failed too; both are reported.
        let message = format!("{error:#}");
        assert!(message.contains("undoing the change failed too"), "{message}");
        assert!(message.contains("Secrets were required"), "{message}");
    }

    #[test]
    fn losing_the_default_gateway_needs_confirmation() {
        // Same static address, but the gateway is gone (or mistyped).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.gateways(&["192.0.2.1"], &[]);
        host.after_activate(&["192.0.2.10"]);
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());

        let response = apply.apply(&change("eth0", &path, "u", b"new")).unwrap();

        assert_eq!(response["confirmation_required"], true);
        let token = response["confirmation_token"].as_str().unwrap();
        // The token can be recovered when the response is lost.
        let pending = apply.pending();
        assert_eq!(pending["pending"]["confirmation_token"], token);
        assert!(pending["pending"]["rollback_in_seconds"].as_u64().unwrap() <= 60);
        apply.confirm(token).unwrap();
        assert!(apply.pending()["pending"].is_null());
    }

    #[test]
    fn keeping_an_address_and_a_gateway_needs_no_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        let host = FakeHost::with(&["192.0.2.10"], None);
        host.gateways(&["192.0.2.1", "fe80::1"], &["fe80::1"]);
        host.after_activate(&["192.0.2.10"]);

        let response = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&change("eth0", &path, "u", b"new"))
            .unwrap();

        assert_eq!(response["confirmation_required"], false);
        assert_eq!(response["gateways_after"], serde_json::json!(["fe80::1"]));
    }

    #[test]
    fn a_failed_activation_that_cuts_the_host_off_is_undone_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], Some("u"));
        host.fail_activation_of("u");
        host.after_activate(&[]);
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());

        let error = apply.apply(&change("eth0", &path, "u", b"new")).unwrap_err();

        assert!(format!("{error:#}").contains("Secrets were required"), "{error:#}");
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(lock(&apply.shared.pending).is_none());
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

        let error = safe_apply(&host, Duration::from_secs(60), dir.path())
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
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());
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

        let error = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&Change { certs: Some(&certs), ..change("eth0", &path, "u", b"new") })
            .unwrap_err();

        assert!(format!("{error:#}").contains("restorecon"), "{error:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), old);
        assert!(old_certs.iter().all(|cert| cert.exists()));
        assert!(host.calls().is_empty());
        assert_eq!(host.checkpoint_calls(), ["create", "destroy"]);
        assert!(!state(dir.path()).exists());
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

    /// A change to profile `same`, active on eth0, that cuts the host off.
    fn cut_off(dir: &Path) -> (PathBuf, Arc<FakeHost>) {
        let path = dir.join("eth0.nmconnection");
        fs::write(&path, b"old").unwrap();
        let host = FakeHost::with(&["192.0.2.10"], Some("same"));
        host.after_activate(&["198.51.100.4"]);
        (path, host)
    }

    #[test]
    fn a_lost_change_keeps_its_checkpoint_until_confirmed() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());

        let response = apply.apply(&change("eth0", &path, "same", b"new")).unwrap();

        assert_eq!(response["confirmation_required"], true);
        assert_eq!(response["rollback_by"], "networkmanager");
        assert_eq!(response["checkpoint"], "/org/freedesktop/NetworkManager/Checkpoint/1");
        assert_eq!(host.checkpoint_calls(), ["create", "adjust"]);
        assert_eq!(host.held_checkpoints(), 1);
        let state = state(dir.path());
        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
        let saved: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(saved["token"], response["confirmation_token"]);
        assert_eq!(saved["checkpoint"], response["checkpoint"]);

        apply.confirm(response["confirmation_token"].as_str().unwrap()).unwrap();

        assert_eq!(host.checkpoint_calls(), ["create", "adjust", "destroy"]);
        assert_eq!(host.held_checkpoints(), 0);
        assert!(!state.exists());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(host.calls(), ["load", "up same"]);
    }

    #[test]
    fn tetra_finishes_networkmanagers_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        // NetworkManager writes the restored profile in its own format.
        host.rollback_writes(&path, Some(b"old, as NetworkManager writes it"));
        let apply = safe_apply(&host, Duration::from_millis(100), dir.path());

        let response = apply.apply(&change("eth0", &path, "same", b"new")).unwrap();
        assert_eq!(response["confirmation_required"], true);
        // NetworkManager's timeout fires, then Tetra's.
        host.expire_checkpoints();
        assert_eq!(host.active_connection("eth0").as_deref(), Some("same"));
        wait_until(|| lock(&apply.shared.pending).is_none());

        // The keyfile is back byte for byte; NetworkManager already
        // reactivated the profile, so Tetra only reloads it.
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(host.calls(), ["load", "up same", "load"]);
        assert_eq!(host.checkpoint_calls(), ["create", "adjust", "rollback"]);
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn a_failed_new_profile_is_rolled_back_through_its_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi-wlan0.nmconnection");
        let host = FakeHost::with(&[], Some("ethernet"));
        host.fail_activation_of("new");
        // DELETE_NEW_CONNECTIONS: NetworkManager deletes the new profile.
        host.rollback_writes(&path, None);

        let error = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply_or_revert(&change("wlan0", &path, "new", b"new"))
            .unwrap_err();

        assert!(format!("{error:#}").contains("the change was undone"), "{error:#}");
        assert!(!path.exists());
        assert_eq!(host.checkpoint_calls(), ["create", "rollback"]);
        assert_eq!(host.calls(), ["load", "up new"]);
        assert_eq!(host.active_connection("wlan0").as_deref(), Some("ethernet"));
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn a_restarted_tetra_recovers_the_pending_change() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        let response = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&change("eth0", &path, "same", b"new"))
            .unwrap();
        let token = response["confirmation_token"].as_str().unwrap();

        let restarted = safe_apply(&host, Duration::from_secs(60), dir.path());

        let pending = restarted.pending();
        assert_eq!(pending["pending"]["confirmation_token"], token);
        assert_eq!(pending["pending"]["checkpoint"], response["checkpoint"]);
        assert_eq!(pending["pending"]["path"], path.to_str().unwrap());
        let remaining = pending["pending"]["rollback_in_seconds"].as_u64().unwrap();
        assert!((58..=60).contains(&remaining), "{remaining}");
        restarted.ensure_settled(&path).unwrap_err();
        restarted.confirm(token).unwrap();
        assert_eq!(host.held_checkpoints(), 0);
        assert!(!state(dir.path()).exists());
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_change_tetra_rolls_back_survives_a_restart_too() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        host.without_checkpoints();
        let response = safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&change("eth0", &path, "same", b"new"))
            .unwrap();
        assert_eq!(response["rollback_by"], "tetra");
        assert!(response["checkpoint"].is_null());

        let restarted = safe_apply(&host, Duration::from_secs(60), dir.path());

        assert_eq!(
            restarted.pending()["pending"]["confirmation_token"],
            response["confirmation_token"]
        );
    }

    /// Make the recorded change's rollback overdue, as after a reboot.
    fn make_overdue(dir: &Path) {
        let mut saved: Value = serde_json::from_slice(&fs::read(state(dir)).unwrap()).unwrap();
        saved["rollback_at"] = 0.into();
        fs::write(state(dir), serde_json::to_vec(&saved).unwrap()).unwrap();
    }

    #[test]
    fn an_overdue_change_whose_checkpoint_is_gone_is_rolled_back_on_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        safe_apply(&host, Duration::from_secs(60), dir.path())
            .apply(&change("eth0", &path, "same", b"new"))
            .unwrap();
        // NetworkManager restarted (with the host, say) and dropped the
        // checkpoint without rolling back.
        host.restart();
        make_overdue(dir.path());

        let restarted = safe_apply(&host, Duration::from_secs(60), dir.path());
        restarted.recover();

        wait_until(|| lock(&restarted.shared.pending).is_none());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        // Nothing restored the profile, so Tetra reactivates it too.
        assert_eq!(host.calls(), ["load", "up same", "load", "up same"]);
        assert_eq!(host.checkpoint_calls(), ["create", "adjust", "rollback"]);
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn a_change_whose_checkpoint_vanished_early_can_still_be_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        let apply = safe_apply(&host, Duration::from_secs(60), dir.path());
        let response = apply.apply(&change("eth0", &path, "same", b"new")).unwrap();
        host.restart();

        assert_eq!(apply.pending()["pending"]["confirmation_token"], response["confirmation_token"]);
        apply.confirm(response["confirmation_token"].as_str().unwrap()).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(host.calls(), ["load", "up same"]);
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn confirming_after_networkmanager_rolled_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, host) = cut_off(dir.path());
        host.rollback_writes(&path, Some(b"old, as NetworkManager writes it"));
        // Tetra's own timer would only fire long after NetworkManager's.
        let apply = SafeApply::with_timing(
            Arc::clone(&host) as Arc<dyn NetworkHost>,
            state(dir.path()),
            Duration::from_millis(20),
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let response = apply.apply(&change("eth0", &path, "same", b"new")).unwrap();
        host.expire_checkpoints();
        thread::sleep(Duration::from_millis(40));

        let error = apply.confirm(response["confirmation_token"].as_str().unwrap()).unwrap_err();

        assert!(error.to_string().contains("already rolled back"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(apply.pending()["pending"].is_null());
        assert!(!state(dir.path()).exists());
    }

    #[test]
    fn an_unreadable_state_file_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(state(dir.path()).parent().unwrap()).unwrap();
        fs::write(state(dir.path()), "{not json").unwrap();
        let host = FakeHost::with(&[], None);

        assert!(safe_apply(&host, Duration::from_secs(60), dir.path()).pending()["pending"].is_null());
        assert!(!state(dir.path()).exists());
    }
}
