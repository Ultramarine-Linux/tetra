//! Update policy: install updates automatically, or leave them to an
//! administrator.
//!
//! The policy is stored in `/var/lib/tetra/updates.json`, with the same
//! versioned-header and rollback rules as the auth files
//! ([`crate::auth::store`]). For now it only enables or disables the timer
//! that applies updates on this install variant:
//!
//! - **bootc** (image-based, `/run/ostree-booted` exists):
//!   `bootc-fetch-apply-updates.timer`, which stages the new image and
//!   reboots into it.
//! - **mutable** (package-based): `dnf5-automatic.timer` from
//!   `dnf5-plugin-automatic`. On its own `dnf5 automatic` only downloads
//!   (`apply_updates = no` by default), so `automatic` also installs a
//!   `dnf5-automatic.service` drop-in that runs it with `--installupdates`,
//!   which overrides the configuration file. The rest of
//!   `/etc/dnf/automatic.conf` (upgrade type, reboot, emitters) still applies.
//!
//! `get_policy` reports the timer's real state next to the stored policy.
//! The OOBE does not know which variant it runs on, so the choice lives
//! here. Full update management (status, history, manual runs) is a later
//! module.

use crate::prelude::*;

use crate::agent::module_support::{
    Commands, NoPayload, drop_in, install_drop_in, parse_action, unit_enabled,
};
use crate::auth::service::{AuthConfig, DEFAULT_STATE_DIR};
use crate::auth::store::{self, Extra, Header, Record};

/// The updates module, with the system's [`Paths`]. See
/// [`UpdatesModule::with_paths`] for others.
#[derive(Clone, Copy, Debug)]
pub struct UpdatesModule;

/// [`UpdatesModule`] with its files at other [`Paths`], such as the ones an
/// [`AuthConfig`](crate::auth::AuthConfig) configures.
#[derive(Clone, Debug)]
pub struct UpdatesWithPaths(Paths);

impl UpdatesModule {
    /// The module with its files at `paths`.
    #[must_use]
    pub const fn with_paths(paths: Paths) -> UpdatesWithPaths {
        UpdatesWithPaths(paths)
    }
}

const INFO: ModuleInfo = ModuleInfo {
    name: "updates",
    feature: "updates",
    description: "Choose whether the host installs updates automatically.",
    status: ModuleStatus::Available,
    actions: &["capabilities", "plan", "get_policy", "set_policy"],
    privileged_actions: &["set_policy"],
};

/// Present on bootc (and other ostree) deployments.
const OSTREE_BOOTED: &str = "/run/ostree-booted";
pub const BOOTC_TIMER: &str = "bootc-fetch-apply-updates.timer";
/// `dnf-automatic.timer` is an alias of this unit in `dnf5-plugin-automatic`.
pub const DNF_TIMER: &str = "dnf5-automatic.timer";
/// The service [`DNF_TIMER`] starts.
const DNF_SERVICE: &str = "dnf5-automatic.service";
/// Makes `dnf5 automatic` install what it downloads, whatever
/// `apply_updates` says. The `ExecStart=` is the packaged one plus
/// `--installupdates`.
const DNF_DROP_IN: &str = "# Managed by Tetra (updates.set_policy).\n\
     [Service]\n\
     ExecStart=\n\
     ExecStart=/usr/bin/dnf5 automatic --timer --installupdates\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// The variant's timer installs updates.
    Automatic,
    /// The timer is off: nothing is downloaded or installed until an
    /// administrator does it. (Nothing sends a notification either; the
    /// name is kept for compatibility.)
    Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    Bootc,
    Mutable,
}

impl Variant {
    fn detect(ostree_booted: &Path) -> Self {
        if ostree_booted.exists() {
            Self::Bootc
        } else {
            Self::Mutable
        }
    }

    #[must_use]
    pub const fn timer(self) -> &'static str {
        match self {
            Self::Bootc => BOOTC_TIMER,
            Self::Mutable => DNF_TIMER,
        }
    }
}

/// Where this module keeps its files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The stored policy (`/var/lib/tetra/updates.json`).
    pub policy: PathBuf,
    /// Unit drop-ins (`/etc/systemd/system`).
    pub systemd_dir: PathBuf,
}

impl Default for Paths {
    /// The paths of [`AuthConfig::system`] in its default state directory.
    fn default() -> Self {
        Self::for_config(&AuthConfig::system(DEFAULT_STATE_DIR.into()))
    }
}

impl Paths {
    /// The paths under `config`'s state and systemd directories.
    #[must_use]
    pub fn for_config(config: &AuthConfig) -> Self {
        Self {
            policy: config.state_dir.join("updates.json"),
            systemd_dir: config.systemd_dir.clone(),
        }
    }

    fn dnf_drop_in(&self) -> PathBuf {
        drop_in(&self.systemd_dir, DNF_SERVICE)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyFile {
    #[serde(flatten)]
    header: Header,
    policy: Policy,
    #[serde(default)]
    updated_at: i64,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for PolicyFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl Mod for UpdatesModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
        handle(&Paths::default(), action, payload)
    }
}

impl Mod for UpdatesWithPaths {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, _user: Option<&str>) -> Result<Value> {
        handle(&self.0, action, payload)
    }
}

/// An action and its payload. Not declared with `actions!`, whose handlers
/// cannot see the module's [`Paths`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    GetPolicy(NoPayload),
    SetPolicy(SetPolicy),
}

#[derive(Debug, Deserialize)]
struct SetPolicy {
    policy: Policy,
    #[serde(default)]
    dry_run: bool,
}

fn handle(paths: &Paths, action: &str, payload: Value) -> Result<Value> {
    let action: Action = parse_action(action, payload)?;
    let variant = Variant::detect(Path::new(OSTREE_BOOTED));
    let timer_enabled = || unit_enabled(variant.timer());
    match action {
        Action::GetPolicy(NoPayload {}) => get_policy(paths, variant, timer_enabled()),
        Action::SetPolicy(SetPolicy { policy, dry_run }) => set_policy(
            paths,
            variant,
            policy,
            Commands::new(dry_run),
            &timer_enabled,
        ),
    }
}

/// The policy the host follows: `automatic` while the timer is enabled (on
/// mutable hosts, with Tetra's drop-in), `notify` while it is not, and
/// `None` when `dnf5-automatic.timer` is enabled without the drop-in (it
/// then installs only if `/etc/dnf/automatic.conf` says so).
fn effective_policy(paths: &Paths, variant: Variant, timer_enabled: bool) -> Option<Policy> {
    match (timer_enabled, variant) {
        (false, _) => Some(Policy::Notify),
        (true, Variant::Bootc) => Some(Policy::Automatic),
        (true, Variant::Mutable) => paths.dnf_drop_in().exists().then_some(Policy::Automatic),
    }
}

/// The stored policy (`null` until one is set), the variant, its timer and
/// what the host actually does, with `mismatch` set when a stored policy
/// differs from it (the timer was changed outside Tetra).
fn get_policy(paths: &Paths, variant: Variant, timer_enabled: bool) -> Result<Value> {
    let policy = store::read::<PolicyFile>(&paths.policy)?.map(|file| file.policy);
    let effective = effective_policy(paths, variant, timer_enabled);
    let mismatch = policy.is_some() && policy != effective;
    Ok(jsonf! {
        policy,
        variant,
        "timer": variant.timer(),
        timer_enabled,
        effective,
        mismatch,
    })
}

/// Enable or disable the variant's timer (and on mutable hosts install or
/// remove the drop-in that makes it install updates) with `commands`, then
/// store the policy unless they are a dry run. The policy is only stored
/// once the host matches it; `timer_enabled` confirms that when disabling
/// the timer fails.
fn set_policy(
    paths: &Paths,
    variant: Variant,
    policy: Policy,
    mut commands: Commands<'_>,
    timer_enabled: &dyn Fn() -> bool,
) -> Result<Value> {
    let dry_run = commands.dry_run();
    // Before changing the host: a file only a newer release may read is
    // refused, and one it can read keeps the fields it does not know.
    let stored = store::read::<PolicyFile>(&paths.policy)?;
    let timer = variant.timer();
    let mut run = |args: &[&str]| commands.run("systemctl", args);
    let drop_in = paths.dnf_drop_in();
    match policy {
        Policy::Automatic => {
            if variant == Variant::Mutable && install_drop_in(&drop_in, DNF_DROP_IN, dry_run)? {
                run(&["daemon-reload"])?;
            }
            run(&["enable", "--now", timer])?;
        }
        Policy::Notify => {
            // Fails when the timer is not installed (no
            // dnf5-plugin-automatic), and then nothing installs updates
            // either; what matters is that the timer is not enabled.
            if let Err(error) = run(&["disable", "--now", timer])
                && timer_enabled()
            {
                return Err(error);
            }
            if drop_in.exists() {
                if !dry_run {
                    store::remove(&drop_in)?;
                }
                run(&["daemon-reload"])?;
            }
        }
    }
    if !dry_run {
        let updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX));
        let mut file = stored.map_or_else(
            || PolicyFile {
                header: Header::default(),
                policy,
                updated_at,
                extra: Extra::new(),
            },
            |file| PolicyFile {
                policy,
                updated_at,
                ..file
            },
        );
        store::write(&paths.policy, &mut file)?;
    }
    Ok(jsonf! { policy, variant, timer, "stored": !dry_run, dry_run, "commands": commands.done })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_variant_decides_the_timer() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ostree-booted");
        assert_eq!(Variant::detect(&marker), Variant::Mutable);
        fs::write(&marker, "").unwrap();
        assert_eq!(Variant::detect(&marker), Variant::Bootc);
        assert_eq!(Variant::Bootc.timer(), "bootc-fetch-apply-updates.timer");
        assert_eq!(Variant::Mutable.timer(), "dnf5-automatic.timer");
    }

    fn paths(root: &Path) -> Paths {
        Paths {
            policy: root.join("updates.json"),
            systemd_dir: root.join("systemd"),
        }
    }

    /// `set_policy` as a dry run.
    fn plan(paths: &Paths, variant: Variant, policy: Policy) -> Result<Value> {
        set_policy(
            paths,
            variant,
            policy,
            Commands::new(true),
            &|| unreachable!("a dry run does not check the timer"),
        )
    }

    /// `set_policy` for real, with a `systemctl` that fails `failing`
    /// commands and succeeds otherwise, and a timer that is enabled when
    /// `timer_enabled` says so.
    fn apply(
        paths: &Paths,
        variant: Variant,
        policy: Policy,
        failing: &str,
        timer_enabled: bool,
    ) -> Result<Value> {
        set_policy(
            paths,
            variant,
            policy,
            Commands::fake(false, failing),
            &|| timer_enabled,
        )
    }

    fn commands(response: &Value) -> Vec<&str> {
        response["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["command"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn set_policy_toggles_the_timer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        for (variant, policy, expected) in [
            (
                Variant::Bootc,
                Policy::Automatic,
                &["systemctl enable --now bootc-fetch-apply-updates.timer"][..],
            ),
            (
                Variant::Bootc,
                Policy::Notify,
                &["systemctl disable --now bootc-fetch-apply-updates.timer"],
            ),
            (
                Variant::Mutable,
                Policy::Automatic,
                &[
                    "systemctl daemon-reload",
                    "systemctl enable --now dnf5-automatic.timer",
                ],
            ),
            (
                Variant::Mutable,
                Policy::Notify,
                &["systemctl disable --now dnf5-automatic.timer"],
            ),
        ] {
            let response = plan(&paths, variant, policy).unwrap();
            assert_eq!(commands(&response), expected);
            assert_eq!(response["stored"], false);
        }
        // Dry runs store nothing.
        assert!(!paths.policy.exists());
        assert!(!paths.dnf_drop_in().exists());
    }

    #[test]
    fn automatic_makes_dnf5_automatic_install_updates() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert!(install_drop_in(&paths.dnf_drop_in(), DNF_DROP_IN, false).unwrap());
        assert_eq!(
            fs::read_to_string(dir.path().join("systemd/dnf5-automatic.service.d/50-tetra.conf"))
                .unwrap(),
            "# Managed by Tetra (updates.set_policy).\n[Service]\nExecStart=\n\
             ExecStart=/usr/bin/dnf5 automatic --timer --installupdates\n"
        );
        // Once in place, systemd is not reloaded again.
        let response = plan(&paths, Variant::Mutable, Policy::Automatic).unwrap();
        assert_eq!(
            commands(&response),
            ["systemctl enable --now dnf5-automatic.timer"]
        );
        // Turning it off removes the drop-in (here only planned).
        let response = plan(&paths, Variant::Mutable, Policy::Notify).unwrap();
        assert_eq!(
            commands(&response),
            [
                "systemctl disable --now dnf5-automatic.timer",
                "systemctl daemon-reload",
            ]
        );
        assert!(paths.dnf_drop_in().exists());
    }

    #[test]
    fn get_policy_reports_what_the_host_does() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        // Nothing stored: no mismatch, whatever the timer does.
        let response = get_policy(&paths, Variant::Bootc, true).unwrap();
        assert_eq!(response["policy"], Value::Null);
        assert_eq!(response["timer_enabled"], true);
        assert_eq!(response["effective"], "automatic");
        assert_eq!(response["mismatch"], false);

        fs::write(&paths.policy, r#"{"schema": 1, "compat": 1, "policy": "automatic"}"#).unwrap();
        for (variant, timer_enabled, drop_in, effective, mismatch) in [
            (Variant::Bootc, true, false, json!("automatic"), false),
            (Variant::Bootc, false, false, json!("notify"), true),
            // dnf5 automatic without the drop-in may only download.
            (Variant::Mutable, true, false, Value::Null, true),
            (Variant::Mutable, true, true, json!("automatic"), false),
            (Variant::Mutable, false, true, json!("notify"), true),
        ] {
            if drop_in {
                install_drop_in(&paths.dnf_drop_in(), DNF_DROP_IN, false).unwrap();
            }
            let response = get_policy(&paths, variant, timer_enabled).unwrap();
            assert_eq!(response["effective"], effective, "{variant:?} {timer_enabled}");
            assert_eq!(response["mismatch"], mismatch, "{variant:?} {timer_enabled}");
        }
    }

    #[test]
    fn the_policy_is_stored_with_a_versioned_header() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let path = &paths.policy;
        assert_eq!(get_policy(&paths, Variant::Bootc, false).unwrap()["policy"], Value::Null);
        // A file written by a newer release keeps its unknown fields.
        fs::write(
            path,
            r#"{"schema": 2, "compat": 1, "policy": "automatic", "window": "sun 03:00"}"#,
        )
        .unwrap();
        let response = get_policy(&paths, Variant::Mutable, false).unwrap();
        assert_eq!(response["policy"], "automatic");
        assert_eq!(response["variant"], "mutable");
        assert_eq!(response["timer"], "dnf5-automatic.timer");

        let mut file = store::read::<PolicyFile>(path).unwrap().unwrap();
        file.policy = Policy::Notify;
        store::write(path, &mut file).unwrap();
        let stored: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(stored["policy"], "notify");
        assert_eq!(stored["window"], "sun 03:00");
        assert_eq!(stored["schema"], store::SCHEMA);

        // A file only a newer release may read is refused.
        fs::write(path, r#"{"schema": 9, "compat": 9, "policy": "notify"}"#).unwrap();
        get_policy(&paths, Variant::Bootc, false).unwrap_err();
    }

    #[test]
    fn set_policy_keeps_what_a_newer_release_stored() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        fs::write(
            &paths.policy,
            r#"{"schema": 2, "compat": 1, "policy": "automatic", "window": "sun 03:00"}"#,
        )
        .unwrap();
        apply(&paths, Variant::Bootc, Policy::Notify, "", false).unwrap();
        let stored: Value = serde_json::from_str(&fs::read_to_string(&paths.policy).unwrap()).unwrap();
        assert_eq!(stored["policy"], "notify");
        assert_eq!(stored["window"], "sun 03:00");
        assert!(stored["updated_at"].as_i64().unwrap() > 0);

        // A file only a newer release may read is left alone, and so is
        // the host.
        let newer = r#"{"schema": 9, "compat": 9, "policy": "notify"}"#;
        fs::write(&paths.policy, newer).unwrap();
        let error = apply(
            &paths,
            Variant::Bootc,
            Policy::Automatic,
            "systemctl enable --now bootc-fetch-apply-updates.timer",
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("needs schema 9"), "{error:#}");
        plan(&paths, Variant::Bootc, Policy::Automatic).unwrap_err();
        assert_eq!(fs::read_to_string(&paths.policy).unwrap(), newer);
    }

    #[test]
    fn notify_succeeds_when_the_timer_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let disable = "systemctl disable --now dnf5-automatic.timer";
        // The timer is still enabled: the failure stands and nothing is
        // stored.
        let error = apply(&paths, Variant::Mutable, Policy::Notify, disable, true).unwrap_err();
        assert!(error.to_string().contains(disable), "{error}");
        assert!(!paths.policy.exists());
        // Not enabled (here, not installed): the failure is listed and the
        // policy stored.
        let response = apply(&paths, Variant::Mutable, Policy::Notify, disable, false).unwrap();
        assert_eq!(response["commands"][0]["command"], disable);
        assert!(response["commands"][0]["error"].is_string());
        assert_eq!(response["stored"], true);
        let file = store::read::<PolicyFile>(&paths.policy).unwrap().unwrap();
        assert_eq!(file.policy, Policy::Notify);
        // Enabling has no such allowance.
        apply(
            &paths,
            Variant::Mutable,
            Policy::Automatic,
            "systemctl enable --now dnf5-automatic.timer",
            false,
        )
        .unwrap_err();
        assert_eq!(
            store::read::<PolicyFile>(&paths.policy).unwrap().unwrap().policy,
            Policy::Notify
        );
    }

    #[test]
    fn the_auth_config_places_the_files() {
        let config = crate::auth::AuthConfig::system("/srv/tetra".into());
        let paths = Paths::for_config(&config);
        assert_eq!(paths.policy, Path::new("/srv/tetra/updates.json"));
        assert_eq!(paths.systemd_dir, config.systemd_dir);
    }

    #[test]
    fn get_policy_takes_null_or_an_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let module = UpdatesModule::with_paths(paths(dir.path()));
        fs::write(dir.path().join("updates.json"), r#"{"schema": 1, "compat": 1, "policy": "notify"}"#)
            .unwrap();
        for payload in [Value::Null, json!({})] {
            let response = module.handle("get_policy", payload, None).unwrap();
            // Read from the module's paths.
            assert_eq!(response["policy"], "notify");
        }
    }

    #[test]
    fn only_known_policies_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let module = UpdatesModule::with_paths(paths(dir.path()));
        module
            .handle("set_policy", json!({"policy": "sometimes", "dry_run": true}), None)
            .unwrap_err();
        let response = module
            .handle("set_policy", json!({"policy": "notify", "dry_run": true}), None)
            .unwrap();
        assert_eq!(response["policy"], "notify");
        assert!(INFO.is_privileged("set_policy"));
        assert!(!INFO.is_privileged("get_policy"));
    }
}
