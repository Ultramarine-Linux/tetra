//! Update policy: install updates automatically, or only notify.
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
//!   `dnf5-plugin-automatic`. Whether it installs or only downloads is
//!   `apply_updates` in `/etc/dnf/automatic.conf`, which the server
//!   configuration package sets.
//!
//! The OOBE does not know which variant it runs on, so the choice lives
//! here. Full update management (status, history, manual runs) is a later
//! module.

use crate::prelude::*;

use crate::auth::store::{self, Extra, Header, Record};

/// Marker type for the updates module.
#[derive(Clone, Copy, Debug)]
pub struct UpdatesModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "updates",
    feature: "updates",
    description: "Choose whether the host installs updates automatically.",
    status: ModuleStatus::Available,
    actions: &["capabilities", "plan", "get_policy", "set_policy"],
    privileged_actions: &["set_policy"],
};

const POLICY_PATH: &str = "/var/lib/tetra/updates.json";
/// Present on bootc (and other ostree) deployments.
const OSTREE_BOOTED: &str = "/run/ostree-booted";
pub const BOOTC_TIMER: &str = "bootc-fetch-apply-updates.timer";
/// `dnf-automatic.timer` is an alias of this unit in `dnf5-plugin-automatic`.
pub const DNF_TIMER: &str = "dnf5-automatic.timer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// Updates are installed on a schedule.
    Automatic,
    /// Nothing is installed without an administrator.
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

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        if let Some(response) = INFO.metadata_response(action, &payload) {
            return Ok(response);
        }
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    GetPolicy => get_policy(Path::new(POLICY_PATH), Variant::detect(Path::new(OSTREE_BOOTED))),
    SetPolicy {
        policy: Policy,
        #[serde(default)]
        dry_run: bool,
    } => set_policy(
        Path::new(POLICY_PATH),
        Variant::detect(Path::new(OSTREE_BOOTED)),
        payload.policy,
        payload.dry_run,
    ),
});

/// The stored policy (`null` until one is set), the variant and its timer.
fn get_policy(path: &Path, variant: Variant) -> Result<Value> {
    let policy = store::read::<PolicyFile>(path)?.map(|file| file.policy);
    Ok(jsonf! { policy, variant, "timer": variant.timer() })
}

/// Enable or disable the variant's timer, then store the policy. The policy
/// is only stored once the timer matches it.
fn set_policy(path: &Path, variant: Variant, policy: Policy, dry_run: bool) -> Result<Value> {
    let timer = variant.timer();
    let verb = match policy {
        Policy::Automatic => "enable",
        Policy::Notify => "disable",
    };
    let command = crate::cmd!((dry_run) "systemctl" [verb, "--now", timer] json)?;
    if !dry_run {
        store::write(
            path,
            &mut PolicyFile {
                header: Header::default(),
                policy,
                updated_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)),
                extra: Extra::new(),
            },
        )?;
    }
    Ok(jsonf! { policy, variant, timer, "stored": !dry_run, dry_run, command })
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

    #[test]
    fn set_policy_toggles_the_timer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("updates.json");
        for (variant, policy, command) in [
            (
                Variant::Bootc,
                Policy::Automatic,
                "systemctl enable --now bootc-fetch-apply-updates.timer",
            ),
            (
                Variant::Bootc,
                Policy::Notify,
                "systemctl disable --now bootc-fetch-apply-updates.timer",
            ),
            (
                Variant::Mutable,
                Policy::Automatic,
                "systemctl enable --now dnf5-automatic.timer",
            ),
            (
                Variant::Mutable,
                Policy::Notify,
                "systemctl disable --now dnf5-automatic.timer",
            ),
        ] {
            let response = set_policy(&path, variant, policy, true).unwrap();
            assert_eq!(response["command"]["command"], command);
            assert_eq!(response["stored"], false);
        }
        // Dry runs store nothing.
        assert!(!path.exists());
    }

    #[test]
    fn the_policy_is_stored_with_a_versioned_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("updates.json");
        assert_eq!(get_policy(&path, Variant::Bootc).unwrap()["policy"], Value::Null);
        // A file written by a newer release keeps its unknown fields.
        fs::write(
            &path,
            r#"{"schema": 2, "compat": 1, "policy": "automatic", "window": "sun 03:00"}"#,
        )
        .unwrap();
        let response = get_policy(&path, Variant::Mutable).unwrap();
        assert_eq!(response["policy"], "automatic");
        assert_eq!(response["variant"], "mutable");
        assert_eq!(response["timer"], "dnf5-automatic.timer");

        let mut file = store::read::<PolicyFile>(&path).unwrap().unwrap();
        file.policy = Policy::Notify;
        store::write(&path, &mut file).unwrap();
        let stored: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["policy"], "notify");
        assert_eq!(stored["window"], "sun 03:00");
        assert_eq!(stored["schema"], store::SCHEMA);

        // A file only a newer release may read is refused.
        fs::write(&path, r#"{"schema": 9, "compat": 9, "policy": "notify"}"#).unwrap();
        get_policy(&path, Variant::Bootc).unwrap_err();
    }

    #[test]
    fn only_known_policies_are_accepted() {
        UpdatesModule
            .handle("set_policy", json!({"policy": "sometimes", "dry_run": true}), None)
            .unwrap_err();
        let response = UpdatesModule
            .handle("set_policy", json!({"policy": "notify", "dry_run": true}), None)
            .unwrap();
        assert_eq!(response["policy"], "notify");
        assert!(INFO.is_privileged("set_policy"));
        assert!(!INFO.is_privileged("get_policy"));
    }
}
