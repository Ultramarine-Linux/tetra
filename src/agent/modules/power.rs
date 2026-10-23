//! Reboot and power off.
//!
//! Both actions are scheduled a few seconds out with a transient systemd
//! timer rather than run directly, so the response reaches the caller (the
//! OOBE shows a "rebooting" screen) before the shutdown begins.

use crate::prelude::*;

/// Marker type for the power module.
#[derive(Clone, Copy, Debug)]
pub struct PowerModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "power",
    feature: "power",
    description: "Reboot or power off the host.",
    status: ModuleStatus::Available,
    actions: &["capabilities", "plan", "reboot", "poweroff"],
    privileged_actions: &["reboot", "poweroff"],
};

/// Seconds between the response and the shutdown.
pub const DELAY_SECONDS: u32 = 3;

impl Mod for PowerModule {
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
    Reboot {
        #[serde(default)]
        dry_run: bool,
    } => schedule("reboot", payload.dry_run),
    Poweroff {
        #[serde(default)]
        dry_run: bool,
    } => schedule("poweroff", payload.dry_run),
});

/// Run `systemctl <verb>` after [`DELAY_SECONDS`]. A second request while
/// one is pending fails, because the transient unit name is taken.
fn schedule(verb: &str, dry_run: bool) -> Result<Value> {
    let on_active = format!("--on-active={DELAY_SECONDS}");
    let unit = format!("--unit=tetra-power-{verb}");
    let description = format!("--description=Tetra {verb} requested through power.{verb}");
    let result = crate::cmd!((dry_run) "systemd-run" [
        on_active.as_str(),
        unit.as_str(),
        description.as_str(),
        "--collect",
        "systemctl",
        verb,
    ] json)?;
    Ok(jsonf! { "action": verb, "in_seconds": DELAY_SECONDS, dry_run, "command": result })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reboot_and_poweroff_are_scheduled_after_the_response() {
        for verb in ["reboot", "poweroff"] {
            let response = PowerModule
                .handle(verb, json!({"dry_run": true}), None)
                .unwrap();
            assert_eq!(response["action"], verb);
            assert_eq!(response["in_seconds"], DELAY_SECONDS);
            assert_eq!(
                response["command"]["command"],
                format!(
                    "systemd-run --on-active={DELAY_SECONDS} --unit=tetra-power-{verb} \
                     --description=Tetra {verb} requested through power.{verb} --collect \
                     systemctl {verb}"
                )
            );
            assert!(INFO.is_privileged(verb));
        }
        PowerModule
            .handle("halt", json!({"dry_run": true}), None)
            .unwrap_err();
    }

    #[test]
    fn the_payload_may_be_left_out() {
        // Parsed only: handling it would schedule a real reboot.
        for verb in ["reboot", "poweroff"] {
            Action::from_payload(verb, Value::Null).unwrap();
        }
    }
}
