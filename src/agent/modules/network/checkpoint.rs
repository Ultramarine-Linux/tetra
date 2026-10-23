//! NetworkManager checkpoints over D-Bus, through `busctl`.
//!
//! A checkpoint snapshots the profile active on a device; NetworkManager
//! rolls the device back to it when the checkpoint's timeout expires, unless
//! it is destroyed first. It lives in the NetworkManager daemon, not in the
//! D-Bus client that created it, so it outlasts a `busctl` call and a Tetra
//! restart. NetworkManager drops it (without rolling back) when it stops.
//!
//! See `org.freedesktop.NetworkManager.CheckpointCreate` and the
//! `org.freedesktop.NetworkManager.Checkpoint` interface:
//! <https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html>.
//!
//! `busctl` is on every systemd host and its `--json=short` output is easy
//! to parse, so this needs no D-Bus library.

use crate::agent::module_support::CommandResult;
use crate::prelude::*;

const SERVICE: &str = "org.freedesktop.NetworkManager";
const OBJECT: &str = "/org/freedesktop/NetworkManager";
const INTERFACE: &str = "org.freedesktop.NetworkManager";
const CHECKPOINT_PREFIX: &str = "/org/freedesktop/NetworkManager/Checkpoint/";

/// `NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS` (NetworkManager 1.6):
/// a rollback deletes profiles added after the checkpoint, keyfiles
/// included, so a new profile goes away with the rest of the change.
///
/// `DISCONNECT_NEW_DEVICES` is not used: NetworkManager only accepts it for
/// a checkpoint of every device, and would then disconnect any device that
/// appeared meanwhile. `DESTROY_ALL` would drop other tools' checkpoints
/// (Cockpit's, say), and without `ALLOW_OVERLAPPING` creation fails while
/// another checkpoint covers the device, which leaves that one in charge.
/// <https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMCheckpointCreateFlags>
const DELETE_NEW_CONNECTIONS: u32 = 0x02;

fn busctl(args: &[&str]) -> Result<CommandResult> {
    let mut command = vec!["--json=short", "--allow-interactive-authorization=no"];
    command.extend_from_slice(args);
    crate::cmd!("busctl" => command.as_slice())
}

/// Call `method` on the NetworkManager object.
fn call(method: &str, signature: &str, args: &[&str]) -> Result<CommandResult> {
    let mut command = vec!["call", SERVICE, OBJECT, INTERFACE, method, signature];
    command.extend_from_slice(args);
    busctl(&command)
}

/// The NetworkManager device object for `interface`.
fn device(interface: &str) -> Result<String> {
    let result = call("GetDeviceByIpIface", "s", &[interface])
        .with_context(|| format!("NetworkManager has no device for `{interface}`"))?;
    object_path(&result.stdout)
}

/// Snapshot `interface`'s device, rolled back after `timeout_secs` unless
/// destroyed. Returns the checkpoint's object path.
pub fn create(interface: &str, timeout_secs: u32) -> Result<String> {
    let device = device(interface)?;
    let result = call(
        "CheckpointCreate",
        "aouu",
        &["1", &device, &timeout_secs.to_string(), &DELETE_NEW_CONNECTIONS.to_string()],
    )
    .context("failed to create a NetworkManager checkpoint")?;
    let checkpoint = object_path(&result.stdout)?;
    validate(&checkpoint)?;
    Ok(checkpoint)
}

/// Keep the current configuration and drop `checkpoint`.
pub fn destroy(checkpoint: &str) -> Result<()> {
    validate(checkpoint)?;
    call("CheckpointDestroy", "o", &[checkpoint]).map(drop)
}

/// Roll back to `checkpoint` now (which also destroys it). Errs when it
/// does not exist or a device failed to roll back.
pub fn rollback(checkpoint: &str) -> Result<()> {
    validate(checkpoint)?;
    let result = call("CheckpointRollback", "o", &[checkpoint])?;
    let failed = rollback_failures(&result.stdout)?;
    ensure!(
        failed.is_empty(),
        "NetworkManager could not roll back {}",
        failed.join(", ")
    );
    Ok(())
}

/// Restart `checkpoint`'s timeout: it now rolls back `timeout_secs` from now.
pub fn adjust_timeout(checkpoint: &str, timeout_secs: u32) -> Result<()> {
    validate(checkpoint)?;
    call("CheckpointAdjustRollbackTimeout", "ou", &[checkpoint, &timeout_secs.to_string()])
        .map(drop)
}

/// Every checkpoint NetworkManager holds.
pub fn list() -> Result<Vec<String>> {
    let result = busctl(&["get-property", SERVICE, OBJECT, INTERFACE, "Checkpoints"])?;
    let value: Value =
        serde_json::from_str(&result.stdout).context("failed to parse `busctl` output")?;
    value["data"]
        .as_array()
        .context("`Checkpoints` is not an array")?
        .iter()
        .map(|path| path.as_str().map(str::to_owned).context("checkpoint path is not a string"))
        .collect()
}

/// Refuse anything but a checkpoint object path, such as one read back
/// from Tetra's state file.
pub fn validate(checkpoint: &str) -> Result<()> {
    ensure!(
        checkpoint
            .strip_prefix(CHECKPOINT_PREFIX)
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())),
        "`{checkpoint}` is not a NetworkManager checkpoint"
    );
    Ok(())
}

/// The object path a method returned: `{"type":"o","data":["/…"]}`.
fn object_path(stdout: &str) -> Result<String> {
    let value: Value = serde_json::from_str(stdout).context("failed to parse `busctl` output")?;
    value["data"][0]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .map(str::to_owned)
        .with_context(|| format!("`busctl` returned no object path: {}", stdout.trim()))
}

/// Devices `CheckpointRollback` reports as not rolled back, from its
/// `{"type":"a{su}","data":[{"/…/Devices/2":0}]}`. A result of 0 is
/// `NM_ROLLBACK_RESULT_OK`.
fn rollback_failures(stdout: &str) -> Result<Vec<String>> {
    let value: Value = serde_json::from_str(stdout).context("failed to parse `busctl` output")?;
    let results = value["data"][0].as_object().context("rollback returned no results")?;
    Ok(results
        .iter()
        .filter(|(_, result)| result.as_u64() != Some(0))
        .map(|(device, result)| {
            let reason = match result.as_u64() {
                Some(1) => "the device no longer exists",
                Some(2) => "the device is unmanaged",
                _ => "it failed",
            };
            format!("{device} ({reason})")
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_paths() {
        assert_eq!(
            object_path(r#"{"type":"o","data":["/org/freedesktop/NetworkManager/Checkpoint/3"]}"#)
                .unwrap(),
            "/org/freedesktop/NetworkManager/Checkpoint/3"
        );
        object_path(r#"{"type":"o","data":[]}"#).unwrap_err();
        object_path("Call failed: No device found for the requested iface.").unwrap_err();
    }

    #[test]
    fn reports_devices_that_did_not_roll_back() {
        assert!(rollback_failures(r#"{"type":"a{su}","data":[{"/d/2":0}]}"#).unwrap().is_empty());
        let failed =
            rollback_failures(r#"{"type":"a{su}","data":[{"/d/2":0,"/d/3":1,"/d/4":3}]}"#).unwrap();
        assert_eq!(failed, ["/d/3 (the device no longer exists)", "/d/4 (it failed)"]);
    }

    #[test]
    fn only_checkpoint_paths_are_accepted() {
        validate("/org/freedesktop/NetworkManager/Checkpoint/12").unwrap();
        for path in [
            "/org/freedesktop/NetworkManager/Checkpoint/",
            "/org/freedesktop/NetworkManager/Devices/2",
            "/org/freedesktop/NetworkManager/Checkpoint/1/../2",
            "--help",
        ] {
            validate(path).unwrap_err();
        }
    }
}
