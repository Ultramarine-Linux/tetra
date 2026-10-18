//! Network interface inspection and NetworkManager keyfile management.
//!
//! This module splits host networking into two concerns:
//!
//! - *Live state* (`interfaces`, `status`) is read from `/sys/class/net` sysfs
//!   and `ip -json addr show`, so callers can see what is currently up. Both
//!   report every address with a scope (`global`, `private`, `ula`,
//!   `link-local`, ...) derived from its prefix; see [`addresses`].
//! - *Persistent configuration* is managed as NetworkManager *keyfiles*:
//!   INI-style `.nmconnection` profiles under
//!   `/etc/NetworkManager/system-connections/`.
//!
//! `configure` is the structured path: it takes an interface plus `ipv4` and
//! `ipv6` sections, validates them ([`keyfile`]), writes the keyfile `0600`
//! with its default SELinux label, loads and activates it, and rolls it back
//! unless confirmed if the interface lost every routable address it had
//! ([`apply`]). `get_config`/`set_config` remain for raw keyfile access, but
//! only for regular `.nmconnection` files directly inside that directory
//! ([`paths`]). All of these are privileged.

mod addresses;
mod apply;
mod keyfile;
mod paths;

use std::{
    net::IpAddr,
    sync::{Arc, LazyLock},
};

use crate::prelude::*;

use crate::agent::module_support::{CommandResult, SelinuxOptions};
use crate::types::{
    DryRunRequest, NetworkConfigRequest, NetworkConfigureRequest, NetworkConfirmRequest,
    NetworkInterfaceRequest, NetworkWriteConfigRequest,
};
use addresses::{InterfaceAddress, parse_ip_addr_json};
use apply::{Change, NetworkHost, SafeApply};
use paths::{SYSTEM_CONNECTIONS_DIR, keyfile_path_for, read_keyfile, validate_keyfile_path, write_keyfile};

/// Marker type for the network module. Stateless apart from the pending
/// rollback held by [`SAFE_APPLY`]; all behavior lives in the [`Mod`] impl
/// and the static [`INFO`] descriptor.
#[derive(Clone, Copy, Debug)]
pub struct NetworkModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "network",
    feature: "network",
    description: "Inspect and configure host network interfaces, addresses, DNS, and routes.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "interfaces",
        "status",
        "dns",
        "routes",
        "configure",
        "confirm",
        "get_config",
        "set_config",
        "reload",
    ],
    privileged_actions: &["configure", "confirm", "get_config", "set_config", "reload"],
};

/// The host's single safe-apply state, shared by `configure` and `confirm`.
static SAFE_APPLY: LazyLock<SafeApply> =
    LazyLock::new(|| SafeApply::new(Arc::new(NetworkManagerHost)));

impl Mod for NetworkModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        // Delegate `capabilities`/`plan` to the shared metadata handler first.
        if let Some(response) = INFO.metadata_response(action, &payload) {
            return Ok(response);
        }
        Action::from_payload(action, payload)?.handle(user)
    }
}
actions!(Action [payload user] => {
    Interfaces => {
        let addresses = crate::cmd!({ &INFO, "interfaces", user } "ip" ["-json", "addr", "show"])
            .ok()
            .and_then(|result: CommandResult| serde_json::from_str(&result.stdout).ok())
            .map(|data: Value| parse_ip_addr_json(&data))
            .unwrap_or_default();
        Ok(jsonf! { "interfaces": read_interfaces(&addresses).unwrap_or_default() })
    },
    Status: NetworkInterfaceRequest => {
        // `ip -json addr show` returns structured JSON we pass through
        // verbatim in `data`; an optional `dev <name>` narrows the scope.
        // `addresses` adds a prefix-based scope to every address.
        let args = payload.ip_args();
        let mut response = crate::cmd!({ &INFO, "status", user } "ip" => &args ; JSON)?;
        response["addresses"] = serde_json::to_value(parse_ip_addr_json(&response["data"]))?;
        Ok(response)
    },
    Dns => Ok(jsonf! { "resolv_conf": read_optional("/etc/resolv.conf") }),
    Routes => crate::cmd!({ &INFO, "routes", user } "ip" ["-json", "route", "show"] JSON),
    Configure: NetworkConfigureRequest => {
        configure(&payload, Path::new(SYSTEM_CONNECTIONS_DIR), &SAFE_APPLY)
    },
    Confirm: NetworkConfirmRequest => SAFE_APPLY.confirm(&payload.token),
    GetConfig: NetworkConfigRequest => {
        get_config(&payload, Path::new(SYSTEM_CONNECTIONS_DIR))
    },
    SetConfig: NetworkWriteConfigRequest => {
        set_config(&payload, Path::new(SYSTEM_CONNECTIONS_DIR))
    },
    Reload: DryRunRequest => {
        crate::cmd!((payload.dry_run) { &INFO, "reload", user } "systemctl" ["reload-or-restart", "NetworkManager.service"] json)
    },
});

/// Validate, render, and (outside dry-run) safely apply a structured
/// configuration as the keyfile `<name>.nmconnection` in `dir`.
fn configure(payload: &NetworkConfigureRequest, dir: &Path, safe_apply: &SafeApply) -> Result<Value> {
    keyfile::validate(payload)?;
    let path = keyfile_path_for(dir, keyfile::connection_name(payload))?;
    // Rewriting a profile keeps its UUID, so NetworkManager treats it as the
    // same connection rather than a new one.
    let uuid = read_keyfile(&path)?
        .as_deref()
        .and_then(keyfile::existing_uuid)
        .unwrap_or_else(keyfile::new_uuid);
    let contents = keyfile::render(payload, &uuid);

    if payload.dry_run {
        return Ok(jsonf! {
            "path": path,
            uuid,
            "keyfile": contents,
            "applied": false,
            payload.dry_run,
        });
    }

    ensure_ethernet(&payload.interface)?;
    let mut response = safe_apply.apply(&Change {
        interface: &payload.interface,
        path: &path,
        uuid: &uuid,
        contents: contents.as_bytes(),
    })?;
    response["uuid"] = uuid.into();
    response["keyfile"] = contents.into();
    response["dry_run"] = false.into();
    Ok(response)
}

fn get_config(payload: &NetworkConfigRequest, dir: &Path) -> Result<Value> {
    let path = validate_keyfile_path(dir, &payload.path)?;
    let contents = read_keyfile(&path)?
        .with_context(|| format!("`{}` does not exist", path.display()))?;
    let contents = String::from_utf8(contents)
        .with_context(|| format!("`{}` is not valid UTF-8", path.display()))?;
    Ok(jsonf! { "path": path, contents })
}

fn set_config(payload: &NetworkWriteConfigRequest, dir: &Path) -> Result<Value> {
    let path = validate_keyfile_path(dir, &payload.path)?;
    // The keyfile always gets its default label; letting a caller choose
    // other paths or types would turn this into a root-run `semanage`.
    if let Some(SelinuxOptions { path: label_path, path_pattern, context_type, .. }) =
        &payload.selinux
    {
        ensure!(
            label_path.is_none() && path_pattern.is_none() && context_type.is_none(),
            "set_config always applies the keyfile's default SELinux label; \
             selinux.path, path_pattern and context_type are not accepted"
        );
    }
    // Only touch the filesystem outside dry-run; SELinux planning below
    // still runs so the response previews the relabel.
    if !payload.dry_run {
        write_keyfile(&path, payload.contents.as_bytes())?;
    }
    let selinux = restorecon(&path, payload.dry_run)?;
    Ok(jsonf! {
        "path": path,
        "written": !payload.dry_run,
        payload.dry_run,
        selinux,
    })
}

/// `restorecon` a keyfile so it gets the policy's default label. Skipped on
/// hosts without SELinux, except in dry-run where it is always previewed.
fn restorecon(path: &Path, dry_run: bool) -> Result<Vec<Value>> {
    if !dry_run && !Path::new("/sys/fs/selinux/enforce").exists() {
        return Ok(Vec::new());
    }
    let path = path.to_string_lossy();
    Ok(vec![crate::cmd!((dry_run) "restorecon" ["-v", &*path] json)?])
}

/// `configure` writes `type=ethernet` profiles; refuse anything else so a
/// wrong interface choice fails up front instead of at activation.
fn ensure_ethernet(interface: &str) -> Result<()> {
    let sysfs = Path::new("/sys/class/net").join(interface);
    ensure!(sysfs.exists(), "interface `{interface}` does not exist");
    let link_type = fs::read_to_string(sysfs.join("type")).unwrap_or_default();
    let has_devtype = fs::read_to_string(sysfs.join("uevent"))
        .unwrap_or_default()
        .lines()
        .any(|line| line.starts_with("DEVTYPE="));
    ensure!(
        link_type.trim() == "1" && !has_devtype && !sysfs.join("wireless").exists(),
        "interface `{interface}` is not an Ethernet device"
    );
    Ok(())
}

/// [`NetworkHost`] backed by `ip`, `nmcli`, and `restorecon`.
struct NetworkManagerHost;

impl NetworkManagerHost {
    fn nmcli(args: &[&str]) -> Result<CommandResult> {
        crate::cmd!("nmcli" => args)
    }
}

impl NetworkHost for NetworkManagerHost {
    fn routable_addresses(&self, interface: &str) -> Result<Vec<IpAddr>> {
        let result = crate::cmd!("ip" ["-json", "addr", "show", "dev", interface])?;
        let data: Value = serde_json::from_str(&result.stdout)
            .context("failed to parse `ip -json addr show` output")?;
        Ok(parse_ip_addr_json(&data)
            .into_iter()
            .filter(|address| address.scope.is_routable())
            .map(|address| address.address)
            .collect())
    }

    fn active_connection(&self, interface: &str) -> Option<String> {
        Self::nmcli(&["-g", "GENERAL.CON-UUID", "device", "show", interface])
            .ok()
            .map(|result| result.stdout.trim().to_owned())
            .filter(|uuid| !uuid.is_empty())
    }

    fn relabel(&self, path: &Path) -> Result<()> {
        restorecon(path, false).map(drop)
    }

    fn load(&self, path: &Path) -> Result<()> {
        Self::nmcli(&["connection", "load", &path.to_string_lossy()]).map(drop)
    }

    fn activate(&self, uuid: &str) -> Result<()> {
        Self::nmcli(&["--wait", "30", "connection", "up", "uuid", uuid]).map(drop)
    }

    fn deactivate(&self, uuid: &str) -> Result<()> {
        Self::nmcli(&["--wait", "30", "connection", "down", "uuid", uuid]).map(drop)
    }

    fn delete(&self, uuid: &str) -> Result<()> {
        Self::nmcli(&["--wait", "30", "connection", "delete", "uuid", uuid]).map(drop)
    }
}

fn read_optional(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_owned())
}

/// Reads the live interface list from `/sys/class/net` sysfs.
///
/// Each entry exposes `operstate` (up/down) and `address` (MAC) as plain text
/// files. Missing attributes are tolerated via `unwrap_or_default` (e.g.
/// virtual or bond devices may not report an operstate), so a single unreadable
/// file does not fail the whole snapshot. Each interface also lists its IPv4
/// and IPv6 `addresses` from `addresses`. Results are sorted by name for stable
/// output to the control plane.
fn read_interfaces(addresses: &[InterfaceAddress]) -> Result<Vec<Value>> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net").context("failed to read /sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let operstate = fs::read_to_string(entry.path().join("operstate"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let address = fs::read_to_string(entry.path().join("address"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let addresses: Vec<_> = addresses
            .iter()
            .filter(|address| address.interface == name)
            .collect();
        interfaces.push(jsonf! { name, operstate, "mac": address, addresses });
    }
    interfaces.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn dns_read_returns_a_stable_shape() {
        let response = Dns.handle(None).unwrap();
        assert!(response.get("resolv_conf").is_some());
    }

    #[test]
    fn configuration_actions_are_privileged() {
        for action in ["configure", "confirm", "get_config", "set_config", "reload"] {
            assert!(INFO.is_privileged(action), "{action}");
            assert!(INFO.actions.contains(&action), "{action}");
        }
    }

    #[test]
    fn dry_run_set_config_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection.nmconnection");
        fs::write(&path, "[connection]\nid=old\n").unwrap();

        let response = set_config(
            &NetworkWriteConfigRequest {
                path: path.clone(),
                contents: "[connection]\nid=new\n".into(),
                dry_run: true,
                selinux: None,
            },
            dir.path(),
        )
        .unwrap();

        assert_eq!(response["written"], false);
        assert_eq!(response["selinux"][0]["command"], format!("restorecon -v {}", path.display()));
        assert_eq!(fs::read_to_string(path).unwrap(), "[connection]\nid=old\n");
    }

    #[test]
    fn set_config_writes_keyfiles_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eth0.nmconnection");
        set_config(
            &NetworkWriteConfigRequest {
                path: path.clone(),
                contents: "[connection]\nid=eth0\n".into(),
                dry_run: false,
                selinux: None,
            },
            dir.path(),
        )
        .unwrap();

        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let response = get_config(&NetworkConfigRequest { path }, dir.path()).unwrap();
        assert_eq!(response["contents"], "[connection]\nid=eth0\n");
    }

    #[test]
    fn raw_config_rejects_paths_outside_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.nmconnection");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("link.nmconnection");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let escape = dir.path().join("../target.nmconnection");

        for path in [
            PathBuf::from("/etc/shadow"),
            PathBuf::from("/etc/NetworkManager/system-connections/eth0.nmconnection"),
            target.clone(),
            link,
            escape,
            dir.path().join("eth0.conf"),
        ] {
            get_config(&NetworkConfigRequest { path: path.clone() }, dir.path()).unwrap_err();
            set_config(
                &NetworkWriteConfigRequest {
                    path: path.clone(),
                    contents: "x".into(),
                    dry_run: false,
                    selinux: None,
                },
                dir.path(),
            )
            .unwrap_err();
        }
        assert_eq!(fs::read_to_string(target).unwrap(), "secret");
    }

    #[test]
    fn set_config_rejects_custom_selinux_targets() {
        let dir = tempfile::tempdir().unwrap();
        let error = set_config(
            &NetworkWriteConfigRequest {
                path: dir.path().join("connection.nmconnection"),
                contents: "[connection]\nid=new\n".into(),
                dry_run: true,
                selinux: Some(SelinuxOptions {
                    context_type: Some("shadow_t".into()),
                    path_pattern: Some("/etc(/.*)?".into()),
                    ..SelinuxOptions::default()
                }),
            },
            dir.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("default SELinux label"));
    }

    #[test]
    fn dry_run_configure_renders_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let payload: NetworkConfigureRequest = serde_json::from_value(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": {
                "method": "manual",
                "addresses": [{ "address": "2001:db8::2", "prefix_length": 64 }],
                "gateway": "fe80::1"
            },
            "dry_run": true
        }))
        .unwrap();

        let response = configure(&payload, dir.path(), &SAFE_APPLY).unwrap();

        assert_eq!(response["path"], dir.path().join("eth0.nmconnection").to_str().unwrap());
        assert_eq!(response["applied"], false);
        let keyfile = response["keyfile"].as_str().unwrap();
        assert!(keyfile.contains("[ipv6]\nmethod=manual\naddress1=2001:db8::2/64\ngateway=fe80::1\n"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn configure_keeps_the_existing_uuid() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("uplink.nmconnection"),
            "[connection]\nid=uplink\nuuid=0b0c3a52-4f43-4b6b-9a54-2d1b0f5e8c11\n",
        )
        .unwrap();
        let payload: NetworkConfigureRequest = serde_json::from_value(json!({
            "interface": "eth0",
            "name": "uplink",
            "dry_run": true
        }))
        .unwrap();

        let response = configure(&payload, dir.path(), &SAFE_APPLY).unwrap();

        assert_eq!(response["uuid"], "0b0c3a52-4f43-4b6b-9a54-2d1b0f5e8c11");
    }

    #[test]
    fn configure_rejects_invalid_requests_before_touching_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let payload: NetworkConfigureRequest = serde_json::from_value(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": { "method": "disabled" }
        }))
        .unwrap();

        configure(&payload, dir.path(), &SAFE_APPLY).unwrap_err();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn interfaces_include_classified_addresses() {
        let addresses = parse_ip_addr_json(&json!([{
            "ifname": "lo",
            "addr_info": [{ "local": "::1", "prefixlen": 128 }]
        }]));
        let interfaces = read_interfaces(&addresses).unwrap();
        let lo = interfaces.iter().find(|i| i["name"] == "lo").unwrap();
        assert_eq!(lo["addresses"][0]["family"], "ipv6");
        assert_eq!(lo["addresses"][0]["scope"], "loopback");
    }

    #[test]
    fn reload_dry_run_does_not_restart_service() {
        let response = Reload(DryRunRequest { dry_run: true })
            .handle(None)
            .unwrap();
        assert_eq!(response["dry_run"], true);
        assert!(response["status"].is_null());
    }
}
