//! Network interface inspection and NetworkManager keyfile management.
//!
//! This module splits host networking into two concerns:
//!
//! - *Live state* (`interfaces`, `status`) is read from `/sys/class/net` sysfs
//!   and `ip -json addr show`, so callers can see what is currently up.
//!   `interfaces` reports each interface's [`InterfaceKind`] (`wifi`,
//!   `ethernet`, or `other`) as `type`. Both report every address with a
//!   scope (`global`, `private`, `ula`, `link-local`, ...) derived from its
//!   prefix; see [`addresses`].
//! - *Persistent configuration* is managed as NetworkManager *keyfiles*:
//!   INI-style `.nmconnection` profiles under
//!   `/etc/NetworkManager/system-connections/`.
//!
//! `configure` is the structured path: it takes an interface plus `ipv4` and
//! `ipv6` sections and optional wired 802.1X settings, validates them
//! ([`keyfile`]), writes the keyfile `0600`
//! with its default SELinux label, loads and activates it, and rolls it back
//! unless confirmed if the interface lost every routable address it had
//! ([`apply`]), through a NetworkManager checkpoint ([`checkpoint`]) so the
//! rollback does not depend on Tetra staying up. `get_config`/`set_config` remain for raw keyfile access, but
//! only for regular `.nmconnection` files directly inside that directory
//! ([`paths`]). All of these are privileged.
//!
//! `scan_wifi` lists the networks a wireless interface can see, and
//! `connect_wifi` writes a Wi-Fi keyfile for it and activates it through the
//! same safe apply, undoing the profile if it does not come up ([`wifi`]).
//! Passwords only ever go into the `0600` keyfile. Both are privileged.

mod addresses;
mod apply;
mod certs;
mod checkpoint;
mod keyfile;
mod paths;
mod wifi;

use std::{
    net::IpAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use serde_json::json;

use crate::prelude::*;

use crate::agent::module_support::{CommandResult, SelinuxOptions, restorecon};
use crate::types::{
    DryRunRequest, NetworkConfigRequest, NetworkConfigureRequest, NetworkConfirmRequest,
    NetworkConnectWifiRequest, NetworkInterfaceRequest, NetworkScanWifiRequest,
    NetworkWriteConfigRequest, WifiSecurity, Wired8021x,
};
use addresses::{InterfaceAddress, parse_ip_addr_json};
use apply::{Change, NetworkHost, SafeApply};
use paths::{SYSTEM_CONNECTIONS_DIR, keyfile_path_for, read_keyfile, validate_keyfile_path, write_keyfile};

/// Marker type for the network module. Stateless apart from the pending
/// rollback held by [`SAFE_APPLY`] (and NetworkManager); all behavior lives in the [`Mod`] impl
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
        "pending",
        "get_config",
        "set_config",
        "reload",
        "scan_wifi",
        "connect_wifi",
    ],
    privileged_actions: &[
        "configure",
        "confirm",
        "pending",
        "get_config",
        "set_config",
        "reload",
        "scan_wifi",
        "connect_wifi",
    ],
};

/// The host's single safe-apply state, shared by `configure` and `confirm`.
static SAFE_APPLY: LazyLock<SafeApply> =
    LazyLock::new(|| SafeApply::new(Arc::new(NetworkManagerHost)));

/// Pick up a network change a previous Tetra left awaiting confirmation.
///
/// Its rollback is re-armed, or done now if it is overdue (see [`apply`]).
/// Every network action does this on first use; calling it at startup also
/// covers a host where none is sent.
pub fn recover_pending() {
    SAFE_APPLY.recover();
}

impl Mod for NetworkModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
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
        Ok(json!({ "interfaces": read_interfaces(Path::new(SYSFS_NET), &addresses).unwrap_or_default() }))
    },
    Status: NetworkInterfaceRequest => {
        // `ip -json addr show` returns structured JSON we pass through
        // verbatim in `data`; an optional `dev <name>` narrows the scope.
        // `addresses` adds a prefix-based scope to every address.
        if let Some(interface) = &payload.interface {
            keyfile::validate_interface(interface)?;
        }
        let args = payload.ip_args();
        let mut response = crate::cmd!({ &INFO, "status", user } "ip" => &args ; JSON)?;
        response["addresses"] = serde_json::to_value(parse_ip_addr_json(&response["data"]))?;
        Ok(response)
    },
    Dns => Ok(json!({ "resolv_conf": read_optional("/etc/resolv.conf") })),
    Routes => crate::cmd!({ &INFO, "routes", user } "ip" ["-json", "route", "show"] JSON),
    Configure: NetworkConfigureRequest => {
        configure(
            &payload,
            Path::new(SYSTEM_CONNECTIONS_DIR),
            Path::new(certs::CERTS_DIR),
            &SAFE_APPLY,
        )
    },
    Confirm: NetworkConfirmRequest => SAFE_APPLY.confirm(&payload.token),
    Pending => Ok(SAFE_APPLY.pending()),
    GetConfig: NetworkConfigRequest => {
        get_config(&payload, Path::new(SYSTEM_CONNECTIONS_DIR))
    },
    SetConfig: NetworkWriteConfigRequest => {
        SAFE_APPLY.ensure_settled(&payload.path)?;
        set_config(&payload, Path::new(SYSTEM_CONNECTIONS_DIR))
    },
    Reload: DryRunRequest => {
        crate::cmd!((payload.dry_run) { &INFO, "reload", user } "systemctl" ["reload-or-restart", "NetworkManager.service"] json)
    },
    ScanWifi: NetworkScanWifiRequest => {
        Ok(json!({ "networks": scan_wifi(&payload.interface, payload.rescan)? }))
    },
    ConnectWifi: NetworkConnectWifiRequest => {
        connect_wifi(
            &payload,
            Path::new(SYSTEM_CONNECTIONS_DIR),
            Path::new(certs::CERTS_DIR),
            &SAFE_APPLY,
            &|interface| scan_wifi(interface, Some(false)),
        )
    },
});

fn scan_wifi(interface: &str, rescan: Option<bool>) -> Result<Vec<wifi::Network>> {
    keyfile::validate_interface(interface)?;
    ensure_wireless(interface)?;
    let rescan = match rescan {
        Some(true) => "yes",
        Some(false) => "no",
        None => "auto",
    };
    let result = crate::cmd!("nmcli" [
        "--terse", "--escape", "yes", "--fields", wifi::SCAN_FIELDS,
        "device", "wifi", "list", "--rescan", rescan, "ifname", interface,
    ])?;
    Ok(wifi::parse_scan(&result.stdout))
}

/// Validate, render, and (outside dry-run) apply a Wi-Fi profile as
/// `wifi-<interface>.nmconnection` in `dir`. `scan` lists the networks the
/// (validated) interface can see, to tell WPA3-only and hidden networks
/// apart, and fails if it is not a Wi-Fi device or cannot scan; it is not
/// run in dry-run, so key management is only decided when connecting.
fn connect_wifi(
    payload: &NetworkConnectWifiRequest,
    dir: &Path,
    certs_dir: &Path,
    safe_apply: &SafeApply,
    scan: &dyn Fn(&str) -> Result<Vec<wifi::Network>>,
) -> Result<Value> {
    keyfile::validate_interface(&payload.interface)?;
    let seen = if payload.dry_run {
        None
    } else {
        scan(&payload.interface)?.into_iter().find(|network| network.ssid == payload.ssid)
    };
    let key_management = if seen.as_ref().is_some_and(|network| network.sae_only) {
        wifi::KeyManagement::Sae
    } else {
        wifi::KeyManagement::WpaPsk
    };
    // A network the scan did not see is probed for, in case it is hidden.
    let hidden = payload.hidden || (!payload.dry_run && seen.is_none());
    // Without a scan, a dry run cannot know whether the network takes SAE,
    // so it only checks the password against SAE's wider rules.
    let checked_as = if payload.dry_run { wifi::KeyManagement::Sae } else { key_management };
    let name = wifi::connection_name(&payload.interface);
    let mut request = payload.clone();
    wifi::validate(&mut request, checked_as, &cert_roots(certs_dir, &name))?;

    let profile = Profile::locate(&name, dir, certs_dir)?;
    let pem_files = profile.externalize(match &mut request.security {
        WifiSecurity::WpaEnterprise(settings) => Some(settings),
        _ => None,
    });
    let contents = wifi::render(&request, key_management, hidden, &profile.uuid);
    let shown = wifi::render_redacted(&request, key_management, hidden, &profile.uuid);

    if payload.dry_run {
        let mut response = profile.dry_run(&shown);
        response["note"] = "nothing was scanned, so key management is decided when connecting: \
                            a network the scan shows as WPA3-only gets key-mgmt=sae (passwords \
                            of 1-128 characters) instead of wpa-psk (8-63), and one it does not \
                            see gets hidden=true"
            .into();
        return Ok(response);
    }

    let response = safe_apply
        .apply_or_revert(&profile.change(&payload.interface, &contents, &pem_files))
        .with_context(|| format!("could not connect to `{}`", payload.ssid))?;
    let mut response = profile.finish(response, shown);
    response["ssid"] = payload.ssid.clone().into();
    response["security"] = match &payload.security {
        WifiSecurity::Open {} => "open",
        WifiSecurity::WpaPersonal { .. } => "wpa-personal",
        WifiSecurity::WpaEnterprise(_) => "wpa-enterprise",
    }
    .into();
    Ok(response)
}

/// Validate, render, and (outside dry-run) safely apply a structured
/// configuration as the keyfile `<name>.nmconnection` in `dir`.
fn configure(
    payload: &NetworkConfigureRequest,
    dir: &Path,
    certs_dir: &Path,
    safe_apply: &SafeApply,
) -> Result<Value> {
    let name = keyfile::connection_name(payload);
    let mut request = payload.clone();
    keyfile::validate(&mut request, &cert_roots(certs_dir, name))?;
    let profile = Profile::locate(name, dir, certs_dir)?;
    let pem_files = profile.externalize(request.wired_8021x.as_deref_mut());
    let contents = keyfile::render(&request, &profile.uuid);
    let shown = keyfile::render_redacted(&request, &profile.uuid);

    if payload.dry_run {
        return Ok(profile.dry_run(&shown));
    }

    ensure_ethernet(&payload.interface)?;
    let response = safe_apply.apply(&profile.change(&payload.interface, &contents, &pem_files))?;
    Ok(profile.finish(response, shown))
}

/// Where `profile`'s 802.1X certificate and key paths may point: the
/// host's certificate store, except other profiles' directories in
/// `certs_dir`, the one Tetra keeps PEM contents in (inside it, except in
/// tests).
fn cert_roots<'a>(certs_dir: &'a Path, profile: &'a str) -> keyfile::CertRoots<'a> {
    keyfile::CertRoots { pki: Path::new(keyfile::PKI_DIR), tetra: certs_dir, profile }
}

/// A connection profile `configure` or `connect_wifi` writes.
struct Profile {
    /// Its keyfile.
    path: PathBuf,
    /// Its UUID: the existing profile's, or a new one. Rewriting a profile
    /// keeps its UUID, so NetworkManager treats it as the same connection
    /// rather than a new one.
    uuid: String,
    /// Where its PEM contents are stored ([`certs`]).
    certs: PathBuf,
}

impl Profile {
    /// The profile `name`, with its keyfile in `dir` and its certificates
    /// in `certs_dir`.
    fn locate(name: &str, dir: &Path, certs_dir: &Path) -> Result<Self> {
        let path = keyfile_path_for(dir, name)?;
        let uuid = read_keyfile(&path)?
            .as_deref()
            .and_then(keyfile::existing_uuid)
            .unwrap_or_else(keyfile::new_uuid);
        Ok(Self { path, uuid, certs: certs_dir.join(name) })
    }

    /// Point `settings`' PEM contents at the files they are stored as,
    /// returning those files for [`SafeApply`] to write.
    fn externalize(&self, settings: Option<&mut Wired8021x>) -> Vec<certs::PemFile> {
        settings
            .map(|settings| certs::externalize(settings, &self.certs))
            .unwrap_or_default()
    }

    /// The change writing `contents` (and `pem_files`) as this profile.
    fn change<'a>(
        &'a self,
        interface: &'a str,
        contents: &'a str,
        pem_files: &'a [certs::PemFile],
    ) -> Change<'a> {
        Change {
            interface,
            path: &self.path,
            uuid: &self.uuid,
            contents: contents.as_bytes(),
            certs: Some(&self.certs),
            pem_files,
        }
    }

    /// A dry run's response: where the profile would go and, with
    /// passwords redacted, what it would hold. PEM contents would be
    /// stored as files, which `keyfile` already points at.
    fn dry_run(self, keyfile: &str) -> Value {
        json!({ "path": self.path, "uuid": self.uuid, "keyfile": keyfile, "applied": false, "dry_run": true })
    }

    /// Completes [`SafeApply`]'s response with the profile's UUID and
    /// redacted keyfile.
    fn finish(self, mut response: Value, keyfile: String) -> Value {
        response["uuid"] = self.uuid.into();
        response["keyfile"] = keyfile.into();
        response["dry_run"] = false.into();
        response
    }
}

fn get_config(payload: &NetworkConfigRequest, dir: &Path) -> Result<Value> {
    let path = validate_keyfile_path(dir, &payload.path)?;
    let contents = read_keyfile(&path)?
        .with_context(|| format!("`{}` does not exist", path.display()))?;
    let contents = String::from_utf8(contents)
        .with_context(|| format!("`{}` is not valid UTF-8", path.display()))?;
    Ok(json!({ "path": path, "contents": contents }))
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
    let selinux = restorecon(&path, &["-v"], payload.dry_run)?;
    Ok(json!({
        "path": path,
        "written": !payload.dry_run,
        "dry_run": payload.dry_run,
        "selinux": selinux,
    }))
}


/// Where the kernel lists network interfaces.
const SYSFS_NET: &str = "/sys/class/net";

/// What kind of device an interface is, as reported in `interfaces` and
/// checked by `configure` (Ethernet) and the Wi-Fi actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum InterfaceKind {
    /// A wireless (cfg80211) device.
    Wifi,
    /// A physical Ethernet device: link type `ARPHRD_ETHER`, backed by a
    /// device, with no `DEVTYPE` (so not wireless, WWAN, a VLAN, ...).
    Ethernet,
    /// Anything else: loopback, bridges, bonds, VLANs, veth, tun, WWAN
    /// modems, and other links.
    Other,
}

/// Classifies the interface whose sysfs directory is `dir`
/// (`/sys/class/net/<interface>`). Missing attributes count as absent.
fn interface_kind(dir: &Path) -> InterfaceKind {
    let uevent = fs::read_to_string(dir.join("uevent")).unwrap_or_default();
    let devtype = uevent.lines().find_map(|line| line.strip_prefix("DEVTYPE="));
    if devtype == Some("wlan") || dir.join("wireless").exists() || dir.join("phy80211").exists() {
        return InterfaceKind::Wifi;
    }
    // `type` 1 is ARPHRD_ETHER; only physical devices have a `device` link.
    // Any `DEVTYPE` (`wwan`, `vlan`, `bridge`, `bond`, ...) means something
    // other than plain Ethernet, even with a device behind it.
    let link_type = fs::read_to_string(dir.join("type")).unwrap_or_default();
    if devtype.is_none() && link_type.trim() == "1" && dir.join("device").exists() {
        return InterfaceKind::Ethernet;
    }
    InterfaceKind::Other
}

/// Classifies `interface`, failing if the host has no such interface.
fn existing_interface_kind(interface: &str) -> Result<InterfaceKind> {
    let dir = Path::new(SYSFS_NET).join(interface);
    ensure!(dir.exists(), "interface `{interface}` does not exist");
    Ok(interface_kind(&dir))
}

/// `configure` writes `type=ethernet` profiles; refuse anything else so a
/// wrong interface choice fails up front instead of at activation.
fn ensure_ethernet(interface: &str) -> Result<()> {
    ensure!(
        existing_interface_kind(interface)? == InterfaceKind::Ethernet,
        "interface `{interface}` is not an Ethernet device"
    );
    Ok(())
}

/// `scan_wifi` and `connect_wifi` need a wireless device.
fn ensure_wireless(interface: &str) -> Result<()> {
    ensure!(
        existing_interface_kind(interface)? == InterfaceKind::Wifi,
        "interface `{interface}` is not a Wi-Fi device"
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

    fn default_gateways(&self, interface: &str) -> Result<Vec<IpAddr>> {
        let mut gateways = Vec::new();
        for family in ["-4", "-6"] {
            let result =
                crate::cmd!("ip" ["-json", family, "route", "show", "default", "dev", interface])?;
            let routes: Value = serde_json::from_str(&result.stdout)
                .context("failed to parse `ip -json route show` output")?;
            gateways.extend(
                routes
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|route| route["gateway"].as_str()?.parse::<IpAddr>().ok()),
            );
        }
        Ok(gateways)
    }

    fn active_connection(&self, interface: &str) -> Option<String> {
        Self::nmcli(&["-g", "GENERAL.CON-UUID", "device", "show", interface])
            .ok()
            .map(|result| result.stdout.trim().to_owned())
            .filter(|uuid| !uuid.is_empty())
    }

    fn relabel(&self, path: &Path) -> Result<()> {
        restorecon(path, &["-v"], false).map(drop)
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

    fn checkpoint_create(&self, interface: &str, timeout: Duration) -> Result<String> {
        checkpoint::create(interface, whole_seconds(timeout))
    }

    fn checkpoint_adjust(&self, checkpoint: &str, timeout: Duration) -> Result<()> {
        checkpoint::adjust_timeout(checkpoint, whole_seconds(timeout))
    }

    fn checkpoint_destroy(&self, checkpoint: &str) -> Result<()> {
        checkpoint::destroy(checkpoint)
    }

    fn checkpoint_rollback(&self, checkpoint: &str) -> Result<()> {
        checkpoint::rollback(checkpoint)
    }

    fn checkpoints(&self) -> Result<Vec<String>> {
        checkpoint::list()
    }
}

/// `duration` in whole seconds for NetworkManager, at least one: zero
/// would mean no timeout.
fn whole_seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX).max(1)
}

fn read_optional(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_owned())
}

/// Reads the live interface list from `sysfs_root` (`/sys/class/net`).
///
/// Each entry exposes `operstate` (up/down) and `address` (MAC) as plain text
/// files. Missing attributes are tolerated via `unwrap_or_default` (e.g.
/// virtual or bond devices may not report an operstate), so a single unreadable
/// file does not fail the whole snapshot. Each interface also reports its
/// [`InterfaceKind`] as `type` and lists its IPv4 and IPv6 `addresses` from
/// `addresses`. Results are sorted by name for stable output to the control
/// plane.
fn read_interfaces(sysfs_root: &Path, addresses: &[InterfaceAddress]) -> Result<Vec<Value>> {
    let mut interfaces = Vec::new();
    let entries = fs::read_dir(sysfs_root)
        .with_context(|| format!("failed to read {}", sysfs_root.display()))?;
    for entry in entries {
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
        let kind = interface_kind(&entry.path());
        interfaces.push(json!({ "name": name, "type": kind, "operstate": operstate, "mac": address, "addresses": addresses }));
    }
    interfaces.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use super::*;
    use apply::fake::FakeHost;

    /// Safe apply on `host`, keeping its state in `dir`.
    fn test_apply(host: &Arc<FakeHost>, dir: &Path) -> SafeApply {
        SafeApply::with_state(
            Arc::clone(host) as Arc<dyn NetworkHost>,
            dir.join("state/pending.json"),
        )
    }

    #[test]
    fn dns_read_returns_a_stable_shape() {
        let response = Dns {}.handle(None).unwrap();
        assert!(response.get("resolv_conf").is_some());
    }

    #[test]
    fn configuration_actions_are_privileged() {
        for action in [
            "configure",
            "confirm",
            "pending",
            "get_config",
            "set_config",
            "reload",
            "scan_wifi",
            "connect_wifi",
        ] {
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

        let response = configure(&payload, dir.path(), &dir.path().join("certs"), &SAFE_APPLY).unwrap();

        assert_eq!(response["path"], dir.path().join("eth0.nmconnection").to_str().unwrap());
        assert_eq!(response["applied"], false);
        let keyfile = response["keyfile"].as_str().unwrap();
        assert!(keyfile.contains("[ipv6]\nmethod=manual\naddress1=2001:db8::2/64\ngateway=fe80::1\n"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn configure_responses_do_not_echo_8021x_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let payload: NetworkConfigureRequest = serde_json::from_value(json!({
            "interface": "eth0",
            "wired_8021x": { "eap": "peap", "identity": "alice", "password": "hunter2-8021x" },
            "dry_run": true
        }))
        .unwrap();

        let response = configure(&payload, dir.path(), &dir.path().join("certs"), &SAFE_APPLY).unwrap();

        let keyfile = response["keyfile"].as_str().unwrap();
        assert!(keyfile.contains("[802-1x]\neap=peap;\nidentity=alice\npassword=<redacted>\n"));
        assert!(!response.to_string().contains("hunter2-8021x"));
    }

    fn wifi_request(ssid: &str, password: &str) -> NetworkConnectWifiRequest {
        serde_json::from_value(json!({
            "interface": "wlan0",
            "ssid": ssid,
            "security": {"type": "wpa-personal", "password": password},
        }))
        .unwrap()
    }

    fn seen(ssid: &str, sae_only: bool) -> Vec<wifi::Network> {
        wifi::parse_scan(&format!(
            " :{}:80:2437 MHz:WPA3:(none):pair_ccmp {}",
            ssid.bytes().map(|byte| format!("{byte:02X}")).join(""),
            if sae_only { "sae" } else { "psk sae" }
        ))
    }

    #[test]
    fn connect_wifi_writes_the_passphrase_only_to_the_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let host = FakeHost::with(&[], None);
        let apply = test_apply(&host, dir.path());
        let request = wifi_request("Home", "wifi-S3CRET-pass");

        let response =
            connect_wifi(&request, dir.path(), &dir.path().join("certs"), &apply, &|_| Ok(seen("Home", true))).unwrap();

        let path = dir.path().join("wifi-wlan0.nmconnection");
        let keyfile = fs::read_to_string(&path).unwrap();
        assert!(keyfile.contains("key-mgmt=sae\npsk=wifi-S3CRET-pass\n"), "{keyfile}");
        assert!(!keyfile.contains("hidden"));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!response.to_string().contains("S3CRET"), "{response}");
        assert_eq!(response["ssid"], "Home");
        assert_eq!(response["security"], "wpa-personal");
        let uuid = response["uuid"].as_str().unwrap();
        assert_eq!(host.calls(), ["load".to_owned(), format!("up {uuid}")]);

        // Reconnecting keeps the profile; a network missing from the scan
        // is probed for as hidden, with WPA-PSK.
        let again = connect_wifi(&wifi_request("Attic", "another-pass"), dir.path(), &dir.path().join("certs"), &apply, &|_| {
            Ok(seen("Home", false))
        })
        .unwrap();
        assert_eq!(again["uuid"], uuid);
        let keyfile = fs::read_to_string(&path).unwrap();
        assert!(keyfile.contains("hidden=true\n"));
        assert!(keyfile.contains("key-mgmt=wpa-psk\npsk=another-pass\n"));
    }

    #[test]
    fn a_failed_scan_fails_the_connection_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let host = FakeHost::with(&[], None);
        let apply = test_apply(&host, dir.path());

        let error = connect_wifi(
            &wifi_request("Home", "wifi-S3CRET-pass"),
            dir.path(),
            &dir.path().join("certs"),
            &apply,
            &|_| bail!("nmcli: Wi-Fi radio is off"),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("radio is off"), "{error:#}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(host.calls().is_empty());
    }

    #[test]
    fn connect_wifi_checks_the_interface_name_before_scanning() {
        let dir = tempfile::tempdir().unwrap();
        let mut request = wifi_request("Home", "wifi-S3CRET-pass");
        request.interface = "../wlan0".into();

        let error = connect_wifi(&request, dir.path(), &dir.path().join("certs"), &SAFE_APPLY, &|_| {
            panic!("scanned an invalid interface")
        })
        .unwrap_err();

        assert!(error.to_string().contains("not a valid interface name"), "{error}");
    }

    #[test]
    fn wifi_profiles_cannot_use_another_profiles_stored_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        let other = certs.join("eth0/ca-cert.pem");
        fs::create_dir_all(other.parent().unwrap()).unwrap();
        fs::write(&other, PEM_CA).unwrap();
        let mut request = enterprise_request();
        let WifiSecurity::WpaEnterprise(settings) = &mut request.security else { unreachable!() };
        settings.ca_cert = Some(other.to_string_lossy().into_owned());

        let error = connect_wifi(&request, dir.path(), &certs, &SAFE_APPLY, &|_| Ok(Vec::new()))
            .unwrap_err();

        assert!(error.to_string().contains("another profile's directory"), "{error}");
        assert!(!dir.path().join("wifi-wlan0.nmconnection").exists());
    }

    #[test]
    fn a_wifi_profile_that_does_not_come_up_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let host = FakeHost::with(&[], None);
        host.fail_every_activation();
        let apply = test_apply(&host, dir.path());

        let error = connect_wifi(
            &wifi_request("Home", "wrong-S3CRET-pass"),
            dir.path(),
            &dir.path().join("certs"),
            &apply,
            &|_| Ok(seen("Home", false)),
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("could not connect to `Home`"), "{message}");
        assert!(!message.contains("S3CRET"), "{message}");
        assert!(!dir.path().join("wifi-wlan0.nmconnection").exists());
        assert!(host.calls().last().unwrap().starts_with("delete "));
    }

    const PEM_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nMIIBVQ-S3CRET-key\n-----END PRIVATE KEY-----\n";
    const PEM_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBca\n-----END CERTIFICATE-----\n";

    fn enterprise_request() -> NetworkConnectWifiRequest {
        serde_json::from_value(json!({
            "interface": "wlan0",
            "ssid": "Corp",
            "security": {
                "type": "wpa-enterprise",
                "eap": "tls",
                "identity": "host/server",
                "ca_cert": PEM_CA,
                "client_cert": PEM_CA,
                "private_key": PEM_KEY,
                "private_key_password": "key-S3CRET-pass",
                "domain_suffix_match": "radius.example.com",
            },
        }))
        .unwrap()
    }

    #[test]
    fn enterprise_wifi_stores_pem_files_and_points_the_keyfile_at_them() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        let host = FakeHost::with(&[], None);
        let apply = test_apply(&host, dir.path());

        let response =
            connect_wifi(&enterprise_request(), dir.path(), &certs, &apply, &|_| Ok(Vec::new()))
                .unwrap();

        let keyfile = fs::read_to_string(dir.path().join("wifi-wlan0.nmconnection")).unwrap();
        let profile_certs = certs.join("wifi-wlan0");
        let key = fs::read_dir(&profile_certs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.file_name().unwrap().to_string_lossy().starts_with("private-key-"))
            .unwrap();
        assert_eq!(fs::read_to_string(&key).unwrap(), PEM_KEY);
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&profile_certs).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(keyfile.contains(&format!("private-key={}\n", key.display())), "{keyfile}");
        assert!(keyfile.contains("domain-suffix-match=radius.example.com\n"));
        assert!(keyfile.contains("private-key-password=key-S3CRET-pass\n"));
        assert!(!keyfile.contains("BEGIN"));
        // Neither the key nor its password reaches the response.
        assert!(!response.to_string().contains("S3CRET"), "{response}");
        assert!(!format!("{:?}", enterprise_request()).contains("S3CRET"));

        // Switching to a network without certificates removes them once the
        // change settles.
        connect_wifi(&wifi_request("Home", "another-pass"), dir.path(), &certs, &apply, &|_| {
            Ok(Vec::new())
        })
        .unwrap();
        assert!(!profile_certs.exists());
    }

    #[test]
    fn certificates_of_a_profile_that_does_not_come_up_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        let host = FakeHost::with(&[], None);
        host.fail_every_activation();
        let apply = test_apply(&host, dir.path());

        let error =
            connect_wifi(&enterprise_request(), dir.path(), &certs, &apply, &|_| Ok(Vec::new()))
                .unwrap_err();

        assert!(!format!("{error:#}").contains("S3CRET"));
        assert!(!certs.join("wifi-wlan0").exists());
    }

    #[test]
    fn dry_run_configure_shows_where_wired_pem_files_would_go() {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        let payload: NetworkConfigureRequest = serde_json::from_value(json!({
            "interface": "eth0",
            "wired_8021x": {
                "eap": "peap",
                "identity": "alice",
                "password": "hunter2-8021x",
                "ca_cert": PEM_CA,
                "domain_suffix_match": "Example.COM",
            },
            "dry_run": true
        }))
        .unwrap();

        let response = configure(&payload, dir.path(), &certs, &SAFE_APPLY).unwrap();

        let keyfile = response["keyfile"].as_str().unwrap();
        assert!(
            keyfile.contains(&format!("ca-cert={}", certs.join("eth0/ca-cert-").display())),
            "{keyfile}"
        );
        assert!(keyfile.contains("domain-suffix-match=example.com\n"));
        assert!(!certs.exists());
    }

    #[test]
    fn dry_run_connect_wifi_does_not_scan_or_write() {
        let dir = tempfile::tempdir().unwrap();
        // Too short for WPA-PSK, but a WPA3-only network would take it.
        for password in ["wifi-S3CRET-pass", "S3CRET"] {
            let request: NetworkConnectWifiRequest = serde_json::from_value(json!({
                "interface": "wlan0",
                "ssid": "Home",
                "security": {"type": "wpa-personal", "password": password},
                "dry_run": true,
            }))
            .unwrap();

            let response = connect_wifi(&request, dir.path(), &dir.path().join("certs"), &SAFE_APPLY, &|_| {
                panic!("dry run scanned")
            })
            .unwrap();

            assert_eq!(response["applied"], false);
            assert!(response["note"].as_str().unwrap().contains("key-mgmt=sae"));
            assert!(response["keyfile"].as_str().unwrap().contains("psk=<redacted>"));
            assert!(!response.to_string().contains("S3CRET"));
            assert!(!dir.path().join("wifi-wlan0.nmconnection").exists());
        }
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

        let response = configure(&payload, dir.path(), &dir.path().join("certs"), &SAFE_APPLY).unwrap();

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

        configure(&payload, dir.path(), &dir.path().join("certs"), &SAFE_APPLY).unwrap_err();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Builds a fake sysfs whose `class/net` (the returned path) holds a
    /// Wi-Fi card, a physical NIC, a USB modem, a veth, a bridge, a tun,
    /// and loopback,
    /// laid out like the kernel's.
    fn fake_sysfs() -> (tempfile::TempDir, PathBuf) {
        let sysfs = tempfile::tempdir().unwrap();
        let net = sysfs.path().join("class/net");
        let devices = sysfs.path().join("devices");
        let iface = |name: &str, link_type: &str, uevent: &str, device: bool, extra: &[&str]| {
            let dir = net.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("type"), format!("{link_type}\n")).unwrap();
            fs::write(dir.join("uevent"), format!("INTERFACE={name}\n{uevent}")).unwrap();
            fs::write(dir.join("operstate"), "up\n").unwrap();
            if device {
                let target = devices.join(name);
                fs::create_dir_all(&target).unwrap();
                std::os::unix::fs::symlink(&target, dir.join("device")).unwrap();
            }
            for entry in extra {
                fs::create_dir_all(dir.join(entry)).unwrap();
            }
        };
        iface("wlan0", "1", "DEVTYPE=wlan\n", true, &["wireless", "phy80211"]);
        iface("enp1s0", "1", "", true, &[]);
        iface("veth0", "1", "", false, &[]);
        iface("wwan0", "1", "DEVTYPE=wwan\n", true, &[]);
        iface("br0", "1", "DEVTYPE=bridge\n", false, &["bridge"]);
        iface("tailscale0", "65534", "", false, &[]);
        iface("lo", "772", "", false, &[]);
        (sysfs, net)
    }

    #[test]
    fn interface_kind_tells_wifi_ethernet_and_virtual_links_apart() {
        let (_sysfs, net) = fake_sysfs();
        let kind = |name: &str| interface_kind(&net.join(name));
        assert_eq!(kind("wlan0"), InterfaceKind::Wifi);
        assert_eq!(kind("enp1s0"), InterfaceKind::Ethernet);
        assert_eq!(kind("veth0"), InterfaceKind::Other);
        // A WWAN modem is a device with an Ethernet link type, but no NIC.
        assert_eq!(kind("wwan0"), InterfaceKind::Other);
        assert_eq!(kind("br0"), InterfaceKind::Other);
        assert_eq!(kind("tailscale0"), InterfaceKind::Other);
        assert_eq!(kind("lo"), InterfaceKind::Other);
    }

    #[test]
    fn interfaces_include_type_and_classified_addresses() {
        let (_sysfs, net) = fake_sysfs();
        let addresses = parse_ip_addr_json(&json!([{
            "ifname": "lo",
            "addr_info": [{ "local": "::1", "prefixlen": 128 }]
        }]));
        let interfaces = read_interfaces(&net, &addresses).unwrap();
        let names: Vec<_> = interfaces.iter().map(|i| i["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["br0", "enp1s0", "lo", "tailscale0", "veth0", "wlan0", "wwan0"]);
        let by_name = |name: &str| interfaces.iter().find(|i| i["name"] == name).unwrap();
        assert_eq!(by_name("lo")["type"], "other");
        assert_eq!(by_name("lo")["operstate"], "up");
        assert_eq!(by_name("lo")["addresses"][0]["family"], "ipv6");
        assert_eq!(by_name("lo")["addresses"][0]["scope"], "loopback");
        assert_eq!(by_name("wlan0")["type"], "wifi");
        assert_eq!(by_name("enp1s0")["type"], "ethernet");
        assert_eq!(by_name("veth0")["type"], "other");
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
