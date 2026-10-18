//! Validation and rendering of `network.configure` requests into
//! NetworkManager keyfiles.
//!
//! Everything a caller sends is checked here before any file is written: the
//! interface and profile names, each family's method, every address, prefix,
//! gateway, and DNS server, and that the result still leaves the host with at
//! least one routable address. Rendering is a pure function of the validated
//! request, so it is unit tested without touching the host.

use std::{
    collections::HashSet,
    fmt::{Display, Write as _},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use rand::RngExt as _;

use super::addresses::AddressScope;
use crate::prelude::*;
use crate::types::{IpAddressConfig, IpConfig, Ipv4Method, Ipv6Method, NetworkConfigureRequest};

/// Upper bound on addresses per family, to keep payloads reasonable.
const MAX_ADDRESSES: usize = 32;
/// Upper bound on DNS servers per family.
const MAX_DNS_SERVERS: usize = 8;
/// Linux `IFNAMSIZ` minus the trailing NUL.
const MAX_INTERFACE_LEN: usize = 15;
const MAX_NAME_LEN: usize = 64;

/// An address family as it appears in a `network.configure` payload.
trait Family: Copy + Display + Eq + Hash {
    const LABEL: &'static str;
    const MAX_PREFIX: u8;

    fn ip(self) -> IpAddr;

    /// Family-specific checks on a manually assigned address.
    fn check_host(self, _prefix_length: u8) -> Result<()> {
        Ok(())
    }
}

impl Family for Ipv4Addr {
    const LABEL: &'static str = "ipv4";
    const MAX_PREFIX: u8 = 32;

    fn ip(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn check_host(self, prefix_length: u8) -> Result<()> {
        // /31 and /32 have no network or broadcast address (RFC 3021).
        if prefix_length <= 30 {
            let host_bits = u32::MAX
                .checked_shr(u32::from(prefix_length))
                .unwrap_or_default();
            let host = u32::from(self) & host_bits;
            ensure!(
                host != 0 && host != host_bits,
                "ipv4 address {self}/{prefix_length} is the network or broadcast address"
            );
        }
        Ok(())
    }
}

impl Family for Ipv6Addr {
    const LABEL: &'static str = "ipv6";
    const MAX_PREFIX: u8 = 128;

    fn ip(self) -> IpAddr {
        IpAddr::V6(self)
    }
}

/// A family's `method` as it appears in a `network.configure` payload.
trait Method: Copy {
    /// The NetworkManager `method=` value.
    fn keyword(self) -> &'static str;
    fn is_manual(self) -> bool;
    /// Whether the method obtains routable addresses on its own.
    fn is_dynamic(self) -> bool;
    /// Whether static DNS servers make sense with this method.
    fn allows_dns(self) -> bool;
}

impl Method for Ipv4Method {
    fn keyword(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        }
    }

    fn is_manual(self) -> bool {
        self == Self::Manual
    }

    fn is_dynamic(self) -> bool {
        self == Self::Auto
    }

    fn allows_dns(self) -> bool {
        self != Self::Disabled
    }
}

impl Method for Ipv6Method {
    fn keyword(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dhcp => "dhcp",
            Self::Manual => "manual",
            Self::LinkLocal => "link-local",
            Self::Disabled => "disabled",
        }
    }

    fn is_manual(self) -> bool {
        self == Self::Manual
    }

    fn is_dynamic(self) -> bool {
        matches!(self, Self::Auto | Self::Dhcp)
    }

    fn allows_dns(self) -> bool {
        matches!(self, Self::Auto | Self::Dhcp | Self::Manual)
    }
}

/// The connection profile name for a request: `name`, or the interface.
#[must_use]
pub fn connection_name(request: &NetworkConfigureRequest) -> &str {
    request.name.as_deref().unwrap_or(&request.interface)
}

/// Validate a `network.configure` request without touching the host.
///
/// # Errors
/// Errs with a message naming the offending field.
pub fn validate(request: &NetworkConfigureRequest) -> Result<()> {
    validate_interface(&request.interface)?;
    if let Some(name) = &request.name {
        validate_name(name)?;
    }
    let ipv4_routable = validate_family(&request.ipv4)?;
    let ipv6_routable = validate_family(&request.ipv6)?;
    ensure!(
        ipv4_routable || ipv6_routable,
        "at least one of ipv4 or ipv6 must give the host a routable address \
         (ipv4 is {}, ipv6 is {})",
        request.ipv4.method.keyword(),
        request.ipv6.method.keyword(),
    );
    Ok(())
}

fn validate_interface(interface: &str) -> Result<()> {
    ensure!(
        (1..=MAX_INTERFACE_LEN).contains(&interface.len())
            && interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && !interface.starts_with(['-', '.']),
        "interface `{interface}` is not a valid interface name"
    );
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        (1..=MAX_NAME_LEN).contains(&name.len())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && !name.starts_with(['-', '.'])
            && !name.contains(".."),
        "name `{name}` must be 1-{MAX_NAME_LEN} letters, digits, `-`, `_` or `.`"
    );
    Ok(())
}

/// Validate one family's section, returning whether it gives the host a
/// routable address.
fn validate_family<M: Method, A: Family>(config: &IpConfig<M, A>) -> Result<bool> {
    let label = A::LABEL;
    let method = config.method.keyword();

    if config.method.is_manual() {
        ensure!(
            !config.addresses.is_empty(),
            "{label}.addresses is required when {label}.method is manual"
        );
        ensure!(
            config.addresses.len() <= MAX_ADDRESSES,
            "{label}.addresses allows at most {MAX_ADDRESSES} entries"
        );
        for IpAddressConfig { address, prefix_length } in &config.addresses {
            ensure!(
                (1..=A::MAX_PREFIX).contains(prefix_length),
                "{label} prefix_length for {address} must be between 1 and {}",
                A::MAX_PREFIX
            );
            ensure!(
                !matches!(
                    AddressScope::of(address.ip()),
                    AddressScope::Unspecified | AddressScope::Loopback | AddressScope::Multicast
                ),
                "{label} address {address} cannot be assigned to an interface"
            );
            address.check_host(*prefix_length)?;
        }
        ensure_unique(config.addresses.iter().map(|a| a.address), label, "address")?;
        if let Some(gateway) = config.gateway {
            ensure!(
                !matches!(
                    AddressScope::of(gateway.ip()),
                    AddressScope::Unspecified | AddressScope::Loopback | AddressScope::Multicast
                ),
                "{label}.gateway {gateway} is not a usable gateway"
            );
            ensure!(
                config.addresses.iter().all(|a| a.address != gateway),
                "{label}.gateway {gateway} is one of the host's own addresses"
            );
        }
    } else {
        ensure!(
            config.addresses.is_empty(),
            "{label}.addresses is only allowed when {label}.method is manual (it is {method})"
        );
        ensure!(
            config.gateway.is_none(),
            "{label}.gateway is only allowed when {label}.method is manual (it is {method})"
        );
    }

    ensure!(
        config.method.allows_dns() || config.dns.is_empty(),
        "{label}.dns is not allowed when {label}.method is {method}"
    );
    ensure!(
        config.dns.len() <= MAX_DNS_SERVERS,
        "{label}.dns allows at most {MAX_DNS_SERVERS} servers"
    );
    for server in &config.dns {
        ensure!(
            !matches!(
                AddressScope::of(server.ip()),
                AddressScope::Unspecified | AddressScope::Multicast
            ),
            "{label}.dns server {server} is not a usable DNS server"
        );
    }
    ensure_unique(config.dns.iter().copied(), label, "DNS server")?;

    Ok(config.method.is_dynamic()
        || (config.method.is_manual()
            && config
                .addresses
                .iter()
                .any(|a| AddressScope::of(a.address.ip()).is_routable())))
}

fn ensure_unique<A: Family>(values: impl Iterator<Item = A>, label: &str, what: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        ensure!(seen.insert(value), "{label} {what} {value} is listed twice");
    }
    Ok(())
}

/// Render a validated request into keyfile contents.
#[must_use]
pub fn render(request: &NetworkConfigureRequest, uuid: &str) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ok: std::fmt::Result = (|| {
        writeln!(out, "# Managed by Tetra (network.configure).")?;
        writeln!(out, "[connection]")?;
        writeln!(out, "id={}", connection_name(request))?;
        writeln!(out, "uuid={uuid}")?;
        writeln!(out, "type=ethernet")?;
        writeln!(out, "interface-name={}", request.interface)?;
        writeln!(out, "autoconnect=true")?;
        writeln!(out)?;
        writeln!(out, "[ethernet]")?;
        writeln!(out)?;
        render_family(&mut out, &request.ipv4)?;
        writeln!(out)?;
        render_family(&mut out, &request.ipv6)
    })();
    out
}

fn render_family<M: Method, A: Family>(
    out: &mut String,
    config: &IpConfig<M, A>,
) -> std::fmt::Result {
    writeln!(out, "[{}]", A::LABEL)?;
    writeln!(out, "method={}", config.method.keyword())?;
    for (index, IpAddressConfig { address, prefix_length }) in
        (1_usize..).zip(&config.addresses)
    {
        writeln!(out, "address{index}={address}/{prefix_length}")?;
    }
    if let Some(gateway) = config.gateway {
        writeln!(out, "gateway={gateway}")?;
    }
    if !config.dns.is_empty() {
        writeln!(out, "dns={};", config.dns.iter().join(";"))?;
    }
    Ok(())
}

/// The `uuid` of an existing keyfile's `[connection]` section, so rewriting
/// a profile keeps its identity.
#[must_use]
pub fn existing_uuid(contents: &[u8]) -> Option<String> {
    let contents = std::str::from_utf8(contents).ok()?;
    let mut in_connection = false;
    for line in contents.lines().map(str::trim) {
        if line.starts_with('[') {
            in_connection = line == "[connection]";
        } else if in_connection
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "uuid"
        {
            let value = value.trim();
            return is_uuid(value).then(|| value.to_ascii_lowercase());
        }
    }
    None
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// A random (version 4) UUID for a new profile.
#[must_use]
pub fn new_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes[..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.iter().map(|byte| format!("{byte:02x}")).join("");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const UUID: &str = "0b0c3a52-4f43-4b6b-9a54-2d1b0f5e8c11";

    fn request(value: Value) -> NetworkConfigureRequest {
        serde_json::from_value(value).unwrap()
    }

    fn rendered(value: Value) -> String {
        let request = request(value);
        validate(&request).unwrap();
        render(&request, UUID)
    }

    fn rejection(value: Value) -> String {
        match serde_json::from_value::<NetworkConfigureRequest>(value) {
            Ok(request) => validate(&request).unwrap_err().to_string(),
            Err(error) => error.to_string(),
        }
    }

    fn header(interface: &str) -> String {
        format!(
            "# Managed by Tetra (network.configure).\n[connection]\nid={interface}\nuuid={UUID}\n\
             type=ethernet\ninterface-name={interface}\nautoconnect=true\n\n[ethernet]\n\n"
        )
    }

    // IPv4-only.

    #[test]
    fn ipv4_auto_only() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "auto" },
            "ipv6": { "method": "disabled" }
        }));
        assert_eq!(
            keyfile,
            header("eth0") + "[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=disabled\n"
        );
    }

    #[test]
    fn ipv4_auto_with_static_dns() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "auto", "dns": ["1.1.1.1", "9.9.9.9"] },
            "ipv6": { "method": "link-local" }
        }));
        assert!(keyfile.ends_with(
            "[ipv4]\nmethod=auto\ndns=1.1.1.1;9.9.9.9;\n\n[ipv6]\nmethod=link-local\n"
        ));
    }

    #[test]
    fn ipv4_manual_only() {
        let keyfile = rendered(json!({
            "interface": "enp1s0",
            "ipv4": {
                "method": "manual",
                "addresses": [
                    { "address": "192.0.2.10", "prefix_length": 24 },
                    { "address": "198.51.100.7", "prefix_length": 32 }
                ],
                "gateway": "192.0.2.1",
                "dns": ["192.0.2.53"]
            },
            "ipv6": { "method": "disabled" }
        }));
        assert_eq!(
            keyfile,
            header("enp1s0")
                + "[ipv4]\nmethod=manual\naddress1=192.0.2.10/24\naddress2=198.51.100.7/32\n\
                   gateway=192.0.2.1\ndns=192.0.2.53;\n\n[ipv6]\nmethod=disabled\n"
        );
    }

    // IPv6-only.

    #[test]
    fn ipv6_auto_only() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": { "method": "auto" }
        }));
        assert_eq!(
            keyfile,
            header("eth0") + "[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=auto\n"
        );
    }

    #[test]
    fn ipv6_dhcp_only() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": { "method": "dhcp", "dns": ["2001:4860:4860::8888"] }
        }));
        assert!(keyfile.ends_with(
            "[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=dhcp\ndns=2001:4860:4860::8888;\n"
        ));
    }

    #[test]
    fn ipv6_manual_only_with_link_local_gateway() {
        // The usual IPv6-only VPS shape: one /64, gateway fe80::1.
        let keyfile = rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": {
                "method": "manual",
                "addresses": [{ "address": "2001:db8:10::2", "prefix_length": 64 }],
                "gateway": "fe80::1",
                "dns": ["2606:4700:4700::1111", "2001:4860:4860::8888"]
            }
        }));
        assert_eq!(
            keyfile,
            header("eth0")
                + "[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=manual\naddress1=2001:db8:10::2/64\n\
                   gateway=fe80::1\ndns=2606:4700:4700::1111;2001:4860:4860::8888;\n"
        );
    }

    #[test]
    fn ipv6_manual_ula_only_is_routable() {
        rendered(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": {
                "method": "manual",
                "addresses": [{ "address": "fd00:1::5", "prefix_length": 128 }]
            }
        }));
    }

    // Dual-stack.

    #[test]
    fn dual_stack_auto_is_the_default() {
        let keyfile = rendered(json!({ "interface": "eth0" }));
        assert_eq!(keyfile, header("eth0") + "[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n");
    }

    #[test]
    fn dual_stack_manual() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "name": "uplink",
            "ipv4": {
                "method": "manual",
                "addresses": [{ "address": "203.0.113.20", "prefix_length": 28 }],
                "gateway": "203.0.113.17",
                "dns": ["203.0.113.2"]
            },
            "ipv6": {
                "method": "manual",
                "addresses": [
                    { "address": "2001:db8::20", "prefix_length": 64 },
                    { "address": "fd00::20", "prefix_length": 64 }
                ],
                "gateway": "2001:db8::1",
                "dns": ["2001:db8::53"]
            }
        }));
        assert_eq!(
            keyfile,
            "# Managed by Tetra (network.configure).\n[connection]\nid=uplink\n".to_owned()
                + &format!("uuid={UUID}\n")
                + "type=ethernet\ninterface-name=eth0\nautoconnect=true\n\n[ethernet]\n\n\
                   [ipv4]\nmethod=manual\naddress1=203.0.113.20/28\ngateway=203.0.113.17\n\
                   dns=203.0.113.2;\n\n[ipv6]\nmethod=manual\naddress1=2001:db8::20/64\n\
                   address2=fd00::20/64\ngateway=2001:db8::1\ndns=2001:db8::53;\n"
        );
    }

    #[test]
    fn dual_stack_mixed_methods() {
        for (v4, v6) in [
            ("auto", "dhcp"),
            ("auto", "link-local"),
            ("auto", "manual"),
            ("manual", "auto"),
            ("manual", "dhcp"),
            ("manual", "link-local"),
        ] {
            let section = |method: &str, address: &str, prefix: u8| {
                if method == "manual" {
                    json!({ "method": method, "addresses": [{ "address": address, "prefix_length": prefix }] })
                } else {
                    json!({ "method": method })
                }
            };
            let keyfile = rendered(json!({
                "interface": "eth0",
                "ipv4": section(v4, "10.0.0.2", 24),
                "ipv6": section(v6, "2001:db8::2", 64),
            }));
            assert!(keyfile.contains(&format!("[ipv4]\nmethod={v4}\n")), "{keyfile}");
            assert!(keyfile.contains(&format!("[ipv6]\nmethod={v6}\n")), "{keyfile}");
        }
    }

    // Rejections.

    #[test]
    fn rejects_configs_without_a_routable_family() {
        for (v4, v6) in [("disabled", "disabled"), ("disabled", "link-local")] {
            let error = rejection(json!({
                "interface": "eth0",
                "ipv4": { "method": v4 },
                "ipv6": { "method": v6 }
            }));
            assert!(error.contains("routable"), "{error}");
        }
        // Manual IPv6 with only a link-local address is not routable either.
        let error = rejection(json!({
            "interface": "eth0",
            "ipv4": { "method": "disabled" },
            "ipv6": { "method": "manual", "addresses": [{ "address": "fe80::5", "prefix_length": 64 }] }
        }));
        assert!(error.contains("routable"), "{error}");
    }

    #[test]
    fn rejects_out_of_range_prefixes() {
        for (family, address, prefix) in [
            ("ipv4", "192.0.2.10", 0),
            ("ipv4", "192.0.2.10", 33),
            ("ipv6", "2001:db8::1", 0),
            ("ipv6", "2001:db8::1", 129),
        ] {
            let error = rejection(json!({
                "interface": "eth0",
                family: { "method": "manual", "addresses": [{ "address": address, "prefix_length": prefix }] }
            }));
            assert!(error.contains("prefix_length"), "{error}");
        }
    }

    #[test]
    fn accepts_boundary_prefixes() {
        for (family, address, prefix) in [
            ("ipv4", "192.0.2.10", 1),
            ("ipv4", "192.0.2.10", 32),
            ("ipv6", "2001:db8::1", 1),
            ("ipv6", "2001:db8::1", 128),
        ] {
            rendered(json!({
                "interface": "eth0",
                family: { "method": "manual", "addresses": [{ "address": address, "prefix_length": prefix }] }
            }));
        }
    }

    #[test]
    fn rejects_addresses_of_the_wrong_family() {
        for body in [
            json!({ "ipv4": { "method": "manual", "addresses": [{ "address": "2001:db8::1", "prefix_length": 24 }] } }),
            json!({ "ipv4": { "method": "auto", "dns": ["2001:db8::53"] } }),
            json!({ "ipv6": { "method": "auto", "dns": ["1.1.1.1"] } }),
            json!({ "ipv6": { "method": "manual", "addresses": [{ "address": "2001:db8::1", "prefix_length": 64 }], "gateway": "192.0.2.1" } }),
        ] {
            let mut body = body;
            body["interface"] = json!("eth0");
            rejection(body);
        }
    }

    #[test]
    fn rejects_unusable_addresses() {
        for (family, address, prefix) in [
            ("ipv4", "0.0.0.0", 24),
            ("ipv4", "127.0.0.2", 8),
            ("ipv4", "224.0.0.1", 24),
            ("ipv4", "192.0.2.0", 24),
            ("ipv4", "192.0.2.255", 24),
            ("ipv6", "::", 64),
            ("ipv6", "::1", 128),
            ("ipv6", "ff02::1", 64),
        ] {
            let error = rejection(json!({
                "interface": "eth0",
                family: { "method": "manual", "addresses": [{ "address": address, "prefix_length": prefix }] }
            }));
            assert!(error.contains(address), "{error}");
        }
    }

    #[test]
    fn rejects_manual_fields_with_other_methods() {
        for body in [
            json!({ "ipv4": { "method": "auto", "addresses": [{ "address": "192.0.2.10", "prefix_length": 24 }] } }),
            json!({ "ipv4": { "method": "auto", "gateway": "192.0.2.1" } }),
            json!({ "ipv6": { "method": "dhcp", "gateway": "fe80::1" } }),
            json!({ "ipv6": { "method": "manual" } }),
            json!({ "ipv4": { "method": "disabled", "dns": ["1.1.1.1"] } }),
            json!({ "ipv6": { "method": "link-local", "dns": ["2001:db8::53"] } }),
        ] {
            let mut body = body;
            body["interface"] = json!("eth0");
            rejection(body);
        }
    }

    #[test]
    fn rejects_duplicates_and_gateway_equal_to_host() {
        rejection(json!({
            "interface": "eth0",
            "ipv4": { "method": "auto", "dns": ["1.1.1.1", "1.1.1.1"] }
        }));
        rejection(json!({
            "interface": "eth0",
            "ipv6": {
                "method": "manual",
                "addresses": [
                    { "address": "2001:db8::2", "prefix_length": 64 },
                    { "address": "2001:db8::2", "prefix_length": 48 }
                ]
            }
        }));
        rejection(json!({
            "interface": "eth0",
            "ipv4": {
                "method": "manual",
                "addresses": [{ "address": "192.0.2.10", "prefix_length": 24 }],
                "gateway": "192.0.2.10"
            }
        }));
    }

    #[test]
    fn rejects_unknown_fields_and_legacy_shape() {
        // The OOBE's earlier single-address shape must not be silently ignored.
        let error = rejection(json!({
            "interface": "eth0",
            "ipv4": { "method": "manual", "address": "192.0.2.10", "prefix_length": 24 }
        }));
        assert!(error.contains("unknown field"), "{error}");
        rejection(json!({ "interface": "eth0", "ipv6": { "method": "slaac" } }));
    }

    #[test]
    fn rejects_bad_interface_and_profile_names() {
        for interface in ["", "../etc", "eth0/x", "-eth0", ".", "a-very-long-interface-name", "eth 0", "eth0\n"] {
            rejection(json!({ "interface": interface }));
        }
        for name in ["", "..", ".hidden", "a/b", "a..b", "with space", "x\ny"] {
            rejection(json!({ "interface": "eth0", "name": name }));
        }
    }

    #[test]
    fn reads_existing_uuid_from_connection_section_only() {
        let keyfile = b"[connection]\nid=eth0\nuuid=0B0C3A52-4F43-4B6B-9A54-2D1B0F5E8C11\n\n[ipv4]\nuuid=nope\n";
        assert_eq!(existing_uuid(keyfile).as_deref(), Some(UUID));
        assert_eq!(existing_uuid(b"[ipv4]\nuuid=0b0c3a52-4f43-4b6b-9a54-2d1b0f5e8c11\n"), None);
        assert_eq!(existing_uuid(b"[connection]\nuuid=garbage\n"), None);
    }

    #[test]
    fn new_uuids_are_version_4() {
        let uuid = new_uuid();
        assert!(is_uuid(&uuid), "{uuid}");
        assert_eq!(&uuid[14..15], "4");
        assert!(matches!(&uuid[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(uuid, new_uuid());
    }
}
