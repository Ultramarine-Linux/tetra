//! Address scope classification for `interfaces`, `status`, and safe apply.
//!
//! The kernel's own `scope` field (`global`/`link`/`host`) reports a ULA
//! (`fd00::/8`) or an RFC 1918 address as `global`, which is not what an
//! administrator deciding "can I still reach this host remotely?" needs. This
//! module classifies addresses by prefix instead.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::prelude::*;

/// Where an address is reachable from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressScope {
    /// Publicly routable unicast.
    Global,
    /// IPv4 private-use (RFC 1918) or shared (RFC 6598, CGNAT) space.
    Private,
    /// IPv6 unique local address (`fc00::/7`).
    Ula,
    /// `169.254.0.0/16` or `fe80::/10`; never routed off the link.
    LinkLocal,
    Loopback,
    Multicast,
    Unspecified,
}

impl AddressScope {
    /// Classify `address` by prefix.
    #[must_use]
    pub fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self::of_v4(address),
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or_else(|| Self::of_v6(address), Self::of_v4),
        }
    }

    const fn of_v4(address: Ipv4Addr) -> Self {
        let [first, second, ..] = address.octets();
        if address.is_unspecified() {
            Self::Unspecified
        } else if address.is_loopback() {
            Self::Loopback
        } else if address.is_link_local() {
            Self::LinkLocal
        } else if address.is_multicast() || address.is_broadcast() {
            Self::Multicast
        } else if address.is_private() || (first == 100 && (second & 0xc0) == 64) {
            Self::Private
        } else {
            Self::Global
        }
    }

    const fn of_v6(address: Ipv6Addr) -> Self {
        if address.is_unspecified() {
            Self::Unspecified
        } else if address.is_loopback() {
            Self::Loopback
        } else if address.is_multicast() {
            Self::Multicast
        } else if address.is_unicast_link_local() {
            Self::LinkLocal
        } else if address.is_unique_local() {
            Self::Ula
        } else {
            Self::Global
        }
    }

    /// Whether an address of this scope can be reached from beyond the local
    /// link. Private IPv4 and ULA count: a remote administrator may well be
    /// reaching the host over a LAN or VPN.
    #[must_use]
    pub const fn is_routable(self) -> bool {
        matches!(self, Self::Global | Self::Private | Self::Ula)
    }
}

/// One address assigned to an interface, as reported by `ip -json addr show`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceAddress {
    pub interface: String,
    pub family: &'static str,
    pub address: IpAddr,
    pub prefix_length: u8,
    pub scope: AddressScope,
}

/// Flatten `ip -json addr show` output into classified addresses. Entries
/// that do not parse are skipped rather than failing the whole listing.
#[must_use]
pub fn parse_ip_addr_json(data: &Value) -> Vec<InterfaceAddress> {
    let Some(links) = data.as_array() else {
        return Vec::new();
    };
    links
        .iter()
        .flat_map(|link| {
            let interface = link["ifname"].as_str().unwrap_or_default().to_owned();
            link["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(move |info| {
                    let address: IpAddr = info["local"].as_str()?.parse().ok()?;
                    let prefix_length = u8::try_from(info["prefixlen"].as_u64()?).ok()?;
                    Some(InterfaceAddress {
                        interface: interface.clone(),
                        family: if address.is_ipv4() { "ipv4" } else { "ipv6" },
                        address,
                        prefix_length,
                        scope: AddressScope::of(address),
                    })
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn scope(address: &str) -> AddressScope {
        AddressScope::of(address.parse().unwrap())
    }

    #[test]
    fn classifies_ipv6_scopes() {
        assert_eq!(scope("2001:db8::10"), AddressScope::Global);
        assert_eq!(scope("2a01:4f8::1"), AddressScope::Global);
        assert_eq!(scope("fd12:3456::1"), AddressScope::Ula);
        assert_eq!(scope("fc00::1"), AddressScope::Ula);
        assert_eq!(scope("fe80::1"), AddressScope::LinkLocal);
        assert_eq!(scope("::1"), AddressScope::Loopback);
        assert_eq!(scope("ff02::1"), AddressScope::Multicast);
        assert_eq!(scope("::ffff:192.168.1.1"), AddressScope::Private);
    }

    #[test]
    fn classifies_ipv4_scopes() {
        assert_eq!(scope("203.0.113.5"), AddressScope::Global);
        assert_eq!(scope("192.168.1.10"), AddressScope::Private);
        assert_eq!(scope("100.64.0.1"), AddressScope::Private);
        assert_eq!(scope("100.128.0.1"), AddressScope::Global);
        assert_eq!(scope("169.254.1.1"), AddressScope::LinkLocal);
        assert_eq!(scope("127.0.0.1"), AddressScope::Loopback);
    }

    #[test]
    fn routable_scopes_exclude_link_local_and_loopback() {
        assert!(AddressScope::Global.is_routable());
        assert!(AddressScope::Private.is_routable());
        assert!(AddressScope::Ula.is_routable());
        assert!(!AddressScope::LinkLocal.is_routable());
        assert!(!AddressScope::Loopback.is_routable());
    }

    #[test]
    fn parses_ip_json_with_both_families() {
        let data = json!([
            {
                "ifname": "eth0",
                "addr_info": [
                    { "family": "inet", "local": "192.0.2.10", "prefixlen": 24, "scope": "global" },
                    { "family": "inet6", "local": "fd00::10", "prefixlen": 64, "scope": "global" },
                    { "family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link" },
                    { "family": "inet6", "prefixlen": 64 }
                ]
            },
            { "ifname": "lo", "addr_info": [ { "local": "::1", "prefixlen": 128 } ] }
        ]);
        let addresses = parse_ip_addr_json(&data);
        let summary: Vec<_> = addresses
            .iter()
            .map(|a| {
                (
                    a.interface.as_str(),
                    a.family,
                    a.address.to_string(),
                    a.scope,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("eth0", "ipv4", "192.0.2.10".into(), AddressScope::Global),
                ("eth0", "ipv6", "fd00::10".into(), AddressScope::Ula),
                ("eth0", "ipv6", "fe80::1".into(), AddressScope::LinkLocal),
                ("lo", "ipv6", "::1".into(), AddressScope::Loopback),
            ]
        );
        assert_eq!(
            serde_json::to_value(&addresses[2]).unwrap()["scope"],
            "link-local"
        );
    }
}
