//! `network` module payloads.

use crate::agent::module_support::SelinuxOptions;
use crate::prelude::*;

#[derive(Debug, Deserialize)]
pub struct NetworkInterfaceRequest {
    pub interface: Option<String>,
}

impl NetworkInterfaceRequest {
    #[must_use]
    pub fn ip_args(&self) -> Vec<String> {
        let mut args = vec!["-json".into(), "addr".into(), "show".into()];
        if let Some(interface) = &self.interface {
            args.extend(["dev".into(), interface.clone()]);
        }
        args
    }
}

/// Payload for `network.get_config`. The path must name a `.nmconnection`
/// file directly inside `/etc/NetworkManager/system-connections/`.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigRequest {
    pub path: PathBuf,
}

/// Payload for `network.set_config`. The path is restricted like
/// [`NetworkConfigRequest`]; the file is always written `0600` and relabeled
/// with its default SELinux context.
#[derive(Debug, Deserialize)]
pub struct NetworkWriteConfigRequest {
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

/// Payload for `network.configure`: a structured profile for one Ethernet
/// interface that Tetra validates and renders into a NetworkManager keyfile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfigureRequest {
    /// Kernel interface name, e.g. `enp1s0`.
    pub interface: String,
    /// Connection profile name and keyfile stem; defaults to `interface`.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ipv4: Ipv4Config,
    #[serde(default)]
    pub ipv6: Ipv6Config,
    /// Wired 802.1X authentication, written to the keyfile's `[802-1x]`
    /// section.
    #[serde(default)]
    pub wired_8021x: Option<Box<Wired8021x>>,
    #[serde(default)]
    pub dry_run: bool,
}

/// `wired_8021x` for [`NetworkConfigureRequest`], also used for
/// `wpa-enterprise` Wi-Fi. `Debug` leaves out the passwords.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wired8021x {
    pub eap: EapMethod,
    pub identity: String,
    /// Outer identity for tunneled methods (`peap`, `ttls`).
    #[serde(default)]
    pub anonymous_identity: Option<String>,
    /// Required for `peap`, `ttls`, `pwd` and `md5`.
    #[serde(default)]
    pub password: Option<String>,
    /// CA certificate that signed the authentication server's certificate.
    /// This and the client certificate and key are each an absolute path or
    /// PEM contents, which Tetra stores root-only and refers to by path.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Client certificate and key, required for `tls`.
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub private_key_password: Option<String>,
    /// Accept only an authentication server whose certificate names this
    /// domain or a subdomain of it (`802-1x.domain-suffix-match`).
    #[serde(default)]
    pub domain_suffix_match: Option<String>,
    /// Inner authentication for `peap` and `ttls` (default `mschapv2`).
    #[serde(default)]
    pub phase2: Option<Phase2Method>,
}

impl std::fmt::Debug for Wired8021x {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PEM contents are not shown, only paths.
        let shown = |value: &Option<String>| {
            value
                .as_deref()
                .map(|value| if is_pem(value) { "<pem>" } else { value }.to_owned())
        };
        // The private key could be in any encoding (a BOM before the PEM,
        // base64 DER, ...), so only a plain absolute path is shown.
        let private_key = self.private_key.as_deref().map(|value| {
            if Path::new(value).is_absolute() && !value.chars().any(char::is_control) {
                value
            } else {
                "<redacted>"
            }
        });
        f.debug_struct("Wired8021x")
            .field("eap", &self.eap)
            .field("identity", &self.identity)
            .field("ca_cert", &shown(&self.ca_cert))
            .field("client_cert", &shown(&self.client_cert))
            .field("private_key", &private_key)
            .field("domain_suffix_match", &self.domain_suffix_match)
            .field("phase2", &self.phase2)
            .finish_non_exhaustive()
    }
}

/// Whether an 802.1X certificate or key field holds PEM contents rather than
/// a path.
#[must_use]
pub fn is_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----BEGIN ")
}

/// EAP method for [`Wired8021x`] (NetworkManager `802-1x.eap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EapMethod {
    Tls,
    Peap,
    Ttls,
    Pwd,
    Md5,
}

/// Inner method for [`Wired8021x`] (NetworkManager `802-1x.phase2-auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase2Method {
    Mschapv2,
    Mschap,
    Pap,
    Chap,
    Gtc,
    Md5,
}

/// `ipv4.method` for [`NetworkConfigureRequest`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv4Method {
    /// DHCP.
    #[default]
    Auto,
    Manual,
    Disabled,
}

/// `ipv6.method` for [`NetworkConfigureRequest`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Method {
    /// `SLAAC`, with `DHCPv6` when router advertisements ask for it.
    #[default]
    Auto,
    /// `DHCPv6` only, without `SLAAC`.
    Dhcp,
    Manual,
    /// Only the link-local address; not routable.
    LinkLocal,
    Disabled,
}

/// One address of a manual configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpAddressConfig<A> {
    pub address: A,
    pub prefix_length: u8,
}

/// One address family's section of [`NetworkConfigureRequest`].
///
/// Using the family's address type means a value of the wrong family (an
/// IPv6 DNS server under `ipv4`, say) fails to deserialize.
#[derive(Debug, Clone, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "M: Deserialize<'de> + Default, A: Deserialize<'de>")
)]
pub struct IpConfig<M, A> {
    #[serde(default)]
    pub method: M,
    /// Required for, and only allowed with, `manual`.
    #[serde(default = "Vec::new")]
    pub addresses: Vec<IpAddressConfig<A>>,
    /// Only allowed with `manual`.
    #[serde(default = "Option::default")]
    pub gateway: Option<A>,
    /// Static DNS servers; not allowed when the family is disabled or
    /// link-local.
    #[serde(default = "Vec::new")]
    pub dns: Vec<A>,
}

impl<M: Default, A> Default for IpConfig<M, A> {
    fn default() -> Self {
        Self {
            method: M::default(),
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
        }
    }
}

pub type Ipv4Config = IpConfig<Ipv4Method, std::net::Ipv4Addr>;
pub type Ipv6Config = IpConfig<Ipv6Method, std::net::Ipv6Addr>;

/// Payload for `network.confirm`: keeps a change made by `network.configure`
/// that would otherwise be rolled back.
#[derive(Debug, Deserialize)]
pub struct NetworkConfirmRequest {
    pub token: String,
}

/// Payload for `network.scan_wifi`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScanWifiRequest {
    /// Wireless interface to scan with, e.g. `wlan0`.
    pub interface: String,
    /// `true` always rescans, `false` never does; by default NetworkManager
    /// rescans when its last scan is older than 30 seconds.
    #[serde(default)]
    pub rescan: Option<bool>,
}

/// Payload for `network.connect_wifi`: a Wi-Fi profile for one interface
/// that Tetra renders into a NetworkManager keyfile and activates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConnectWifiRequest {
    /// Wireless interface, e.g. `wlan0`.
    pub interface: String,
    pub ssid: String,
    /// Probe for a network that does not broadcast its SSID. Networks the
    /// last scan did not see are treated as hidden anyway.
    #[serde(default)]
    pub hidden: bool,
    pub security: WifiSecurity,
    #[serde(default)]
    pub dry_run: bool,
}

/// `security` for [`NetworkConnectWifiRequest`], tagged by `type`.
/// `Debug` leaves out the passwords.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WifiSecurity {
    /// A struct variant so that stray fields are refused.
    #[allow(clippy::empty_enum_variants_with_brackets)]
    Open {},
    /// WPA2 or WPA3 with a passphrase.
    WpaPersonal { password: String },
    /// WPA2 or WPA3 Enterprise (802.1X), with the same settings as
    /// [`Wired8021x`].
    WpaEnterprise(Box<Wired8021x>),
}

impl std::fmt::Debug for WifiSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open {} => f.write_str("Open"),
            Self::WpaPersonal { .. } => f.debug_struct("WpaPersonal").finish_non_exhaustive(),
            Self::WpaEnterprise(settings) => {
                f.debug_tuple("WpaEnterprise").field(settings).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wired_8021x_debug_shows_only_a_private_key_path() {
        let debug = |private_key: &str| {
            let settings: Wired8021x = serde_json::from_value(json!({
                "eap": "tls",
                "identity": "host",
                "private_key": private_key,
            }))
            .unwrap();
            format!("{settings:?}")
        };
        assert!(debug("/etc/pki/tls/private/host.key").contains("/etc/pki/tls/private/host.key"));
        for secret in [
            "-----BEGIN PRIVATE KEY-----\nS3CRET\n-----END PRIVATE KEY-----\n",
            "\u{feff}-----BEGIN PRIVATE KEY-----\nS3CRET\n-----END PRIVATE KEY-----\n",
            "MIIEvS3CRETbase64DER",
            "/S3CRET\nline",
        ] {
            let shown = debug(secret);
            assert!(!shown.contains("S3CRET"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
    }

    #[test]
    fn network_interface_request_builds_optional_device_arguments() {
        assert_eq!(
            NetworkInterfaceRequest { interface: None }.ip_args(),
            ["-json", "addr", "show"]
        );
        assert_eq!(
            NetworkInterfaceRequest {
                interface: Some("eno1".into())
            }
            .ip_args(),
            ["-json", "addr", "show", "dev", "eno1"]
        );
    }
}
