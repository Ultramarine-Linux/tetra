//! Wi-Fi for `network.scan_wifi` and `network.connect_wifi`.
//!
//! Scanning reads `nmcli`'s terse output ([`parse_scan`]) and reports each
//! network once, with the security the OOBE offers for it. Connecting
//! renders a `type=wifi` keyfile ([`render`]) that is written and activated
//! like a `network.configure` profile. The passphrase or 802.1X password is
//! only ever written into that keyfile (`0600`): never into a command line,
//! a response ([`render_redacted`]) or an error.

use std::{collections::BTreeMap, fmt::Write as _};

use serde::Serialize;

use super::keyfile::{REDACTED, keyfile_value, render_8021x, validate_8021x, validate_interface};
use crate::prelude::*;
use crate::types::{NetworkConnectWifiRequest, WifiSecurity};

/// The longest SSID 802.11 allows, in bytes.
const MAX_SSID_BYTES: usize = 32;
/// The longest SAE password Tetra accepts; WPA-PSK passphrases are 8-63.
const MAX_SAE_PASSWORD_LEN: usize = 128;

/// The fields `nmcli device wifi list` prints for [`parse_scan`].
pub const SCAN_FIELDS: &str = "IN-USE,SSID-HEX,SIGNAL,FREQ,SECURITY,WPA-FLAGS,RSN-FLAGS";

/// The security of a scanned network, as the OOBE names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    Open,
    WpaPersonal,
    WpaEnterprise,
    /// WEP, OWE and anything else Tetra cannot connect to.
    Unknown,
}

/// How a `wpa-personal` network authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyManagement {
    /// WPA2 (or WPA2/WPA3 transition) with a pre-shared key.
    WpaPsk,
    /// WPA3-only networks.
    Sae,
}

/// One network from a scan, strongest access point first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    pub ssid: String,
    pub security: Security,
    /// 0-100.
    pub signal: u8,
    /// Frequency of the strongest access point, in MHz.
    pub frequency: Option<u32>,
    /// Whether this interface is connected to it.
    pub in_use: bool,
    /// Whether every access point seen is WPA3-only (needs SAE).
    #[serde(skip)]
    pub sae_only: bool,
}

/// Parse `nmcli --terse --escape yes --fields` [`SCAN_FIELDS`] `device wifi
/// list` output. Hidden networks (no SSID) and SSIDs that are not UTF-8 are
/// left out; each SSID appears once, with its strongest access point's
/// signal, sorted by signal.
#[must_use]
pub fn parse_scan(output: &str) -> Vec<Network> {
    let mut networks: BTreeMap<String, Network> = BTreeMap::new();
    for line in output.lines() {
        let fields = split_terse(line);
        let [in_use, ssid_hex, signal, frequency, security, wpa_flags, rsn_flags] =
            fields.as_slice()
        else {
            continue;
        };
        let Some(ssid) = decode_ssid(ssid_hex) else {
            continue;
        };
        let flags = format!("{wpa_flags} {rsn_flags}");
        let flags: Vec<&str> = flags.split_whitespace().collect();
        let network = Network {
            ssid: ssid.clone(),
            security: classify(security, &flags),
            signal: signal.trim().parse().unwrap_or(0),
            frequency: frequency.split_whitespace().next().and_then(|mhz| mhz.parse().ok()),
            in_use: in_use.trim() == "*",
            sae_only: flags.contains(&"sae") && !flags.contains(&"psk"),
        };
        networks
            .entry(ssid)
            .and_modify(|existing| {
                existing.in_use |= network.in_use;
                existing.sae_only &= network.sae_only;
                if network.signal > existing.signal {
                    existing.signal = network.signal;
                    existing.frequency = network.frequency;
                }
                // An SSID with a mix of security types is shown as its most
                // demanding one.
                existing.security = existing.security.max_with(network.security);
            })
            .or_insert(network);
    }
    let mut networks: Vec<Network> = networks.into_values().collect();
    networks.sort_by(|left, right| right.signal.cmp(&left.signal).then(left.ssid.cmp(&right.ssid)));
    networks
}

impl Security {
    const fn rank(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::WpaPersonal => 1,
            Self::WpaEnterprise => 2,
            Self::Unknown => 3,
        }
    }

    const fn max_with(self, other: Self) -> Self {
        if other.rank() > self.rank() { other } else { self }
    }
}

/// Classify an access point from nmcli's `SECURITY` text and its WPA/RSN
/// key management flags (`psk`, `sae`, `802.1X`, `owe`, ...).
fn classify(security: &str, flags: &[&str]) -> Security {
    if flags.iter().any(|flag| flag.eq_ignore_ascii_case("802.1X") || *flag == "eap_suite_b_192") {
        Security::WpaEnterprise
    } else if flags.iter().any(|flag| matches!(*flag, "psk" | "sae")) {
        Security::WpaPersonal
    } else if security.trim().is_empty() || security.trim() == "--" {
        Security::Open
    } else {
        Security::Unknown
    }
}

/// Split one terse nmcli line on unescaped `:`, undoing `\:` and `\\`.
fn split_terse(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next()
                    && let Some(field) = fields.last_mut()
                {
                    field.push(next);
                }
            }
            ':' => fields.push(String::new()),
            c => {
                if let Some(field) = fields.last_mut() {
                    field.push(c);
                }
            }
        }
    }
    fields
}

fn decode_ssid(hex: &str) -> Option<String> {
    let hex: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok().filter(|ssid| !ssid.is_empty())
}

/// The profile name and keyfile stem for an interface's Wi-Fi profile. Each
/// interface has one, so connecting to another network replaces it.
#[must_use]
pub fn connection_name(interface: &str) -> String {
    format!("wifi-{interface}")
}

/// Validate a `network.connect_wifi` request without touching the host.
/// Errors name the field, never a password.
///
/// # Errors
/// Errs with a message naming the offending field.
pub fn validate(request: &NetworkConnectWifiRequest, key_management: KeyManagement) -> Result<()> {
    validate_interface(&request.interface)?;
    ensure!(
        (1..=MAX_SSID_BYTES).contains(&request.ssid.len())
            && !request.ssid.chars().any(char::is_control),
        "ssid must be 1 to {MAX_SSID_BYTES} bytes with no control characters"
    );
    match &request.security {
        WifiSecurity::Open {} => {}
        WifiSecurity::WpaPersonal { password } => validate_password(password, key_management)?,
        WifiSecurity::WpaEnterprise(settings) => validate_8021x("security", settings)?,
    }
    Ok(())
}

fn validate_password(password: &str, key_management: KeyManagement) -> Result<()> {
    match key_management {
        KeyManagement::WpaPsk => ensure!(
            (password.len() == 64 && password.chars().all(|c| c.is_ascii_hexdigit()))
                || ((8..=63).contains(&password.len())
                    && password.chars().all(|c| c.is_ascii() && !c.is_ascii_control())),
            "security.password must be 8 to 63 printable ASCII characters, or 64 hex digits"
        ),
        KeyManagement::Sae => ensure!(
            (1..=MAX_SAE_PASSWORD_LEN).contains(&password.len())
                && !password.chars().any(char::is_control),
            "security.password must be 1 to {MAX_SAE_PASSWORD_LEN} characters on one line"
        ),
    }
    Ok(())
}

/// Render a validated request into keyfile contents.
#[must_use]
pub fn render(
    request: &NetworkConnectWifiRequest,
    key_management: KeyManagement,
    hidden: bool,
    uuid: &str,
) -> String {
    render_keyfile(request, key_management, hidden, uuid, false)
}

/// [`render`] with every password replaced, for responses.
#[must_use]
pub fn render_redacted(
    request: &NetworkConnectWifiRequest,
    key_management: KeyManagement,
    hidden: bool,
    uuid: &str,
) -> String {
    render_keyfile(request, key_management, hidden, uuid, true)
}

fn render_keyfile(
    request: &NetworkConnectWifiRequest,
    key_management: KeyManagement,
    hidden: bool,
    uuid: &str,
    redact: bool,
) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ok: std::fmt::Result = (|| {
        writeln!(out, "# Managed by Tetra (network.connect_wifi).")?;
        writeln!(out, "[connection]")?;
        writeln!(out, "id={}", connection_name(&request.interface))?;
        writeln!(out, "uuid={uuid}")?;
        writeln!(out, "type=wifi")?;
        writeln!(out, "interface-name={}", request.interface)?;
        writeln!(out, "autoconnect=true")?;
        writeln!(out)?;
        writeln!(out, "[wifi]")?;
        writeln!(out, "mode=infrastructure")?;
        // As a list of bytes, so no SSID needs escaping or is read back as
        // something else.
        writeln!(out, "ssid={};", request.ssid.bytes().join(";"))?;
        if hidden {
            writeln!(out, "hidden=true")?;
        }
        writeln!(out)?;
        match &request.security {
            WifiSecurity::Open {} => {}
            WifiSecurity::WpaPersonal { password } => {
                writeln!(out, "[wifi-security]")?;
                let keyword = match key_management {
                    KeyManagement::WpaPsk => "wpa-psk",
                    KeyManagement::Sae => "sae",
                };
                writeln!(out, "key-mgmt={keyword}")?;
                let shown = if redact { REDACTED.to_owned() } else { keyfile_value(password) };
                writeln!(out, "psk={shown}")?;
                writeln!(out)?;
            }
            WifiSecurity::WpaEnterprise(settings) => {
                writeln!(out, "[wifi-security]")?;
                writeln!(out, "key-mgmt=wpa-eap")?;
                writeln!(out)?;
                render_8021x(&mut out, settings, redact)?;
                writeln!(out)?;
            }
        }
        writeln!(out, "[ipv4]")?;
        writeln!(out, "method=auto")?;
        writeln!(out)?;
        writeln!(out, "[ipv6]")?;
        writeln!(out, "method=auto")
    })();
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SCAN: &str = "\
*:486F6D65:82:5180 MHz:WPA2:(none):pair_ccmp group_ccmp psk
 :486F6D65:64:2437 MHz:WPA2:(none):pair_ccmp group_ccmp psk
 :436F7270:70:5500 MHz:WPA2 802.1X:(none):pair_ccmp group_ccmp 802.1X
 ::40:2412 MHz:WPA2:(none):pair_ccmp group_ccmp psk
 :4775657374:58:2462 MHz::(none):(none)
 :4E6577:90:5745 MHz:WPA3:(none):pair_ccmp group_ccmp sae
 :4F6C64:30:2412 MHz:WEP:(none):(none)
 :613A62:20:2412 MHz:WPA1 WPA2:pair_tkip group_tkip psk:pair_ccmp group_tkip psk
 :FF:10:2412 MHz::(none):(none)
";

    fn request(security: &Value) -> NetworkConnectWifiRequest {
        serde_json::from_value(json!({
            "interface": "wlan0",
            "ssid": "Home",
            "security": security,
        }))
        .unwrap()
    }

    #[test]
    fn scans_list_each_network_once_with_its_security() {
        let networks = parse_scan(SCAN);
        let summary: Vec<_> = networks
            .iter()
            .map(|network| (network.ssid.as_str(), network.security, network.signal, network.in_use))
            .collect();
        assert_eq!(
            summary,
            [
                ("New", Security::WpaPersonal, 90, false),
                ("Home", Security::WpaPersonal, 82, true),
                ("Corp", Security::WpaEnterprise, 70, false),
                ("Guest", Security::Open, 58, false),
                ("Old", Security::Unknown, 30, false),
                ("a:b", Security::WpaPersonal, 20, false),
            ]
        );
        assert_eq!(networks[1].frequency, Some(5180));
        assert!(networks[0].sae_only);
        assert!(!networks[1].sae_only);
        assert_eq!(
            serde_json::to_value(&networks[2]).unwrap(),
            json!({
                "ssid": "Corp",
                "security": "wpa-enterprise",
                "signal": 70,
                "frequency": 5500,
                "in_use": false,
            })
        );
    }

    #[test]
    fn lowercase_and_separated_ssid_hex_is_decoded() {
        assert_eq!(decode_ssid("68:6f:6d:65").as_deref(), Some("home"));
        assert_eq!(decode_ssid(""), None);
        assert_eq!(decode_ssid("ABC"), None);
    }

    #[test]
    fn wpa_personal_renders_the_passphrase_only_into_the_keyfile() {
        let request = request(&json!({"type": "wpa-personal", "password": "correct horse"}));
        validate(&request, KeyManagement::WpaPsk).unwrap();
        let keyfile = render(&request, KeyManagement::WpaPsk, false, "u");
        assert_eq!(
            keyfile,
            "# Managed by Tetra (network.connect_wifi).\n\
             [connection]\nid=wifi-wlan0\nuuid=u\ntype=wifi\ninterface-name=wlan0\nautoconnect=true\n\n\
             [wifi]\nmode=infrastructure\nssid=72;111;109;101;\n\n\
             [wifi-security]\nkey-mgmt=wpa-psk\npsk=correct horse\n\n\
             [ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n"
        );
        let shown = render_redacted(&request, KeyManagement::Sae, true, "u");
        assert!(!shown.contains("correct horse"));
        assert!(shown.contains("key-mgmt=sae\npsk=<redacted>\n"));
        assert!(shown.contains("hidden=true\n"));
        assert!(!format!("{request:?}").contains("correct horse"));
    }

    #[test]
    fn open_networks_have_no_security_section() {
        let keyfile = render(&request(&json!({"type": "open"})), KeyManagement::WpaPsk, false, "u");
        assert!(!keyfile.contains("[wifi-security]"));
    }

    #[test]
    fn wpa_enterprise_uses_the_8021x_section() {
        let request = request(&json!({
            "type": "wpa-enterprise",
            "eap": "peap",
            "identity": "alice",
            "password": "hunter22",
            "ca_cert": "/etc/pki/corp.pem",
        }));
        validate(&request, KeyManagement::WpaPsk).unwrap();
        let keyfile = render(&request, KeyManagement::WpaPsk, false, "u");
        assert!(keyfile.contains(
            "[wifi-security]\nkey-mgmt=wpa-eap\n\n[802-1x]\neap=peap;\nidentity=alice\n\
             ca-cert=/etc/pki/corp.pem\npassword=hunter22\nphase2-auth=mschapv2\n"
        ));
        assert!(!render_redacted(&request, KeyManagement::WpaPsk, false, "u").contains("hunter22"));
        assert!(!format!("{request:?}").contains("hunter22"));
    }

    #[test]
    fn invalid_requests_are_rejected_without_echoing_passwords() {
        for (security, ssid) in [
            (json!({"type": "wpa-personal", "password": "short"}), "Home"),
            (json!({"type": "wpa-personal", "password": "bad\npassword"}), "Home"),
            (json!({"type": "open"}), ""),
            (json!({"type": "open"}), "an SSID longer than thirty-two bytes"),
            (json!({"type": "wpa-enterprise", "eap": "tls", "identity": "a"}), "Home"),
        ] {
            let mut request = request(&security);
            request.ssid = ssid.to_owned();
            let error = validate(&request, KeyManagement::WpaPsk).unwrap_err().to_string();
            assert!(!error.contains("short") && !error.contains("bad"), "{error}");
        }
        // SAE passwords are not limited to WPA-PSK's 8-63 characters.
        let request = request(&json!({"type": "wpa-personal", "password": "short"}));
        validate(&request, KeyManagement::Sae).unwrap();
        // Unknown fields and security types are refused.
        for security in [
            json!({"type": "wep", "password": "x"}),
            json!({"type": "open", "password": "x"}),
            json!({"type": "wpa-personal", "password": "long-enough", "eap": "peap"}),
        ] {
            serde_json::from_value::<NetworkConnectWifiRequest>(json!({
                "interface": "wlan0", "ssid": "Home", "security": security,
            }))
            .unwrap_err();
        }
    }
}
