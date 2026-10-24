//! Validation and rendering of `network.configure` requests into
//! NetworkManager keyfiles.
//!
//! Everything a caller sends is checked here before any file is written: the
//! interface and profile names, each family's method, every address, prefix,
//! gateway, and DNS server, and that the result still leaves the host with at
//! least one routable address. Rendering is a pure function of the validated
//! request, so it is unit tested without touching the host.
//!
//! An optional `wired_8021x` section becomes the keyfile's `[802-1x]`
//! section. Its passwords are stored in the keyfile (which is `0600`, like
//! NetworkManager's own), and [`render_redacted`] gives the copy that is
//! returned to callers. Certificate and key paths must name regular files
//! in a certificate store ([`PKI_DIR`]), since NetworkManager reads them as
//! root, and not files Tetra stores for another profile ([`CertRoots`]).
//! Validation replaces each such path with the resolved one it checked, so
//! the keyfile names exactly that file.

use std::{
    collections::HashSet,
    fmt::{Display, Write as _},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use itertools::Itertools;
use rand::RngExt as _;

use super::addresses::AddressScope;
use crate::prelude::*;
use crate::types::{
    EapMethod, IpAddressConfig, IpConfig, Ipv4Config, Ipv4Method, Ipv6Config, Ipv6Method,
    NetworkConfigureRequest, Phase2Method, Wired8021x, is_pem,
};

/// Upper bound on addresses per family, to keep payloads reasonable.
const MAX_ADDRESSES: usize = 32;
/// Upper bound on DNS servers per family.
const MAX_DNS_SERVERS: usize = 8;
/// Linux `IFNAMSIZ` minus the trailing NUL.
const MAX_INTERFACE_LEN: usize = 15;
const MAX_NAME_LEN: usize = 64;
/// Upper bound on 802.1X identities and passwords.
const MAX_8021X_VALUE_LEN: usize = 256;
/// Upper bound on one PEM certificate (chain) or key.
const MAX_PEM_BYTES: usize = 64 * 1024;
/// The host's certificate store: 802.1X certificate and key paths must be
/// under it ([`CertRoots`]).
pub(super) const PKI_DIR: &str = "/etc/pki";
pub(super) const REDACTED: &str = "<redacted>";

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

/// Where a profile's 802.1X certificate and key paths may point.
#[derive(Clone, Copy, Debug)]
pub struct CertRoots<'a> {
    /// The host's certificate store ([`PKI_DIR`]).
    pub pki: &'a Path,
    /// Where Tetra stores PEM contents, one directory per profile
    /// ([`super::certs::CERTS_DIR`], inside `pki` except in tests). Each
    /// directory is pruned to what its own profile names, so a path in it
    /// is only accepted for that profile.
    pub tetra: &'a Path,
    /// The profile being validated, which names its directory in `tetra`.
    pub profile: &'a str,
}

impl CertRoots<'_> {
    /// Whether `real` (a resolved path) is a file this profile may use.
    fn allow(&self, real: &Path) -> bool {
        let under = |root: &Path| fs::canonicalize(root).is_ok_and(|root| real.starts_with(root));
        if under(self.tetra) {
            under(&self.tetra.join(self.profile))
        } else {
            under(self.pki)
        }
    }
}

/// Validate a `network.configure` request without changing the host.
/// 802.1X certificate and key paths must be regular files `cert_roots`
/// allows, and are replaced with their resolved paths (no symlinks, `.` or
/// `//`), so the keyfile names the very file checked, by the path
/// [`super::certs::prune`] looks for.
///
/// # Errors
/// Errs with a message naming the offending field.
pub fn validate(request: &mut NetworkConfigureRequest, cert_roots: &CertRoots<'_>) -> Result<()> {
    validate_interface(&request.interface)?;
    if let Some(name) = &request.name {
        validate_name(name)?;
    }
    let ipv4_routable = validate_family(&request.ipv4)?;
    let ipv6_routable = validate_family(&request.ipv6)?;
    if let Some(wired) = &mut request.wired_8021x {
        validate_8021x("wired_8021x", wired, cert_roots)?;
    }
    ensure!(
        ipv4_routable || ipv6_routable,
        "at least one of ipv4 or ipv6 must give the host a routable address \
         (ipv4 is {}, ipv6 is {})",
        request.ipv4.method.keyword(),
        request.ipv6.method.keyword(),
    );
    Ok(())
}

/// 1 to `max` letters, digits, `-`, `_` and `.`, not starting with `-` or
/// `.` nor containing `..`: safe as an argument, file name and keyfile value.
fn is_plain_name(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !value.starts_with(['-', '.'])
        && !value.contains("..")
}

pub(super) fn validate_interface(interface: &str) -> Result<()> {
    ensure!(
        is_plain_name(interface, MAX_INTERFACE_LEN),
        "interface `{interface}` is not a valid interface name"
    );
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        is_plain_name(name, MAX_NAME_LEN),
        "name `{name}` must be 1-{MAX_NAME_LEN} letters, digits, `-`, `_` or `.`"
    );
    Ok(())
}

/// A string value written to the keyfile: one line, no control characters.
/// Errors name the field, never the value (it may be a password).
fn validate_8021x_value(section: &str, field: &str, value: &str) -> Result<()> {
    ensure!(
        (1..=MAX_8021X_VALUE_LEN).contains(&value.len()) && !value.chars().any(char::is_control),
        "{section}.{field} must be 1 to {MAX_8021X_VALUE_LEN} characters on one line"
    );
    Ok(())
}

/// A certificate or key: PEM contents, or the absolute path of a regular
/// file `cert_roots` allows. NetworkManager reads it as root, so a path may
/// not name just any host file (another service's private key, say), nor a
/// FIFO or device it would block on; symlinks are followed before checking.
/// Returns the resolved path of a path, `None` for PEM contents. Errors
/// never show the value (it may be a private key).
fn validate_8021x_file(
    section: &str,
    field: &str,
    value: &str,
    cert_roots: &CertRoots<'_>,
) -> Result<Option<String>> {
    if is_pem(value) {
        ensure!(
            value.len() <= MAX_PEM_BYTES
                && value.contains("-----END ")
                && value
                    .chars()
                    .all(|c| c.is_ascii_graphic() || matches!(c, ' ' | '\n' | '\r' | '\t')),
            "{section}.{field} must be PEM text of at most {MAX_PEM_BYTES} bytes"
        );
        return Ok(None);
    }
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && !value.chars().any(char::is_control)
            && !path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir)),
        "{section}.{field} must be an absolute path or PEM contents"
    );
    let real = fs::canonicalize(path)
        .ok()
        .filter(|real| real.is_file() && cert_roots.allow(real))
        .and_then(|real| real.into_os_string().into_string().ok());
    ensure!(
        real.is_some(),
        "{section}.{field} must be a regular file under {}, and not in another \
         profile's directory in {}",
        cert_roots.pki.display(),
        cert_roots.tetra.display(),
    );
    Ok(real)
}

/// `domain_suffix_match`: a DNS name, matched case-insensitively.
fn validate_domain(section: &str, domain: &str) -> Result<()> {
    let valid = (1..=253).contains(&domain.len())
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    ensure!(
        valid,
        "{section}.domain_suffix_match `{domain}` is not a domain name"
    );
    Ok(())
}

/// Validate 802.1X settings; `section` names them in errors. Certificate
/// and key paths must be files `cert_roots` allows, and are replaced with
/// their resolved paths ([`validate`]).
pub(super) fn validate_8021x(
    section: &str,
    wired: &mut Wired8021x,
    cert_roots: &CertRoots<'_>,
) -> Result<()> {
    validate_8021x_value(section, "identity", &wired.identity)?;
    if let Some(anonymous) = &wired.anonymous_identity {
        validate_8021x_value(section, "anonymous_identity", anonymous)?;
    }
    if let Some(password) = &wired.password {
        validate_8021x_value(section, "password", password)?;
    }
    if let Some(password) = &wired.private_key_password {
        validate_8021x_value(section, "private_key_password", password)?;
    }
    for (field, value) in [
        ("ca_cert", &mut wired.ca_cert),
        ("client_cert", &mut wired.client_cert),
        ("private_key", &mut wired.private_key),
    ] {
        if let Some(value) = value
            && let Some(real) = validate_8021x_file(section, field, value, cert_roots)?
        {
            *value = real;
        }
    }
    if let Some(domain) = &wired.domain_suffix_match {
        validate_domain(section, domain)?;
        // Only these methods check the server's certificate.
        ensure!(
            matches!(
                wired.eap,
                EapMethod::Tls | EapMethod::Peap | EapMethod::Ttls
            ),
            "{section}.domain_suffix_match is only used with tls, peap and ttls"
        );
    }
    let tunneled = matches!(wired.eap, EapMethod::Peap | EapMethod::Ttls);
    ensure!(
        tunneled || (wired.phase2.is_none() && wired.anonymous_identity.is_none()),
        "{section}.phase2 and anonymous_identity are only used with peap and ttls"
    );
    // Inside PEAP only EAP methods run; pap, chap and mschap are TTLS's.
    ensure!(
        wired.eap != EapMethod::Peap
            || matches!(
                wired.phase2,
                None | Some(Phase2Method::Mschapv2 | Phase2Method::Gtc | Phase2Method::Md5)
            ),
        "{section}.phase2 for peap must be mschapv2, gtc or md5"
    );
    if wired.eap == EapMethod::Tls {
        ensure!(
            wired.client_cert.is_some() && wired.private_key.is_some(),
            "{section}.client_cert and private_key are required for tls"
        );
        ensure!(
            wired.password.is_none(),
            "{section}.password is not used with tls; use private_key_password"
        );
    } else {
        ensure!(
            wired.password.is_some(),
            "{section}.password is required unless eap is tls"
        );
        ensure!(
            wired.client_cert.is_none()
                && wired.private_key.is_none()
                && wired.private_key_password.is_none(),
            "{section}.client_cert and private_key are only used with tls"
        );
    }
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
        for IpAddressConfig {
            address,
            prefix_length,
        } in &config.addresses
        {
            ensure!(
                (1..=A::MAX_PREFIX).contains(prefix_length),
                "{label} prefix_length for {address} must be between 1 and {}",
                A::MAX_PREFIX
            );
            ensure!(
                is_unicast(address.ip()),
                "{label} address {address} cannot be assigned to an interface"
            );
            address.check_host(*prefix_length)?;
        }
        ensure_unique(config.addresses.iter().map(|a| a.address), label, "address")?;
        if let Some(gateway) = config.gateway {
            ensure!(
                is_unicast(gateway.ip()),
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

/// Whether `address` can be an interface's address or a gateway.
fn is_unicast(address: IpAddr) -> bool {
    !matches!(
        AddressScope::of(address),
        AddressScope::Unspecified | AddressScope::Loopback | AddressScope::Multicast
    )
}

fn ensure_unique<A: Family>(
    values: impl Iterator<Item = A>,
    label: &str,
    what: &str,
) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        ensure!(seen.insert(value), "{label} {what} {value} is listed twice");
    }
    Ok(())
}

/// Render a validated request into keyfile contents.
#[must_use]
pub fn render(request: &NetworkConfigureRequest, uuid: &str) -> String {
    render_keyfile(request, uuid, false)
}

/// [`render`] with 802.1X passwords replaced, for responses.
#[must_use]
pub fn render_redacted(request: &NetworkConfigureRequest, uuid: &str) -> String {
    render_keyfile(request, uuid, true)
}

fn render_keyfile(request: &NetworkConfigureRequest, uuid: &str, redact: bool) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ok: std::fmt::Result = (|| {
        render_connection(
            &mut out,
            "configure",
            connection_name(request),
            uuid,
            "ethernet",
            &request.interface,
        )?;
        writeln!(out, "[ethernet]")?;
        writeln!(out)?;
        if let Some(wired) = &request.wired_8021x {
            render_8021x(&mut out, wired, redact)?;
            writeln!(out)?;
        }
        render_ip(&mut out, &request.ipv4, &request.ipv6)
    })();
    out
}

/// The header and `[connection]` section of a profile `network.<action>`
/// writes, with the blank line after it.
pub(super) fn render_connection(
    out: &mut String,
    action: &str,
    id: &str,
    uuid: &str,
    kind: &str,
    interface: &str,
) -> std::fmt::Result {
    writeln!(out, "# Managed by Tetra (network.{action}).")?;
    writeln!(out, "[connection]")?;
    writeln!(out, "id={id}")?;
    writeln!(out, "uuid={uuid}")?;
    writeln!(out, "type={kind}")?;
    writeln!(out, "interface-name={interface}")?;
    writeln!(out, "autoconnect=true")?;
    writeln!(out)
}

/// The `[ipv4]` and `[ipv6]` sections, which end the profile.
pub(super) fn render_ip(
    out: &mut String,
    ipv4: &Ipv4Config,
    ipv6: &Ipv6Config,
) -> std::fmt::Result {
    render_family(out, ipv4)?;
    writeln!(out)?;
    render_family(out, ipv6)
}

const fn eap_keyword(method: EapMethod) -> &'static str {
    match method {
        EapMethod::Tls => "tls",
        EapMethod::Peap => "peap",
        EapMethod::Ttls => "ttls",
        EapMethod::Pwd => "pwd",
        EapMethod::Md5 => "md5",
    }
}

const fn phase2_keyword(method: Phase2Method) -> &'static str {
    match method {
        Phase2Method::Mschapv2 => "mschapv2",
        Phase2Method::Mschap => "mschap",
        Phase2Method::Pap => "pap",
        Phase2Method::Chap => "chap",
        Phase2Method::Gtc => "gtc",
        Phase2Method::Md5 => "md5",
    }
}

/// Escape a string for a keyfile (`GKeyFile`) value: backslashes, and
/// leading whitespace, which `GKeyFile` would otherwise strip. Control
/// characters were rejected by validation.
pub(super) fn keyfile_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut leading = true;
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' if leading => out.push_str("\\s"),
            c => out.push(c),
        }
        leading = leading && c == ' ';
    }
    out
}

pub(super) fn render_8021x(out: &mut String, wired: &Wired8021x, redact: bool) -> std::fmt::Result {
    let secret = |value: &str| {
        if redact {
            REDACTED.to_owned()
        } else {
            keyfile_value(value)
        }
    };
    writeln!(out, "[802-1x]")?;
    writeln!(out, "eap={};", eap_keyword(wired.eap))?;
    writeln!(out, "identity={}", keyfile_value(&wired.identity))?;
    if let Some(anonymous) = &wired.anonymous_identity {
        writeln!(out, "anonymous-identity={}", keyfile_value(anonymous))?;
    }
    // PEM contents have been stored as files by now (see `certs`); only
    // paths are written.
    for (key, value) in [
        ("ca-cert", &wired.ca_cert),
        ("client-cert", &wired.client_cert),
        ("private-key", &wired.private_key),
    ] {
        if let Some(path) = value.as_deref().filter(|value| !is_pem(value)) {
            writeln!(out, "{key}={}", keyfile_value(path))?;
        }
    }
    if let Some(domain) = &wired.domain_suffix_match {
        writeln!(out, "domain-suffix-match={}", domain.to_ascii_lowercase())?;
        // Matching a name is only meaningful for a certificate checked
        // against some CA: without `ca_cert`, the system's.
        if wired.ca_cert.is_none() {
            writeln!(out, "system-ca-certs=true")?;
        }
    }
    if let Some(password) = &wired.private_key_password {
        writeln!(out, "private-key-password={}", secret(password))?;
    } else if wired.eap == EapMethod::Tls {
        // An unencrypted key: otherwise NetworkManager asks for its
        // password and the activation fails (`NM_SETTING_SECRET_FLAG_NOT_REQUIRED`).
        writeln!(out, "private-key-password-flags=4")?;
    }
    if let Some(password) = &wired.password {
        writeln!(out, "password={}", secret(password))?;
    }
    if matches!(wired.eap, EapMethod::Peap | EapMethod::Ttls) {
        let phase2 = wired.phase2.unwrap_or(Phase2Method::Mschapv2);
        // TTLS runs EAP inner methods through `phase2-autheap`.
        let key = match (wired.eap, phase2) {
            (EapMethod::Ttls, Phase2Method::Gtc | Phase2Method::Md5) => "phase2-autheap",
            _ => "phase2-auth",
        };
        writeln!(out, "{key}={}", phase2_keyword(phase2))?;
    }
    Ok(())
}

fn render_family<M: Method, A: Family>(
    out: &mut String,
    config: &IpConfig<M, A>,
) -> std::fmt::Result {
    writeln!(out, "[{}]", A::LABEL)?;
    writeln!(out, "method={}", config.method.keyword())?;
    for (
        index,
        IpAddressConfig {
            address,
            prefix_length,
        },
    ) in (1_usize..).zip(&config.addresses)
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
    let hex = crate::auth::sessions::hex(&bytes);
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

    /// Roots no path is under.
    fn no_roots() -> CertRoots<'static> {
        CertRoots {
            pki: Path::new("/nonexistent"),
            tetra: Path::new("/nonexistent"),
            profile: "eth0",
        }
    }

    /// `store` as the host's certificate store.
    fn roots(store: &Path) -> CertRoots<'_> {
        CertRoots {
            pki: store,
            ..no_roots()
        }
    }

    fn rendered(value: Value) -> String {
        let mut request = request(value);
        validate(&mut request, &no_roots()).unwrap();
        render(&request, UUID)
    }

    fn rejection(value: Value) -> String {
        match serde_json::from_value::<NetworkConfigureRequest>(value) {
            Ok(mut request) => validate(&mut request, &no_roots()).unwrap_err().to_string(),
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
        assert!(
            keyfile.ends_with(
                "[ipv4]\nmethod=auto\ndns=1.1.1.1;9.9.9.9;\n\n[ipv6]\nmethod=link-local\n"
            )
        );
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
        assert_eq!(
            keyfile,
            header("eth0") + "[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n"
        );
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
            assert!(
                keyfile.contains(&format!("[ipv4]\nmethod={v4}\n")),
                "{keyfile}"
            );
            assert!(
                keyfile.contains(&format!("[ipv6]\nmethod={v6}\n")),
                "{keyfile}"
            );
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
        for interface in [
            "",
            "../etc",
            "eth0/x",
            "-eth0",
            ".",
            "a-very-long-interface-name",
            "eth 0",
            "eth0\n",
        ] {
            rejection(json!({ "interface": interface }));
        }
        for name in ["", "..", ".hidden", "a/b", "a..b", "with space", "x\ny"] {
            rejection(json!({ "interface": "eth0", "name": name }));
        }
    }

    // Wired 802.1X.

    /// A certificate store holding `radius-ca.pem`.
    fn store() -> (tempfile::TempDir, String) {
        let store = tempfile::tempdir().unwrap();
        let ca = store.path().join("radius-ca.pem");
        fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        (store, ca.to_string_lossy().into_owned())
    }

    #[test]
    fn wired_8021x_peap_renders_an_8021x_section() {
        let (store, ca) = store();
        let mut request = request(json!({
            "interface": "eth0",
            "wired_8021x": {
                "eap": "peap",
                "identity": "alice@example.com",
                "anonymous_identity": "anonymous@example.com",
                "password": " pa\\ss word",
                "ca_cert": ca,
            }
        }));
        validate(&mut request, &roots(store.path())).unwrap();
        assert!(!format!("{request:?}").contains("pa\\ss"));
        let keyfile = render(&request, UUID);
        assert_eq!(
            keyfile,
            header("eth0")
                + "[802-1x]\neap=peap;\nidentity=alice@example.com\n\
                   anonymous-identity=anonymous@example.com\n"
                + &format!("ca-cert={ca}\n")
                + "password=\\spa\\\\ss word\nphase2-auth=mschapv2\n\n\
                   [ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n"
        );
        let redacted = render_redacted(&request, UUID);
        assert!(redacted.contains("password=<redacted>\n"));
        assert!(!redacted.contains("ss word"));
    }

    #[test]
    fn wired_8021x_tls_uses_certificates() {
        let keyfile = render(
            &request(json!({
                "interface": "eth0",
                "wired_8021x": {
                    "eap": "tls",
                    "identity": "host.example.com",
                    "ca_cert": "/etc/pki/8021x/ca.pem",
                    "client_cert": "/etc/pki/8021x/client.pem",
                    "private_key": "/etc/pki/8021x/client.key",
                    "private_key_password": "keypass"
                }
            })),
            UUID,
        );
        assert!(keyfile.contains(
            "[802-1x]\neap=tls;\nidentity=host.example.com\nca-cert=/etc/pki/8021x/ca.pem\n\
             client-cert=/etc/pki/8021x/client.pem\nprivate-key=/etc/pki/8021x/client.key\n\
             private-key-password=keypass\n\n[ipv4]"
        ));
        assert!(!keyfile.contains("phase2"));
    }

    #[test]
    fn wired_8021x_ttls_takes_a_phase2_method() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "wired_8021x": { "eap": "ttls", "identity": "bob", "password": "x", "phase2": "pap" }
        }));
        assert!(keyfile.contains("phase2-auth=pap\n"));
        // EAP inner methods go in `phase2-autheap`, for TTLS.
        let keyfile = rendered(json!({
            "interface": "eth0",
            "wired_8021x": { "eap": "ttls", "identity": "bob", "password": "x", "phase2": "gtc" }
        }));
        assert!(keyfile.contains("phase2-autheap=gtc\n") && !keyfile.contains("phase2-auth="));
        let keyfile = rendered(json!({
            "interface": "eth0",
            "wired_8021x": { "eap": "peap", "identity": "bob", "password": "x", "phase2": "md5" }
        }));
        assert!(keyfile.contains("phase2-auth=md5\n"));
    }

    #[test]
    fn wired_8021x_tls_key_without_a_password_needs_none() {
        let keyfile = render(
            &request(json!({
                "interface": "eth0",
                "wired_8021x": {
                    "eap": "tls",
                    "identity": "host.example.com",
                    "client_cert": "/etc/pki/8021x/client.pem",
                    "private_key": "/etc/pki/8021x/client.key"
                }
            })),
            UUID,
        );
        assert!(
            keyfile
                .contains("private-key=/etc/pki/8021x/client.key\nprivate-key-password-flags=4\n")
        );
    }

    #[test]
    fn domain_suffix_match_without_a_ca_uses_the_system_cas() {
        let keyfile = rendered(json!({
            "interface": "eth0",
            "wired_8021x": {
                "eap": "peap", "identity": "bob", "password": "x",
                "domain_suffix_match": "radius.example.com"
            }
        }));
        assert!(keyfile.contains("domain-suffix-match=radius.example.com\nsystem-ca-certs=true\n"));
        // With a CA of its own, that CA is the one the server is checked against.
        let keyfile = render(
            &request(json!({
                "interface": "eth0",
                "wired_8021x": {
                    "eap": "peap", "identity": "bob", "password": "x",
                    "ca_cert": "/etc/pki/ca.pem", "domain_suffix_match": "radius.example.com"
                }
            })),
            UUID,
        );
        assert!(!keyfile.contains("system-ca-certs"));
    }

    #[test]
    fn certificate_paths_must_be_regular_files_in_a_store() {
        let (store, ca) = store();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("host.key");
        fs::write(&secret, "key").unwrap();
        let escape = store.path().join("escape.pem");
        std::os::unix::fs::symlink(&secret, &escape).unwrap();
        let alias = store.path().join("alias.pem");
        std::os::unix::fs::symlink(&ca, &alias).unwrap();
        let fifo = store.path().join("fifo.pem");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let check = |path: &Path| {
            validate(
                &mut request(json!({
                    "interface": "eth0",
                    "wired_8021x": { "eap": "peap", "identity": "bob", "password": "x", "ca_cert": path }
                })),
                &roots(store.path()),
            )
        };

        check(Path::new(&ca)).unwrap();
        check(&alias).unwrap();
        for path in [
            &secret,
            &escape,
            &fifo,
            &store.path().join("missing.pem"),
            store.path(),
        ] {
            let error = check(path).unwrap_err().to_string();
            assert!(error.contains("must be a regular file under"), "{error}");
        }
    }

    #[test]
    fn stored_certificates_only_serve_their_own_profile() {
        // Tetra's store, inside the host's, with a file for `eth0` and one
        // for `eth1`, which pruning `eth1`'s directory would delete.
        let (store, ca) = store();
        let tetra = store.path().join("tetra");
        for profile in ["eth0", "eth1"] {
            fs::create_dir_all(tetra.join(profile)).unwrap();
            fs::write(
                tetra.join(profile).join("ca-cert.pem"),
                "-----BEGIN CERTIFICATE-----\n",
            )
            .unwrap();
        }
        let roots = CertRoots {
            pki: store.path(),
            tetra: &tetra,
            profile: "eth0",
        };
        let check = |path: &Path| {
            validate(
                &mut request(json!({
                    "interface": "eth0",
                    "wired_8021x": { "eap": "peap", "identity": "bob", "password": "x", "ca_cert": path }
                })),
                &roots,
            )
        };

        check(Path::new(&ca)).unwrap();
        check(&tetra.join("eth0/ca-cert.pem")).unwrap();
        let error = check(&tetra.join("eth1/ca-cert.pem"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("another profile's directory"), "{error}");
        // Nor through a symlink, or a file directly in Tetra's store.
        let alias = store.path().join("alias.pem");
        std::os::unix::fs::symlink(tetra.join("eth1/ca-cert.pem"), &alias).unwrap();
        check(&alias).unwrap_err();
        fs::write(tetra.join("loose.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
        check(&tetra.join("loose.pem")).unwrap_err();
    }

    #[test]
    fn certificate_paths_are_rendered_as_the_file_checked() {
        // Pruning keeps only the stored files a keyfile names by their real
        // path, so `eth0`'s own file reached another way must be rendered
        // by that path, or pruning would delete it.
        let (store, _) = store();
        let tetra = store.path().join("tetra");
        fs::create_dir_all(tetra.join("eth0")).unwrap();
        let real = tetra.join("eth0/ca-cert.pem");
        fs::write(&real, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let alias = store.path().join("alias.pem");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let roots = CertRoots {
            pki: store.path(),
            tetra: &tetra,
            profile: "eth0",
        };
        let real = fs::canonicalize(&real)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        for path in [
            alias.to_string_lossy().into_owned(),
            format!("{}//eth0/./ca-cert.pem", tetra.display()),
        ] {
            let mut request = request(json!({
                "interface": "eth0",
                "wired_8021x": { "eap": "peap", "identity": "bob", "password": "x", "ca_cert": path }
            }));
            validate(&mut request, &roots).unwrap();
            assert!(
                render(&request, UUID).contains(&format!("\nca-cert={real}\n")),
                "{path}"
            );
        }
    }

    #[test]
    fn wired_8021x_rejects_incomplete_or_unsafe_settings() {
        for wired in [
            // Password methods need a password.
            json!({ "eap": "peap", "identity": "bob" }),
            // TLS needs a certificate and key.
            json!({ "eap": "tls", "identity": "bob", "client_cert": "/c.pem" }),
            json!({ "eap": "tls", "identity": "bob", "client_cert": "/c.pem", "private_key": "/k", "password": "x" }),
            // Inner methods only for tunneled EAP.
            json!({ "eap": "md5", "identity": "bob", "password": "x", "phase2": "pap" }),
            // PEAP runs only EAP methods inside.
            json!({ "eap": "peap", "identity": "bob", "password": "x", "phase2": "pap" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "phase2": "mschap" }),
            // Certificates only for TLS.
            json!({ "eap": "pwd", "identity": "bob", "password": "x", "client_cert": "/c.pem" }),
            // Keyfile injection.
            json!({ "eap": "peap", "identity": "bob\n[connection]\nautoconnect=false", "password": "x" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x\ny=z" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "ca_cert": "relative.pem" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "ca_cert": "-----BEGIN CERTIFICATE-----\nno end" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "ca_cert": format!("-----BEGIN X-----\n{}\n-----END X-----", "A".repeat(70_000)) }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "domain_suffix_match": "not a domain" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "domain_suffix_match": "-bad.example" }),
            json!({ "eap": "md5", "identity": "bob", "password": "x", "domain_suffix_match": "example.com" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "ca_cert": "/etc/../shadow" }),
            json!({ "eap": "peap", "identity": "", "password": "x" }),
            json!({ "eap": "leap", "identity": "bob", "password": "x" }),
            json!({ "eap": "peap", "identity": "bob", "password": "x", "domain": "y" }),
        ] {
            let error = rejection(json!({ "interface": "eth0", "wired_8021x": wired }));
            assert!(!error.contains("y=z"), "{error}");
            // Nor any certificate or key contents.
            assert!(
                !error.contains("no end") && !error.contains("AAAA"),
                "{error}"
            );
        }
    }

    #[test]
    fn reads_existing_uuid_from_connection_section_only() {
        let keyfile = b"[connection]\nid=eth0\nuuid=0B0C3A52-4F43-4B6B-9A54-2D1B0F5E8C11\n\n[ipv4]\nuuid=nope\n";
        assert_eq!(existing_uuid(keyfile).as_deref(), Some(UUID));
        assert_eq!(
            existing_uuid(b"[ipv4]\nuuid=0b0c3a52-4f43-4b6b-9a54-2d1b0f5e8c11\n"),
            None
        );
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
