//! ACME DNS-01 for the dashboard's certificate.
//!
//! `access.set` may ask Caddy to prove control of the domain through the DNS
//! provider instead of HTTP-01 (for servers that are not reachable on port 80,
//! or for internal names). The providers are the caddy-dns modules built into
//! terra-caddy; credential keys are named as in each module's Caddy JSON
//! config (and its Caddyfile subdirectives, which use the same names).
//!
//! Credentials never go into the Caddyfile. Tetra seals them in its secret
//! store ([`super::secrets::DNS_CREDENTIALS`]) and writes the secret ones to
//! `/etc/caddy/tetra-dns.env` (`root:caddy`, `0640`), which a
//! `caddy.service` drop-in loads with `EnvironmentFile=`. The site refers to
//! them as `{env.TETRA_DNS_<KEY>}` runtime placeholders, which the module
//! resolves when it is provisioned, so the adapted JSON config (and Caddy's
//! admin API) only ever contains the placeholder. Non-secret settings (a
//! region, a server URL) are written literally: not every module expands
//! placeholders in them (caddy-dns/acmedns only does for `password`).

use std::collections::BTreeMap;

use crate::prelude::*;

/// A caddy-dns module shipped in terra-caddy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProvider {
    Cloudflare,
    Porkbun,
    Desec,
    Route53,
    Hetzner,
    Ovh,
    Gandi,
    Linode,
    Powerdns,
    Rfc2136,
    Acmedns,
}

/// One credential key of a provider.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    /// Passed through the environment file rather than written literally.
    pub secret: bool,
    pub optional: bool,
}

const fn secret(name: &'static str) -> Field {
    Field {
        name,
        secret: true,
        optional: false,
    }
}

const fn setting(name: &'static str) -> Field {
    Field {
        name,
        secret: false,
        optional: false,
    }
}

const fn optional_setting(name: &'static str) -> Field {
    Field {
        name,
        secret: false,
        optional: true,
    }
}

impl DnsProvider {
    /// The Caddyfile `dns` provider name (`dns.providers.<name>`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Porkbun => "porkbun",
            Self::Desec => "desec",
            Self::Route53 => "route53",
            Self::Hetzner => "hetzner",
            Self::Ovh => "ovh",
            Self::Gandi => "gandi",
            Self::Linode => "linode",
            Self::Powerdns => "powerdns",
            Self::Rfc2136 => "rfc2136",
            Self::Acmedns => "acmedns",
        }
    }

    /// The credential keys this provider accepts.
    #[must_use]
    pub const fn fields(self) -> &'static [Field] {
        match self {
            Self::Cloudflare | Self::Hetzner | Self::Linode => API_TOKEN,
            Self::Porkbun => PORKBUN,
            Self::Desec => DESEC,
            Self::Route53 => ROUTE53,
            Self::Ovh => OVH,
            Self::Gandi => GANDI,
            Self::Powerdns => POWERDNS,
            Self::Rfc2136 => RFC2136,
            Self::Acmedns => ACMEDNS,
        }
    }
}

const API_TOKEN: &[Field] = &[secret("api_token")];
const PORKBUN: &[Field] = &[secret("api_key"), secret("api_secret_key")];
const DESEC: &[Field] = &[secret("token")];
const ROUTE53: &[Field] = &[
    setting("access_key_id"),
    secret("secret_access_key"),
    optional_setting("region"),
];
const OVH: &[Field] = &[
    setting("endpoint"),
    setting("application_key"),
    secret("application_secret"),
    secret("consumer_key"),
];
const GANDI: &[Field] = &[secret("bearer_token")];
const POWERDNS: &[Field] = &[setting("server_url"), secret("api_token")];
const RFC2136: &[Field] = &[
    setting("server"),
    setting("key_name"),
    setting("key_alg"),
    secret("key"),
];
const ACMEDNS: &[Field] = &[
    setting("server_url"),
    setting("subdomain"),
    setting("username"),
    secret("password"),
];

/// DNS provider credentials, keyed as in the module's Caddy config. Never
/// printed: `Debug` shows only the keys.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DnsCredentials(pub BTreeMap<String, String>);

impl std::fmt::Debug for DnsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

/// What Tetra seals: the provider together with its credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDnsCredentials {
    pub provider: DnsProvider,
    pub credentials: DnsCredentials,
}

const MAX_SECRET_LEN: usize = 4096;
const MAX_SETTING_LEN: usize = 512;

/// Check `credentials` against `provider`'s keys and values.
///
/// # Errors
/// Fails on an unknown or missing key, or a value that cannot be passed
/// safely. Messages name keys, never values.
pub fn validate(provider: DnsProvider, credentials: &DnsCredentials) -> Result<()> {
    let fields = provider.fields();
    for (key, value) in &credentials.0 {
        let field = fields
            .iter()
            .find(|field| field.name == key)
            .with_context(|| format!("`{key}` is not a {} credential", provider.name()))?;
        if field.secret {
            // Passed in a double-quoted environment file value.
            ensure!(
                (1..=MAX_SECRET_LEN).contains(&value.len()) && !value.chars().any(char::is_control),
                "`{key}` must be 1 to {MAX_SECRET_LEN} characters on one line"
            );
        } else {
            // Written into the Caddyfile as a quoted token.
            ensure!(
                (1..=MAX_SETTING_LEN).contains(&value.len())
                    && value.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || matches!(c, '.' | '-' | '_' | ':' | '/' | '@' | '+' | '=')
                    }),
                "`{key}` may only contain letters, digits and . - _ : / @ + ="
            );
        }
    }
    for field in fields.iter().filter(|field| !field.optional) {
        ensure!(
            credentials.0.contains_key(field.name),
            "`{}` is required for {}",
            field.name,
            provider.name()
        );
    }
    Ok(())
}

/// The environment variable that carries `key`.
#[must_use]
pub fn env_var(key: &str) -> String {
    format!("TETRA_DNS_{}", key.to_ascii_uppercase())
}

/// A value in the site's `dns` provider block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsValue {
    /// A secret: Caddy's runtime placeholder for this environment variable
    /// (see [`env_var`]), never the credential.
    Env(String),
    /// A setting, written literally (quoted).
    Literal(String),
}

/// `(key, value)` pairs for the site's `dns` block: an environment variable
/// for secrets, a literal for settings. Expects validated credentials.
#[must_use]
pub fn caddy_fields(
    provider: DnsProvider,
    credentials: &DnsCredentials,
) -> Vec<(&'static str, DnsValue)> {
    provider
        .fields()
        .iter()
        .filter_map(|field| {
            let value = credentials.0.get(field.name)?;
            let value = if field.secret {
                DnsValue::Env(env_var(field.name))
            } else {
                DnsValue::Literal(value.clone())
            };
            Some((field.name, value))
        })
        .collect()
}

/// The environment file holding the secret credentials. Expects validated
/// credentials.
#[must_use]
pub fn env_file(provider: DnsProvider, credentials: &DnsCredentials) -> String {
    let mut out = String::from(
        "# Managed by Tetra (access.set): DNS-01 credentials for the dashboard's\n\
         # certificate. Loaded by caddy.service; do not edit.\n",
    );
    for field in provider.fields().iter().filter(|field| field.secret) {
        if let Some(value) = credentials.0.get(field.name) {
            out.push_str(&env_var(field.name));
            out.push_str("=\"");
            for c in value.chars() {
                // systemd unescapes these inside double quotes.
                if matches!(c, '\\' | '"' | '`' | '$') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push_str("\"\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn credentials(value: Value) -> DnsCredentials {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn every_terra_caddy_module_is_known() {
        for name in [
            "cloudflare",
            "porkbun",
            "desec",
            "route53",
            "hetzner",
            "ovh",
            "gandi",
            "linode",
            "powerdns",
            "rfc2136",
            "acmedns",
        ] {
            let provider: DnsProvider = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(provider.name(), name);
            assert!(provider.fields().iter().any(|field| field.secret), "{name}");
        }
        serde_json::from_value::<DnsProvider>(json!("duckdns")).unwrap_err();
    }

    #[test]
    fn credentials_must_match_the_provider() {
        let token = credentials(json!({"api_token": "s3cret"}));
        validate(DnsProvider::Cloudflare, &token).unwrap();
        validate(DnsProvider::Porkbun, &token).unwrap_err();
        validate(DnsProvider::Cloudflare, &credentials(json!({}))).unwrap_err();
        validate(
            DnsProvider::Cloudflare,
            &credentials(json!({"api_token": "x", "zone": "y"})),
        )
        .unwrap_err();
        // Optional keys may be left out.
        validate(
            DnsProvider::Route53,
            &credentials(json!({"access_key_id": "AKIA1", "secret_access_key": "k"})),
        )
        .unwrap();
    }

    #[test]
    fn values_that_could_break_out_are_rejected_without_echoing_them() {
        for (provider, value) in [
            (
                DnsProvider::Cloudflare,
                json!({"api_token": "line\nTETRA_DNS_X=1"}),
            ),
            (DnsProvider::Cloudflare, json!({"api_token": ""})),
            (
                DnsProvider::Powerdns,
                json!({"server_url": "https://x\" }\nimport /etc/passwd", "api_token": "t"}),
            ),
            (
                DnsProvider::Powerdns,
                json!({"server_url": "{env.HOME}", "api_token": "t"}),
            ),
        ] {
            let error = validate(provider, &credentials(value))
                .unwrap_err()
                .to_string();
            assert!(
                !error.contains("TETRA_DNS_X=1") && !error.contains("passwd"),
                "{error}"
            );
        }
    }

    #[test]
    fn secrets_become_placeholders_and_settings_literals() {
        let acmedns = credentials(json!({
            "server_url": "https://auth.acme-dns.io",
            "subdomain": "d420c923-bbd7-4056-ab64-c3ca54c9b3cf",
            "username": "c36f50e8-4632-44f0-83fe-e070fef28a10",
            "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z"
        }));
        validate(DnsProvider::Acmedns, &acmedns).unwrap();
        let fields = caddy_fields(DnsProvider::Acmedns, &acmedns);
        let literal = |value: &str| DnsValue::Literal(value.into());
        assert_eq!(
            fields,
            [
                ("server_url", literal("https://auth.acme-dns.io")),
                ("subdomain", literal("d420c923-bbd7-4056-ab64-c3ca54c9b3cf")),
                ("username", literal("c36f50e8-4632-44f0-83fe-e070fef28a10")),
                ("password", DnsValue::Env("TETRA_DNS_PASSWORD".into())),
            ]
        );
        let env = env_file(DnsProvider::Acmedns, &acmedns);
        assert!(env.contains("TETRA_DNS_PASSWORD=\"htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z\"\n"));
        assert!(!env.contains("acme-dns.io"));
    }

    #[test]
    fn env_file_values_are_escaped() {
        let tsig = credentials(json!({
            "server": "ns1.example.com:53",
            "key_name": "tetra.",
            "key_alg": "hmac-sha256",
            "key": "a\"b\\c$d`e"
        }));
        validate(DnsProvider::Rfc2136, &tsig).unwrap();
        assert!(
            env_file(DnsProvider::Rfc2136, &tsig)
                .ends_with("TETRA_DNS_KEY=\"a\\\"b\\\\c\\$d\\`e\"\n")
        );
    }

    #[test]
    fn debug_output_shows_keys_only() {
        let token = credentials(json!({"api_token": "s3cret"}));
        assert_eq!(format!("{token:?}"), "{\"api_token\"}");
    }
}
