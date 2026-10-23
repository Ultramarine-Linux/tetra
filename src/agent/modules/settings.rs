//! Always-available settings module.
//!
//! Unlike the feature-gated modules in this crate, `settings` is compiled
//! unconditionally so the control plane can always discover basic host facts
//! (OS, architecture, family) via `get_system`. It is also the simplest
//! reference implementation of the `AgentModule` trait for new contributors.
//!
//! The host-wide console settings the OOBE asks for are here too:
//! `set_keymap` (`localectl set-x11-keymap`, which also converts the layout to
//! the virtual console keymap), `set_locale` (`localectl set-locale`) and
//! `set_timezone` (`timedatectl set-timezone`).

use serde_json::json;

use crate::agent::module_support::run_for;
use crate::prelude::*;

/// Marker type for the always-on settings module. It carries no state: all
/// behavior is expressed through the `Mod` impl and the static
/// [`INFO`] descriptor below.
#[derive(Clone, Copy, Debug)]
pub struct SettingsModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "settings",
    // "core" is a pseudo-feature: this module has no Cargo feature flag and is
    // always compiled in. The field exists only so the descriptor shape matches
    // the other modules.
    feature: "core",
    description: "Agent and host settings that are always available.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "get_system",
        "set_hostname",
        "set_keymap",
        "set_locale",
        "set_timezone",
    ],
    privileged_actions: &["set_hostname", "set_keymap", "set_locale", "set_timezone"],
};

impl Mod for SettingsModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    // `std::env::consts` are compile-time constants derived from the
    // target triple, so `get_system` performs no host probe and is safe
    // to call in any context.
    GetSystem => Ok(json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
    })),
    SetHostname {
        hostname: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        validate_hostname(&payload.hostname)?;
        Ok(run_for(
            &INFO, "set_hostname", user,
            "hostnamectl", ["set-hostname", &payload.hostname], payload.dry_run,
        )?.into_json())
    },
    SetKeymap {
        /// X11 layout, such as `us` or `de` (comma-separated for several).
        layout: String,
        /// X11 variant, such as `dvorak` or `nodeadkeys`.
        #[serde(default)]
        variant: Option<String>,
        #[serde(default)]
        dry_run: bool,
    } => {
        validate_keymap_part("layout", &payload.layout)?;
        let variant = payload.variant.as_deref().filter(|variant| !variant.is_empty());
        if let Some(variant) = variant {
            validate_keymap_part("variant", variant)?;
        }
        // `set-x11-keymap LAYOUT [MODEL [VARIANT]]`; an empty model keeps
        // the default. localectl also converts it to the console keymap.
        let mut args = vec!["set-x11-keymap", payload.layout.as_str()];
        if let Some(variant) = variant {
            args.extend(["", variant]);
        }
        Ok(run_for(&INFO, "set_keymap", user, "localectl", &args, payload.dry_run)?.into_json())
    },
    SetLocale {
        /// System locale (`LANG`), such as `en_US.UTF-8`.
        locale: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        validate_locale(&payload.locale)?;
        let lang = format!("LANG={}", payload.locale);
        Ok(run_for(
            &INFO, "set_locale", user,
            "localectl", ["set-locale", &lang], payload.dry_run,
        )?.into_json())
    },
    SetTimezone {
        /// IANA time zone, such as `Europe/Berlin` or `UTC`.
        timezone: String,
        #[serde(default)]
        dry_run: bool,
    } => {
        validate_timezone(&payload.timezone)?;
        Ok(run_for(
            &INFO, "set_timezone", user,
            "timedatectl", ["set-timezone", &payload.timezone], payload.dry_run,
        )?.into_json())
    },
});

/// A hostname for `hostnamectl set-hostname`, which also accepts a "pretty"
/// name (spaces, Unicode). Refuses what would be read as an option (the
/// setup session can call this) and control characters.
fn validate_hostname(hostname: &str) -> Result<()> {
    crate::agent::module_support::positional("hostname", hostname)?;
    ensure!(
        hostname.len() <= 255 && !hostname.chars().any(char::is_control),
        "hostname must be at most 255 bytes without control characters"
    );
    Ok(())
}

/// XKB layout and variant names: letters, digits, `_`, `-`, and `,` between
/// several layouts.
fn validate_keymap_part(field: &str, value: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&value.len())
            && !value.starts_with('-')
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ',')),
        "{field} `{value}` is not a valid keyboard {field}"
    );
    Ok(())
}

/// `language[_TERRITORY][.codeset][@modifier]`, as in `/usr/share/i18n`.
fn validate_locale(locale: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&locale.len())
            && locale.starts_with(|c: char| c.is_ascii_alphabetic())
            && locale
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@')),
        "`{locale}` is not a valid locale"
    );
    Ok(())
}

/// A relative path under `/usr/share/zoneinfo`; timedatectl checks that it
/// exists.
fn validate_timezone(timezone: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&timezone.len())
            && timezone.starts_with(|c: char| c.is_ascii_alphabetic())
            && !timezone.contains("..")
            && !timezone.ends_with('/')
            && timezone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/')),
        "`{timezone}` is not a valid time zone"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn dry_run(action: &str, payload: Value) -> Result<Value> {
        SettingsModule.handle(action, payload, None)
    }

    #[test]
    fn set_keymap_runs_localectl_with_optional_variant() {
        let response = dry_run("set_keymap", json!({"layout": "de", "dry_run": true})).unwrap();
        assert_eq!(response["command"], "localectl set-x11-keymap de");
        assert_eq!(response["dry_run"], true);
        let response = dry_run(
            "set_keymap",
            json!({"layout": "us", "variant": "dvorak", "dry_run": true}),
        )
        .unwrap();
        // The empty model argument keeps the default model.
        assert_eq!(response["command"], "localectl set-x11-keymap us  dvorak");
    }

    #[test]
    fn set_keymap_rejects_option_like_or_odd_values() {
        for payload in [
            json!({"layout": "--help", "dry_run": true}),
            json!({"layout": "us; reboot", "dry_run": true}),
            json!({"layout": "", "dry_run": true}),
            json!({"layout": "us", "variant": "-x", "dry_run": true}),
        ] {
            dry_run("set_keymap", payload).unwrap_err();
        }
    }

    #[test]
    fn set_locale_runs_localectl() {
        let response = dry_run(
            "set_locale",
            json!({"locale": "de_DE.UTF-8", "dry_run": true}),
        )
        .unwrap();
        assert_eq!(response["command"], "localectl set-locale LANG=de_DE.UTF-8");
        for locale in ["", "LC_ALL=C x", "-C", "en US"] {
            dry_run("set_locale", json!({"locale": locale, "dry_run": true})).unwrap_err();
        }
    }

    #[test]
    fn set_timezone_runs_timedatectl() {
        let response = dry_run(
            "set_timezone",
            json!({"timezone": "America/Argentina/Buenos_Aires", "dry_run": true}),
        )
        .unwrap();
        assert_eq!(
            response["command"],
            "timedatectl set-timezone America/Argentina/Buenos_Aires"
        );
        dry_run(
            "set_timezone",
            json!({"timezone": "Etc/GMT+5", "dry_run": true}),
        )
        .unwrap();
        for timezone in ["", "../etc/shadow", "/etc/localtime", "-x", "Europe/"] {
            dry_run(
                "set_timezone",
                json!({"timezone": timezone, "dry_run": true}),
            )
            .unwrap_err();
        }
    }

    #[test]
    fn console_settings_are_privileged() {
        for action in ["set_keymap", "set_locale", "set_timezone"] {
            assert!(INFO.is_privileged(action), "{action}");
        }
    }
}
