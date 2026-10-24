//! `nfs` and `samba` configuration payloads.

use crate::agent::module_support::SelinuxOptions;
use crate::prelude::*;

use super::files::{read_text, write_text};

/// Default `nfs` config path; non-admins may not override it.
pub const EXPORTS_PATH: &str = "/etc/exports";
/// Default `samba` config path; non-admins may not override it.
pub const SAMBA_CONFIG_PATH: &str = "/etc/samba/smb.conf";

fn default_exports_path() -> PathBuf {
    PathBuf::from(EXPORTS_PATH)
}

#[derive(Debug, Deserialize)]
pub struct NfsConfigRequest {
    #[serde(default = "default_exports_path")]
    pub path: PathBuf,
}

impl NfsConfigRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct NfsWriteConfigRequest {
    #[serde(default = "default_exports_path")]
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl NfsWriteConfigRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

fn default_samba_config_path() -> PathBuf {
    PathBuf::from(SAMBA_CONFIG_PATH)
}

#[derive(Debug, Deserialize)]
pub struct SambaConfigRequest {
    #[serde(default = "default_samba_config_path")]
    pub path: PathBuf,
}

impl SambaConfigRequest {
    pub fn read(&self) -> Result<String> {
        read_text(&self.path)
    }
}

#[derive(Debug, Deserialize)]
pub struct SambaWriteConfigRequest {
    #[serde(default = "default_samba_config_path")]
    pub path: PathBuf,
    pub contents: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub selinux: Option<SelinuxOptions>,
}

impl SambaWriteConfigRequest {
    pub fn write(&self) -> Result<()> {
        write_text(&self.path, &self.contents, self.dry_run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn configuration_requests_keep_their_module_defaults() {
        let nfs: NfsConfigRequest = serde_json::from_value(json!({})).unwrap();
        let samba: SambaConfigRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(nfs.path, PathBuf::from("/etc/exports"));
        assert_eq!(samba.path, PathBuf::from("/etc/samba/smb.conf"));
    }
}
