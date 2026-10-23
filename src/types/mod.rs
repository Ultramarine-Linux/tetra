//! Shared domain types used by Tetra's agent modules
//!
//! Grouped by the module that uses them; everything is re-exported here, so
//! `crate::types::X` names any of them.

mod apps;
mod files;
mod network;
mod services;
mod shares;
mod virtual_machines;

pub use apps::*;
pub use files::*;
pub use network::*;
pub use services::*;
pub use shares::*;
pub use virtual_machines::*;

use crate::prelude::*;

#[derive(Debug, Deserialize)]
pub struct DryRunRequest {
    #[serde(default)]
    pub dry_run: bool,
}

/// `true`, for `#[serde(default = "crate::types::default_true")]`.
pub(crate) const fn default_true() -> bool {
    true
}

const fn default_log_lines() -> u16 {
    100
}
