//! `virtual_machines` module payloads.

use crate::prelude::*;

use super::default_log_lines;

#[derive(Debug, Deserialize)]
pub struct VirtualMachineCreateRequest {
    pub xml_path: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
pub struct VirtualMachineLogsRequest {
    #[serde(default = "default_log_lines")]
    pub lines: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn virtual_machine_log_request_defaults_to_one_hundred_lines() {
        let logs: VirtualMachineLogsRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(logs.lines, 100);
    }
}
