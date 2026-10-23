//! Frames of a shell stream, after `shell.open` succeeded.
//!
//! Binary messages carry terminal bytes both ways. Text messages are small
//! JSON control frames: [`ClientControl`] from the dashboard,
//! [`ServerControl`] from Tetra.

use serde::{Deserialize, Serialize};

/// Largest terminal side Tetra accepts, in cells.
pub const MAX_DIMENSION: u16 = 1000;
/// Largest control frame read; longer text messages are ignored.
pub const MAX_CONTROL_BYTES: usize = 1024;
/// Terminal size when `shell.open` names none.
pub const DEFAULT_SIZE: WindowSize = WindowSize { cols: 80, rows: 24 };

/// A terminal size in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSize {
    pub cols: u16,
    pub rows: u16,
}

impl WindowSize {
    /// A size of 1 to [`MAX_DIMENSION`] cells each way.
    ///
    /// # Errors
    /// Says which side is out of range.
    pub fn new(cols: u16, rows: u16) -> Result<Self, String> {
        for (name, value) in [("cols", cols), ("rows", rows)] {
            if !(1..=MAX_DIMENSION).contains(&value) {
                return Err(format!("{name} must be between 1 and {MAX_DIMENSION}"));
            }
        }
        Ok(Self { cols, rows })
    }
}

/// `shell.open` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenParams {
    /// From `shell.ticket`.
    pub ticket: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
}

const fn default_cols() -> u16 {
    DEFAULT_SIZE.cols
}

const fn default_rows() -> u16 {
    DEFAULT_SIZE.rows
}

/// A control frame from the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientControl {
    /// The browser's terminal changed size.
    Resize { cols: u16, rows: u16 },
}

impl ClientControl {
    /// Parse a text message. Anything that is not a known, valid control
    /// frame is `None` and ignored, so newer dashboards can send frames this
    /// build does not know.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_CONTROL_BYTES {
            return None;
        }
        match serde_json::from_str(text).ok()? {
            Self::Resize { cols, rows } => WindowSize::new(cols, rows)
                .ok()
                .map(|_| Self::Resize { cols, rows }),
        }
    }
}

/// Why a shell ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitReason {
    /// The shell exited (the user typed `exit`, or it was killed).
    Exited,
    /// Its session ended: logout, revocation, expiry, or the account may no
    /// longer log in or open a shell.
    SessionEnded,
    /// No input for the idle timeout.
    IdleTimeout,
    /// The dashboard closed the connection (never sent: it is gone).
    ClientClosed,
    /// The dashboard broke the protocol (an oversized input message).
    ProtocolError,
}

/// A control frame from Tetra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerControl {
    /// The shell has ended; Tetra closes the connection next. `status` is the
    /// exit status when the shell exited by itself with one, else `null`.
    Exit {
        status: Option<i32>,
        reason: ExitReason,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_frames_parse_and_are_checked() {
        assert_eq!(
            ClientControl::parse(r#"{"type":"resize","cols":120,"rows":40}"#),
            Some(ClientControl::Resize {
                cols: 120,
                rows: 40
            })
        );
        for invalid in [
            r#"{"type":"resize","cols":0,"rows":40}"#,
            r#"{"type":"resize","cols":120,"rows":1001}"#,
            r#"{"type":"resize","cols":-1,"rows":40}"#,
            r#"{"type":"resize","cols":70000,"rows":40}"#,
            r#"{"type":"resize","cols":120}"#,
            r#"{"type":"paste","data":"rm -rf /"}"#,
            r#"{"cols":120,"rows":40}"#,
            "resize 120 40",
            "",
        ] {
            assert_eq!(ClientControl::parse(invalid), None, "{invalid}");
        }
        let padded = format!(
            r#"{{"type":"resize","cols":120,"rows":40}}{}"#,
            " ".repeat(MAX_CONTROL_BYTES)
        );
        assert_eq!(ClientControl::parse(&padded), None);
    }

    #[test]
    fn open_params_default_to_80_by_24_and_refuse_unknown_fields() {
        let params: OpenParams = serde_json::from_str(r#"{"ticket":"t"}"#).unwrap();
        assert_eq!((params.cols, params.rows), (80, 24));
        serde_json::from_str::<OpenParams>(r#"{"ticket":"t","uid":0}"#).unwrap_err();
        serde_json::from_str::<OpenParams>(r#"{"cols":80}"#).unwrap_err();
        WindowSize::new(1, MAX_DIMENSION).unwrap();
        WindowSize::new(0, 1).unwrap_err();
    }

    #[test]
    fn exit_frames_serialize_with_a_type_tag() {
        let frame = ServerControl::Exit {
            status: Some(3),
            reason: ExitReason::Exited,
        };
        assert_eq!(
            serde_json::to_value(frame).unwrap(),
            serde_json::json!({"type": "exit", "status": 3, "reason": "exited"})
        );
        let frame = ServerControl::Exit {
            status: None,
            reason: ExitReason::SessionEnded,
        };
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"type":"exit","status":null,"reason":"session_ended"}"#
        );
    }
}
