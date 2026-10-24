//! Request and response shapes of the local socket API. Documented in
//! `docs/auth-protocol.md`.

use serde::de::DeserializeOwned;

use crate::prelude::*;

/// Version announced in the `hello` frame. Bump on incompatible changes.
pub const PROTOCOL_VERSION: &str = "2026-10-session-v1";

/// One operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Echoed in the response, so requests can be pipelined.
    pub id: String,
    /// Session token. Required for every operation except the `auth.*`
    /// login operations and `setup.status`/`setup.redeem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub op: String,
    #[serde(default)]
    pub params: Value,
}

/// The answer to one [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Response {
    #[must_use]
    pub fn new(id: String, result: Result<Value, ApiError>) -> Self {
        match result {
            Ok(result) => Self {
                id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                id,
                ok: false,
                result: None,
                error: Some(error),
            },
        }
    }
}

/// Stable, machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed parameters.
    BadRequest,
    UnknownOperation,
    /// Missing, expired or revoked token.
    Unauthenticated,
    /// Authenticated, but not allowed.
    Forbidden,
    /// Wrong password, code or passkey, unknown or ineligible account, or a
    /// locked account. Deliberately not more specific.
    InvalidCredentials,
    /// The password is right but expired; change it on the console or over
    /// SSH.
    PasswordExpired,
    /// Retry after `retry_after` seconds.
    RateLimited,
    /// The server is in IP mode (or has no access configuration), so
    /// WebAuthn cannot work.
    PasskeysUnavailable,
    /// The token or operation belongs to the other local client.
    WrongClient,
    /// Setup has already completed.
    SetupComplete,
    /// Setup cannot complete yet (for example, no eligible administrator).
    SetupIncomplete,
    NotFound,
    Conflict,
    /// The module action ran and failed; `message` has its error.
    ActionFailed,
    /// Tetra's command queue is full; retry after backoff.
    QueueFull,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<i64>,
}

impl ApiError {
    pub fn new<M: Into<String>>(code: ErrorCode, message: M) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    #[must_use]
    pub fn rate_limited(retry_after: i64) -> Self {
        Self {
            code: ErrorCode::RateLimited,
            message: "too many attempts; try again later".into(),
            retry_after: Some(retry_after),
        }
    }

    #[must_use]
    pub fn invalid_credentials() -> Self {
        Self::new(ErrorCode::InvalidCredentials, "invalid credentials")
    }

    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::new(
            ErrorCode::Unauthenticated,
            "a valid session token is required; log in again",
        )
    }

    pub fn forbidden<M: Into<String>>(message: M) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    pub fn bad_request<M: std::fmt::Display>(message: M) -> Self {
        Self::new(ErrorCode::BadRequest, message.to_string())
    }
}

/// Internal errors are logged in full and reported generically, so host
/// details do not leak to clients.
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        eprintln!("internal error handling a request: {error:#}");
        Self::new(ErrorCode::Internal, "internal error; see the Tetra journal")
    }
}

pub type ApiResult = Result<Value, ApiError>;

/// Parse operation parameters, treating missing parameters as `{}`.
///
/// # Errors
/// Returns `bad_request` when the parameters do not match `T`.
pub fn params<T: DeserializeOwned>(params: &Value) -> Result<T, ApiError> {
    let params = if params.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        params.clone()
    };
    serde_json::from_value(params)
        .map_err(|error| ApiError::bad_request(format!("invalid params: {error}")))
}
