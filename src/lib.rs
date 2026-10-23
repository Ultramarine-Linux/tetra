//! Tetra: a modular host agent and recipe renderer for the Ultramarine Server
//! web control plane.
//!
//! The crate is organized into two top-level modules:
//!
//! - [`agent`]: the dispatcher, its feature-gated modules, and the transports
//!   (local Unix socket, development loopback TCP, and outbound WSS) that
//!   expose the same command-envelope protocol to local clients or the control
//!   plane.
//! - [`catalog`]: the recipe engine that renders YAML recipes into Quadlet and
//!   companion files using Tera templates.
//!
//! The binary in `src/main.rs` wires these into CLI subcommands.

pub mod agent;
pub mod auth;
pub mod catalog;
pub mod enrollment;
pub mod prelude;
pub mod types;
