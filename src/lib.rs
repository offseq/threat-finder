//! OffSeq Threat Finder — library crate.
//!
//! The engine (API client, version/constraint matcher, per-OS discovery,
//! package inventory, and network-exposure correlation) lives here so it is
//! reusable and integration-testable; the `threat-finder` binary is a thin CLI
//! over it.

pub mod api;
pub mod auth;
pub mod cpe;
pub mod engine;
pub mod sarif;
pub mod logging;
pub mod scan;
pub mod windows;

// Stable re-exports so `find_threats::Thing` keeps working for the binary and
// downstream consumers regardless of internal module layout.
pub use api::*;
pub use engine::*;
pub use scan::{Asset, Collector, Ecosystem, ScanScope, Source};
