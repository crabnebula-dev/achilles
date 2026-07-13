//! Passive network monitor.
//!
//! Attaches to a running application (by PID) and passively records its network
//! traffic for a session to inventory the **cryptography** it uses (TLS versions,
//! cipher suites, groups, signature schemes, JA3/JA4, SNI) and the **destination
//! routes** it talks to. No decryption. Runtime evidence feeds the [`cbom`]
//! aggregator alongside static binary analysis.
//!
//! Platform capture backends implement [`source::CaptureSource`]; the
//! platform-agnostic [`engine::Session`] consumes their events.

pub mod backends;
pub mod engine;
pub mod model;
pub mod source;
pub mod wire;

pub use backends::{capture_available, default_source, helper_installed, list_processes};
#[cfg(target_os = "macos")]
pub use backends::direct_capture_source;
pub use engine::Session;
pub use model::{
    Destination, L7Kind, RunningProcess, SessionDelta, SessionMeta, SessionReport, TargetProcess,
    TlsHandshake,
};
pub use source::{
    CaptureError, CaptureHandle, CaptureSource, CapturedEvent, Direction, FlowKey, L4Proto,
    LinkType, PidFilter,
};
