//! Serializable session model: the live-traffic view streamed to the UI and the
//! final report persisted to the journal.

use serde::{Deserialize, Serialize};

/// A running process the user can pick as a capture target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
}

/// The process a capture session targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProcess {
    pub pid: u32,
    pub exe_path: Option<String>,
    pub display_name: Option<String>,
    pub bundle_id: Option<String>,
}

/// Lightweight metadata returned when a session starts / on status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    pub session_id: String,
    pub target: TargetProcess,
    pub backend_id: String,
    pub started_at: u64,
}

/// A network destination the app talked to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Destination {
    pub remote_ip: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub sni: Option<String>,
    pub bytes_total: u64,
    pub flow_count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Layer-7 classification of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum L7Kind {
    Tls,
    PlaintextHttp,
    Quic,
    Unknown,
}

/// A parsed TLS handshake observed on a flow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsHandshake {
    pub destination: String,
    pub sni: Option<String>,
    /// Negotiated version (from ServerHello / supported_versions), e.g. `"1.3"`.
    pub negotiated_version: Option<String>,
    /// Versions the client offered.
    pub offered_versions: Vec<String>,
    pub cipher_suites_offered: Vec<u16>,
    pub cipher_suite_selected: Option<u16>,
    pub groups: Vec<u16>,
    pub signature_schemes: Vec<u16>,
    pub alpn: Vec<String>,
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    /// `true` when only a partial handshake was recovered (e.g. split beyond
    /// the reassembly cap, or a TLS 1.3 handshake whose cert is encrypted).
    pub incomplete: bool,
}

/// A live update streamed to the UI during a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SessionDelta {
    Destination(Destination),
    Handshake(TlsHandshake),
    Counters {
        flows: u32,
        handshakes: u32,
        bytes: u64,
    },
    Warning {
        message: String,
    },
}

/// Final session report (persisted to the journal alongside the CBOM).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReport {
    pub session_id: String,
    pub target: TargetProcess,
    pub backend_id: String,
    pub started_at: u64,
    pub ended_at: u64,
    pub destinations: Vec<Destination>,
    pub handshakes: Vec<TlsHandshake>,
    pub flow_count: u32,
    pub bytes_total: u64,
}
