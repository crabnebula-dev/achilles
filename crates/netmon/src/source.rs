//! Capture abstraction: a `CaptureSource` yields a stream of `CapturedEvent`s
//! attributed (where possible) to a target PID. Each OS backend implements this;
//! the analysis engine consumes the events regardless of backend.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Which process(es) to capture. Also the control message a privileged helper
/// receives to begin capturing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PidFilter {
    pub root_pid: u32,
    pub include_children: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// A connection's five-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Link-layer framing of a raw `Packet` event, so the engine knows how many
/// bytes to strip before the IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
    /// macOS pktap: a pktap header (with PID) precedes the packet.
    Pktap,
}

/// One unit produced by a backend. Backends emit whichever variants they can:
/// pcap emits `Packet`; the macOS Network Extension emits `FlowOpened` +
/// `StreamData` (per-flow bytes already attributed to a PID). Serializable so a
/// privileged helper process can forward events over a socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapturedEvent {
    /// A flow was attributed to a PID (NE, or after an OS lookup).
    FlowOpened {
        key: FlowKey,
        pid: Option<u32>,
        at: u64,
    },
    /// Raw link-or-IP-layer bytes. PID may be unknown and resolved later.
    Packet {
        data: Vec<u8>,
        link: LinkType,
        at: u64,
    },
    /// Pre-sliced application-stream bytes for one direction of a flow.
    StreamData {
        key: FlowKey,
        dir: Direction,
        bytes: Vec<u8>,
        pid: Option<u32>,
        at: u64,
    },
    FlowClosed {
        key: FlowKey,
        at: u64,
    },
    Warning(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("capture backend unavailable: {0}")]
    Unavailable(String),
    #[error("insufficient privileges for capture: {0}")]
    Privileges(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Owns the OS capture resources. Dropping it (or calling [`CaptureHandle::stop`])
/// tears the capture down.
pub struct CaptureHandle {
    cancel: CancellationToken,
}

impl CaptureHandle {
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel }
    }
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Every OS backend implements this.
#[async_trait::async_trait]
pub trait CaptureSource: Send + Sync {
    /// Human name for logs/UI, e.g. `"pcap"`, `"macos-pktap"`.
    fn backend_id(&self) -> &'static str;

    /// Begin capturing flows owned by `filter`. Returns an event receiver and a
    /// handle whose drop stops the capture.
    async fn start(
        &self,
        filter: PidFilter,
    ) -> Result<(mpsc::Receiver<CapturedEvent>, CaptureHandle), CaptureError>;
}
