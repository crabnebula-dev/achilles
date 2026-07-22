//! libpcap / Npcap capture backend.
//!
//! On macOS it opens the `pktap` pseudo-interface, whose per-packet header
//! carries the originating PID — giving passive per-app attribution with no
//! Network Extension (at the cost of needing capture privilege at runtime).
//! On other platforms it captures on the default device and forwards frames;
//! per-PID attribution there is added in a later phase.
//!
//! Capture runs on a dedicated OS thread (libpcap is blocking) and forwards
//! events over a tokio channel; a `CancellationToken` stops it.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::source::{
    CaptureError, CaptureHandle, CaptureSource, CapturedEvent, LinkType, PidFilter,
};

pub struct PcapSource {
    device: Option<String>,
    pktap: bool,
}

impl PcapSource {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            // pktap tags each packet with its originating PID.
            Self {
                device: Some("pktap".into()),
                pktap: true,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self {
                device: None,
                pktap: false,
            }
        }
    }
}

#[async_trait::async_trait]
impl CaptureSource for PcapSource {
    fn backend_id(&self) -> &'static str {
        if self.pktap {
            "macos-pktap"
        } else {
            "pcap"
        }
    }

    async fn start(
        &self,
        filter: PidFilter,
    ) -> Result<(mpsc::Receiver<CapturedEvent>, CaptureHandle), CaptureError> {
        // Open the capture *before* returning so a privilege failure surfaces as
        // an error the UI can show (Record → error), rather than a capture thread
        // that dies silently while the UI sits on a frozen "recording".
        let (cap, pktap, warning) = open_capture(self.device.as_deref(), self.pktap)?;

        let (tx, rx) = mpsc::channel(2048);
        let cancel = CancellationToken::new();
        let pids = super::collect_pids(filter);
        let cancel2 = cancel.clone();
        std::thread::spawn(move || {
            // Report a non-fatal fallback (e.g. host-wide capture) before looping.
            if let Some(w) = warning {
                let _ = tx.blocking_send(CapturedEvent::Warning(w));
            }
            run_loop(cap, pktap, pids, tx, cancel2);
        });
        Ok((rx, CaptureHandle::new(cancel)))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open(device: Option<&str>) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
    let inactive = match device {
        Some(d) => pcap::Capture::from_device(d)?,
        None => {
            let dev = pcap::Device::lookup()?
                .ok_or_else(|| pcap::Error::PcapError("no default capture device".into()))?;
            pcap::Capture::from_device(dev)?
        }
    };
    inactive
        .timeout(500)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
}

/// macOS privilege guidance surfaced to the UI when capture can't start.
fn privilege_hint(err: &pcap::Error) -> String {
    format!(
        "could not start capture: {err}. Packet capture needs elevated privileges \
         (on macOS the per-app `pktap` interface requires root). For now run Achilles with \
         sudo or grant BPF access; the planned no-prompt path is a privileged helper / \
         Network Extension."
    )
}

/// Open a capture, returning `(capture, effective_pktap, fallback_warning)`.
///
/// Tries the requested device (pktap = per-app attribution). If that can't be
/// created (needs root), falls back to the default interface, which only needs
/// BPF access (ChmodBPF) — capturing host-wide, without a per-PID filter — and
/// reports that as a non-fatal warning. A total failure is returned as an error
/// so `start` can reject it and the UI can show it.
#[allow(clippy::type_complexity)]
fn open_capture(
    device: Option<&str>,
    want_pktap: bool,
) -> Result<(pcap::Capture<pcap::Active>, bool, Option<String>), CaptureError> {
    match open(device) {
        Ok(c) => Ok((c, want_pktap, None)),
        Err(first) if want_pktap => match open(None) {
            Ok(c) => Ok((
                c,
                false,
                Some(format!(
                    "per-app capture unavailable ({first}); capturing host-wide on the default \
                     interface instead (no per-app filter). Grant capture privileges for \
                     per-application attribution."
                )),
            )),
            Err(e) => Err(CaptureError::Unavailable(privilege_hint(&e))),
        },
        Err(e) => Err(CaptureError::Unavailable(privilege_hint(&e))),
    }
}

fn run_loop(
    mut cap: pcap::Capture<pcap::Active>,
    pktap: bool,
    pids: HashSet<u32>,
    tx: mpsc::Sender<CapturedEvent>,
    cancel: CancellationToken,
) {
    // A BPF prefilter helps on normal link types; pktap frames carry a header
    // the filter can't parse, so skip it there.
    if !pktap {
        let _ = cap.filter("tcp", true);
    }
    let link = map_datalink(cap.get_datalink());

    loop {
        if cancel.is_cancelled() || tx.is_closed() {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let at = now();
                if pktap {
                    if let Some((pid, inner_link, inner)) = parse_pktap(pkt.data) {
                        if pids.is_empty() || pids.contains(&pid) {
                            let _ = tx.blocking_send(CapturedEvent::Packet {
                                data: inner.to_vec(),
                                link: inner_link,
                                at,
                            });
                        }
                    }
                } else if let Some(l) = link {
                    let _ = tx.blocking_send(CapturedEvent::Packet {
                        data: pkt.data.to_vec(),
                        link: l,
                        at,
                    });
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
}

fn map_datalink(dlt: pcap::Linktype) -> Option<LinkType> {
    match dlt.0 {
        1 => Some(LinkType::Ethernet),      // DLT_EN10MB
        12 | 14 => Some(LinkType::RawIp),   // DLT_RAW
        113 => Some(LinkType::LinuxSll),    // DLT_LINUX_SLL
        _ => None,                          // NULL/loopback etc. — skipped for now
    }
}

/// Parse a macOS `pktap` header, returning `(pid, inner_link, inner_frame)`.
///
/// Layout (`struct pktap_header`): `pth_length` @0, `pth_dlt` @8, `pth_pid` @52,
/// all little-endian; the enclosed frame starts at `pth_length`.
fn parse_pktap(data: &[u8]) -> Option<(u32, LinkType, &[u8])> {
    if data.len() < 56 {
        return None;
    }
    let pth_length = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let pth_dlt = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let pth_pid = i32::from_le_bytes(data[52..56].try_into().ok()?);
    if pth_length == 0 || data.len() < pth_length {
        return None;
    }
    let inner = &data[pth_length..];
    let link = map_datalink(pcap::Linktype(pth_dlt as i32))?;
    Some((pth_pid.max(0) as u32, link, inner))
}
