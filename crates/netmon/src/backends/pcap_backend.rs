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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::source::{
    CaptureError, CaptureHandle, CaptureSource, CapturedEvent, LinkType, PidFilter,
};

pub struct PcapSource {
    /// macOS: capture via the `pktap` pseudo-interface (per-PID attribution).
    pktap: bool,
}

impl PcapSource {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            // pktap tags each packet with its originating PID.
            Self { pktap: true }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self { pktap: false }
        }
    }
}

/// pktap device specs to try, in order. `pktap,all` taps **every** interface,
/// crucially including loopback and tunnels (`utun`/VPN) — plain `pktap` on some
/// libpcap builds only follows the primary interfaces, which is why loopback
/// capture came up empty. Fall back to bare `pktap` for older libpcap that
/// rejects the multi-interface spec.
#[cfg(target_os = "macos")]
const PKTAP_DEVICES: &[&str] = &["pktap,all", "pktap"];

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
        let (cap, pktap, warning) = open_capture(self.pktap)?;
        let dlt = cap.get_datalink().0;

        let (tx, rx) = mpsc::channel(2048);
        let cancel = CancellationToken::new();
        let pids = super::collect_pids(filter);
        let cancel2 = cancel.clone();
        std::thread::spawn(move || {
            // Report a non-fatal fallback (e.g. host-wide capture) before looping.
            if let Some(w) = warning {
                let _ = tx.blocking_send(CapturedEvent::Warning(w));
            }
            run_loop(cap, pktap, dlt, pids, tx, cancel2);
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

/// macOS `DLT_PKTAP` — aliased to `DLT_USER2` (149) in Apple's `bpf.h`. This is
/// the on-the-wire value the system libpcap reports; the portable libpcap value
/// (258, `pcap::Linktype::PKTAP`) is matched too for safety.
#[cfg(target_os = "macos")]
const DLT_PKTAP_VALUES: [i32; 2] = [149, 258];

// Apple's libpcap gates per-packet process metadata behind an opt-in that must
// be set on the handle *before* activation. Without it the pktap device
// activates as `DLT_RAW` and never even offers `DLT_PKTAP` in its datalink list,
// so packets arrive as bare IP with no PID — which is exactly the "everything
// is datalink 12 (RAW)" symptom. The `pcap` crate doesn't wrap this call, so we
// invoke it on the raw handle. The symbol lives in the libpcap the crate links.
#[cfg(target_os = "macos")]
extern "C" {
    fn pcap_set_want_pktap(
        p: *mut std::ffi::c_void,
        want: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}

fn open(
    device: Option<&str>,
    want_pktap: bool,
) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
    let inactive = match device {
        Some(d) => pcap::Capture::from_device(d)?,
        None => {
            let dev = pcap::Device::lookup()?
                .ok_or_else(|| pcap::Error::PcapError("no default capture device".into()))?;
            pcap::Capture::from_device(dev)?
        }
    };
    let inactive = inactive.timeout(500).immediate_mode(true).snaplen(65535);

    // Opt into pktap metadata before activating (see the extern above).
    #[cfg(target_os = "macos")]
    if want_pktap {
        unsafe { pcap_set_want_pktap(inactive.as_ptr().cast(), 1) };
    }

    let mut cap = inactive.open()?;

    // With pktap wanted, the device now offers `DLT_PKTAP`; select it so every
    // packet is prefixed with the process header. Best-effort — if it still
    // isn't offered, the run-loop diagnostic reports the datalink we got.
    #[cfg(target_os = "macos")]
    if want_pktap {
        if let Ok(dls) = cap.list_datalinks() {
            if let Some(pktap) = dls.into_iter().find(|d| DLT_PKTAP_VALUES.contains(&d.0)) {
                let _ = cap.set_datalink(pktap);
            }
        }
    }
    let _ = want_pktap; // (unused on non-macOS)

    // Run nonblocking so the capture loop can observe cancellation promptly.
    // A blocking `next_packet()` can wait indefinitely when no packets arrive —
    // the pcap read timeout is *not* guaranteed to fire on macOS — which would
    // leave the loop stuck past `cancel`, wedging Stop (`netmon_stop` awaits the
    // loop's task). Nonblocking makes `next_packet` return at once; the loop
    // sleeps briefly between empty polls (see `run_loop`).
    let cap = cap.setnonblock()?;
    Ok(cap)
}

/// macOS privilege guidance surfaced to the UI when capture can't start.
fn privilege_hint(err: &pcap::Error) -> String {
    format!(
        "could not start capture: {err}. Packet capture needs elevated privileges \
         (on macOS the per-app `pktap` interface requires root). Install the privileged \
         capture helper and approve it in System Settings for the no-sudo path; otherwise \
         run Achilles with sudo or grant BPF access."
    )
}

/// Open a capture, returning `(capture, effective_pktap, fallback_warning)`.
///
/// When `want_pktap` (macOS), tries each pktap device spec in turn for per-app
/// attribution. If none can be created (needs root), falls back to the default
/// interface, which only needs BPF access (ChmodBPF) — capturing host-wide,
/// without a per-PID filter — and reports that as a non-fatal warning. A total
/// failure is returned as an error so `start` can reject it and the UI can show
/// it.
#[allow(clippy::type_complexity)]
fn open_capture(
    want_pktap: bool,
) -> Result<(pcap::Capture<pcap::Active>, bool, Option<String>), CaptureError> {
    #[cfg(target_os = "macos")]
    if want_pktap {
        let mut first_err: Option<pcap::Error> = None;
        for dev in PKTAP_DEVICES {
            match open(Some(dev), true) {
                Ok(c) => return Ok((c, true, None)),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        // pktap needs root; fall back to a host-wide capture on the default
        // interface (BPF access only), noting the loss of per-app attribution.
        return match open(None, false) {
            Ok(c) => Ok((
                c,
                false,
                Some(format!(
                    "per-app capture unavailable ({}); capturing host-wide on the default \
                     interface instead (no per-app filter). Grant capture privileges for \
                     per-application attribution.",
                    first_err
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "pktap unavailable".into())
                )),
            )),
            Err(e) => Err(CaptureError::Unavailable(privilege_hint(&e))),
        };
    }
    match open(None, false) {
        Ok(c) => Ok((c, false, None)),
        Err(e) => Err(CaptureError::Unavailable(privilege_hint(&e))),
    }
}

fn run_loop(
    mut cap: pcap::Capture<pcap::Active>,
    pktap: bool,
    dlt: i32,
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

    // Diagnostic bookkeeping (pktap only): so a stuck session surfaces *why*
    // instead of sitting on a silent "waiting for the first packet". Three
    // stages, so we can tell them apart: `raw` = packets libpcap delivered,
    // `parsed` = pktap headers we understood, `matched` = attributed to target.
    let started = Instant::now();
    let mut raw: u64 = 0;
    let mut parsed: u64 = 0;
    let mut matched: u64 = 0;
    let mut warned = false;

    loop {
        if cancel.is_cancelled() || tx.is_closed() {
            break;
        }
        // After a grace period with nothing attributed, report the furthest
        // stage reached — the three cases have very different causes.
        if pktap && !warned && matched == 0 && started.elapsed() >= Duration::from_secs(3) {
            let msg = if raw == 0 {
                format!(
                    "Capture is open (pktap, datalink {dlt}) but no packets are arriving. \
                     Generate traffic in the target app; if still nothing, the pktap interface \
                     may not be delivering on this macOS version."
                )
            } else if parsed == 0 {
                format!(
                    "Receiving packets ({raw}) but their pktap headers aren't recognised \
                     (datalink {dlt}). The capture header format may differ on this macOS version."
                )
            } else {
                format!(
                    "Capturing, but none of the {parsed} attributed packets belong to the selected \
                     process. It may route traffic through a process outside the capture set — \
                     try selecting the parent process."
                )
            };
            let _ = tx.blocking_send(CapturedEvent::Warning(msg));
            warned = true;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let at = now();
                if pktap {
                    raw += 1;
                    if let Some((pid, epid, inner_link, inner)) = parse_pktap(pkt.data) {
                        parsed += 1;
                        // Attribute by originating PID or effective PID — the
                        // latter catches traffic a process does on another's
                        // behalf.
                        let hit = pids.is_empty()
                            || pids.contains(&pid)
                            || epid.is_some_and(|e| pids.contains(&e));
                        if hit {
                            matched += 1;
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
            // Nonblocking: no packet available right now. Sleep briefly so the
            // loop re-checks `cancel` promptly (Stop stays responsive) without
            // busy-spinning the CPU.
            Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn map_datalink(dlt: pcap::Linktype) -> Option<LinkType> {
    match dlt.0 {
        1 => Some(LinkType::Ethernet),    // DLT_EN10MB
        0 | 108 => Some(LinkType::Null),  // DLT_NULL / DLT_LOOP (BSD loopback, utun/VPN)
        12 | 14 => Some(LinkType::RawIp), // DLT_RAW
        113 => Some(LinkType::LinuxSll),  // DLT_LINUX_SLL
        _ => None,                        // other exotic link types — skipped for now
    }
}

/// `pth_flags` bit marking a version-2 pktap header (Apple `bsd/net/pktap.h`).
const PTH_FLAG_V2_HDR: u32 = 0x0008_0000;

/// Parse a macOS `pktap` header, returning `(pid, effective_pid, inner_link,
/// inner_frame)`.
///
/// Handles **both header versions**. `pth_flags` sits at offset 36 in each, so
/// it's read first to detect v2 (recent macOS emits v2). The versions place the
/// length / DLT / pid at different offsets:
///
/// | field   | v1 (`pktap_header`)        | v2 (`pktap_v2_hdr`)     |
/// |---------|----------------------------|-------------------------|
/// | length  | `u32` @0                   | `u8`  @0                |
/// | DLT     | `u32` @8                   | `u16` @6                |
/// | pid     | @52                        | @28                     |
/// | e_pid   | @84                        | @32                     |
///
/// The enclosed frame starts at the header length. Reading a v2 header with the
/// v1 offsets yielded a garbage length (→ packet dropped), which is why capture
/// silently produced nothing on modern macOS.
fn parse_pktap(data: &[u8]) -> Option<(u32, Option<u32>, LinkType, &[u8])> {
    // pth_flags @36 exists in both versions; need it to pick the layout.
    if data.len() < 40 {
        return None;
    }
    let flags = u32::from_le_bytes(data[36..40].try_into().ok()?);

    let (hdr_len, dlt, pid, epid) = if flags & PTH_FLAG_V2_HDR != 0 {
        let hdr_len = data[0] as usize;
        let dlt = u16::from_le_bytes(data[6..8].try_into().ok()?) as i32;
        let pid = i32::from_le_bytes(data[28..32].try_into().ok()?);
        let epid = i32::from_le_bytes(data[32..36].try_into().ok()?);
        (hdr_len, dlt, pid, epid)
    } else {
        if data.len() < 56 {
            return None;
        }
        let hdr_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        let dlt = u32::from_le_bytes(data[8..12].try_into().ok()?) as i32;
        let pid = i32::from_le_bytes(data[52..56].try_into().ok()?);
        let epid = if data.len() >= 88 {
            i32::from_le_bytes(data[84..88].try_into().ok()?)
        } else {
            0
        };
        (hdr_len, dlt, pid, epid)
    };

    if hdr_len == 0 || data.len() < hdr_len {
        return None;
    }
    let inner = &data[hdr_len..];
    let link = map_datalink(pcap::Linktype(dlt))?;
    let epid = (epid > 0).then_some(epid as u32);
    Some((pid.max(0) as u32, epid, link, inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_v1_header() {
        let mut buf = vec![0u8; 108];
        put_u32(&mut buf, 0, 108); // pth_length
        put_u32(&mut buf, 8, 1); // pth_dlt = DLT_EN10MB
        put_u32(&mut buf, 36, 0); // pth_flags: v2 bit clear
        put_u32(&mut buf, 52, 4321); // pth_pid
        put_u32(&mut buf, 84, 8765); // pth_epid
        buf.extend_from_slice(b"INNERFRAME");

        let (pid, epid, link, inner) = parse_pktap(&buf).expect("v1 parse");
        assert_eq!(pid, 4321);
        assert_eq!(epid, Some(8765));
        assert_eq!(link, LinkType::Ethernet);
        assert_eq!(inner, b"INNERFRAME");
    }

    #[test]
    fn parses_v2_header() {
        // Recent macOS: compact v2 header with the length/DLT/pid at their own
        // offsets and the v2 flag set. This is the case the old parser dropped.
        let hdr_len = 44usize;
        let mut buf = vec![0u8; hdr_len];
        buf[0] = hdr_len as u8; // pth_length (u8)
        put_u16(&mut buf, 6, 0); // pth_dlt = DLT_NULL (loopback)
        put_u32(&mut buf, 28, 4321); // pth_pid
        put_u32(&mut buf, 32, 8765); // pth_e_pid
        put_u32(&mut buf, 36, PTH_FLAG_V2_HDR); // pth_flags with v2 bit
        buf.extend_from_slice(b"INNERFRAME");

        let (pid, epid, link, inner) = parse_pktap(&buf).expect("v2 parse");
        assert_eq!(pid, 4321);
        assert_eq!(epid, Some(8765));
        assert_eq!(link, LinkType::Null); // loopback decodes now, too
        assert_eq!(inner, b"INNERFRAME");
    }

    #[test]
    fn v2_header_is_not_dropped_like_before() {
        // Regression guard for the actual bug: a v2 header read with the v1 u32
        // length @0 produced a bogus length and got dropped. Detecting v2 first
        // must keep it.
        let hdr_len = 44usize;
        let mut buf = vec![0u8; hdr_len];
        buf[0] = hdr_len as u8;
        put_u16(&mut buf, 6, 1); // Ethernet
        put_u32(&mut buf, 28, 42);
        put_u32(&mut buf, 36, PTH_FLAG_V2_HDR);
        buf.extend_from_slice(b"x");
        assert!(parse_pktap(&buf).is_some());
    }

    #[test]
    fn unset_effective_pid_is_none() {
        let mut buf = vec![0u8; 108];
        put_u32(&mut buf, 0, 108);
        put_u32(&mut buf, 8, 1);
        put_u32(&mut buf, 52, 100);
        // pth_epid left 0 → None
        buf.extend_from_slice(b"f");
        let (_, epid, _, _) = parse_pktap(&buf).expect("parse");
        assert_eq!(epid, None);
    }
}
