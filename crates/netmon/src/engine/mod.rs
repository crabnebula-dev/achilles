//! Analysis engine: consume `CapturedEvent`s, reconstruct TLS handshakes and
//! destinations, and emit both live `SessionDelta`s (for the UI) and, at the
//! end, a `SessionReport` plus the `CryptoEvidence` that feeds the CBOM.

pub mod packet;
pub mod tls;

use std::collections::BTreeMap;

use cbom::{CryptoEvidence, ProtocolFamily, Provenance};

use crate::model::{Destination, SessionDelta, SessionReport, TargetProcess, TlsHandshake};
use crate::source::{CapturedEvent, Direction};

pub struct Session {
    session_id: String,
    target: TargetProcess,
    backend_id: String,
    started_at: u64,
    last_at: u64,
    destinations: BTreeMap<String, Destination>,
    handshakes: Vec<TlsHandshake>,
    /// destination → index of its (first) handshake, for ServerHello matching.
    hs_by_dest: BTreeMap<String, usize>,
    bytes_total: u64,
    flow_count: u32,
}

impl Session {
    pub fn new(session_id: String, target: TargetProcess, backend_id: String, started_at: u64) -> Self {
        Self {
            session_id,
            target,
            backend_id,
            started_at,
            last_at: started_at,
            destinations: BTreeMap::new(),
            handshakes: Vec::new(),
            hs_by_dest: BTreeMap::new(),
            bytes_total: 0,
            flow_count: 0,
        }
    }

    /// Feed one captured event; returns any new observations to stream.
    pub fn ingest(&mut self, ev: CapturedEvent) -> Vec<SessionDelta> {
        match ev {
            CapturedEvent::StreamData {
                key, dir, bytes, at, ..
            } => {
                self.last_at = at.max(self.last_at);
                let dest = key.remote.to_string();
                self.touch_destination(&dest, key.remote.ip().to_string(), key.remote.port(), bytes.len() as u64, at);
                self.handle_stream(&dest, dir, &bytes, at)
            }
            CapturedEvent::FlowOpened { key, at, .. } => {
                self.last_at = at.max(self.last_at);
                self.flow_count += 1;
                let dest = key.remote.to_string();
                self.touch_destination(&dest, key.remote.ip().to_string(), key.remote.port(), 0, at);
                vec![SessionDelta::Destination(self.destinations[&dest].clone())]
            }
            CapturedEvent::FlowClosed { .. } => vec![],
            CapturedEvent::Packet { data, link, at } => {
                self.last_at = at.max(self.last_at);
                match packet::decode(link, &data) {
                    Some(d) => {
                        let dest = d.remote.to_string();
                        self.touch_destination(
                            &dest,
                            d.remote.ip().to_string(),
                            d.remote.port(),
                            d.payload.len() as u64,
                            at,
                        );
                        let dir = if d.outbound {
                            Direction::Outbound
                        } else {
                            Direction::Inbound
                        };
                        self.handle_stream(&dest, dir, &d.payload, at)
                    }
                    None => vec![],
                }
            }
            CapturedEvent::Warning(w) => vec![SessionDelta::Warning { message: w }],
        }
    }

    fn touch_destination(&mut self, key: &str, ip: String, port: u16, bytes: u64, at: u64) {
        self.bytes_total += bytes;
        let d = self.destinations.entry(key.to_string()).or_insert_with(|| Destination {
            remote_ip: ip,
            port,
            first_seen: at,
            flow_count: 1,
            ..Default::default()
        });
        d.bytes_total += bytes;
        d.last_seen = at;
    }

    fn handle_stream(&mut self, dest: &str, dir: Direction, bytes: &[u8], _at: u64) -> Vec<SessionDelta> {
        let mut out = Vec::new();
        match tls::parse_handshake(bytes) {
            Some(tls::Handshake::Client(ch)) if dir == Direction::Outbound => {
                let (raw, hash) = tls::ja3(&ch);
                let offered_versions: Vec<String> = if ch.supported_versions.is_empty() {
                    tls::version_str(ch.legacy_version).into_iter().collect()
                } else {
                    ch.supported_versions.iter().filter_map(|v| tls::version_str(*v)).collect()
                };
                let hs = TlsHandshake {
                    destination: dest.to_string(),
                    sni: ch.sni.clone(),
                    negotiated_version: None,
                    offered_versions,
                    cipher_suites_offered: ch.ciphers.clone(),
                    cipher_suite_selected: None,
                    groups: ch.groups.clone(),
                    signature_schemes: ch.sig_algs.clone(),
                    alpn: ch.alpn.clone(),
                    ja3: Some(hash),
                    ja3_raw: Some(raw),
                    ja4: None,
                    incomplete: false,
                };
                if let Some(sni) = &ch.sni {
                    if let Some(d) = self.destinations.get_mut(dest) {
                        d.sni = Some(sni.clone());
                        d.hostname.get_or_insert_with(|| sni.clone());
                    }
                }
                self.hs_by_dest.entry(dest.to_string()).or_insert(self.handshakes.len());
                self.handshakes.push(hs.clone());
                if let Some(d) = self.destinations.get(dest) {
                    out.push(SessionDelta::Destination(d.clone()));
                }
                out.push(SessionDelta::Handshake(hs));
            }
            Some(tls::Handshake::Server(sh)) if dir == Direction::Inbound => {
                if let Some(&idx) = self.hs_by_dest.get(dest) {
                    let hs = &mut self.handshakes[idx];
                    hs.cipher_suite_selected = Some(sh.cipher);
                    let neg = sh.supported_version.or(Some(sh.legacy_version)).and_then(tls::version_str);
                    hs.negotiated_version = neg;
                    // TLS 1.3 encrypts the cert — mark that the record is partial
                    // (no certificate observable) so the UI can explain it.
                    if hs.negotiated_version.as_deref() == Some("1.3") {
                        hs.incomplete = true;
                    }
                    out.push(SessionDelta::Handshake(hs.clone()));
                }
            }
            _ => {}
        }
        out
    }

    /// Cryptographic evidence for the CBOM, derived from observed handshakes.
    pub fn crypto_evidence(&self) -> Vec<CryptoEvidence> {
        let mut ev = Vec::new();
        for hs in &self.handshakes {
            let loc = Some(hs.destination.clone());
            let version = hs
                .negotiated_version
                .clone()
                .or_else(|| hs.offered_versions.last().cloned());
            ev.push(CryptoEvidence::Protocol {
                family: ProtocolFamily::Tls,
                version,
                provenance: Provenance::ObservedRuntime,
                location: loc.clone(),
            });
            if let Some(sel) = hs.cipher_suite_selected {
                ev.push(CryptoEvidence::CipherSuite {
                    id: sel,
                    selected: true,
                    provenance: Provenance::ObservedRuntime,
                    location: loc.clone(),
                });
            }
            for &id in &hs.cipher_suites_offered {
                ev.push(CryptoEvidence::CipherSuite {
                    id,
                    selected: false,
                    provenance: Provenance::ObservedRuntime,
                    location: loc.clone(),
                });
            }
            for &id in &hs.groups {
                ev.push(CryptoEvidence::Group {
                    id,
                    provenance: Provenance::ObservedRuntime,
                    location: loc.clone(),
                });
            }
            for &id in &hs.signature_schemes {
                ev.push(CryptoEvidence::SignatureScheme {
                    id,
                    provenance: Provenance::ObservedRuntime,
                    location: loc.clone(),
                });
            }
        }
        ev
    }

    pub fn counters(&self) -> SessionDelta {
        SessionDelta::Counters {
            flows: self.flow_count.max(self.destinations.len() as u32),
            handshakes: self.handshakes.len() as u32,
            bytes: self.bytes_total,
        }
    }

    /// Finalize into a report for the journal.
    pub fn finish(self) -> SessionReport {
        SessionReport {
            session_id: self.session_id,
            target: self.target,
            backend_id: self.backend_id,
            started_at: self.started_at,
            ended_at: self.last_at,
            destinations: self.destinations.into_values().collect(),
            handshakes: self.handshakes,
            flow_count: self.flow_count,
            bytes_total: self.bytes_total,
        }
    }
}
