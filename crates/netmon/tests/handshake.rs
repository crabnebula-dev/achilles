//! End-to-end: a synthetic ClientHello → engine → CryptoEvidence → CBOM.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use netmon::source::{CapturedEvent, Direction, FlowKey, L4Proto};
use netmon::Session;

mod common;
use common::{client_hello_record, target};

#[test]
fn client_hello_yields_handshake_and_cbom() {
    let mut session = Session::new("s1".into(), target(), "test".into(), 100);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51000);
    let key = FlowKey {
        proto: L4Proto::Tcp,
        local,
        remote,
    };

    let deltas = session.ingest(CapturedEvent::StreamData {
        key,
        dir: Direction::Outbound,
        bytes: client_hello_record(),
        pid: Some(1234),
        at: 101,
    });
    // A handshake delta was emitted with the SNI + JA3 + offered cipher.
    let hs = deltas
        .iter()
        .find_map(|d| match d {
            netmon::SessionDelta::Handshake(h) => Some(h),
            _ => None,
        })
        .expect("handshake delta");
    assert_eq!(hs.sni.as_deref(), Some("example.com"));
    assert_eq!(hs.cipher_suites_offered, vec![0xC02F]);
    assert_eq!(hs.groups, vec![0x001d]);
    assert!(hs.offered_versions.contains(&"1.3".to_string()));
    assert!(hs.ja3.as_ref().is_some_and(|j| j.len() == 32)); // md5 hex

    // The observed evidence aggregates into a CBOM that flags quantum risk.
    let evidence = session.crypto_evidence();
    let inv = cbom::build_inventory(
        cbom::AppRef {
            name: "Example".into(),
            version: None,
            bundle_id: Some("com.example.app".into()),
            path: None,
        },
        &evidence,
    );
    assert!(inv
        .assets
        .iter()
        .any(|a| a.bom_ref == "crypto/algorithm/ecdhe"));
    assert!(inv
        .assets
        .iter()
        .any(|a| a.bom_ref == "crypto/algorithm/x25519"));
    assert!(inv
        .assets
        .iter()
        .any(|a| a.bom_ref == "crypto/algorithm/aes-128-gcm"));
    assert_eq!(inv.readiness.grade, "vulnerable"); // ECDHE/RSA/x25519 present
}

#[test]
fn raw_ethernet_frame_is_decoded_to_a_handshake() {
    // Wrap the ClientHello record in a real Ethernet/IPv4/TCP frame (dst :443,
    // so it's classified outbound) and feed it as a raw captured Packet.
    let payload = client_hello_record();
    let mut frame = Vec::new();
    etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 2], [93, 184, 216, 34], 64)
        .tcp(51000, 443, 1, 64000)
        .write(&mut frame, &payload)
        .unwrap();

    let mut session = Session::new("s2".into(), target(), "pcap".into(), 100);
    let deltas = session.ingest(CapturedEvent::Packet {
        data: frame,
        link: netmon::LinkType::Ethernet,
        at: 101,
    });
    let hs = deltas
        .iter()
        .find_map(|d| match d {
            netmon::SessionDelta::Handshake(h) => Some(h),
            _ => None,
        })
        .expect("handshake decoded from raw frame");
    assert_eq!(hs.sni.as_deref(), Some("example.com"));
    assert_eq!(hs.destination, "93.184.216.34:443");
}
