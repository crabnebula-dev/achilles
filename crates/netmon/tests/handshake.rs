//! End-to-end: a synthetic ClientHello → engine → CryptoEvidence → CBOM.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use netmon::source::{CapturedEvent, Direction, FlowKey, L4Proto};
use netmon::{Session, TargetProcess};

/// Build a minimal but valid TLS ClientHello record with:
/// cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F), SNI "example.com",
/// supported_groups [x25519 (0x001d)], signature_algorithms [0x0403].
fn client_hello_record() -> Vec<u8> {
    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    // SNI: server_name_list = [ host_name(0), len, "example.com" ]
    let host = b"example.com";
    let mut sni_entry = vec![0u8]; // host_name
    sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_entry.extend_from_slice(host);
    let mut sni_list = (sni_entry.len() as u16).to_be_bytes().to_vec();
    sni_list.extend_from_slice(&sni_entry);

    // supported_groups: list_len(2) + x25519
    let groups = {
        let mut b = 2u16.to_be_bytes().to_vec();
        b.extend_from_slice(&0x001du16.to_be_bytes());
        b
    };
    // signature_algorithms: list_len(2) + 0x0403
    let sigs = {
        let mut b = 2u16.to_be_bytes().to_vec();
        b.extend_from_slice(&0x0403u16.to_be_bytes());
        b
    };
    // supported_versions: u8 len + TLS 1.3, 1.2
    let sv = vec![4u8, 0x03, 0x04, 0x03, 0x03];

    let mut exts = Vec::new();
    exts.extend(ext(0x0000, &sni_list));
    exts.extend(ext(0x000a, &groups));
    exts.extend(ext(0x000d, &sigs));
    exts.extend(ext(0x002b, &sv));

    // ClientHello body
    let mut ch = Vec::new();
    ch.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version 1.2
    ch.extend_from_slice(&[0u8; 32]); // random
    ch.push(0); // session_id len
    ch.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
    ch.extend_from_slice(&0xC02Fu16.to_be_bytes());
    ch.push(1); // compression methods len
    ch.push(0); // null
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    // Handshake header: type(1)=client_hello + u24 len
    let mut hs = vec![1u8];
    let l = ch.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&ch);

    // Record header: content_type(22), version 0x0301, u16 len
    let mut rec = vec![0x16u8, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn target() -> TargetProcess {
    TargetProcess {
        pid: 1234,
        exe_path: Some("/Applications/Example.app/Contents/MacOS/Example".into()),
        display_name: Some("Example".into()),
        bundle_id: Some("com.example.app".into()),
    }
}

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
    assert!(inv.assets.iter().any(|a| a.bom_ref == "crypto/algorithm/ecdhe"));
    assert!(inv.assets.iter().any(|a| a.bom_ref == "crypto/algorithm/x25519"));
    assert!(inv.assets.iter().any(|a| a.bom_ref == "crypto/algorithm/aes-128-gcm"));
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
