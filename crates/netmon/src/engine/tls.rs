//! Minimal, self-contained passive TLS handshake parser.
//!
//! Parses a TLS record's `ClientHello` / `ServerHello` from raw bytes — enough
//! for cryptography inventory: offered/selected cipher suites, supported groups,
//! signature schemes, SNI, ALPN, offered/negotiated versions, and the JA3
//! fingerprint. No decryption; TLS 1.3 hides the certificate so none is exposed.

use md5::{Digest, Md5};

/// A GREASE code point (RFC 8701): `0x?A?A`. Excluded from JA3 and asset lists.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub ext_types: Vec<u16>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub sig_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub cipher: u16,
    pub supported_version: Option<u16>,
}

/// Cursor helpers over a byte slice.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.b[self.pos], self.b[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let v = u32::from_be_bytes([0, self.b[self.pos], self.b[self.pos + 1], self.b[self.pos + 2]]);
        self.pos += 3;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

/// The handshake message inside a record.
pub enum Handshake {
    Client(ClientHello),
    Server(ServerHello),
}

/// Parse a TLS handshake record (`content_type == 22`) from the start of a
/// (reassembled) stream. Returns the parsed ClientHello/ServerHello, or `None`
/// if the bytes are not a complete handshake record we understand.
pub fn parse_handshake(bytes: &[u8]) -> Option<Handshake> {
    let mut r = Reader::new(bytes);
    // Record header.
    if r.u8()? != 0x16 {
        return None; // not a handshake record
    }
    let _rec_version = r.u16()?;
    let rec_len = r.u16()? as usize;
    let body = r.take(rec_len.min(r.remaining()))?;

    // Handshake header.
    let mut h = Reader::new(body);
    let hs_type = h.u8()?;
    let hs_len = h.u24()? as usize;
    let hs_body = h.take(hs_len.min(h.remaining()))?;

    match hs_type {
        1 => Some(Handshake::Client(parse_client_hello(hs_body)?)),
        2 => Some(Handshake::Server(parse_server_hello(hs_body)?)),
        _ => None,
    }
}

fn parse_client_hello(b: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(b);
    let mut ch = ClientHello {
        legacy_version: r.u16()?,
        ..Default::default()
    };
    r.take(32)?; // random
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?; // session id
    let cs_len = r.u16()? as usize;
    let cs = r.take(cs_len)?;
    for pair in cs.chunks_exact(2) {
        let id = u16::from_be_bytes([pair[0], pair[1]]);
        if !is_grease(id) {
            ch.ciphers.push(id);
        }
    }
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?; // compression methods

    // Extensions (optional).
    if let Some(ext_total) = r.u16() {
        let ext = r.take(ext_total as usize)?;
        parse_extensions(ext, &mut ch);
    }
    Some(ch)
}

fn parse_extensions(ext: &[u8], ch: &mut ClientHello) {
    let mut r = Reader::new(ext);
    while r.remaining() >= 4 {
        let Some(ext_type) = r.u16() else { break };
        let Some(len) = r.u16() else { break };
        let Some(body) = r.take(len as usize) else { break };
        if !is_grease(ext_type) {
            ch.ext_types.push(ext_type);
        }
        match ext_type {
            0x0000 => ch.sni = parse_sni(body),
            0x000a => ch.groups = parse_u16_list(body, true), // supported_groups
            0x000b => ch.point_formats = body.get(1..).map(|s| s.to_vec()).unwrap_or_default(), // ec_point_formats
            0x000d => ch.sig_algs = parse_u16_list(body, true), // signature_algorithms
            0x002b => ch.supported_versions = parse_u16_list_u8len(body), // supported_versions
            0x0010 => ch.alpn = parse_alpn(body),
            _ => {}
        }
    }
}

/// A 2-byte-length-prefixed list of u16 values (supported_groups, sig_algs).
fn parse_u16_list(body: &[u8], strip_grease: bool) -> Vec<u16> {
    let mut r = Reader::new(body);
    let Some(list_len) = r.u16() else {
        return Vec::new();
    };
    let Some(list) = r.take(list_len as usize) else {
        return Vec::new();
    };
    list.chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .filter(|v| !strip_grease || !is_grease(*v))
        .collect()
}

/// supported_versions: 1-byte length prefix then u16 versions.
fn parse_u16_list_u8len(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    let Some(list_len) = r.u8() else {
        return Vec::new();
    };
    let Some(list) = r.take(list_len as usize) else {
        return Vec::new();
    };
    list.chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .filter(|v| !is_grease(*v))
        .collect()
}

fn parse_sni(body: &[u8]) -> Option<String> {
    let mut r = Reader::new(body);
    let _list_len = r.u16()?;
    let name_type = r.u8()?;
    if name_type != 0 {
        return None; // host_name(0)
    }
    let name_len = r.u16()? as usize;
    let name = r.take(name_len)?;
    std::str::from_utf8(name).ok().map(str::to_owned)
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    if r.u16().is_none() {
        return out; // protocol_name_list length
    }
    while let Some(len) = r.u8() {
        match r.take(len as usize) {
            Some(p) => {
                if let Ok(s) = std::str::from_utf8(p) {
                    out.push(s.to_owned());
                }
            }
            None => break,
        }
    }
    out
}

fn parse_server_hello(b: &[u8]) -> Option<ServerHello> {
    let mut r = Reader::new(b);
    let mut sh = ServerHello {
        legacy_version: r.u16()?,
        ..Default::default()
    };
    r.take(32)?; // random
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?;
    sh.cipher = r.u16()?;
    let _comp = r.u8()?;
    // supported_versions (TLS 1.3 negotiates the real version here).
    if let Some(ext_total) = r.u16() {
        let ext = r.take(ext_total as usize)?;
        let mut er = Reader::new(ext);
        while er.remaining() >= 4 {
            let Some(t) = er.u16() else { break };
            let Some(len) = er.u16() else { break };
            let Some(body) = er.take(len as usize) else { break };
            if t == 0x002b && body.len() >= 2 {
                sh.supported_version = Some(u16::from_be_bytes([body[0], body[1]]));
            }
        }
    }
    Some(sh)
}

/// Compute the JA3 fingerprint (raw decimal string + md5 hex) from a ClientHello.
pub fn ja3(ch: &ClientHello) -> (String, String) {
    let join = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let point_fmts = ch
        .point_formats
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let raw = format!(
        "{},{},{},{},{}",
        ch.legacy_version,
        join(&ch.ciphers),
        join(&ch.ext_types),
        join(&ch.groups),
        point_fmts,
    );
    let digest = Md5::digest(raw.as_bytes());
    (raw, hex(&digest))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Map a TLS wire version to a human string (`0x0303` → `"1.2"`).
pub fn version_str(v: u16) -> Option<String> {
    Some(
        match v {
            0x0300 => "ssl",
            0x0301 => "1.0",
            0x0302 => "1.1",
            0x0303 => "1.2",
            0x0304 => "1.3",
            _ => return None,
        }
        .to_string(),
    )
}
