//! Locate the payload inside an RPM package.
//!
//! An `.rpm` is a 96-byte lead, a signature header, the main header, then the
//! payload — historically always a compressed cpio archive. The two headers
//! share one structure (an index of tagged entries over a data store), and only
//! two of the main header's tags matter here: which archive format the payload
//! is in (`PAYLOADFORMAT`) and how it's compressed (`PAYLOADCOMPRESSOR`).
//!
//! Nothing else in the metadata is read — the package's own claims about its
//! name and version are not evidence about the binaries inside, which is what
//! Achilles goes on to look at.

use crate::decompress::Codec;
use crate::PkgError;

const LEAD_MAGIC: &[u8] = b"\xed\xab\xee\xdb";
const HEADER_MAGIC: &[u8] = b"\x8e\xad\xe8\x01";
const LEAD_LEN: usize = 96;
const HEADER_PRELUDE: usize = 16;
const INDEX_ENTRY: usize = 16;

const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;

pub fn is_rpm(bytes: &[u8]) -> bool {
    bytes.starts_with(LEAD_MAGIC)
}

/// The raw (still compressed) payload and the compressor that covers it.
pub fn payload(bytes: &[u8]) -> Result<(&[u8], Codec), PkgError> {
    if !is_rpm(bytes) {
        return Err(PkgError::Malformed("rpm", "missing lead magic".into()));
    }

    let signature = Header::parse(bytes, LEAD_LEN)?;
    // Only the signature header's data store is padded to an 8-byte boundary.
    let main_start = (signature.end + 7) & !7;
    let main = Header::parse(bytes, main_start)?;

    let format = main.string(bytes, TAG_PAYLOADFORMAT);
    if let Some(format) = &format {
        if format != "cpio" {
            return Err(PkgError::Unsupported(format!(
                "this rpm carries a {format} payload; only cpio payloads (every ordinary package) can be read"
            )));
        }
    }

    let payload = bytes
        .get(main.end..)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| PkgError::Malformed("rpm", "no payload after the header".into()))?;

    // The declared compressor is the truth for `lzma`, which has no magic to
    // sniff; everything else agrees with its magic, so sniffing is the
    // fallback for packages that omit the tag.
    let codec = match main.string(bytes, TAG_PAYLOADCOMPRESSOR).as_deref() {
        Some("gzip") => Codec::Gzip,
        Some("xz") => Codec::Xz,
        Some("zstd") => Codec::Zstd,
        Some("bzip2") => Codec::Bzip2,
        Some("lzma") => Codec::Lzma,
        Some("none") => Codec::None,
        Some(other) => {
            return Err(PkgError::UnsupportedCompression(match other {
                "lzo" => "lzo",
                _ => "unknown",
            }))
        }
        None => Codec::sniff(payload).unwrap_or(Codec::None),
    };
    Ok((payload, codec))
}

/// One RPM header section: an index of tagged entries over a data store.
struct Header {
    index: usize,
    count: usize,
    store: usize,
    /// First byte after the header (its data store included).
    end: usize,
}

impl Header {
    fn parse(bytes: &[u8], at: usize) -> Result<Header, PkgError> {
        let prelude = bytes
            .get(at..at + HEADER_PRELUDE)
            .ok_or_else(|| PkgError::Malformed("rpm", "truncated header".into()))?;
        if !prelude.starts_with(HEADER_MAGIC) {
            return Err(PkgError::Malformed("rpm", "bad header magic".into()));
        }
        let count = be32(&prelude[8..12]) as usize;
        let store_len = be32(&prelude[12..16]) as usize;
        let index = at + HEADER_PRELUDE;
        let store = index + count * INDEX_ENTRY;
        let end = store + store_len;
        if end > bytes.len() {
            return Err(PkgError::Malformed(
                "rpm",
                "header runs past end of file".into(),
            ));
        }
        Ok(Header {
            index,
            count,
            store,
            end,
        })
    }

    /// The NUL-terminated string stored for `tag`, if present.
    fn string(&self, bytes: &[u8], tag: u32) -> Option<String> {
        for i in 0..self.count {
            let entry =
                bytes.get(self.index + i * INDEX_ENTRY..self.index + (i + 1) * INDEX_ENTRY)?;
            if be32(&entry[0..4]) != tag {
                continue;
            }
            // Type 6 is RPM_STRING_TYPE; anything else for these tags is a
            // malformed package, and guessing at it helps nobody.
            if be32(&entry[4..8]) != 6 {
                return None;
            }
            let start = self.store + be32(&entry[8..12]) as usize;
            let rest = bytes.get(start..self.end)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            return Some(String::from_utf8_lossy(&rest[..end]).into_owned());
        }
        None
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one header section holding `(tag, string)` entries.
    fn header(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut store = Vec::new();
        let mut index = Vec::new();
        for (tag, value) in entries {
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&6u32.to_be_bytes()); // RPM_STRING_TYPE
            index.extend_from_slice(&(store.len() as u32).to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes());
            store.extend_from_slice(value.as_bytes());
            store.push(0);
        }
        let mut out = HEADER_MAGIC.to_vec();
        out.extend_from_slice(&[0; 4]); // reserved
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&store);
        out
    }

    /// Assemble lead + signature + main header + payload, exercising the
    /// 8-byte alignment between the two headers.
    fn build(main: &[(u32, &str)], payload: &[u8]) -> Vec<u8> {
        let mut out = LEAD_MAGIC.to_vec();
        out.resize(LEAD_LEN, 0);
        out.extend(header(&[(1000, "sig")])); // signature header
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out.extend(header(main));
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn reads_the_declared_compressor_past_the_padded_signature_header() {
        let rpm = build(
            &[(TAG_PAYLOADFORMAT, "cpio"), (TAG_PAYLOADCOMPRESSOR, "zstd")],
            b"payload-bytes",
        );
        let (payload, codec) = super::payload(&rpm).unwrap();
        assert_eq!(payload, b"payload-bytes");
        assert_eq!(codec, Codec::Zstd);
    }

    #[test]
    fn falls_back_to_sniffing_when_no_compressor_tag_is_present() {
        let rpm = build(&[(TAG_PAYLOADFORMAT, "cpio")], b"\xfd7zXZ\x00rest");
        let (_, codec) = super::payload(&rpm).unwrap();
        assert_eq!(codec, Codec::Xz);
    }

    #[test]
    fn a_non_cpio_payload_is_reported_rather_than_misparsed() {
        let rpm = build(&[(TAG_PAYLOADFORMAT, "drpm")], b"delta");
        assert!(matches!(
            super::payload(&rpm),
            Err(PkgError::Unsupported(_))
        ));
    }
}
