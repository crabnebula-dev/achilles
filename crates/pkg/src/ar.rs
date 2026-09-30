//! The `ar` archive that wraps a Debian package.
//!
//! A `.deb` is three ar members in order: `debian-binary` (the format version),
//! `control.tar.*` (maintainer scripts and metadata), and `data.tar.*` (the
//! files that get installed). Only the last one holds the application.
//!
//! Debian's own tooling writes short, plain member names, so the GNU/BSD
//! long-name extensions never appear here and aren't implemented — a member
//! whose name we can't read is simply skipped.

use crate::decompress::Codec;
use crate::PkgError;

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;

pub fn is_ar(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// True if this ar archive is a Debian package rather than, say, a static
/// library. `debian-binary` is mandatory and always first.
pub fn looks_like_deb(bytes: &[u8]) -> bool {
    members(bytes).any(|m| m.name == "debian-binary" || m.name.starts_with("data.tar"))
}

/// The `data.tar.*` member and the compressor its extension declares.
pub fn data_member(bytes: &[u8]) -> Result<(&[u8], Codec), PkgError> {
    if !is_ar(bytes) {
        return Err(PkgError::Malformed("deb", "missing ar magic".into()));
    }
    let member = members(bytes)
        .find(|m| m.name.starts_with("data.tar"))
        .ok_or_else(|| PkgError::Malformed("deb", "no data.tar member".into()))?;

    // The extension is authoritative in a `.deb`, but a stream that sniffs as
    // something else wins: some producers write `data.tar.gz` holding xz.
    let codec = Codec::sniff(member.data).unwrap_or_else(|| match member.name.rsplit('.').next() {
        Some("gz") => Codec::Gzip,
        Some("xz") => Codec::Xz,
        Some("zst") => Codec::Zstd,
        Some("bz2") => Codec::Bzip2,
        Some("lzma") => Codec::Lzma,
        _ => Codec::None,
    });
    Ok((member.data, codec))
}

struct Member<'a> {
    name: String,
    data: &'a [u8],
}

/// Walk the members, stopping at the first malformed header rather than
/// erroring — a truncated archive still yields whatever preceded the damage.
fn members(bytes: &[u8]) -> impl Iterator<Item = Member<'_>> {
    let mut pos = MAGIC.len();
    std::iter::from_fn(move || {
        let header = bytes.get(pos..pos + HEADER_LEN)?;
        if &header[58..60] != b"`\n" {
            return None;
        }
        let name = std::str::from_utf8(&header[0..16])
            .ok()?
            .trim_end()
            // GNU appends `/` to member names to allow trailing spaces.
            .trim_end_matches('/')
            .to_string();
        let size: usize = std::str::from_utf8(&header[48..58])
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let start = pos + HEADER_LEN;
        let data = bytes.get(start..start.checked_add(size)?)?;
        // Members are padded to an even offset.
        pos = start + size + (size % 2);
        Some(Member { name, data })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ar archive from `(name, body)` pairs.
    fn build(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (name, body) in members {
            let mut header = vec![b' '; HEADER_LEN];
            header[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{}", body.len());
            header[48..48 + size.len()].copy_from_slice(size.as_bytes());
            header[58..60].copy_from_slice(b"`\n");
            out.extend_from_slice(&header);
            out.extend_from_slice(body);
            if body.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn finds_the_data_member_after_odd_sized_ones() {
        // `debian-binary` is 4 bytes ("2.0\n") — even; make control odd so the
        // padding byte has to be accounted for to find `data.tar`.
        let deb = build(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", b"odd"),
            ("data.tar.xz", b"\xfd7zXZ\x00payload"),
        ]);
        assert!(is_ar(&deb) && looks_like_deb(&deb));
        let (data, codec) = data_member(&deb).unwrap();
        assert_eq!(data, b"\xfd7zXZ\x00payload");
        assert_eq!(codec, Codec::Xz);
    }

    #[test]
    fn a_static_library_is_not_a_deb() {
        let lib = build(&[("foo.o", b"\x7fELF")]);
        assert!(is_ar(&lib) && !looks_like_deb(&lib));
    }

    #[test]
    fn compression_is_taken_from_the_name_when_the_stream_is_opaque() {
        let deb = build(&[("debian-binary", b"2.0\n"), ("data.tar.zst", b"not-zstd")]);
        let (_, codec) = data_member(&deb).unwrap();
        assert_eq!(codec, Codec::Zstd);
    }
}
