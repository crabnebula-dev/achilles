//! The compressors the Linux package formats use, behind one enum.
//!
//! Every backend is pure Rust so this compiles for `wasm32-unknown-unknown`
//! alongside the desktop build. The one gap is LZO (a squashfs option): there
//! is no decompressor we're willing to depend on, so it fails with a message
//! naming the compressor rather than a generic parse error.

use std::io::Read;

use crate::PkgError;

/// A compression algorithm, as identified by a container's own header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Stored uncompressed.
    None,
    /// gzip container (`\x1f\x8b`) — `.tar.gz`, `data.tar.gz`, rpm payloads.
    Gzip,
    /// Raw zlib stream — what squashfs means by "gzip".
    Zlib,
    /// `.xz` container.
    Xz,
    /// Bare LZMA1 (`.lzma`) — legacy rpm payloads.
    Lzma,
    Zstd,
    Bzip2,
    /// LZ4 frame format (`.tar.lz4`).
    Lz4Frame,
    /// A raw LZ4 block of known output size — squashfs's flavour.
    Lz4Block,
    /// Recognised but unsupported; carried so the error can name it.
    Lzo,
}

impl Codec {
    /// The compressor a magic number implies, for containers that don't declare
    /// one (a tarball is named `.tar.xz` but a stream is just bytes).
    pub fn sniff(bytes: &[u8]) -> Option<Codec> {
        Some(match bytes {
            _ if bytes.starts_with(b"\x1f\x8b") => Codec::Gzip,
            _ if bytes.starts_with(b"\xfd7zXZ\x00") => Codec::Xz,
            _ if bytes.starts_with(b"\x28\xb5\x2f\xfd") => Codec::Zstd,
            _ if bytes.starts_with(b"BZh") => Codec::Bzip2,
            _ if bytes.starts_with(b"\x04\x22\x4d\x18") => Codec::Lz4Frame,
            // LZMA1 has no magic: a 0x5d properties byte followed by a
            // power-of-two dictionary size is the conventional tell.
            _ if bytes.starts_with(b"\x5d\x00\x00") => Codec::Lzma,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Codec::None => "none",
            Codec::Gzip => "gzip",
            Codec::Zlib => "zlib",
            Codec::Xz => "xz",
            Codec::Lzma => "lzma",
            Codec::Zstd => "zstd",
            Codec::Bzip2 => "bzip2",
            Codec::Lz4Frame | Codec::Lz4Block => "lz4",
            Codec::Lzo => "lzo",
        }
    }
}

/// Decompress `input` in full.
///
/// `expected` is the output size when the container knows it (squashfs blocks
/// do). It sizes the buffer up front, and for [`Codec::Lz4Block`] — a raw block
/// with no framing — it is *required*, since the format carries no length.
pub fn decompress(
    codec: Codec,
    input: &[u8],
    expected: Option<usize>,
) -> Result<Vec<u8>, PkgError> {
    let mut out = Vec::with_capacity(expected.unwrap_or(input.len() * 3).min(64 << 20));
    match codec {
        Codec::None => out.extend_from_slice(input),
        // Multi-member: concatenated gzip streams are legal and `tar` writers
        // occasionally emit them.
        Codec::Gzip => read_all(flate2::read::MultiGzDecoder::new(input), &mut out)?,
        Codec::Zlib => read_all(flate2::read::ZlibDecoder::new(input), &mut out)?,
        Codec::Xz => {
            let mut cursor = std::io::Cursor::new(input);
            lzma_rs::xz_decompress(&mut cursor, &mut out)
                .map_err(|e| PkgError::Decompress("xz", e.to_string()))?;
        }
        Codec::Lzma => {
            let mut cursor = std::io::Cursor::new(input);
            lzma_rs::lzma_decompress(&mut cursor, &mut out)
                .map_err(|e| PkgError::Decompress("lzma", e.to_string()))?;
        }
        Codec::Zstd => {
            let decoder = ruzstd::decoding::StreamingDecoder::new(input)
                .map_err(|e| PkgError::Decompress("zstd", e.to_string()))?;
            read_all(decoder, &mut out)?;
        }
        Codec::Bzip2 => read_all(bzip2_rs::DecoderReader::new(input), &mut out)?,
        Codec::Lz4Frame => read_all(lz4_flex::frame::FrameDecoder::new(input), &mut out)?,
        Codec::Lz4Block => {
            let size = expected.ok_or_else(|| {
                PkgError::Decompress("lz4", "raw block with no declared output size".into())
            })?;
            out = lz4_flex::block::decompress(input, size)
                .map_err(|e| PkgError::Decompress("lz4", e.to_string()))?;
        }
        Codec::Lzo => {
            return Err(PkgError::UnsupportedCompression("lzo"));
        }
    }
    Ok(out)
}

fn read_all(mut reader: impl Read, out: &mut Vec<u8>) -> Result<(), PkgError> {
    reader
        .read_to_end(out)
        .map_err(|e| PkgError::Decompress("stream", e.to_string()))?;
    Ok(())
}
