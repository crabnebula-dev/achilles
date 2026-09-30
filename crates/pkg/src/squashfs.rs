//! A read-only squashfs 4.0 reader — the filesystem inside a snap and inside
//! every type-2 AppImage.
//!
//! Squashfs stores its metadata (inodes, directory listings, the fragment
//! table) in a stream of independently-compressed ≤8 KiB blocks, and addresses
//! into it with 48-bit block offsets plus a 16-bit offset within the
//! decompressed block. Rather than decompress on demand and juggle a cache,
//! this reader expands the inode and directory tables once into contiguous
//! buffers ([`MetaTable`]) — they're metadata, a few MB at most even for a
//! large image — after which every reference resolves to a plain slice index.
//! File *data* stays lazy: only the blocks of files actually unpacked get
//! decompressed.
//!
//! The layout constants come from the kernel's `squashfs_fs.h`. Input is
//! untrusted, so every field read is bounds-checked and every record's length
//! is validated before it is parsed: a corrupt image yields a warning and a
//! partial tree, never a panic.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use crate::decompress::{decompress, Codec};
use crate::{account, join_safe, link_target, PkgError, Sink, Unpacked};

const MAGIC: &[u8] = b"hsqs";
const BIG_ENDIAN_MAGIC: &[u8] = b"sqsh";
const SUPERBLOCK_LEN: usize = 96;
const METADATA_MAX: usize = 8192;
/// Metadata block header bit: the block is stored uncompressed.
const META_UNCOMPRESSED: u16 = 0x8000;
/// Data block size bit: same meaning, different position.
const DATA_UNCOMPRESSED: u32 = 1 << 24;
const DATA_SIZE_MASK: u32 = (1 << 24) - 1;
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;

/// Inode types: the basic forms, then the extended ones that widen the same
/// fields for large files and deep directories.
const INODE_DIR: u16 = 1;
const INODE_FILE: u16 = 2;
const INODE_SYMLINK: u16 = 3;
const INODE_EXT_DIR: u16 = 8;
const INODE_EXT_FILE: u16 = 9;
const INODE_EXT_SYMLINK: u16 = 10;

/// Smallest valid record for each inode form, excluding trailing block lists
/// and symlink targets (checked separately).
const DIR_INODE_LEN: usize = 32;
const EXT_DIR_INODE_LEN: usize = 40;
const FILE_INODE_LEN: usize = 32;
const EXT_FILE_INODE_LEN: usize = 56;
const SYMLINK_INODE_LEN: usize = 24;

/// Depth cap while walking directories: deeper than any real application tree,
/// shallow enough that a crafted image can't exhaust the stack.
const MAX_DEPTH: u32 = 64;

pub fn is_squashfs(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC) || bytes.starts_with(BIG_ENDIAN_MAGIC)
}

/// Unpack every file in the image at `bytes` under `base`.
pub fn unpack(
    bytes: &[u8],
    base: &Path,
    sink: &mut dyn Sink,
    out: &mut Unpacked,
) -> Result<(), PkgError> {
    let fs = Squashfs::open(bytes)?;
    let root = fs.superblock.root_inode;
    fs.walk(root, base, base, 0, sink, out)
}

struct Superblock {
    block_size: u32,
    fragments: u32,
    compression: u16,
    root_inode: u64,
    bytes_used: u64,
    id_table: u64,
    xattr_table: u64,
    inode_table: u64,
    directory_table: u64,
    fragment_table: u64,
    lookup_table: u64,
}

struct Squashfs<'a> {
    bytes: &'a [u8],
    superblock: Superblock,
    codec: Codec,
    inodes: MetaTable,
    directories: MetaTable,
    /// `(start_block, size)` per fragment, indexed by fragment number.
    fragments: Vec<(u64, u32)>,
    /// The most recently expanded fragment block. Small files are packed into
    /// shared fragments in tree order, so one slot catches nearly every reuse.
    last_fragment: RefCell<Option<(u32, Vec<u8>)>>,
}

impl<'a> Squashfs<'a> {
    fn open(bytes: &'a [u8]) -> Result<Squashfs<'a>, PkgError> {
        if bytes.starts_with(BIG_ENDIAN_MAGIC) {
            return Err(PkgError::Unsupported(
                "this is a big-endian squashfs image (pre-4.0); only the current \
                 little-endian format can be read"
                    .into(),
            ));
        }
        let sb = bytes
            .get(..SUPERBLOCK_LEN)
            .filter(|b| b.starts_with(MAGIC))
            .ok_or_else(|| PkgError::Malformed("squashfs", "missing superblock".into()))?;

        let major = le16(sb, 28);
        if major != 4 {
            return Err(PkgError::Unsupported(format!(
                "squashfs version {major}.{} is not supported (this reader handles 4.0)",
                le16(sb, 30)
            )));
        }

        let superblock = Superblock {
            block_size: le32(sb, 12),
            fragments: le32(sb, 16),
            compression: le16(sb, 20),
            root_inode: le64(sb, 32),
            bytes_used: le64(sb, 40),
            id_table: le64(sb, 48),
            xattr_table: le64(sb, 56),
            inode_table: le64(sb, 64),
            directory_table: le64(sb, 72),
            fragment_table: le64(sb, 80),
            lookup_table: le64(sb, 88),
        };

        let codec = match superblock.compression {
            // Squashfs calls it "gzip", but the blocks are raw zlib streams.
            1 => Codec::Zlib,
            2 => Codec::Lzma,
            3 => Codec::Lzo,
            4 => Codec::Xz,
            5 => Codec::Lz4Block,
            6 => Codec::Zstd,
            other => {
                return Err(PkgError::Malformed(
                    "squashfs",
                    format!("unknown compression id {other}"),
                ))
            }
        };
        if codec == Codec::Lzo {
            return Err(PkgError::UnsupportedCompression("lzo"));
        }
        if superblock.block_size == 0 || superblock.block_size > (1 << 20) {
            return Err(PkgError::Malformed(
                "squashfs",
                format!("implausible block size {}", superblock.block_size),
            ));
        }

        // The tables are laid out in order, each ending where the next starts.
        // Anything that isn't present is written as a sentinel far past the end
        // of the image, so only offsets that actually land inside it count.
        let dir_end = [
            superblock.fragment_table,
            superblock.lookup_table,
            superblock.id_table,
            superblock.xattr_table,
            superblock.bytes_used,
        ]
        .into_iter()
        .filter(|&t| t > superblock.directory_table && t <= bytes.len() as u64)
        .min()
        .unwrap_or(superblock.bytes_used.min(bytes.len() as u64));

        let inodes = MetaTable::expand(
            bytes,
            superblock.inode_table,
            superblock.directory_table,
            codec,
        )?;
        let directories = MetaTable::expand(bytes, superblock.directory_table, dir_end, codec)?;
        let fragments = read_fragment_table(bytes, &superblock, codec)?;

        Ok(Squashfs {
            bytes,
            superblock,
            codec,
            inodes,
            directories,
            fragments,
            last_fragment: RefCell::new(None),
        })
    }

    /// Emit the inode at `reference` and, if it's a directory, everything under
    /// it. `path` is where the inode lands in the sink; `base` is the unpack
    /// root, which absolute symlink targets resolve against.
    fn walk(
        &self,
        reference: u64,
        path: &Path,
        base: &Path,
        depth: u32,
        sink: &mut dyn Sink,
        out: &mut Unpacked,
    ) -> Result<(), PkgError> {
        let Some(inode) = self.inodes.at(reference) else {
            out.warnings
                .push(format!("squashfs: unreadable inode for {}", path.display()));
            return Ok(());
        };
        if inode.len() < 16 {
            out.warnings
                .push(format!("squashfs: truncated inode for {}", path.display()));
            return Ok(());
        }
        let kind = le16(inode, 0);
        let mode = le16(inode, 2) as u32 & 0o7777;
        let min_len = match kind {
            INODE_DIR => DIR_INODE_LEN,
            INODE_EXT_DIR => EXT_DIR_INODE_LEN,
            INODE_FILE => FILE_INODE_LEN,
            INODE_EXT_FILE => EXT_FILE_INODE_LEN,
            INODE_SYMLINK | INODE_EXT_SYMLINK => SYMLINK_INODE_LEN,
            // Devices, FIFOs, sockets: nothing an application tree needs.
            _ => return Ok(()),
        };
        if inode.len() < min_len {
            out.warnings
                .push(format!("squashfs: truncated inode for {}", path.display()));
            return Ok(());
        }

        match kind {
            INODE_DIR | INODE_EXT_DIR => {
                sink.dir(path)?;
                if depth >= MAX_DEPTH {
                    out.warnings.push(format!(
                        "squashfs: stopped at {} — nested deeper than {MAX_DEPTH} levels",
                        path.display()
                    ));
                    return Ok(());
                }
                for (name, child) in self.read_dir(inode, kind, out) {
                    // A squashfs listing holds plain names — it stores `.` and
                    // `..` as counts, not entries. Anything else is a crafted
                    // image trying to walk out of the tree, or back into a
                    // parent forever.
                    let child_path = match join_safe(path, &name) {
                        Some(p) if is_plain_name(&name) => p,
                        _ => {
                            out.warnings
                                .push(format!("squashfs: skipped entry named {name:?}"));
                            continue;
                        }
                    };
                    self.walk(child, &child_path, base, depth + 1, sink, out)?;
                }
            }
            INODE_FILE | INODE_EXT_FILE => match self.read_file(inode, kind, out.limit) {
                Ok(data) => {
                    account(out, data.len())?;
                    sink.file(path, data, mode)?;
                }
                // One unreadable file (a compression variant we can't handle,
                // a truncated image) shouldn't cost the whole tree.
                Err(e @ PkgError::TooLarge(_)) => return Err(e),
                Err(e) => out
                    .warnings
                    .push(format!("squashfs: could not read {}: {e}", path.display())),
            },
            INODE_SYMLINK | INODE_EXT_SYMLINK => {
                let len = le32(inode, 20) as usize;
                match inode.get(24..24 + len) {
                    Some(target) => {
                        let target = String::from_utf8_lossy(target).into_owned();
                        sink.symlink(path, &link_target(base, &target))?;
                    }
                    None => out.warnings.push(format!(
                        "squashfs: unreadable symlink target for {}",
                        path.display()
                    )),
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The `(name, inode reference)` pairs a directory inode lists.
    fn read_dir(&self, inode: &[u8], kind: u16, out: &mut Unpacked) -> Vec<(String, u64)> {
        // Basic and extended dir inodes carry the same three fields in
        // different places and widths.
        let (start_block, file_size, offset) = if kind == INODE_DIR {
            (
                le32(inode, 16) as u64,
                le16(inode, 24) as u32,
                le16(inode, 26),
            )
        } else {
            (le32(inode, 24) as u64, le32(inode, 20), le16(inode, 34))
        };
        // `file_size` counts three bytes that aren't in the listing — how
        // mksquashfs accounts for `.` and `..`.
        let len = file_size.saturating_sub(3) as usize;
        let reference = (start_block << 16) | offset as u64;
        let Some(mut listing) = self.directories.slice(reference, len) else {
            out.warnings
                .push("squashfs: unreadable directory listing".to_string());
            return Vec::new();
        };

        let mut entries = Vec::new();
        // The listing is a series of headers, each covering up to 256 entries
        // whose inodes share one metadata block.
        while listing.len() >= 12 {
            let count = le32(listing, 0) as usize + 1;
            let inode_block = le32(listing, 4) as u64;
            listing = &listing[12..];
            for _ in 0..count {
                if listing.len() < 8 {
                    return entries;
                }
                let entry_offset = le16(listing, 0) as u64;
                let name_len = le16(listing, 6) as usize + 1;
                let Some(name) = listing.get(8..8 + name_len) else {
                    return entries;
                };
                entries.push((
                    String::from_utf8_lossy(name).into_owned(),
                    (inode_block << 16) | entry_offset,
                ));
                listing = &listing[8 + name_len..];
            }
        }
        entries
    }

    /// The full contents of a file inode. `limit` is checked before the buffer
    /// is reserved, so a crafted size field can't turn into a huge allocation.
    fn read_file(&self, inode: &[u8], kind: u16, limit: u64) -> Result<Vec<u8>, PkgError> {
        let (start_block, file_size, fragment, offset, list_at) = if kind == INODE_FILE {
            (
                le32(inode, 16) as u64,
                le32(inode, 28) as u64,
                le32(inode, 20),
                le32(inode, 24) as usize,
                FILE_INODE_LEN,
            )
        } else {
            (
                le64(inode, 16),
                le64(inode, 24),
                le32(inode, 44),
                le32(inode, 48) as usize,
                EXT_FILE_INODE_LEN,
            )
        };
        if file_size > limit {
            return Err(PkgError::TooLarge(limit));
        }

        let block_size = self.superblock.block_size as u64;
        // A file whose tail lives in a fragment lists only whole blocks; one
        // without a fragment lists a (possibly partial) final block too.
        let listed_blocks = if fragment == NO_FRAGMENT {
            file_size.div_ceil(block_size)
        } else {
            file_size / block_size
        } as usize;

        let mut out = Vec::with_capacity(file_size as usize);
        let mut cursor = start_block;
        for i in 0..listed_blocks {
            let entry = inode
                .get(list_at + i * 4..list_at + i * 4 + 4)
                .map(|b| le32(b, 0))
                .ok_or_else(|| PkgError::Malformed("squashfs", "truncated block list".into()))?;
            let size = (entry & DATA_SIZE_MASK) as usize;
            let remaining = (file_size as usize).saturating_sub(out.len());
            let expected = remaining.min(block_size as usize);
            if size == 0 {
                // A hole: squashfs stores nothing at all for an all-zero block.
                out.resize(out.len() + expected, 0);
                continue;
            }
            let raw = self.at(cursor, size)?;
            cursor += size as u64;
            if entry & DATA_UNCOMPRESSED != 0 {
                out.extend_from_slice(raw);
            } else {
                out.extend_from_slice(&decompress(self.codec, raw, Some(expected))?);
            }
        }

        if fragment != NO_FRAGMENT {
            let remaining = (file_size as usize).saturating_sub(out.len());
            let block = self.read_fragment(fragment)?;
            let tail = block
                .get(offset..offset + remaining)
                .ok_or_else(|| PkgError::Malformed("squashfs", "fragment out of range".into()))?;
            out.extend_from_slice(tail);
        }
        out.truncate(file_size as usize);
        Ok(out)
    }

    /// Expand the fragment block holding the tails of one or more small files.
    fn read_fragment(&self, index: u32) -> Result<Vec<u8>, PkgError> {
        if let Some((cached, data)) = self.last_fragment.borrow().as_ref() {
            if *cached == index {
                return Ok(data.clone());
            }
        }
        let &(start, size) = self.fragments.get(index as usize).ok_or_else(|| {
            PkgError::Malformed("squashfs", format!("fragment {index} out of range"))
        })?;
        let raw = self.at(start, (size & DATA_SIZE_MASK) as usize)?;
        let data = if size & DATA_UNCOMPRESSED != 0 {
            raw.to_vec()
        } else {
            decompress(self.codec, raw, Some(self.superblock.block_size as usize))?
        };
        *self.last_fragment.borrow_mut() = Some((index, data.clone()));
        Ok(data)
    }

    fn at(&self, offset: u64, len: usize) -> Result<&'a [u8], PkgError> {
        usize::try_from(offset)
            .ok()
            .and_then(|s| self.bytes.get(s..s.checked_add(len)?))
            .ok_or_else(|| {
                PkgError::Malformed(
                    "squashfs",
                    format!("read of {len} bytes at {offset} is out of range"),
                )
            })
    }
}

/// A metadata region (the inode table or the directory table) expanded into one
/// buffer, with an index from each source block's offset — the form squashfs
/// references use — to its position in that buffer.
struct MetaTable {
    data: Vec<u8>,
    /// Source offset of a block relative to the table start → position in `data`.
    index: BTreeMap<u64, usize>,
}

impl MetaTable {
    fn expand(bytes: &[u8], start: u64, end: u64, codec: Codec) -> Result<MetaTable, PkgError> {
        let mut table = MetaTable {
            data: Vec::new(),
            index: BTreeMap::new(),
        };
        if end <= start || start >= bytes.len() as u64 {
            return Ok(table);
        }
        let mut at = start;
        while at < end {
            table.index.insert(at - start, table.data.len());
            let (block, next) = read_metadata_block(bytes, at, codec)?;
            table.data.extend_from_slice(&block);
            at = next;
        }
        Ok(table)
    }

    /// Resolve a squashfs reference — block offset in the high 48 bits, offset
    /// within the expanded block in the low 16 — to a position in `data`.
    fn position(&self, reference: u64) -> Option<usize> {
        let block = reference >> 16;
        let offset = (reference & 0xFFFF) as usize;
        self.index.get(&block)?.checked_add(offset)
    }

    /// Everything from `reference` to the end of the table. Inode records are
    /// variable-length, so callers read fields off the front of this and
    /// validate the length themselves.
    fn at(&self, reference: u64) -> Option<&[u8]> {
        self.data.get(self.position(reference)?..)
    }

    fn slice(&self, reference: u64, len: usize) -> Option<&[u8]> {
        let at = self.position(reference)?;
        self.data.get(at..at.checked_add(len)?)
    }
}

/// Expand one metadata block, returning it and the offset of the next.
fn read_metadata_block(bytes: &[u8], at: u64, codec: Codec) -> Result<(Vec<u8>, u64), PkgError> {
    let at =
        usize::try_from(at).map_err(|_| PkgError::Malformed("squashfs", "bad offset".into()))?;
    let header = bytes
        .get(at..at + 2)
        .map(|h| le16(h, 0))
        .ok_or_else(|| PkgError::Malformed("squashfs", "metadata block out of range".into()))?;
    let size = (header & !META_UNCOMPRESSED) as usize;
    let raw = bytes
        .get(at + 2..at + 2 + size)
        .ok_or_else(|| PkgError::Malformed("squashfs", "metadata block truncated".into()))?;
    let next = (at + 2 + size) as u64;
    if header & META_UNCOMPRESSED != 0 {
        Ok((raw.to_vec(), next))
    } else {
        Ok((decompress(codec, raw, Some(METADATA_MAX))?, next))
    }
}

/// The fragment table: a lookup array of metadata-block offsets, each block
/// holding a run of 16-byte `(start_block, size)` entries.
fn read_fragment_table(
    bytes: &[u8],
    sb: &Superblock,
    codec: Codec,
) -> Result<Vec<(u64, u32)>, PkgError> {
    if sb.fragments == 0 || sb.fragment_table >= bytes.len() as u64 {
        return Ok(Vec::new());
    }
    let entries = sb.fragments as usize;
    let blocks = (entries * 16).div_ceil(METADATA_MAX);
    let table_at = sb.fragment_table as usize;

    let mut raw = Vec::with_capacity(entries * 16);
    for i in 0..blocks {
        let at = bytes
            .get(table_at + i * 8..table_at + i * 8 + 8)
            .map(|b| le64(b, 0))
            .ok_or_else(|| {
                PkgError::Malformed("squashfs", "fragment lookup table truncated".into())
            })?;
        raw.extend_from_slice(&read_metadata_block(bytes, at, codec)?.0);
    }

    Ok((0..entries)
        .filter_map(|i| {
            let e = raw.get(i * 16..i * 16 + 16)?;
            Some((le64(e, 0), le32(e, 8)))
        })
        .collect())
}

/// A single path component and nothing more.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/')
}

// Bounds-checked little-endian field reads. Out-of-range yields 0 rather than a
// panic; every record's length is validated before its fields are read, so a 0
// here means a corrupt image that has already been reported.
fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map(|s| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(s);
            u64::from_le_bytes(buf)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Collector, Entry, Format};

    /// Build a minimal, fully-uncompressed squashfs image: a root directory
    /// holding one regular file and one symlink to it. Uncompressed blocks are
    /// a legal encoding (mksquashfs emits them for incompressible data), so
    /// this exercises the real layout without depending on a compressor.
    fn build_image() -> Vec<u8> {
        const BODY: &[u8] = b"\x7fELFhello";
        let mut image = vec![0u8; SUPERBLOCK_LEN];

        // --- data blocks ---
        let data_at = image.len() as u32;
        image.extend_from_slice(BODY);

        // --- inode table: file, symlink, then the root directory ---
        let mut inodes = Vec::new();
        let file_off = inodes.len() as u16;
        inodes.extend_from_slice(&INODE_FILE.to_le_bytes());
        inodes.extend_from_slice(&0o755u16.to_le_bytes());
        inodes.extend_from_slice(&[0u8; 12]); // uid, gid, mtime, inode number
        inodes.extend_from_slice(&data_at.to_le_bytes());
        inodes.extend_from_slice(&NO_FRAGMENT.to_le_bytes());
        inodes.extend_from_slice(&0u32.to_le_bytes()); // fragment offset
        inodes.extend_from_slice(&(BODY.len() as u32).to_le_bytes());
        // One block, stored uncompressed.
        inodes.extend_from_slice(&(BODY.len() as u32 | DATA_UNCOMPRESSED).to_le_bytes());

        let link_off = inodes.len() as u16;
        inodes.extend_from_slice(&INODE_SYMLINK.to_le_bytes());
        inodes.extend_from_slice(&0o777u16.to_le_bytes());
        inodes.extend_from_slice(&[0u8; 12]);
        inodes.extend_from_slice(&1u32.to_le_bytes()); // nlink
        inodes.extend_from_slice(&3u32.to_le_bytes()); // target length
        inodes.extend_from_slice(b"app");

        // --- directory listing for the root ---
        let mut listing = Vec::new();
        listing.extend_from_slice(&1u32.to_le_bytes()); // count, less one
        listing.extend_from_slice(&0u32.to_le_bytes()); // inode block offset
        listing.extend_from_slice(&0u32.to_le_bytes()); // base inode number
        for (offset, kind, name) in [
            (file_off, INODE_FILE, "app"),
            (link_off, INODE_SYMLINK, "link"),
        ] {
            listing.extend_from_slice(&offset.to_le_bytes());
            listing.extend_from_slice(&0u16.to_le_bytes()); // inode number delta
            listing.extend_from_slice(&kind.to_le_bytes());
            listing.extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
            listing.extend_from_slice(name.as_bytes());
        }

        let root_off = inodes.len() as u16;
        inodes.extend_from_slice(&INODE_DIR.to_le_bytes());
        inodes.extend_from_slice(&0o755u16.to_le_bytes());
        inodes.extend_from_slice(&[0u8; 12]);
        inodes.extend_from_slice(&0u32.to_le_bytes()); // listing block offset
        inodes.extend_from_slice(&2u32.to_le_bytes()); // nlink
        inodes.extend_from_slice(&(listing.len() as u16 + 3).to_le_bytes());
        inodes.extend_from_slice(&0u16.to_le_bytes()); // offset into the block
        inodes.extend_from_slice(&0u32.to_le_bytes()); // parent inode

        let inode_table = image.len() as u64;
        image.extend_from_slice(&(inodes.len() as u16 | META_UNCOMPRESSED).to_le_bytes());
        image.extend_from_slice(&inodes);

        let directory_table = image.len() as u64;
        image.extend_from_slice(&(listing.len() as u16 | META_UNCOMPRESSED).to_le_bytes());
        image.extend_from_slice(&listing);

        let id_table = image.len() as u64;
        let bytes_used = image.len() as u64;

        // --- superblock ---
        let sb = &mut image[..SUPERBLOCK_LEN];
        sb[0..4].copy_from_slice(MAGIC);
        sb[4..8].copy_from_slice(&3u32.to_le_bytes()); // inode count
        sb[12..16].copy_from_slice(&4096u32.to_le_bytes()); // block size
        sb[16..20].copy_from_slice(&0u32.to_le_bytes()); // fragment count
        sb[20..22].copy_from_slice(&1u16.to_le_bytes()); // compression: gzip
        sb[22..24].copy_from_slice(&12u16.to_le_bytes()); // block log
        sb[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
        sb[32..40].copy_from_slice(&(root_off as u64).to_le_bytes());
        sb[40..48].copy_from_slice(&bytes_used.to_le_bytes());
        sb[48..56].copy_from_slice(&id_table.to_le_bytes());
        sb[56..64].copy_from_slice(&u64::MAX.to_le_bytes()); // no xattrs
        sb[64..72].copy_from_slice(&inode_table.to_le_bytes());
        sb[72..80].copy_from_slice(&directory_table.to_le_bytes());
        sb[80..88].copy_from_slice(&u64::MAX.to_le_bytes()); // no fragments
        sb[88..96].copy_from_slice(&u64::MAX.to_le_bytes()); // no export table

        image
    }

    fn run(image: &[u8]) -> (Collector, Unpacked) {
        let mut sink = Collector::default();
        let mut out = Unpacked::new(Format::Snap, Path::new("/scan"), crate::MAX_PAYLOAD_BYTES);
        unpack(image, Path::new("/scan"), &mut sink, &mut out).unwrap();
        (sink, out)
    }

    #[test]
    fn reads_the_root_directory_its_file_and_its_symlink() {
        let image = build_image();
        assert!(is_squashfs(&image));

        let (sink, out) = run(&image);
        assert_eq!(out.files, 1);
        assert_eq!(out.warnings, Vec::<String>::new());
        assert_eq!(sink.entries[0], Entry::Dir("/scan".into()));
        assert!(matches!(&sink.entries[1], Entry::File { path, data, mode }
            if path == Path::new("/scan/app") && data == b"\x7fELFhello" && *mode == 0o755));
        assert_eq!(
            sink.entries[2],
            Entry::Symlink {
                path: "/scan/link".into(),
                target: "app".into(),
            }
        );
    }

    #[test]
    fn a_big_endian_image_is_named_rather_than_misparsed() {
        let mut image = build_image();
        image[..4].copy_from_slice(BIG_ENDIAN_MAGIC);
        let Err(err) = Squashfs::open(&image) else {
            panic!("a big-endian image must not parse as little-endian");
        };
        assert!(err.to_string().contains("big-endian"));
    }

    #[test]
    fn a_truncated_image_errors_instead_of_panicking() {
        let image = build_image();
        for cut in [4, 50, 96, 100, image.len() - 1] {
            // Any of these may fail; none may panic.
            let mut sink = Collector::default();
            let mut out = Unpacked::new(Format::Snap, Path::new("/scan"), crate::MAX_PAYLOAD_BYTES);
            let _ = unpack(&image[..cut], Path::new("/scan"), &mut sink, &mut out);
        }
    }
}
