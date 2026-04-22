//! Minimal reader for Electron's ASAR archive format.
//!
//! Just enough to enumerate regular files and extract their bytes — no
//! writing, no integrity verification (that lives in `macho-audit::asar`).
//!
//! Format:
//!
//! ```text
//!   offset  0: u32 le  = 4            // pickle outer size
//!   offset  4: u32 le  = header_size  // bytes from offset 8 to start of file bodies
//!   offset  8: u32 le  = json_pickle_size
//!   offset 12: u32 le  = json_len
//!   offset 16: json_len bytes         // UTF-8 JSON header
//!   …padding to 4-byte boundary within header_size…
//!   offset 8 + header_size: first file body
//! ```
//!
//! JSON header shape:
//!
//! ```json
//! {
//!   "files": {
//!     "package.json": { "size": 869, "offset": "0" },
//!     "out": { "files": { "main": { "files": { "index.js": { "size": 42, "offset": "869" } } } } },
//!     "empty.txt": { "size": 0, "offset": "911" }
//!   }
//! }
//! ```
//!
//! `offset` is a string because Electron supports archives larger than JS's
//! 2^53 integer range.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use memmap2::Mmap;

#[derive(Debug, thiserror::Error)]
pub enum AsarError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed header: {0}")]
    Malformed(String),
    #[error("json parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// One regular file inside an ASAR archive.
#[derive(Debug, Clone)]
pub struct Entry {
    /// POSIX-style path relative to the archive root.
    pub path: String,
    /// Body size in bytes.
    pub size: u64,
    /// Body offset relative to the start of the archive's body region.
    pub body_offset: u64,
}

pub struct Archive {
    #[allow(dead_code)] // retained for future diagnostics (stable across the archive's lifetime)
    path: PathBuf,
    /// Memory-mapped archive, retained for the archive's lifetime.
    mmap: Mmap,
    /// Byte offset of the first file body within the mmap.
    body_start: u64,
    entries: Vec<Entry>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Self, AsarError> {
        let file = File::open(path)?;
        // Safety: we only read the mapping and never alias it as `&mut`.
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.len() < 16 {
            return Err(AsarError::Malformed("file shorter than 16 bytes".into()));
        }
        let outer = u32::from_le_bytes(mmap[0..4].try_into().unwrap());
        if outer != 4 {
            return Err(AsarError::Malformed(format!(
                "unexpected pickle outer value {outer}"
            )));
        }
        let header_size = u32::from_le_bytes(mmap[4..8].try_into().unwrap()) as u64;
        let _json_pickle_size = u32::from_le_bytes(mmap[8..12].try_into().unwrap());
        let json_len = u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as usize;

        let json_start = 16usize;
        let json_end = json_start
            .checked_add(json_len)
            .ok_or_else(|| AsarError::Malformed("json length overflow".into()))?;
        if json_end > mmap.len() {
            return Err(AsarError::Malformed("json header extends past file".into()));
        }
        let body_start = 8u64.saturating_add(header_size);
        if body_start as usize > mmap.len() {
            return Err(AsarError::Malformed("body start past end of file".into()));
        }

        let json_bytes = &mmap[json_start..json_end];
        let root: serde_json::Value = serde_json::from_slice(json_bytes)?;

        let mut entries = Vec::new();
        walk_node(&root, "", &mut entries);

        Ok(Archive {
            path: path.to_path_buf(),
            mmap,
            body_start,
            entries,
        })
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a single file by its ASAR-internal path, returning its bytes.
    /// `None` if no such file exists.
    pub fn read_path(&self, logical_path: &str) -> Option<Vec<u8>> {
        let entry = self.entries.iter().find(|e| e.path == logical_path)?;
        self.read(entry).ok()
    }

    pub fn files(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Return the file body as a byte slice backed by the mmap.
    pub fn read(&self, entry: &Entry) -> Result<Vec<u8>, AsarError> {
        let start = self
            .body_start
            .checked_add(entry.body_offset)
            .ok_or_else(|| AsarError::Malformed("body offset overflow".into()))?
            as usize;
        let end = start
            .checked_add(entry.size as usize)
            .ok_or_else(|| AsarError::Malformed("file extent overflow".into()))?;
        if end > self.mmap.len() {
            return Err(AsarError::Malformed(format!(
                "file {} extends past archive",
                entry.path
            )));
        }
        Ok(self.mmap[start..end].to_vec())
    }
}

fn walk_node(node: &serde_json::Value, prefix: &str, out: &mut Vec<Entry>) {
    let Some(files) = node.get("files").and_then(|v| v.as_object()) else {
        return;
    };
    for (name, entry) in files {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.get("files").is_some() {
            walk_node(entry, &path, out);
            continue;
        }
        if entry.get("link").is_some() {
            // Symbolic link; skip — we'd chase it and get noise.
            continue;
        }
        let Some(size) = entry.get("size").and_then(|v| v.as_u64()) else {
            continue;
        };
        let body_offset = match entry.get("offset") {
            Some(serde_json::Value::String(s)) => s.parse::<u64>().unwrap_or(0),
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            _ => 0,
        };
        out.push(Entry {
            path,
            size,
            body_offset,
        });
    }
}

/// Read the first `json_len` bytes as a UTF-8 header without mmapping (used
/// by tools that only want the header JSON and not file bodies).
#[allow(dead_code)]
pub fn read_header_bytes(path: &Path) -> Result<Vec<u8>, AsarError> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix)?;
    let json_len = u32::from_le_bytes(prefix[12..16].try_into().unwrap()) as usize;
    file.seek(SeekFrom::Start(16))?;
    let mut buf = vec![0u8; json_len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}
