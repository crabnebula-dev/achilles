//! The "new ASCII" (`newc`) cpio archive an RPM payload expands to.
//!
//! Every entry is a 110-byte header of hex fields, the NUL-terminated name, and
//! the body, each padded to a 4-byte boundary. The one wrinkle is hard links:
//! RPM emits every link to a file as a zero-length entry and attaches the body
//! to the *last* of them, so the earlier ones have to wait for it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{account, join_safe, link_target, PkgError, Sink, Unpacked};

const HEADER_LEN: usize = 110;
const TRAILER: &str = "TRAILER!!!";

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

pub fn unpack(
    bytes: &[u8],
    base: &Path,
    sink: &mut dyn Sink,
    out: &mut Unpacked,
) -> Result<(), PkgError> {
    let mut pos = 0usize;
    let mut saw_entry = false;
    // Hard-link members still waiting for the one that carries the body,
    // keyed by (device, inode) the way the archive identifies them.
    let mut pending: HashMap<(u32, u32, u32), Vec<PathBuf>> = HashMap::new();

    while let Some(header) = bytes.get(pos..pos + HEADER_LEN) {
        if !header.starts_with(b"07070") {
            break;
        }
        let Some(fields) = Fields::parse(header) else {
            break;
        };
        let name_start = pos + HEADER_LEN;
        let name_end = name_start + fields.namesize;
        let Some(raw_name) = bytes.get(name_start..name_end) else {
            break;
        };
        let name = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();
        if name == TRAILER {
            saw_entry = true;
            break;
        }

        // Both the name and the body are padded to a 4-byte boundary measured
        // from the start of the archive.
        let data_start = pad4(name_end);
        let data_end = data_start + fields.filesize;
        let Some(data) = bytes.get(data_start..data_end) else {
            out.warnings
                .push("cpio payload ends mid-entry; analysed what was readable".to_string());
            break;
        };
        pos = pad4(data_end);
        saw_entry = true;

        let Some(path) = join_safe(base, &name) else {
            out.warnings
                .push(format!("skipped cpio entry with an unsafe path: {name}"));
            continue;
        };
        let mode = fields.mode & 0o7777;

        match fields.mode & S_IFMT {
            S_IFDIR => sink.dir(&path)?,
            S_IFLNK => {
                let target = String::from_utf8_lossy(data)
                    .trim_end_matches('\0')
                    .to_string();
                sink.symlink(&path, &link_target(base, &target))?;
            }
            S_IFREG => {
                let key = (fields.devmajor, fields.devminor, fields.ino);
                if fields.nlink > 1 && fields.filesize == 0 {
                    // A link whose body comes later.
                    pending.entry(key).or_default().push(path);
                    continue;
                }
                account(out, data.len())?;
                sink.file(&path, data.to_vec(), mode)?;
                for link in pending.remove(&key).unwrap_or_default() {
                    sink.symlink(&link, &path)?;
                }
            }
            // Sockets, FIFOs, device nodes: nothing an application tree needs.
            _ => {}
        }
    }

    // Links whose body never arrived: keep the names, empty. Dropping them
    // would silently shrink the tree the analysis walks.
    for (_, links) in pending {
        for link in links {
            sink.file(&link, Vec::new(), 0o644)?;
        }
    }

    if saw_entry {
        Ok(())
    } else {
        Err(PkgError::Malformed("cpio", "no readable entries".into()))
    }
}

struct Fields {
    ino: u32,
    mode: u32,
    nlink: u32,
    filesize: usize,
    devmajor: u32,
    devminor: u32,
    namesize: usize,
}

impl Fields {
    /// The 13 fixed-width hex fields following the 6-byte magic.
    fn parse(header: &[u8]) -> Option<Fields> {
        let hex = |i: usize| -> Option<u32> {
            let at = 6 + i * 8;
            u32::from_str_radix(std::str::from_utf8(header.get(at..at + 8)?).ok()?, 16).ok()
        };
        Some(Fields {
            ino: hex(0)?,
            mode: hex(1)?,
            nlink: hex(4)?,
            filesize: hex(6)? as usize,
            devmajor: hex(7)?,
            devminor: hex(8)?,
            namesize: hex(11)? as usize,
        })
    }
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Collector, Entry, Format};

    #[allow(clippy::too_many_arguments)]
    fn entry(name: &str, mode: u32, ino: u32, nlink: u32, body: &[u8]) -> Vec<u8> {
        let mut out = b"070701".to_vec();
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            0,
            body.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        for f in fields {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(body);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn run(archive: &[u8]) -> (Collector, Unpacked) {
        let mut sink = Collector::default();
        let mut out = Unpacked::new(Format::Rpm, Path::new("/scan"), crate::MAX_PAYLOAD_BYTES);
        unpack(archive, Path::new("/scan"), &mut sink, &mut out).unwrap();
        (sink, out)
    }

    #[test]
    fn reads_dirs_files_and_symlinks() {
        let mut archive = entry("./usr/bin", S_IFDIR | 0o755, 1, 1, b"");
        archive.extend(entry("./usr/bin/app", S_IFREG | 0o755, 2, 1, b"\x7fELF"));
        archive.extend(entry("./usr/bin/link", S_IFLNK | 0o777, 3, 1, b"app"));
        archive.extend(entry(TRAILER, 0, 0, 1, b""));

        let (sink, out) = run(&archive);
        assert_eq!(out.files, 1);
        assert_eq!(sink.entries[0], Entry::Dir("/scan/usr/bin".into()));
        assert!(matches!(&sink.entries[1], Entry::File { path, mode, .. }
            if path == Path::new("/scan/usr/bin/app") && *mode == 0o755));
        assert_eq!(
            sink.entries[2],
            Entry::Symlink {
                path: "/scan/usr/bin/link".into(),
                target: "app".into()
            }
        );
    }

    #[test]
    fn hard_links_resolve_to_the_member_that_carries_the_body() {
        // RPM's shape: the empty link comes first, the body last.
        let mut archive = entry("./usr/bin/alias", S_IFREG | 0o755, 7, 2, b"");
        archive.extend(entry("./usr/bin/real", S_IFREG | 0o755, 7, 2, b"BODY"));
        archive.extend(entry(TRAILER, 0, 0, 1, b""));

        let (sink, out) = run(&archive);
        assert_eq!(out.files, 1);
        assert!(matches!(&sink.entries[0], Entry::File { path, data, .. }
            if path == Path::new("/scan/usr/bin/real") && data == b"BODY"));
        assert_eq!(
            sink.entries[1],
            Entry::Symlink {
                path: "/scan/usr/bin/alias".into(),
                target: "/scan/usr/bin/real".into()
            }
        );
    }
}
