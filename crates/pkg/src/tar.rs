//! A tar reader: the payload of a `.deb`, and the whole of a vendor tarball.
//!
//! Covers what real producers emit — ustar with `prefix`, GNU `L`/`K` long
//! names, pax `x` records, and GNU base-256 sizes for members above 8 GiB.
//! Anything else (device nodes, FIFOs) is skipped: an application tree has no
//! use for it, and creating one in a sink would be a liability, not a feature.

use std::path::Path;

use crate::{account, join_safe, link_target, PkgError, Sink, Unpacked};

const BLOCK: usize = 512;

/// True if `bytes` is an uncompressed tar — the `ustar` magic sits inside the
/// first header rather than at offset 0, which is why a `.tar` needs looking
/// *into* rather than sniffing.
pub fn is_tar(bytes: &[u8]) -> bool {
    bytes.get(257..262).map(|m| m == b"ustar").unwrap_or(false)
}

pub fn unpack(
    bytes: &[u8],
    base: &Path,
    sink: &mut dyn Sink,
    out: &mut Unpacked,
) -> Result<(), PkgError> {
    let mut pos = 0usize;
    // Set by a preceding GNU `L`/`K` block or pax `x` record, consumed by the
    // member that follows.
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut saw_member = false;

    while let Some(header) = bytes.get(pos..pos + BLOCK) {
        pos += BLOCK;
        // A block of zeroes is the end-of-archive marker (there are two, but
        // one is enough to stop on).
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let Some(size) = field_size(header) else {
            return finish(saw_member, out, "unreadable member size");
        };
        let data_end = pos + size;
        let Some(data) = bytes.get(pos..data_end) else {
            out.warnings
                .push("tar ends mid-member; analysed what was readable".to_string());
            break;
        };
        // Members are padded out to a block boundary.
        pos = data_end + (BLOCK - data_end % BLOCK) % BLOCK;
        saw_member = true;

        let typeflag = header[156];
        match typeflag {
            // GNU long name / long link: the *next* member's name is this
            // member's body.
            b'L' => {
                long_name = Some(cstr(data));
                continue;
            }
            b'K' => {
                long_link = Some(cstr(data));
                continue;
            }
            // pax extended headers, per-member (`x`) or global (`g`).
            b'x' | b'X' | b'g' => {
                if typeflag != b'g' {
                    if let Some(p) = pax_field(data, "path") {
                        long_name = Some(p);
                    }
                    if let Some(p) = pax_field(data, "linkpath") {
                        long_link = Some(p);
                    }
                }
                continue;
            }
            _ => {}
        }

        let name = long_name.take().unwrap_or_else(|| ustar_name(header));
        let link = long_link.take();
        let Some(path) = join_safe(base, &name) else {
            out.warnings
                .push(format!("skipped tar entry with an unsafe path: {name}"));
            continue;
        };
        let mode = field_octal(&header[100..108]).unwrap_or(0o644) as u32 & 0o7777;

        match typeflag {
            b'5' => sink.dir(&path)?,
            b'2' => {
                let target = link.unwrap_or_else(|| cstr(&header[157..257]));
                sink.symlink(&path, &link_target(base, &target))?;
            }
            // A hard link points at another member of this same archive, so it
            // resolves like a symlink to that path under the payload root.
            b'1' => {
                let target = link.unwrap_or_else(|| cstr(&header[157..257]));
                let Some(target) = join_safe(base, &target) else {
                    continue;
                };
                sink.symlink(&path, &target)?;
            }
            b'0' | 0 | b'7' => {
                account(out, data.len())?;
                sink.file(&path, data.to_vec(), mode)?;
            }
            // Character/block devices, FIFOs, and anything unknown.
            _ => {}
        }
    }

    finish(saw_member, out, "no readable members")
}

fn finish(saw_member: bool, _out: &mut Unpacked, why: &str) -> Result<(), PkgError> {
    if saw_member {
        Ok(())
    } else {
        Err(PkgError::Malformed("tar", why.to_string()))
    }
}

/// The member name, joining the ustar `prefix` field when it's in use.
fn ustar_name(header: &[u8]) -> String {
    let name = cstr(&header[0..100]);
    let prefix = cstr(&header[345..500]);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// Member size: octal, or GNU's base-256 form (high bit of the first byte set)
/// for sizes that don't fit in 11 octal digits.
fn field_size(header: &[u8]) -> Option<usize> {
    let field = &header[124..136];
    if field[0] & 0x80 != 0 {
        let mut value: u64 = 0;
        for &b in &field[field.len().saturating_sub(8)..] {
            value = value.checked_mul(256)?.checked_add(b as u64)?;
        }
        return usize::try_from(value).ok();
    }
    field_octal(field)
}

fn field_octal(field: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(field).ok()?;
    let text = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() {
        return Some(0);
    }
    usize::from_str_radix(text, 8).ok()
}

/// A NUL-terminated fixed-width string field.
fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Pull `key` out of a pax extended header body, whose records are
/// `"<len> <key>=<value>\n"` with `len` counting the whole record.
fn pax_field(data: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let mut rest = text.as_ref();
    while let Some(space) = rest.find(' ') {
        let len: usize = rest[..space].parse().ok()?;
        let record = rest.get(..len)?;
        let body = record[space + 1..].trim_end_matches('\n');
        if let Some((k, v)) = body.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
        rest = &rest[len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Collector, Entry, Format};

    /// Build a tar member header + body.
    fn member(name: &str, typeflag: u8, link: &str, body: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; BLOCK];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        header[100..108].copy_from_slice(b"0000755\0");
        let size = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = typeflag;
        header[157..157 + link.len()].copy_from_slice(link.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        let mut out = header;
        out.extend_from_slice(body);
        let pad = (BLOCK - body.len() % BLOCK) % BLOCK;
        out.extend(std::iter::repeat(0).take(pad));
        out
    }

    fn run(archive: &[u8]) -> (Collector, Unpacked) {
        let mut sink = Collector::default();
        let mut out = Unpacked::new(
            Format::Tarball,
            Path::new("/scan"),
            crate::MAX_PAYLOAD_BYTES,
        );
        unpack(archive, Path::new("/scan"), &mut sink, &mut out).unwrap();
        (sink, out)
    }

    #[test]
    fn reads_files_dirs_and_symlinks() {
        let mut archive = member("./usr/bin/", b'5', "", b"");
        archive.extend(member("./usr/bin/foo", b'0', "", b"\x7fELFbody"));
        archive.extend(member("./usr/bin/bar", b'2', "foo", b""));
        archive.extend(vec![0u8; BLOCK * 2]);

        let (sink, out) = run(&archive);
        assert_eq!(out.files, 1);
        assert_eq!(out.bytes, 8);
        assert_eq!(sink.entries[0], Entry::Dir("/scan/usr/bin".into()));
        assert!(matches!(&sink.entries[1], Entry::File { path, data, mode }
            if path == Path::new("/scan/usr/bin/foo") && data == b"\x7fELFbody" && *mode == 0o755));
        assert_eq!(
            sink.entries[2],
            Entry::Symlink {
                path: "/scan/usr/bin/bar".into(),
                target: "foo".into(),
            }
        );
    }

    #[test]
    fn gnu_long_names_apply_to_the_following_member() {
        let long = format!("usr/lib/{}/app", "d".repeat(120));
        let mut archive = member("././@LongLink", b'L', "", long.as_bytes());
        archive.extend(member("truncated-name", b'0', "", b"x"));
        archive.extend(vec![0u8; BLOCK * 2]);

        let (sink, _) = run(&archive);
        assert_eq!(sink.entries[0].path(), Path::new("/scan").join(&long));
    }

    #[test]
    fn pax_path_records_override_the_header_name() {
        let record = "27 path=usr/share/app/real\n";
        let mut archive = member("PaxHeader", b'x', "", record.as_bytes());
        archive.extend(member("short", b'0', "", b"x"));
        archive.extend(vec![0u8; BLOCK * 2]);

        let (sink, _) = run(&archive);
        assert_eq!(
            sink.entries[0].path(),
            Path::new("/scan/usr/share/app/real")
        );
    }

    #[test]
    fn absolute_symlink_targets_are_rerooted_into_the_payload() {
        let mut archive = member("usr/bin/app", b'2', "/usr/lib/app/app", b"");
        archive.extend(vec![0u8; BLOCK * 2]);

        let (sink, _) = run(&archive);
        assert_eq!(
            sink.entries[0],
            Entry::Symlink {
                path: "/scan/usr/bin/app".into(),
                target: "/scan/usr/lib/app/app".into(),
            }
        );
    }

    #[test]
    fn traversal_entries_are_skipped_not_written() {
        let mut archive = member("../../etc/cron.d/pwn", b'0', "", b"x");
        archive.extend(member("usr/bin/app", b'0', "", b"y"));
        archive.extend(vec![0u8; BLOCK * 2]);

        let (sink, out) = run(&archive);
        assert_eq!(sink.entries.len(), 1);
        assert_eq!(sink.entries[0].path(), Path::new("/scan/usr/bin/app"));
        assert_eq!(out.warnings.len(), 1);
    }
}
