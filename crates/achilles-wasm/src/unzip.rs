//! Unpack an uploaded zip into a [`pkg::Sink`].
//!
//! Kept out of the `wasm32`-only bindings so the zip code path builds and is
//! tested natively against real archives.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Most entries an uploaded zip may hold. An entry costs a path and a sink
/// record even when it is empty, so the expanded-size cap alone does not
/// bound it. Far above a real app: an Electron app with its `node_modules`
/// runs to tens of thousands of files.
const MAX_ZIP_ENTRIES: usize = 1 << 20;

/// Longest symlink target read from an entry. PATH_MAX is 4096 on Linux and
/// 1024 on macOS; anything longer is not a link a real app ships.
const MAX_LINK_TARGET: u64 = 4096;

/// Most memory reserved up front for one entry, as `pkg`'s `decompress` caps
/// it. The size an entry declares is the uploader's claim, so it only sizes
/// the first allocation; the bytes read are what count against the limit.
const MAX_PREALLOC: u64 = 64 << 20;

/// Unpack a zip archive into `sink` under `base`, preserving unix modes and
/// symlinks (macOS frameworks rely on `Versions/Current -> A`).
///
/// The upload is untrusted. Unpacking stops with an error when the archive
/// holds more than [`MAX_ZIP_ENTRIES`] entries, when what its entries yield
/// passes `max_bytes` in total, or when two entries unpack to the same path
/// (zip's own duplicate check compares the raw names, before `enclosed_name`
/// strips a root or drive prefix), counting the directories a path implies.
pub fn unzip_into(
    bytes: &[u8],
    base: &Path,
    sink: &mut dyn pkg::Sink,
    max_bytes: u64,
) -> Result<(), String> {
    unzip_limited(bytes, base, sink, max_bytes, MAX_ZIP_ENTRIES)
}

fn unzip_limited(
    bytes: &[u8],
    base: &Path,
    sink: &mut dyn pkg::Sink,
    max_bytes: u64,
    max_entries: usize,
) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    if zip.len() > max_entries {
        return Err(format!(
            "the archive has {} entries, more than the {max_entries} this scan reads",
            zip.len()
        ));
    }
    let too_large = || pkg::PkgError::TooLarge(max_bytes).to_string();
    let mut expanded: u64 = 0;
    // Each unpacked path, with the raw name it came from and whether it is a
    // directory, listed or implied by a deeper entry. A directory seen twice
    // is harmless; anything else that lands on a path already taken would
    // silently replace what is there, or put a file over a directory.
    let mut seen: HashMap<PathBuf, (String, bool)> = HashMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
        // `enclosed_name` rejects path-traversal (`..`) entries.
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let is_dir = entry.is_dir();
        // A name that cleans up to nothing (`.`, `a/..`, `C:`) is the base
        // itself, which the collision check never records. As a directory
        // (`./`) it adds nothing; as a file or a link it would replace the
        // folder that holds every other entry.
        if rel.as_os_str().is_empty() {
            if is_dir {
                continue;
            }
            return Err(format!("entry {name:?} unpacks to the scan root itself"));
        }
        let dest = base.join(rel);
        for parent in dest.ancestors().skip(1).take_while(|p| *p != base) {
            match seen.get(parent) {
                Some((_, true)) => break, // its own parents are recorded already
                Some((first, false)) => {
                    return Err(format!(
                        "entry {name:?} unpacks inside {}, which entry {first:?} is a file at",
                        parent.display()
                    ))
                }
                None => {
                    seen.insert(parent.to_path_buf(), (name.clone(), true));
                }
            }
        }
        match seen.get(&dest) {
            Some((_, true)) if is_dir => {}
            Some((first, _)) => {
                return Err(format!(
                    "entries {first:?} and {name:?} both unpack to {}",
                    dest.display()
                ))
            }
            None => {
                seen.insert(dest.clone(), (name.clone(), is_dir));
            }
        }
        if is_dir {
            sink.dir(&dest).map_err(|e| e.to_string())?;
            continue;
        }
        let mode = entry.unix_mode().unwrap_or(0o644);
        // Every addition to `expanded` is checked against what is left, as
        // `pkg`'s `account` does, so this cannot underflow.
        let remaining = max_bytes - expanded;
        // S_IFLNK
        if mode & 0o170000 == 0o120000 {
            let mut raw = Vec::new();
            (&mut entry)
                .take(MAX_LINK_TARGET + 1)
                .read_to_end(&mut raw)
                .map_err(|e| e.to_string())?;
            if raw.len() as u64 > MAX_LINK_TARGET {
                return Err(format!(
                    "the symlink {name:?} has a target longer than {MAX_LINK_TARGET} bytes"
                ));
            }
            if raw.len() as u64 > remaining {
                return Err(too_large());
            }
            expanded += raw.len() as u64;
            let target = String::from_utf8(raw).map_err(|e| e.to_string())?;
            sink.symlink(&dest, Path::new(&target))
                .map_err(|e| e.to_string())?;
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size().min(remaining).min(MAX_PREALLOC) as usize);
        // One byte past what is left tells an entry that fits exactly from
        // one that would pass the limit.
        (&mut entry)
            .take(remaining.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        if buf.len() as u64 > remaining {
            return Err(too_large());
        }
        expanded += buf.len() as u64;
        // An entry can declare more than it holds, and the sink keeps the
        // buffer as it is: give back what the declared size reserved.
        buf.shrink_to_fit();
        sink.file(&dest, buf, mode).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkg::{Collector, Entry};
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// Build a real deflate-compressed archive: dir, executable file, plain
    /// file, symlink, and a path-traversal entry that must be skipped.
    fn sample_zip() -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        w.add_directory("App.app/Contents/", opts.unix_permissions(0o755))
            .unwrap();
        w.start_file("App.app/Contents/run", opts.unix_permissions(0o755))
            .unwrap();
        // Repetitive so deflate actually compresses it.
        w.write_all(&b"hello zip ".repeat(500)).unwrap();
        w.start_file("App.app/Contents/info.txt", opts.unix_permissions(0o644))
            .unwrap();
        w.write_all(b"plain").unwrap();
        w.add_symlink("App.app/Contents/Current", "run", opts)
            .unwrap();
        w.start_file("../evil.txt", opts).unwrap();
        w.write_all(b"nope").unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_a_real_archive() {
        let bytes = sample_zip();
        let base = PathBuf::from("/scan");
        let mut sink = Collector::default();
        unzip_into(&bytes, &base, &mut sink, u64::MAX).unwrap();

        let find = |p: &str| sink.entries.iter().find(|e| e.path() == Path::new(p));
        assert!(matches!(
            find("/scan/App.app/Contents"),
            Some(Entry::Dir(_))
        ));
        match find("/scan/App.app/Contents/run") {
            Some(Entry::File { data, mode, .. }) => {
                assert_eq!(data, &b"hello zip ".repeat(500));
                assert_eq!(mode & 0o777, 0o755);
            }
            other => panic!("run: {other:?}"),
        }
        match find("/scan/App.app/Contents/info.txt") {
            Some(Entry::File { data, mode, .. }) => {
                assert_eq!(data, b"plain");
                assert_eq!(mode & 0o777, 0o644);
            }
            other => panic!("info.txt: {other:?}"),
        }
        match find("/scan/App.app/Contents/Current") {
            Some(Entry::Symlink { target, .. }) => assert_eq!(target, Path::new("run")),
            other => panic!("symlink: {other:?}"),
        }
        assert!(
            sink.entries.iter().all(|e| !e.path().ends_with("evil.txt")),
            "traversal entry must be skipped"
        );
    }

    /// The upload is untrusted. Whatever zip does with a hostile name, nothing
    /// may land outside the base and no `..` may reach the sink. The per-name
    /// results pin zip 9.0.5 (zip 2 skipped the absolute and drive names).
    #[test]
    fn hostile_names_stay_under_the_base() {
        let names = [
            "/abs.txt",        // root stripped
            "C:\\win.txt",     // drive prefix stripped
            "..\\up.txt",      // backslash `..` treated as a separator
            "a/../../esc.txt", // climbs above the archive root
            "./ok.txt",        // current-dir component dropped
        ];
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        for n in names {
            // The writer stores these names verbatim.
            w.start_file(n, opts).unwrap();
            w.write_all(n.as_bytes()).unwrap();
        }
        let bytes = w.finish().unwrap().into_inner();

        let base = Path::new("/scan");
        let mut sink = Collector::default();
        unzip_into(&bytes, base, &mut sink, u64::MAX).unwrap();

        // Invariant first.
        for e in &sink.entries {
            assert!(e.path().starts_with(base), "outside base: {:?}", e.path());
            assert!(
                e.path()
                    .components()
                    .all(|c| c != std::path::Component::ParentDir),
                "`..` in {:?}",
                e.path()
            );
        }

        // Then what zip 9.0.5 does with each name.
        let mut got: Vec<(PathBuf, Vec<u8>)> = sink
            .entries
            .iter()
            .map(|e| match e {
                Entry::File { path, data, .. } => (path.clone(), data.clone()),
                other => panic!("unexpected entry {other:?}"),
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                // "/abs.txt" is accepted, relocated under the base.
                (PathBuf::from("/scan/abs.txt"), b"/abs.txt".to_vec()),
                // "./ok.txt" is accepted as "ok.txt".
                (PathBuf::from("/scan/ok.txt"), b"./ok.txt".to_vec()),
                // "C:\\win.txt" is accepted, drive stripped, under the base.
                (PathBuf::from("/scan/win.txt"), b"C:\\win.txt".to_vec()),
                // "..\\up.txt" and "a/../../esc.txt" are skipped (not listed).
            ]
        );
    }

    #[test]
    fn rejects_garbage() {
        let mut sink = Collector::default();
        assert!(unzip_into(b"not a zip at all", Path::new("/scan"), &mut sink, u64::MAX).is_err());
    }

    /// An archive of `(name, contents)` files, deflated so the expanded size
    /// is well above the upload's.
    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn refuses_an_entry_that_expands_past_the_limit() {
        let zeros = vec![0u8; 1 << 20];
        let bytes = zip_of(&[("bomb.bin", &zeros)]);
        assert!(
            bytes.len() < 16 << 10,
            "deflate should shrink 1 MiB of zeros"
        );

        let mut sink = Collector::default();
        let err = unzip_into(&bytes, Path::new("/scan"), &mut sink, 64 << 10).unwrap_err();
        assert!(err.contains("limit"), "{err}");
        assert!(
            sink.entries.is_empty(),
            "nothing of the entry may reach the sink"
        );
    }

    #[test]
    fn counts_the_limit_across_entries() {
        let part = vec![b'a'; 40 << 10];
        let bytes = zip_of(&[("one.bin", &part), ("two.bin", &part)]);

        let mut sink = Collector::default();
        assert!(unzip_into(&bytes, Path::new("/scan"), &mut sink, 64 << 10).is_err());

        // Exactly at the limit is still allowed.
        let mut sink = Collector::default();
        unzip_into(&bytes, Path::new("/scan"), &mut sink, 80 << 10).unwrap();
        assert_eq!(sink.entries.len(), 2);
    }

    #[test]
    fn refuses_more_entries_than_the_cap() {
        let names = ["a", "b", "c", "d", "e"];
        let files: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, &b""[..])).collect();
        let bytes = zip_of(&files);

        let mut sink = Collector::default();
        let err = unzip_limited(&bytes, Path::new("/scan"), &mut sink, u64::MAX, 4).unwrap_err();
        assert!(err.contains("5 entries"), "{err}");

        let mut sink = Collector::default();
        unzip_limited(&bytes, Path::new("/scan"), &mut sink, u64::MAX, 5).unwrap();
    }

    /// zip refuses two entries with the same raw name, but not two whose names
    /// differ only by what `enclosed_name` strips.
    #[test]
    fn refuses_two_entries_that_unpack_to_the_same_path() {
        for (first, second) in [
            ("abs.txt", "/abs.txt"),
            ("win.txt", "C:\\win.txt"),
            ("ok.txt", "./ok.txt"),
        ] {
            let bytes = zip_of(&[(first, b"first"), (second, b"second")]);
            let mut sink = Collector::default();
            let err = unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap_err();
            assert!(
                err.contains(first) && err.contains("/scan/"),
                "{first} / {second}: {err}"
            );
        }
    }

    #[test]
    fn refuses_a_file_and_a_directory_on_the_same_path() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.start_file("lib", opts).unwrap();
        w.write_all(b"file").unwrap();
        w.add_directory("/lib/", opts).unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut sink = Collector::default();
        assert!(unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).is_err());
    }

    #[test]
    fn refuses_a_file_over_a_directory_another_entry_implies() {
        for names in [["lib/a.txt", "/lib"], ["lib", "lib/a.txt"]] {
            let bytes = zip_of(&[(names[0], b"one"), (names[1], b"two")]);
            let mut sink = Collector::default();
            let err = unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap_err();
            assert!(err.contains("/scan/lib"), "{names:?}: {err}");
        }
    }

    #[test]
    fn refuses_a_file_at_the_base_itself() {
        // Each of these names cleans up to nothing, so the file would sit at
        // /scan while x.txt sits inside it. Either order.
        for name in [".", "a/..", "C:"] {
            for files in [
                [(name, &b"one"[..]), ("x.txt", b"two")],
                [("x.txt", b"two"), (name, b"one")],
            ] {
                let bytes = zip_of(&files);
                let mut sink = Collector::default();
                let err = unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap_err();
                assert!(err.contains("scan root"), "{name:?}: {err}");
            }
        }
    }

    #[test]
    fn allows_a_directory_entry_for_the_base() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.add_directory("./", opts).unwrap();
        w.start_file("x.txt", opts).unwrap();
        w.write_all(b"x").unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut sink = Collector::default();
        unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap();
        assert_eq!(sink.entries.len(), 1, "{:?}", sink.entries);
    }

    #[test]
    fn allows_a_directory_entry_after_the_files_inside_it() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.start_file("App.app/Contents/run", opts).unwrap();
        w.write_all(b"run").unwrap();
        w.start_file("App.app/Contents/info", opts).unwrap();
        w.write_all(b"info").unwrap();
        w.add_directory("App.app/Contents/", opts).unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut sink = Collector::default();
        unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap();
        assert_eq!(sink.entries.len(), 3);
    }

    /// An entry that declares far more than it holds must not keep the memory
    /// its declared size reserved: the sink stores the buffer as it is.
    #[test]
    fn keeps_no_capacity_an_entry_only_declared() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(
            "empty",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        let mut bytes = w.finish().unwrap().into_inner();
        // Claim 32 MiB in the local header (offset 22) and the central
        // directory record (offset 24); the entry still holds nothing.
        let claim = (32u32 << 20).to_le_bytes();
        let at = |sig: &[u8]| bytes.windows(4).position(|w| w == sig).unwrap();
        let (local, central) = (at(b"PK\x03\x04"), at(b"PK\x01\x02"));
        bytes[local + 22..local + 26].copy_from_slice(&claim);
        bytes[central + 24..central + 28].copy_from_slice(&claim);

        let mut sink = Collector::default();
        unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap();
        match &sink.entries[..] {
            [Entry::File { data, .. }] => {
                assert!(data.is_empty());
                assert!(data.capacity() < 1 << 20, "kept {} bytes", data.capacity());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn allows_a_directory_listed_twice() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.add_directory("App.app/", opts).unwrap();
        w.add_directory("/App.app/", opts).unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut sink = Collector::default();
        unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap();
    }

    #[test]
    fn refuses_an_overlong_symlink_target() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let long = "a/".repeat(MAX_LINK_TARGET as usize);
        w.add_symlink("link", long, SimpleFileOptions::default())
            .unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let mut sink = Collector::default();
        let err = unzip_into(&bytes, Path::new("/scan"), &mut sink, u64::MAX).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }
}
