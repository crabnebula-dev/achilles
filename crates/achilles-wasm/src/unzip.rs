//! Unpack an uploaded zip into a [`pkg::Sink`].
//!
//! Kept out of the `wasm32`-only bindings so the zip code path builds and is
//! tested natively against real archives.

use std::io::{Cursor, Read};
use std::path::Path;

/// Unpack a zip archive into `sink` under `base`, preserving unix modes and
/// symlinks (macOS frameworks rely on `Versions/Current -> A`).
pub fn unzip_into(bytes: &[u8], base: &Path, sink: &mut dyn pkg::Sink) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        // `enclosed_name` rejects path-traversal (`..`) entries.
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let dest = base.join(rel);
        if entry.is_dir() {
            sink.dir(&dest).map_err(|e| e.to_string())?;
            continue;
        }
        let mode = entry.unix_mode().unwrap_or(0o644);
        // S_IFLNK
        if mode & 0o170000 == 0o120000 {
            let mut target = String::new();
            entry
                .read_to_string(&mut target)
                .map_err(|e| e.to_string())?;
            sink.symlink(&dest, Path::new(&target))
                .map_err(|e| e.to_string())?;
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
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
        unzip_into(&bytes, &base, &mut sink).unwrap();

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
        unzip_into(&bytes, base, &mut sink).unwrap();

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
        assert!(unzip_into(b"not a zip at all", Path::new("/scan"), &mut sink).is_err());
    }
}
