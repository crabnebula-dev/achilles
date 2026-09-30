//! Round-trip the readers against archives built by the real packaging tools.
//!
//! The unit tests hand-build minimal containers, which proves the field
//! offsets but not that a reader survives what `mksquashfs` and friends
//! actually emit — fragments, multi-block files, blocks the compressor gave up
//! on and stored raw. These tests pack a known tree with the system tools and
//! assert it comes back byte-identical.
//!
//! Each test skips (rather than fails) when its tool isn't installed, so the
//! suite still runs on a machine without squashfs-tools.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pkg::{Entry, Format};

/// A file large enough to span several squashfs blocks (the default is 128 KiB)
/// and incompressible enough that some blocks get stored uncompressed.
fn noisy_blob(len: usize) -> Vec<u8> {
    // A xorshift PRNG: deterministic, and no dependency for one test fixture.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// The tree every test packs: a big file, a tiny one (which squashfs packs into
/// a fragment), a nested directory, and a symlink.
fn source_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("bin/app".to_string(), noisy_blob(400 * 1024));
    files.insert(
        "bin/tiny.txt".to_string(),
        b"small enough to be a fragment\n".to_vec(),
    );
    files.insert(
        "share/nested/deep/resources.json".to_string(),
        br#"{"name":"fixture"}"#.to_vec(),
    );

    for (rel, body) in &files {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink("app", root.join("bin/launch")).unwrap();
    files
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pkg-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn tool_missing(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .output()
        .or_else(|_| Command::new(tool).arg("--version").output())
        .is_err()
}

/// Collect an unpacked payload into `relative path -> contents`, alongside the
/// symlinks found.
fn collect(bytes: &[u8], format: Format) -> (BTreeMap<String, Vec<u8>>, BTreeMap<String, String>) {
    let base = Path::new("/scan");
    let mut sink = pkg::Collector::default();
    let summary = pkg::unpack(bytes, format, base, &mut sink).expect("unpack");
    assert_eq!(summary.warnings, Vec::<String>::new(), "unpack warnings");

    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    for entry in sink.entries {
        let rel = entry
            .path()
            .strip_prefix(base)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();
        match entry {
            Entry::File { data, .. } => {
                files.insert(rel, data);
            }
            Entry::Symlink { target, .. } => {
                links.insert(rel, target.to_string_lossy().into_owned());
            }
            Entry::Dir(_) => {}
        }
    }
    (files, links)
}

#[test]
fn squashfs_images_from_mksquashfs_round_trip_in_every_compression() {
    if tool_missing("mksquashfs") {
        eprintln!("skipping: mksquashfs not installed");
        return;
    }
    let dir = temp_dir("squashfs");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let expected = source_tree(&src);

    for compression in ["gzip", "xz", "zstd", "lz4"] {
        let image = dir.join(format!("{compression}.squashfs"));
        let mut cmd = Command::new("mksquashfs");
        cmd.arg(&src)
            .arg(&image)
            .args(["-comp", compression, "-noappend", "-no-progress"]);
        // lz4 needs an explicit flag to be accepted as a filesystem compressor.
        if compression == "lz4" {
            cmd.arg("-Xhc");
        }
        let output = cmd.output().expect("run mksquashfs");
        if !output.status.success() {
            // Not every build of squashfs-tools has every compressor.
            eprintln!("skipping {compression}: mksquashfs refused it");
            continue;
        }

        let bytes = fs::read(&image).unwrap();
        let (files, links) = collect(&bytes, Format::Snap);
        assert_eq!(files, expected, "{compression}: file contents differ");
        #[cfg(unix)]
        assert_eq!(links.get("bin/launch").map(String::as_str), Some("app"));
        let _ = links;
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_deb_built_by_ar_and_tar_round_trips() {
    if tool_missing("ar") || tool_missing("tar") {
        eprintln!("skipping: ar/tar not installed");
        return;
    }
    let dir = temp_dir("deb");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let expected = source_tree(&src);

    for (flag, ext) in [("-z", "gz"), ("-J", "xz"), ("--zstd", "zst")] {
        let data = dir.join(format!("data.tar.{ext}"));
        let packed = Command::new("tar")
            .arg("-c")
            .arg(flag)
            .arg("-f")
            .arg(&data)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .output()
            .expect("run tar");
        if !packed.status.success() {
            eprintln!("skipping {ext}: tar refused it");
            continue;
        }
        fs::write(dir.join("debian-binary"), b"2.0\n").unwrap();

        let deb = dir.join(format!("fixture-{ext}.deb"));
        let built = Command::new("ar")
            .arg("rc")
            .arg(&deb)
            .arg(dir.join("debian-binary"))
            .arg(&data)
            .current_dir(&dir)
            .output()
            .expect("run ar");
        assert!(built.status.success(), "ar failed");

        let bytes = fs::read(&deb).unwrap();
        assert_eq!(pkg::sniff(&bytes, "fixture.deb"), Some(Format::Deb));
        let (files, links) = collect(&bytes, Format::Deb);
        assert_eq!(files, expected, "{ext}: file contents differ");
        #[cfg(unix)]
        assert_eq!(links.get("bin/launch").map(String::as_str), Some("app"));
        let _ = links;
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_compressed_tarball_round_trips() {
    if tool_missing("tar") {
        eprintln!("skipping: tar not installed");
        return;
    }
    let dir = temp_dir("tarball");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let expected = source_tree(&src);

    for (flag, ext) in [("-z", "tar.gz"), ("-J", "tar.xz"), ("--zstd", "tar.zst")] {
        let tarball = dir.join(format!("app.{ext}"));
        let packed = Command::new("tar")
            .arg("-c")
            .arg(flag)
            .arg("-f")
            .arg(&tarball)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .output()
            .expect("run tar");
        if !packed.status.success() {
            eprintln!("skipping {ext}: tar refused it");
            continue;
        }

        let bytes = fs::read(&tarball).unwrap();
        assert_eq!(
            pkg::sniff(&bytes, &format!("app.{ext}")),
            Some(Format::Tarball),
            "{ext}: not sniffed as a tarball"
        );
        let (files, _) = collect(&bytes, Format::Tarball);
        assert_eq!(files, expected, "{ext}: file contents differ");
    }

    let _ = fs::remove_dir_all(&dir);
}

/// The AppImage path on top of a real squashfs image: a runtime stub with the
/// filesystem appended, which is exactly how `appimagetool` builds one.
#[test]
fn an_appimage_shaped_file_finds_its_appended_filesystem() {
    if tool_missing("mksquashfs") {
        eprintln!("skipping: mksquashfs not installed");
        return;
    }
    let dir = temp_dir("appimage");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let expected = source_tree(&src);

    let image = dir.join("payload.squashfs");
    let built = Command::new("mksquashfs")
        .arg(&src)
        .arg(&image)
        .args(["-noappend", "-no-progress"])
        .output()
        .expect("run mksquashfs");
    assert!(built.status.success(), "mksquashfs failed");

    // A minimal ELF runtime: enough header for the offset calculation, with
    // the AppImage type-2 marker in `e_ident`'s padding.
    let mut appimage = vec![0u8; 8192];
    appimage[..4].copy_from_slice(b"\x7fELF");
    appimage[4] = 2; // 64-bit
    appimage[5] = 1; // little-endian
    appimage[8..11].copy_from_slice(&[0x41, 0x49, 0x02]);
    appimage[0x28..0x30].copy_from_slice(&(8192u64 - 128).to_le_bytes()); // e_shoff
    appimage[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    appimage[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
    appimage.extend_from_slice(&fs::read(&image).unwrap());

    assert_eq!(
        pkg::sniff(&appimage, "Fixture-1.0-x86_64.AppImage"),
        Some(Format::AppImage)
    );
    let (files, links) = collect(&appimage, Format::AppImage);
    assert_eq!(files, expected);
    #[cfg(unix)]
    assert_eq!(links.get("bin/launch").map(String::as_str), Some("app"));
    let _ = links;

    let _ = fs::remove_dir_all(&dir);
}
