//! Fixtures for the browser's "what did the user just hand me?" step.
//!
//! In the browser these run against an in-memory tree, but the module goes
//! through [`vfs`], so on native the same code walks a real temp directory —
//! which is what these tests build. No wasm toolchain needed.

use std::fs;
use std::path::{Path, PathBuf};

use achilles_wasm::upload::{find_app, find_app_in_payload, locate_scan_target, sniff_platform};
use vfs::Platform;

fn tempdir(name: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let base = std::env::temp_dir().join(format!(
        "achilles-upload-{}-{}-{}",
        name,
        std::process::id(),
        nonce
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A byte blob that starts with ELF magic and is `size` bytes long, so the
/// "largest binary wins" tie-break has something to compare.
fn elf(size: usize) -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.resize(size.max(4), 0);
    bytes
}

fn pe(size: usize) -> Vec<u8> {
    let mut bytes = b"MZ".to_vec();
    bytes.resize(size.max(2), 0);
    bytes
}

// ---- platform sniffing ------------------------------------------------

#[test]
fn sniffs_macos_from_a_dot_app_child() {
    let base = tempdir("sniff-macos");
    write(&base.join("Signal.app/Contents/Info.plist"), b"<plist/>");
    write(&base.join("Signal.app/Contents/MacOS/Signal"), &elf(64));

    assert_eq!(sniff_platform(&base), Platform::Macos);
    fs::remove_dir_all(&base).ok();
}

/// A zip made from *inside* the bundle puts `Contents/` at the archive root,
/// with no `.app` directory name left to recognise.
#[test]
fn sniffs_macos_from_a_bare_contents_dir() {
    let base = tempdir("sniff-contents");
    write(&base.join("Contents/Info.plist"), b"<plist/>");

    assert_eq!(sniff_platform(&base), Platform::Macos);
    fs::remove_dir_all(&base).ok();
}

#[test]
fn sniffs_windows_from_an_exe() {
    let base = tempdir("sniff-windows");
    write(&base.join("Slack/slack.exe"), &pe(4096));
    write(&base.join("Slack/ffmpeg.dll"), &pe(64));

    assert_eq!(sniff_platform(&base), Platform::Windows);
    fs::remove_dir_all(&base).ok();
}

/// Linux is the fallback: an ELF binary plus sibling `.so`s has no marker of
/// its own, only the absence of the other two.
#[test]
fn sniffs_linux_from_an_elf_tree() {
    let base = tempdir("sniff-linux");
    write(&base.join("slack/slack"), &elf(4096));
    write(&base.join("slack/libffmpeg.so"), &elf(64));

    assert_eq!(sniff_platform(&base), Platform::Linux);
    fs::remove_dir_all(&base).ok();
}

// ---- locating the app + its executable --------------------------------

#[test]
fn finds_the_macos_bundle_root() {
    let base = tempdir("find-macos");
    write(&base.join("Signal.app/Contents/Info.plist"), b"<plist/>");

    let app = find_app(&base, Platform::Macos).expect("bundle should be found");
    assert_eq!(app.path, base.join("Signal.app"));
    assert_eq!(app.root, base.join("Signal.app"));
    // macOS resolves the executable from Info.plist's CFBundleExecutable.
    assert_eq!(app.executable, None);
    fs::remove_dir_all(&base).ok();
}

/// The picked folder *is* the bundle — the common case for both the folder
/// picker and a drag-dropped `.app`.
#[test]
fn treats_a_picked_bundle_as_the_app() {
    let base = tempdir("picked-bundle");
    let bundle = base.join("Signal.app");
    write(&bundle.join("Contents/Info.plist"), b"<plist/>");

    let app = find_app(&bundle, Platform::Macos).expect("the picked bundle is the app");
    assert_eq!(app.root, bundle);
    fs::remove_dir_all(&base).ok();
}

/// The UI only unwraps `.app` children one level down, so a picked folder may
/// still wrap the bundle deeper. Analysing the picked folder itself would read
/// a non-existent `Contents/Info.plist` and report an app with nothing in it.
#[test]
fn finds_a_bundle_nested_below_the_picked_root() {
    let base = tempdir("find-nested");
    write(
        &base.join("Apps/Signal.app/Contents/Info.plist"),
        b"<plist/>",
    );

    let app = find_app(&base, Platform::Macos).expect("nested bundle should be found");
    assert_eq!(app.root, base.join("Apps/Signal.app"));
    fs::remove_dir_all(&base).ok();
}

/// A folder holding no bundle must report nothing rather than describing the
/// folder itself as an app.
#[test]
fn reports_no_bundle_when_the_folder_holds_none() {
    let base = tempdir("find-no-bundle");
    write(&base.join("notes.txt"), b"hello");

    assert!(find_app(&base, Platform::Macos).is_none());
    fs::remove_dir_all(&base).ok();
}

/// The zip wraps the app in a folder, and the folder holds several `.exe`s.
/// The one named after its directory is the app; the rest are helpers.
#[test]
fn finds_the_windows_executable_by_name() {
    let base = tempdir("find-windows");
    let root = base.join("Slack");
    write(&root.join("slack.exe"), &pe(1024));
    // Bigger, but an updater — must not win.
    write(&root.join("Update.exe"), &pe(8192));
    write(&root.join("squirrel.exe"), &pe(8192));
    write(&root.join("resources/app.asar"), b"asar");

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(app.root, root);
    assert_eq!(
        app.executable.as_deref(),
        Some(root.join("slack.exe").as_path())
    );
    // Windows keys an app on its executable, as desktop discovery does.
    assert_eq!(app.path, root.join("slack.exe"));
    assert_eq!(app.name.as_deref(), Some("Slack"));
    fs::remove_dir_all(&base).ok();
}

/// Nothing is named after the directory, so the largest non-helper binary wins
/// — the main binary dwarfs the helpers it ships beside.
#[test]
fn falls_back_to_the_largest_executable() {
    let base = tempdir("find-largest");
    write(&base.join("bin/helper.exe"), &pe(128));
    write(&base.join("bin/main-app.exe"), &pe(65536));

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("bin/main-app.exe").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

#[test]
fn finds_the_linux_executable_and_skips_shared_objects() {
    let base = tempdir("find-linux");
    let root = base.join("obsidian");
    // Larger than the binary, but a shared object is never the entry point.
    write(&root.join("libffmpeg.so"), &elf(65536));
    write(&root.join("libEGL.so.1"), &elf(65536));
    write(&root.join("obsidian"), &elf(4096));
    write(&root.join("chrome-sandbox"), &elf(32768));
    write(&root.join("resources.pak"), &[0u8; 65536]);

    let app = find_app(&base, Platform::Linux).expect("app should be found");
    assert_eq!(app.root, root);
    assert_eq!(
        app.executable.as_deref(),
        Some(root.join("obsidian").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

/// A non-ELF file must never be mistaken for the executable, however large.
#[test]
fn linux_ignores_non_elf_files() {
    let base = tempdir("find-linux-nonelf");
    write(&base.join("app/resources.pak"), &[0u8; 65536]);
    write(&base.join("app/README"), b"hello");

    assert!(find_app(&base, Platform::Linux).is_none());
    fs::remove_dir_all(&base).ok();
}

/// Squirrel installs leave only `Update.exe` at the root and put the real app
/// in a versioned subdirectory, so the search has to descend past a directory
/// whose own executables were all filtered out as helpers.
#[test]
fn descends_past_a_squirrel_stub_root() {
    let base = tempdir("find-squirrel");
    write(&base.join("Update.exe"), &pe(8192));
    write(&base.join("packages/full.nupkg"), b"nupkg");
    write(&base.join("app-1.2.3/gitkraken.exe"), &pe(4096));

    let app = find_app(&base, Platform::Windows).expect("app should be found");
    assert_eq!(app.root, base.join("app-1.2.3"));
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("app-1.2.3/gitkraken.exe").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

// ---- static-scan target ------------------------------------------------

#[test]
fn locates_the_asar_per_platform() {
    let base = tempdir("asar");

    let mac = base.join("Foo.app");
    write(&mac.join("Contents/Resources/app.asar"), b"asar");
    assert_eq!(
        locate_scan_target(&mac, Platform::Macos),
        Some(mac.join("Contents/Resources/app.asar"))
    );
    // The bundle layout's path must not be found under the portable one.
    assert_eq!(locate_scan_target(&mac, Platform::Windows), None);

    let win = base.join("Foo");
    write(&win.join("resources/app.asar"), b"asar");
    assert_eq!(
        locate_scan_target(&win, Platform::Windows),
        Some(win.join("resources/app.asar"))
    );
    assert_eq!(
        locate_scan_target(&win, Platform::Linux),
        Some(win.join("resources/app.asar"))
    );

    fs::remove_dir_all(&base).ok();
}

/// Apps that ship `resources/app/` unpacked (VS Code) have no archive to read,
/// so the scan targets the directory instead.
#[test]
fn locates_an_unpacked_app_directory() {
    let base = tempdir("unpacked");
    let root = base.join("VSCode");
    write(&root.join("resources/app/package.json"), b"{}");

    assert_eq!(
        locate_scan_target(&root, Platform::Linux),
        Some(root.join("resources/app"))
    );
    fs::remove_dir_all(&base).ok();
}

// ---- locating the app inside an unpacked package -----------------------

/// A distro package reproduces a slice of the filesystem, so the *shallowest*
/// executable is the `usr/bin` launcher and the application is somewhere below
/// it. Size is what tells them apart.
#[test]
fn payload_search_prefers_the_application_over_the_usr_bin_launcher() {
    let base = tempdir("payload-optdir");
    write(&base.join("usr/bin/foo"), &elf(2048));
    write(&base.join("opt/Foo/foo"), &elf(200_000));
    write(&base.join("opt/Foo/libffmpeg.so"), &elf(400_000));
    write(
        &base.join("usr/share/applications/foo.desktop"),
        b"[Desktop Entry]",
    );

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.root, base.join("opt/Foo"));
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("opt/Foo/foo").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

/// Distro packages alias one binary under several names — `usr/bin/foo`, the
/// `.build-id` entries. Following those would root the app in whichever
/// directory happened to hold an alias.
#[cfg(unix)]
#[test]
fn payload_search_ignores_symlinked_aliases_of_the_binary() {
    let base = tempdir("payload-symlink");
    write(&base.join("usr/lib/foo/foo"), &elf(200_000));
    fs::create_dir_all(base.join("usr/lib/.build-id/ab")).unwrap();
    std::os::unix::fs::symlink(
        base.join("usr/lib/foo/foo"),
        base.join("usr/lib/.build-id/ab/cdef"),
    )
    .unwrap();
    fs::create_dir_all(base.join("usr/bin")).unwrap();
    std::os::unix::fs::symlink(base.join("usr/lib/foo/foo"), base.join("usr/bin/foo")).unwrap();

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.root, base.join("usr/lib/foo"));
    fs::remove_dir_all(&base).ok();
}

/// An AppImage's squashfs root holds the app directly, next to `AppRun` and the
/// desktop entry — the payload search has to handle that shape too.
#[test]
fn payload_search_handles_an_appimage_root() {
    let base = tempdir("payload-appimage");
    write(&base.join("AppRun"), b"#!/bin/sh\nexec ./myapp\n");
    write(&base.join("myapp"), &elf(300_000));
    write(&base.join("myapp.desktop"), b"[Desktop Entry]");
    write(&base.join("resources/app.asar"), b"asar");
    write(&base.join("chrome-sandbox"), &elf(500_000));

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.root, base);
    assert_eq!(
        app.executable.as_deref(),
        Some(base.join("myapp").as_path())
    );
    fs::remove_dir_all(&base).ok();
}

#[test]
fn a_payload_with_no_executable_reports_nothing() {
    let base = tempdir("payload-empty");
    write(&base.join("usr/share/doc/foo/README"), b"docs only");

    assert!(find_app_in_payload(&base).is_none());
    fs::remove_dir_all(&base).ok();
}

/// End to end: unpack a package to a real directory with `pkg`, then run the
/// same app-finding the browser runs against its in-memory tree.
#[test]
fn unpacking_a_package_leaves_a_tree_the_app_search_can_read() {
    let base = tempdir("payload-unpack");
    let payload = base.join("payload");

    // A tar holding the layout a `.deb` installs.
    let mut archive = Vec::new();
    let mut member = |name: &str, typeflag: u8, body: &[u8]| {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000755\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        archive.extend_from_slice(&header);
        archive.extend_from_slice(body);
        archive.extend(std::iter::repeat(0).take((512 - body.len() % 512) % 512));
    };
    member("./usr/bin/foo", b'0', &elf(1024));
    member("./opt/Foo/foo", b'0', &elf(120_000));
    member("./opt/Foo/resources/app.asar", b'0', b"asar-bytes");
    archive.extend(std::iter::repeat(0).take(1024));

    assert_eq!(
        pkg::sniff(&archive, "foo.tar"),
        Some(pkg::Format::Tarball),
        "an uncompressed tar should be recognised"
    );
    let mut sink = pkg::DirSink::new(&payload).unwrap();
    let summary = pkg::unpack(&archive, pkg::Format::Tarball, &payload, &mut sink).unwrap();
    sink.finish().unwrap();
    assert_eq!(summary.files, 3);

    let app = find_app_in_payload(&payload).expect("app should be found");
    assert_eq!(app.root, payload.join("opt/Foo"));
    assert_eq!(
        locate_scan_target(&app.root, Platform::Linux).as_deref(),
        Some(payload.join("opt/Foo/resources/app.asar").as_path()),
        "the static scan should find the asar beside the binary"
    );
    fs::remove_dir_all(&base).ok();
}

/// The app is named by the package's own `.desktop` entry. Naming it after the
/// containing directory instead calls every packaged app "bin", since that is
/// where a packaged binary lives.
#[test]
fn payload_app_is_named_by_its_desktop_entry_not_its_directory() {
    let base = tempdir("payload-name");
    write(&base.join("usr/bin/achilles"), &elf(200_000));
    write(
        &base.join("usr/share/applications/Achilles.desktop"),
        b"[Desktop Entry]\nType=Application\nName=Achilles\nExec=achilles\n\n\
          [Desktop Action new]\nName=New Window\n",
    );

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.root, base.join("usr/bin"));
    assert_eq!(app.name.as_deref(), Some("Achilles"));
    fs::remove_dir_all(&base).ok();
}

/// An AppImage keeps its entry at the payload root.
#[test]
fn an_appimage_desktop_entry_at_the_root_names_the_app() {
    let base = tempdir("payload-name-appimage");
    write(&base.join("AppRun"), b"#!/bin/sh\nexec ./usr/bin/app\n");
    write(&base.join("usr/bin/app"), &elf(200_000));
    write(
        &base.join("MyApp.desktop"),
        b"[Desktop Entry]\nName=My App\nExec=AppRun\n",
    );

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.name.as_deref(), Some("My App"));
    fs::remove_dir_all(&base).ok();
}

/// With no entry to read, the binary's own name beats the directory's.
#[test]
fn a_payload_without_a_desktop_entry_falls_back_to_the_binary_name() {
    let base = tempdir("payload-name-none");
    write(&base.join("usr/bin/hello"), &elf(200_000));

    let app = find_app_in_payload(&base).expect("app should be found");
    assert_eq!(app.name.as_deref(), Some("hello"));
    fs::remove_dir_all(&base).ok();
}
