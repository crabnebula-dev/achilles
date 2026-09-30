//! Cross-platform (Windows / Linux) detection fixtures.
//!
//! On these platforms an app is an executable plus sibling files, and the
//! framework/version signals live as literal strings in the binary — which we
//! can forge in a temp dir. macOS uses the `.app` bundle layout instead
//! (`more_runtimes.rs`).
#![cfg(not(target_os = "macos"))]

use std::fs;
use std::path::PathBuf;

use detect::{detect, Framework};

fn tempdir(name: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let base = std::env::temp_dir().join(format!(
        "detect-portable-{}-{}-{}",
        name,
        std::process::id(),
        nonce
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

/// An Electron app on Windows/Linux: a `resources/app.asar` next to a binary
/// whose user-agent strings carry the Electron / Chromium / Node versions.
#[test]
fn electron_fixture_detected_with_versions() {
    let app = tempdir("electron");
    fs::create_dir_all(app.join("resources")).unwrap();
    fs::write(app.join("resources/app.asar"), b"\x00asar-fixture").unwrap();

    // A fake "binary" carrying the UA fingerprints the string-scanner reads.
    let exe = app.join("app-bin");
    let blob = b"...Chrome/120.0.6099.109 ...Electron/28.1.0 ...node-v18.18.2/node.tar.gz...";
    fs::write(&exe, blob).unwrap();

    let result = detect(&exe).expect("detect should succeed");
    assert_eq!(result.framework, Framework::Electron);
    assert_eq!(result.versions.electron.as_deref(), Some("28.1.0"));
    assert_eq!(result.versions.chromium.as_deref(), Some("120.0.6099.109"));
    assert_eq!(result.versions.node.as_deref(), Some("18.18.2"));

    fs::remove_dir_all(&app).ok();
}

/// A Tauri app: the binary carries the `tauri.localhost` + `__TAURI_INTERNALS__`
/// IPC fingerprints and a cargo-registry version path.
#[test]
fn tauri_fixture_detected() {
    let app = tempdir("tauri");
    let exe = app.join("my-tauri-app");
    let blob = b"...tauri.localhost...__TAURI_INTERNALS__.../root/.cargo/registry/src/tauri-2.1.0/lib.rs...";
    fs::write(&exe, blob).unwrap();

    let result = detect(&exe).expect("detect should succeed");
    assert_eq!(result.framework, Framework::Tauri);
    assert_eq!(result.versions.tauri.as_deref(), Some("2.1.0"));

    fs::remove_dir_all(&app).ok();
}

/// An Electron app shipped as an AppImage: the same fixture, but sealed inside
/// a squashfs image behind an ELF runtime stub, which is all a user ever has on
/// disk. Nothing in the file itself carries the fingerprints — they only become
/// readable once the payload is expanded — so this is the test that the
/// expansion happens and that detection follows it to the real tree.
///
/// Skips when `mksquashfs` isn't installed; the readers themselves are covered
/// by the `pkg` crate's own tests.
#[cfg(target_os = "linux")]
#[test]
fn an_electron_appimage_is_expanded_and_detected() {
    use std::process::Command;

    let missing = Command::new("mksquashfs").arg("-version").output().is_err();
    if missing {
        eprintln!("skipping: mksquashfs not installed");
        return;
    }

    let base = tempdir("appimage");
    let payload = base.join("payload");
    fs::create_dir_all(payload.join("resources")).unwrap();
    fs::write(payload.join("resources/app.asar"), b"\x00asar-fixture").unwrap();
    // Unlike the bare-binary fixtures above, this one has to carry ELF magic:
    // the payload search picks the app out of a whole tree, so it checks that a
    // candidate really is a binary rather than a script or a data file.
    let mut binary = b"\x7fELF".to_vec();
    binary.extend_from_slice(
        b"...Chrome/120.0.6099.109 ...Electron/28.1.0 ...node-v18.18.2/node.tar.gz...",
    );
    fs::write(payload.join("electron-sample"), &binary).unwrap();
    fs::write(
        payload.join("AppRun"),
        b"#!/bin/sh\nexec ./electron-sample\n",
    )
    .unwrap();

    let image = base.join("payload.squashfs");
    let built = Command::new("mksquashfs")
        .arg(&payload)
        .arg(&image)
        .args(["-noappend", "-no-progress"])
        .output()
        .expect("run mksquashfs");
    assert!(built.status.success(), "mksquashfs failed");

    // The runtime stub: enough ELF header for the payload offset to be found.
    let mut appimage = vec![0u8; 4096];
    appimage[..4].copy_from_slice(b"\x7fELF");
    appimage[4] = 2; // 64-bit
    appimage[5] = 1; // little-endian
    appimage[8..11].copy_from_slice(&[0x41, 0x49, 0x02]); // AppImage type 2
    appimage[0x28..0x30].copy_from_slice(&(4096u64 - 128).to_le_bytes()); // e_shoff
    appimage[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    appimage[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
    appimage.extend_from_slice(&fs::read(&image).unwrap());

    let file = base.join("ElectronSample-1.0-x86_64.AppImage");
    fs::write(&file, &appimage).unwrap();

    // Keep the expansion inside the temp dir rather than the user's cache.
    let cache = base.join("cache");
    // What `detect_app` does for an AppImage it is handed, with the expansion
    // pointed at the temp dir instead of the user's cache.
    let expanded = pkg::extract_cached_in(&file, &cache).expect("expand the AppImage");
    let app = detect::DiscoveredApp {
        path: file.clone(),
        executable: detect::payload_executable(&expanded),
        root: expanded,
        name: None,
    };

    let result = detect::detect_app(&app).expect("detect should succeed");
    assert_eq!(result.framework, Framework::Electron);
    assert_eq!(result.versions.electron.as_deref(), Some("28.1.0"));
    assert_eq!(result.versions.chromium.as_deref(), Some("120.0.6099.109"));
    assert_eq!(result.versions.node.as_deref(), Some("18.18.2"));

    fs::remove_dir_all(&base).ok();
}
