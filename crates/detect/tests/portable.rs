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
