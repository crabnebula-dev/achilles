//! Integration tests against real bundles on the local machine.
//!
//! These tests are opportunistic: each looks for a bundle path supplied
//! through an environment variable and silently passes (skips) if the
//! variable is unset or the path doesn't exist. Keeps the suite running
//! cleanly on CI and on any fresh clone.
//!
//! To run the bundled-Electron-app fixture, point the env var at any
//! installed Electron app (Signal, Discord, VS Code, …):
//!
//! ```sh
//! export ACHILLES_TESTAPP_BUNDLE=/Applications/Signal.app
//! ```

use std::path::{Path, PathBuf};

use detect::{detect, Framework};

/// Env var naming the path to a real `.app` bundle for opportunistic
/// integration testing.
const TESTAPP_BUNDLE_ENV: &str = "ACHILLES_TESTAPP_BUNDLE";

fn testapp_bundle() -> Option<PathBuf> {
    let raw = std::env::var_os(TESTAPP_BUNDLE_ENV)?;
    let path = PathBuf::from(raw);
    path.exists().then_some(path)
}

#[test]
fn testapp_is_detected_as_electron() {
    let Some(path) = testapp_bundle() else {
        eprintln!("skipping: ${TESTAPP_BUNDLE_ENV} unset or path missing");
        return;
    };

    let result = detect(&path).expect("detect should succeed on a real bundle");

    assert_eq!(result.framework, Framework::Electron);
    assert!(
        result.versions.electron.is_some(),
        "electron version should be extracted"
    );
    assert!(
        result.versions.chromium.is_some(),
        "chromium version should be extracted"
    );
    assert!(
        result.versions.node.is_some(),
        "node version should be extracted"
    );
    assert!(
        result.bundle_id.is_some(),
        "bundle id should be present"
    );
}

/// Detection should return `Unknown`, not error, on random directories.
#[test]
fn non_bundle_returns_unknown() {
    // `/tmp` is always a directory without a Contents/ child.
    let tmp = Path::new("/tmp");
    if !tmp.is_dir() {
        return;
    }
    let result = detect(tmp).expect("detect tolerates non-bundles");
    assert_eq!(result.framework, Framework::Unknown);
    assert_eq!(result.versions, Default::default());
}

/// Non-existent path must be a hard error — the scanner relies on this to
/// surface "stale cache" entries.
#[test]
fn missing_path_errors() {
    let err = detect(Path::new("/nonexistent/__achilles_test__.app"))
        .expect_err("missing path should error");
    matches!(err, detect::DetectError::NotFound(_));
}
