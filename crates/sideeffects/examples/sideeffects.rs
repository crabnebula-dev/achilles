//! `cargo run -p sideeffects --example sideeffects -- <path>`
//!
//! Pass a `.app` bundle on macOS, or an executable on Windows / Linux. We run
//! `detect` first to resolve the bundle id + real executable, then analyse.

use std::path::PathBuf;

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: sideeffects <path-to-app-or-exe>");

    let detection = detect::detect(&path).expect("detect failed");
    let report = sideeffects::analyse(
        &detection.path,
        detection.bundle_id.as_deref(),
        detection.executable.as_deref(),
    )
    .expect("analyse failed");

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize")
    );
}
