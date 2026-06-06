//! `cargo run -p app-audit --example audit -- <path>`
//!
//! Pass a `.app` bundle on macOS, or an executable on Windows / Linux.

use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: audit <path-to-app-or-exe>");

    // Mirror `detect::DiscoveredApp::from_path`'s per-OS interpretation.
    let (root, executable): (PathBuf, Option<PathBuf>) = if cfg!(target_os = "macos") {
        (path.clone(), None)
    } else {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.clone());
        (root, Some(path.clone()))
    };

    let audit = app_audit::audit(&path, &root, executable.as_deref())
        .await
        .expect("audit failed");
    let json = serde_json::to_string_pretty(&audit).expect("serialize");
    println!("{json}");
}
