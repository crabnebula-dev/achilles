//! Discover installed `.app` bundles and stream [`detect::Detection`] results.
//!
//! On macOS we rely on Spotlight's [`mdfind`] to enumerate application
//! bundles — it's dramatically faster than walking the filesystem and picks
//! up apps outside `/Applications` (e.g. `~/Applications`, managed app
//! locations). Results are filtered to "top-level" bundles in standard install
//! roots, then each bundle is detected on a blocking thread pool, with
//! progress events pushed over a tokio channel.
//!
//! # Example
//!
//! ```no_run
//! # async fn ex() {
//! use tokio::sync::mpsc;
//! let (tx, mut rx) = mpsc::channel(64);
//! let paths = scan::discover_applications().await.unwrap();
//! tokio::spawn(scan::scan(paths, 8, tx));
//! while let Some(event) = rx.recv().await {
//!     println!("{event:?}");
//! }
//! # }
//! ```
//!
//! [`mdfind`]: https://ss64.com/mac/mdfind.html

use std::path::{Path, PathBuf};

use futures::stream::StreamExt;
use tokio::sync::mpsc;

pub use detect::{Confidence, DetectError, Detection, Framework, Versions};

/// Event emitted during a scan.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Scan is about to start; `total` is the number of bundles discovered.
    Started { total: usize },
    /// A bundle was detected. May appear with [`Framework::Unknown`] when the
    /// path had no identifiable framework; consumers may choose to hide those.
    Detected(Detection),
    /// Detection failed for a single bundle. The scan continues.
    Error { path: PathBuf, message: String },
    /// Scan finished. `count` matches the initial `total`.
    Finished { count: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("spawning mdfind failed: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("mdfind exited non-zero: {0}")]
    Mdfind(String),
    #[error("mdfind output was not utf-8")]
    NotUtf8,
}

/// Ask Spotlight for every application bundle on the system and narrow to
/// bundles installed in standard user-facing locations.
///
/// On systems where `mdfind` is unavailable or returns nothing this falls
/// back to walking the well-known install roots.
pub async fn discover_applications() -> Result<Vec<PathBuf>, ScanError> {
    let from_spotlight = spotlight_apps().await.unwrap_or_default();
    let mut paths = if from_spotlight.is_empty() {
        filesystem_walk_apps()
    } else {
        from_spotlight
    };
    paths.retain(|p| is_top_level_app(p) && in_standard_location(p));
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Run detection over `paths` with bounded concurrency, forwarding progress
/// through `tx`. This function never returns errors — per-bundle failures are
/// surfaced as [`ScanEvent::Error`] so the UI can keep a stable list.
pub async fn scan(paths: Vec<PathBuf>, concurrency: usize, tx: mpsc::Sender<ScanEvent>) {
    let total = paths.len();
    let _ = tx.send(ScanEvent::Started { total }).await;

    let concurrency = concurrency.max(1);

    futures::stream::iter(paths)
        .for_each_concurrent(concurrency, |path| {
            let tx = tx.clone();
            async move {
                let probe = path.clone();
                let result = tokio::task::spawn_blocking(move || detect::detect(&probe)).await;
                let event = match result {
                    Ok(Ok(detection)) => ScanEvent::Detected(detection),
                    Ok(Err(err)) => ScanEvent::Error {
                        path,
                        message: err.to_string(),
                    },
                    Err(join_err) => ScanEvent::Error {
                        path,
                        message: format!("detection task panicked: {join_err}"),
                    },
                };
                let _ = tx.send(event).await;
            }
        })
        .await;

    let _ = tx.send(ScanEvent::Finished { count: total }).await;
}

async fn spotlight_apps() -> Result<Vec<PathBuf>, ScanError> {
    let output = tokio::process::Command::new("mdfind")
        .arg("-0")
        .arg("kMDItemContentType == 'com.apple.application-bundle'")
        .output()
        .await
        .map_err(ScanError::Spawn)?;

    if !output.status.success() {
        return Err(ScanError::Mdfind(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let text = std::str::from_utf8(&output.stdout).map_err(|_| ScanError::NotUtf8)?;
    Ok(text
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn filesystem_walk_apps() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in standard_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "app").unwrap_or(false) {
                out.push(path);
            }
        }
    }
    out
}

fn standard_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    if let Some(home) = home_dir() {
        roots.push(home.join("Applications"));
    }
    roots
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Return true only if the path is a top-level `.app` — the *last* path
/// component ends in `.app` and no earlier component does. This rejects
/// helper apps embedded inside Xcode, 1Password, etc.
fn is_top_level_app(path: &Path) -> bool {
    let components: Vec<_> = path.components().collect();
    if components.is_empty() {
        return false;
    }

    let last_is_app = components
        .last()
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.ends_with(".app"))
        .unwrap_or(false);
    if !last_is_app {
        return false;
    }

    // No other component may end in `.app`.
    components[..components.len() - 1]
        .iter()
        .all(|c| !c.as_os_str().to_string_lossy().ends_with(".app"))
}

fn in_standard_location(path: &Path) -> bool {
    standard_roots().iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_accepts_simple_app() {
        assert!(is_top_level_app(Path::new("/Applications/Safari.app")));
    }

    #[test]
    fn top_level_rejects_nested_app() {
        assert!(!is_top_level_app(Path::new(
            "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app"
        )));
    }

    #[test]
    fn top_level_rejects_non_app() {
        assert!(!is_top_level_app(Path::new("/Applications/Safari")));
    }

    #[test]
    fn standard_location_accepts_applications() {
        assert!(in_standard_location(Path::new("/Applications/Safari.app")));
        assert!(in_standard_location(Path::new(
            "/System/Applications/Calculator.app"
        )));
    }

    #[test]
    fn standard_location_rejects_elsewhere() {
        assert!(!in_standard_location(Path::new("/opt/Foo.app")));
        assert!(!in_standard_location(Path::new("/tmp/Foo.app")));
    }
}
