//! Discover installed GUI applications and stream [`detect::Detection`]
//! results.
//!
//! Discovery is platform-specific (see the per-OS modules) but converges on a
//! list of [`DiscoveredApp`]s — each carrying the install root, primary
//! executable, and display name — which are then detected on a blocking thread
//! pool with progress pushed over a tokio channel.
//!
//! * **macOS**: Spotlight (`mdfind`) enumerates `.app` bundles, falling back to
//!   walking the standard install roots.
//! * **Linux**: XDG `.desktop` entries (the freedesktop menu) resolved to their
//!   executables — naturally GUI-only.
//! * **Windows**: Start Menu `.lnk` shortcuts plus per-user `Programs` installs
//!   — also a natural GUI filter.
//!
//! # Example
//!
//! ```no_run
//! # async fn ex() {
//! use tokio::sync::mpsc;
//! let (tx, mut rx) = mpsc::channel(64);
//! let apps = scan::discover_applications().await.unwrap();
//! tokio::spawn(scan::scan(apps, 8, tx));
//! while let Some(event) = rx.recv().await {
//!     println!("{event:?}");
//! }
//! # }
//! ```

use std::path::PathBuf;

use tokio::sync::mpsc;

pub use detect::{Confidence, DetectError, Detection, DiscoveredApp, Framework, Versions};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Event emitted during a scan.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Scan is about to start; `total` is the number of apps discovered.
    Started { total: usize },
    /// An app was detected. May appear with [`Framework::Unknown`] when the
    /// path had no identifiable framework; consumers may choose to hide those.
    /// Boxed because a `Detection` is far larger than the other variants.
    Detected(Box<Detection>),
    /// Detection failed for a single app. The scan continues.
    Error { path: PathBuf, message: String },
    /// Scan finished. `count` matches the initial `total`.
    Finished { count: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// Discovery failed in a platform-specific way (spawning a helper,
    /// reading a system directory, …).
    #[error("application discovery failed: {0}")]
    Discovery(String),
    #[cfg(target_os = "macos")]
    #[error("spawning mdfind failed: {0}")]
    Spawn(#[source] std::io::Error),
    #[cfg(target_os = "macos")]
    #[error("mdfind exited non-zero: {0}")]
    Mdfind(String),
    #[cfg(target_os = "macos")]
    #[error("mdfind output was not utf-8")]
    NotUtf8,
}

/// Enumerate installed GUI applications in standard, user-facing locations.
pub async fn discover_applications() -> Result<Vec<DiscoveredApp>, ScanError> {
    #[cfg(target_os = "macos")]
    {
        macos::discover().await
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover()
    }
    #[cfg(target_os = "windows")]
    {
        windows::discover()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Run detection over `apps` with bounded concurrency, forwarding progress
/// through `tx`. This function never returns errors — per-app failures are
/// surfaced as [`ScanEvent::Error`] so the UI can keep a stable list.
pub async fn scan(apps: Vec<DiscoveredApp>, concurrency: usize, tx: mpsc::Sender<ScanEvent>) {
    use futures::stream::StreamExt;

    let total = apps.len();
    let _ = tx.send(ScanEvent::Started { total }).await;

    let concurrency = concurrency.max(1);

    futures::stream::iter(apps)
        .for_each_concurrent(concurrency, |app| {
            let tx = tx.clone();
            async move {
                let path = app.path.clone();
                let result = tokio::task::spawn_blocking(move || detect::detect_app(&app)).await;
                let event = match result {
                    Ok(Ok(detection)) => ScanEvent::Detected(Box::new(detection)),
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
