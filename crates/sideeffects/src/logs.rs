//! Detect `~/Library/Logs/<app>/` directories.
//!
//! Many apps self-log, and those logs often reveal behavior the app's
//! public UI doesn't surface (install events, background network calls,
//! auto-updater activity). We just point users at the directory — the UI
//! offers a click-to-open; no attempt to parse or interpret logs
//! automatically.

use std::fs;
use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LogDirectory {
    pub path: PathBuf,
    pub file_count: usize,
    pub total_bytes: u64,
    pub last_modified: Option<u64>,
}

/// Probe `~/Library/Logs/` for subdirectories named after the bundle id
/// or a best-effort slug derived from it.
pub fn find(bundle_id: Option<&str>) -> Option<LogDirectory> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let logs_root = home.join("Library/Logs");

    // Try a short series of candidate names for the logs directory.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(id) = bundle_id {
        candidates.push(id.to_owned());
        // Apps often use the last reverse-DNS component as the folder name
        // (`com.example.Foo` → `Foo`).
        if let Some(tail) = id.rsplit('.').next() {
            if !tail.is_empty() {
                candidates.push(tail.to_owned());
            }
        }
    }

    for name in candidates {
        let dir = logs_root.join(&name);
        if dir.is_dir() {
            return Some(summarise(&dir));
        }
    }
    None
}

fn summarise(dir: &std::path::Path) -> LogDirectory {
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    let mut last_modified: Option<u64> = None;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            file_count += 1;
            total_bytes = total_bytes.saturating_add(meta.len());
            if let Ok(mt) = meta.modified() {
                if let Ok(d) = mt.duration_since(std::time::UNIX_EPOCH) {
                    let secs = d.as_secs();
                    last_modified = Some(last_modified.map_or(secs, |prev| prev.max(secs)));
                }
            }
        }
    }

    LogDirectory {
        path: dir.to_path_buf(),
        file_count,
        total_bytes,
        last_modified,
    }
}
