//! Persistent results journal.
//!
//! Each time the UI completes a full detail fetch we save the merged payload
//! (detection + audit + cves + static_scan + dep_advisories) to disk, keyed
//! by the app's bundle path. Files live under
//! `dirs::data_dir()/achilles/journal/<slug>/<iso-timestamp>.json`, which
//! on macOS is `~/Library/Application Support/achilles/journal/…`.
//!
//! Timestamps are ISO-8601 with `:` → `-` so the filenames are safe on
//! case-insensitive filesystems and sortable lexicographically.
//!
//! We only *save* and *list* — the UI can pull individual entries with a
//! plain file read. Pruning old entries is the user's concern for now.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A single saved research result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unix seconds at write time — authoritative regardless of filename.
    pub saved_at: u64,
    /// ISO-8601 rendering of `saved_at` for easy display.
    pub saved_at_iso: String,
    /// Absolute bundle path (e.g. `/Applications/Foo.app`).
    pub app_path: String,
    /// Optional display name for UI grouping.
    pub display_name: Option<String>,
    /// Optional bundle id for UI grouping.
    pub bundle_id: Option<String>,
    /// The research payload. Structure is intentionally opaque here — the
    /// frontend assembles it and round-trips it through the journal.
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub saved_at: u64,
    pub saved_at_iso: String,
    pub app_path: String,
    pub display_name: Option<String>,
    pub bundle_id: Option<String>,
    /// Path to the JSON file on disk — the UI can `invoke` a future
    /// `journal_load` for the full entry if needed.
    pub file: String,
}

/// Root directory for journal entries, creating it if necessary.
pub fn root() -> std::io::Result<PathBuf> {
    let base = dirs::data_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine data directory",
        )
    })?;
    let dir = base.join("achilles").join("journal");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Public helper so the UI can show where files land.
pub fn root_display() -> Option<String> {
    dirs::data_dir().map(|p| {
        p.join("achilles")
            .join("journal")
            .to_string_lossy()
            .into_owned()
    })
}

pub fn save(entry_input: SaveInput) -> std::io::Result<Entry> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let iso = format_iso(now_unix);

    let slug_dir = root()?.join(slug_for(&entry_input));
    std::fs::create_dir_all(&slug_dir)?;

    let entry = Entry {
        saved_at: now_unix,
        saved_at_iso: iso.clone(),
        app_path: entry_input.app_path,
        display_name: entry_input.display_name,
        bundle_id: entry_input.bundle_id,
        payload: entry_input.payload,
    };

    // Filenames are the ISO timestamp with `:`→`-` so they sort cleanly and
    // are valid on all filesystems.
    let fname = format!("{}.json", iso.replace(':', "-"));
    let path = slug_dir.join(&fname);

    let bytes = serde_json::to_vec_pretty(&entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    atomic_write(&path, &bytes)?;

    Ok(entry)
}

/// Return the most recent entry stored for `app_path`, or `None` if no
/// entries exist.
pub fn latest(app_path: &str) -> std::io::Result<Option<Entry>> {
    let root = root()?;
    let slug = slug_for_path(app_path);
    let dir = root.join(slug);
    if !dir.is_dir() {
        return Ok(None);
    }

    let mut newest: Option<(u64, PathBuf)> = None;
    for entry in std::fs::read_dir(&dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match &newest {
            Some((best, _)) if *best >= mtime => {}
            _ => newest = Some((mtime, path)),
        }
    }

    let Some((_, path)) = newest else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path)?;
    let parsed: Entry = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(parsed))
}

/// List every entry on disk, newest first, returning a compact summary
/// rather than loading full payloads.
pub fn list_all() -> std::io::Result<Vec<EntrySummary>> {
    let root = root()?;
    let mut out = Vec::new();

    for slug_dir in std::fs::read_dir(&root)?.flatten() {
        let path = slug_dir.path();
        if !path.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(&path)?.flatten() {
            let fp = file.path();
            if fp.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&fp) else {
                continue;
            };
            let Ok(parsed): Result<Entry, _> = serde_json::from_slice(&bytes) else {
                continue;
            };
            out.push(EntrySummary {
                saved_at: parsed.saved_at,
                saved_at_iso: parsed.saved_at_iso,
                app_path: parsed.app_path,
                display_name: parsed.display_name,
                bundle_id: parsed.bundle_id,
                file: fp.to_string_lossy().into_owned(),
            });
        }
    }

    out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at));
    Ok(out)
}

pub struct SaveInput {
    pub app_path: String,
    pub display_name: Option<String>,
    pub bundle_id: Option<String>,
    pub payload: serde_json::Value,
}

/// Filesystem-safe key for a bundle. Prefers `bundle_id`, falls back to a
/// slug of the path. Keeps scope within `root()` so we never leak outside.
fn slug_for(input: &SaveInput) -> String {
    if let Some(id) = input.bundle_id.as_deref().filter(|s| !s.is_empty()) {
        return sanitise(id);
    }
    slug_for_path(&input.app_path)
}

fn slug_for_path(app_path: &str) -> String {
    let last = Path::new(app_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(app_path);
    sanitise(last)
}

fn sanitise(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "app".to_string()
    } else {
        s
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// `2026-04-20T09:12:34Z` rendered from unix seconds. Hand-rolled to avoid
/// pulling in `chrono`; millisecond/ns precision would be nice but isn't
/// load-bearing for a journal.
fn format_iso(unix_secs: u64) -> String {
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_DAY: u64 = 86_400;
    const DAYS_IN_MONTH: [u16; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let days_since_epoch = unix_secs / SECS_PER_DAY;
    let time_of_day = unix_secs % SECS_PER_DAY;
    let hour = time_of_day / SECS_PER_HOUR;
    let minute = (time_of_day % SECS_PER_HOUR) / SECS_PER_MINUTE;
    let second = time_of_day % SECS_PER_MINUTE;

    // Compute (year, month, day) from days_since_epoch via a simple algorithm.
    let mut year = 1970u32;
    let mut days_remaining = days_since_epoch as i64;
    loop {
        let is_leap =
            (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let yr_days = if is_leap { 366 } else { 365 };
        if days_remaining < yr_days as i64 {
            break;
        }
        days_remaining -= yr_days as i64;
        year += 1;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mut month = 0u32;
    let mut day = days_remaining as u32 + 1;
    for (i, &dm) in DAYS_IN_MONTH.iter().enumerate() {
        let dm = if i == 1 && is_leap { dm + 1 } else { dm };
        if day <= dm as u32 {
            month = i as u32 + 1;
            break;
        }
        day -= dm as u32;
    }
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}
