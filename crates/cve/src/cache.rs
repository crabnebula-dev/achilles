//! Disk cache for advisory lookups.
//!
//! Historical CVE data for a given `(source, name, version)` is monotonic:
//! new advisories appear over time, existing ones don't retroactively change.
//! So we cache aggressively (24h TTL) and refetch on expiry to pick up
//! anything new.
//!
//! Cache format:
//!   path:   `<cache_dir>/achilles/cve/<sanitised-key>.json`
//!   value:  `{ "stored_at": <epoch_secs>, "value": <anything serde> }`

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{de::DeserializeOwned, Serialize};

const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Serialize, serde::Deserialize)]
struct Envelope<T> {
    stored_at: u64,
    value: T,
}

pub fn get<T: DeserializeOwned>(key: &str) -> Option<T> {
    let path = cache_path(key)?;
    let bytes = std::fs::read(&path).ok()?;
    let env: Envelope<T> = serde_json::from_slice(&bytes).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.saturating_sub(env.stored_at) > DEFAULT_TTL.as_secs() {
        return None;
    }
    Some(env.value)
}

pub fn put<T: Serialize>(key: &str, value: &T) {
    let Some(path) = cache_path(key) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let stored_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let env = Envelope { stored_at, value };
    if let Ok(bytes) = serde_json::to_vec(&env) {
        let _ = std::fs::write(&path, bytes);
    }
}

fn cache_path(key: &str) -> Option<PathBuf> {
    let base = dirs::cache_dir()?.join("achilles").join("cve");
    let safe: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(base.join(format!("{safe}.json")))
}
