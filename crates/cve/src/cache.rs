//! Cache for advisory lookups.
//!
//! Historical CVE data for a given `(source, name, version)` is monotonic:
//! new advisories appear over time, existing ones don't retroactively change.
//! So we cache aggressively (24h TTL) and refetch on expiry to pick up
//! anything new.
//!
//! Envelope (both backends):
//!   `{ "stored_at": <epoch_secs>, "value": <anything serde> }`
//!
//! Storage backend:
//!   * native — `<cache_dir>/achilles/cve/<sanitised-key>.json`.
//!   * wasm — an in-memory, per-session map (a browser tab is short-lived and
//!     the data is monotonic, so on-disk persistence isn't worth the OPFS /
//!     IndexedDB plumbing here).

use serde::{de::DeserializeOwned, Serialize};

const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Serialize, serde::Deserialize)]
struct Envelope<T> {
    stored_at: u64,
    value: T,
}

pub fn get<T: DeserializeOwned>(key: &str) -> Option<T> {
    let bytes = backend::read_raw(&sanitise(key))?;
    let env: Envelope<T> = serde_json::from_slice(&bytes).ok()?;
    if crate::now_unix().saturating_sub(env.stored_at) > DEFAULT_TTL_SECS {
        return None;
    }
    Some(env.value)
}

pub fn put<T: Serialize>(key: &str, value: &T) {
    let env = Envelope {
        stored_at: crate::now_unix(),
        value,
    };
    if let Ok(bytes) = serde_json::to_vec(&env) {
        backend::write_raw(&sanitise(key), bytes);
    }
}

/// Drop every cached entry. wasm-only: committing a fresh EUVD snapshot clears
/// the per-session memo so newly-updated advisories aren't masked by a stale
/// lookup result from earlier in the session.
#[cfg(target_arch = "wasm32")]
pub fn clear() {
    backend::clear();
}

/// Reduce a lookup key to a filesystem-/map-safe token.
fn sanitise(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
mod backend {
    use std::path::PathBuf;

    pub fn read_raw(safe_key: &str) -> Option<Vec<u8>> {
        std::fs::read(path(safe_key)?).ok()
    }

    pub fn write_raw(safe_key: &str, bytes: Vec<u8>) {
        let Some(path) = path(safe_key) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, bytes);
    }

    fn path(safe_key: &str) -> Option<PathBuf> {
        let base = dirs::cache_dir()?.join("achilles").join("cve");
        Some(base.join(format!("{safe_key}.json")))
    }
}

#[cfg(target_arch = "wasm32")]
mod backend {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static STORE: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
    }

    pub fn read_raw(safe_key: &str) -> Option<Vec<u8>> {
        STORE.with(|s| s.borrow().get(safe_key).cloned())
    }

    pub fn write_raw(safe_key: &str, bytes: Vec<u8>) {
        STORE.with(|s| s.borrow_mut().insert(safe_key.to_owned(), bytes));
    }

    pub fn clear() {
        STORE.with(|s| s.borrow_mut().clear());
    }
}
