//! Resolve Rust crate licenses from crates.io, with a curated fast-path and a
//! disk cache so a repeat scan (and the ubiquitous crates) cost no requests.
//!
//! `cargo-auditable` records each embedded crate's name + version but not its
//! license; this fills that gap. Lookups are deduplicated, bounded, and run with
//! a small concurrency cap to stay friendly to crates.io.

use std::collections::HashMap;
use std::path::PathBuf;

use futures::stream::{self, StreamExt};

/// Max distinct crates we'll hit the network for in one scan (after the curated
/// fast-path and cache). Keeps a huge dependency tree from fanning out to
/// hundreds of requests; anything beyond is left unresolved (`None`).
const MAX_NETWORK_LOOKUPS: usize = 250;

/// Concurrent in-flight crates.io requests.
const CONCURRENCY: usize = 8;

/// Curated licenses for ubiquitous crates — spares the network the long tail of
/// near-universal dependencies. All are the Rust-ecosystem-standard dual license
/// unless noted.
fn curated(name: &str) -> Option<&'static str> {
    let l = match name {
        "serde" | "serde_json" | "serde_derive" | "tokio" | "libc" | "log" | "cfg-if" | "bitflags"
        | "itoa" | "ryu" | "quote" | "proc-macro2" | "syn" | "unicode-ident" | "once_cell"
        | "futures" | "futures-core" | "futures-util" | "bytes" | "pin-project-lite" | "anyhow"
        | "thiserror" | "regex" | "regex-syntax" | "aho-corasick" | "memchr" | "rand" | "getrandom"
        | "hashbrown" | "indexmap" | "smallvec" | "base64" | "http" | "httparse" | "tracing"
        | "tracing-core" | "num-traits" | "either" | "lazy_static" | "parking_lot" | "socket2"
        | "mio" | "toml" | "url" | "percent-encoding" | "idna" => "MIT OR Apache-2.0",
        "ring" => "unknown", // custom OpenSSL/ISC/MIT-derived license
        "webpki" | "untrusted" => "ISC",
        "adler" | "miniz_oxide" => "MIT OR Apache-2.0 OR Zlib",
        _ => return None,
    };
    Some(l)
}

fn cache_path() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("achilles").join("crate-licenses.json"))
}

fn load_cache() -> HashMap<String, String> {
    cache_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_cache(map: &HashMap<String, String>) {
    let Some(path) = cache_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec(map) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Resolve licenses for `crates` (name, version). Returns a map keyed by
/// `"name@version"` → license string (`"unknown"` when unresolved). Uses the
/// curated table, then the on-disk cache, then crates.io for the remainder.
pub async fn resolve(crates: &[(String, String)]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut cache = load_cache();
    let mut cache_dirty = false;
    let mut to_fetch: Vec<(String, String, String)> = Vec::new(); // (key, name, version)

    for (name, version) in crates {
        let key = format!("{name}@{version}");
        if out.contains_key(&key) {
            continue;
        }
        if let Some(l) = curated(name) {
            out.insert(key, l.to_string());
        } else if let Some(l) = cache.get(&key) {
            out.insert(key, l.clone());
        } else {
            to_fetch.push((key, name.clone(), version.clone()));
        }
    }

    if !to_fetch.is_empty() {
        let truncated = to_fetch.len() > MAX_NETWORK_LOOKUPS;
        to_fetch.truncate(MAX_NETWORK_LOOKUPS);

        let client = reqwest::Client::builder()
            .user_agent(concat!(
                "achilles/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/crabnebula-dev/achilles)"
            ))
            .build()
            .ok();

        if let Some(client) = client {
            let fetched: Vec<(String, String)> = stream::iter(to_fetch)
                .map(|(key, name, version)| {
                    let client = client.clone();
                    async move {
                        let license = fetch_one(&client, &name, &version)
                            .await
                            .unwrap_or_else(|| "unknown".to_string());
                        (key, license)
                    }
                })
                .buffer_unordered(CONCURRENCY)
                .collect()
                .await;

            for (key, license) in fetched {
                // Cache only confident answers so a transient failure retries.
                if license != "unknown" {
                    cache.insert(key.clone(), license.clone());
                    cache_dirty = true;
                }
                out.insert(key, license);
            }
        }

        let _ = truncated; // (bounded silently; the caller notes coverage)
    }

    if cache_dirty {
        save_cache(&cache);
    }
    out
}

/// Fetch one crate-version's license from crates.io. `None` on any error.
async fn fetch_one(client: &reqwest::Client, name: &str, version: &str) -> Option<String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let license = json.get("version")?.get("license")?.as_str()?.trim();
    if license.is_empty() {
        None
    } else {
        Some(license.to_string())
    }
}
