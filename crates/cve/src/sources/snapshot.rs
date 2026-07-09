//! Local VDB snapshot reader.
//!
//! Instead of querying NVD/OSV/EUVD live, a device can match against a snapshot
//! bundle downloaded from a trusted host (see the app's VDB-refresh logic). The
//! bundle groups normalised [`Advisory`] records by **product key** (matching
//! the report buckets), each carrying a `fixed_in` ceiling so version matching
//! reuses the same logic as the live path.
//!
//! This module only *reads* the on-disk snapshot; downloading/refreshing (and
//! removing a stale one) is the app's job. If the file is absent the caller
//! falls back to the public sources, so a missing/garbage snapshot is a no-op.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::advisory::Advisory;
use crate::version;

/// A downloaded VDB snapshot: advisories grouped by product key.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    /// Bundle format version; reserved for future migrations. Parsed (and thus
    /// validated) here but freshness/versioning policy lives app-side.
    #[serde(default)]
    #[allow(dead_code)]
    pub schema_version: u32,
    /// Unix seconds the host generated the bundle. Freshness is judged by the
    /// downloader, not here.
    #[serde(default)]
    #[allow(dead_code)]
    pub generated_at: u64,
    /// Advisories keyed by product (`chromium`, `electron`, `node`, `deno`, …).
    #[serde(default)]
    pub products: BTreeMap<String, Vec<Advisory>>,
}

/// Path of the on-disk snapshot: `<cache-dir>/achilles/vdb-snapshot.json`
/// (beside the per-lookup cache the live sources use).
fn snapshot_path() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("achilles").join("vdb-snapshot.json"))
}

/// Load the snapshot from disk, or `None` if it's absent/unreadable/garbage.
pub fn load() -> Option<Snapshot> {
    let bytes = std::fs::read(snapshot_path()?).ok()?;
    serde_json::from_slice(&bytes).ok()
}

impl Snapshot {
    /// Whether the snapshot carries advisories for `product` — i.e. whether it
    /// can answer for this runtime without falling back to public sources.
    pub fn covers(&self, product: &str) -> bool {
        self.products.contains_key(product)
    }

    /// Advisories for `product` that apply to `version`, pre-filtered by the
    /// `fixed_in` ceiling so the bucket isn't flooded (the central relevance
    /// filter re-applies the same rule, so this stays consistent). An advisory
    /// with no `fixed_in` is kept — the central pass can still trim it via
    /// prose ceilings.
    pub fn advisories_for(&self, product: &str, version: &str) -> Vec<Advisory> {
        let Some(list) = self.products.get(product) else {
            return Vec::new();
        };
        list.iter()
            .filter(|a| match a.fixed_in.as_deref() {
                Some(ceiling) => !version::at_or_above(version, ceiling),
                None => true,
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{Advisory, Source};

    fn adv(id: &str, fixed_in: Option<&str>) -> Advisory {
        Advisory {
            id: id.into(),
            source: Source::Nvd,
            summary: String::new(),
            severity: None,
            fixed_in: fixed_in.map(str::to_owned),
            aliases: vec![],
            published: None,
            references: vec![],
        }
    }

    fn snap() -> Snapshot {
        let mut products = BTreeMap::new();
        products.insert(
            "chromium".to_string(),
            vec![
                adv("A", Some("142.0.0.0")), // fixed at 142 → affects <142
                adv("B", Some("120.0.0.0")), // fixed at 120 → affects <120
                adv("C", None),              // no ceiling → always kept here
            ],
        );
        Snapshot {
            schema_version: 1,
            generated_at: 0,
            products,
        }
    }

    #[test]
    fn covers_reports_known_products() {
        assert!(snap().covers("chromium"));
        assert!(!snap().covers("node"));
    }

    #[test]
    fn advisories_for_filters_by_fix_ceiling() {
        // Build 138 is below the 142 fix but at/above the 120 fix.
        let hits: Vec<_> = snap()
            .advisories_for("chromium", "138.0.7204.251")
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(hits, vec!["A", "C"]);

        // A build past all ceilings keeps only the no-ceiling advisory.
        let hits: Vec<_> = snap()
            .advisories_for("chromium", "999.0.0.0")
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(hits, vec!["C"]);

        // Unknown product → nothing.
        assert!(snap().advisories_for("node", "24.0.0").is_empty());
    }
}
