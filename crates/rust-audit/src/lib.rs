//! Detect `cargo-auditable` Rust binaries inside an application and audit their
//! embedded crate dependencies against the RustSec advisory database.
//!
//! Rust binaries built with `cargo auditable build` embed their full dependency
//! tree; this adapter extracts it ([`extract`]) and cross-references each crate
//! against RustSec ([`db`]), surfacing vulnerable / unmaintained dependencies
//! that ship inside an app.

mod db;
mod extract;

pub use db::Database;
pub use extract::{extract, AuditedCrate};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use serde::Serialize;

/// A binary found to carry `cargo-auditable` data.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditableBinary {
    pub path: String,
    pub crate_count: usize,
}

/// A crate matched to a RustSec advisory.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustFinding {
    pub binary: String,
    pub crate_name: String,
    pub version: String,
    pub id: String,
    pub title: String,
    pub aliases: Vec<String>,
    pub cvss: Option<String>,
    /// Non-null for informational advisories (unmaintained/unsound/notice).
    pub informational: Option<String>,
    pub patched: Vec<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RustAuditReport {
    pub auditable_binaries: Vec<AuditableBinary>,
    pub findings: Vec<RustFinding>,
    /// Set when the advisory-db couldn't be fetched (findings then empty).
    pub db_error: Option<String>,
}

/// Scan an app for `cargo-auditable` binaries and audit them against RustSec.
/// `executable` is the primary binary; `root` (the bundle dir) is walked for
/// additional Rust binaries.
pub fn audit(executable: &Path, root: Option<&Path>) -> RustAuditReport {
    let mut binaries: Vec<(String, Vec<AuditedCrate>)> = Vec::new();
    for path in candidate_binaries(executable, root) {
        if let Some(crates) = extract_file(&path) {
            binaries.push((path.to_string_lossy().into_owned(), crates));
        }
    }

    let mut report = RustAuditReport {
        auditable_binaries: binaries
            .iter()
            .map(|(p, c)| AuditableBinary {
                path: p.clone(),
                crate_count: c.len(),
            })
            .collect(),
        ..Default::default()
    };
    if binaries.is_empty() {
        return report;
    }

    let db = match Database::ensure() {
        Ok(db) => db,
        Err(e) => {
            report.db_error = Some(e);
            return report;
        }
    };

    // Look up each distinct crate once, then match every (binary, crate) pair.
    let mut cache: HashMap<String, Vec<db::Advisory>> = HashMap::new();
    for (binary, crates) in &binaries {
        for c in crates {
            let advisories = cache
                .entry(c.name.clone())
                .or_insert_with(|| db.advisories_for(&c.name));
            for a in advisories.iter() {
                if a.affects(&c.version) {
                    report.findings.push(RustFinding {
                        binary: binary.clone(),
                        crate_name: c.name.clone(),
                        version: c.version.to_string(),
                        id: a.id.clone(),
                        title: a.title.clone(),
                        aliases: a.aliases.clone(),
                        cvss: a.cvss.clone(),
                        informational: a.informational.clone(),
                        patched: a.patched.clone(),
                        url: a.url.clone(),
                    });
                }
            }
        }
    }
    report
}

/// Extract audit data from a file via mmap (avoids reading large binaries fully
/// into memory), skipping files over a sanity cap.
fn extract_file(path: &Path) -> Option<Vec<AuditedCrate>> {
    const MAX_BYTES: u64 = 300 * 1024 * 1024;
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_BYTES {
        return None;
    }
    // Safety: read-only mapping, never aliased mutably.
    let mmap = unsafe { Mmap::map(&file) }.ok()?;
    extract(&mmap)
}

/// The executable plus a bounded set of bundle binaries likely to be Rust
/// (framework main binaries, shared libraries, files under `MacOS/`).
fn candidate_binaries(executable: &Path, root: Option<&Path>) -> Vec<PathBuf> {
    const MAX_FILES: usize = 40;
    let mut out = vec![executable.to_path_buf()];
    let Some(root) = root else {
        return out;
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_FILES {
                return out;
            }
            let path = entry.path();
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(path);
                continue;
            }
            if path == executable {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            let is_lib =
                lower.ends_with(".dylib") || lower.ends_with(".so") || lower.ends_with(".dll");
            let in_macos = dir.file_name().and_then(|n| n.to_str()) == Some("MacOS");
            let framework_main = is_framework_main(&path, name);
            if is_lib || in_macos || framework_main {
                out.push(path);
            }
        }
    }
    out
}

fn is_framework_main(path: &Path, name: &str) -> bool {
    if name.contains('.') {
        return false;
    }
    let fw = format!("{name}.framework");
    path.ancestors()
        .any(|a| a.file_name().and_then(|n| n.to_str()) == Some(fw.as_str()))
}
