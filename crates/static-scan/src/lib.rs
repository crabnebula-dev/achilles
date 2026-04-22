//! Rust-native static analysis for Electron application bundles.
//!
//! Given a path to an `app.asar` archive (or a directory of renderer source),
//! [`scan`] returns a [`Report`] listing findings from a catalogue of
//! regex-based rules.
//!
//! # Why regex, not AST?
//!
//! A previous iteration of this project wrapped `@doyensec/electronegativity`
//! as a bundled sidecar. That dragged in ~70 MB of Bun runtime per platform
//! and macOS code-signing friction we didn't want. The rules we care about
//! for a user-facing risk indicator — "is CSP present?", "is `sandbox:false`
//! set anywhere?", "is `contextIsolation` disabled?" — have unambiguous,
//! short regex expressions that survive modern bundlers (esbuild / rollup /
//! vite / webpack).
//!
//! False positives are possible; we mark every rule with a confidence level
//! so the UI can grey out tentative findings. Upgrading a rule to AST
//! precision later (via `oxc_parser` or `swc`) is a drop-in swap for its
//! matcher — the public API doesn't change.
//!
//! # Input types
//!
//! - An `app.asar` file ([`scan_asar`]).
//! - A directory containing extracted source ([`scan_directory`]).
//! - [`scan`] dispatches based on path type.

use std::path::Path;

use serde::Serialize;

mod asar;
mod ast;
mod deps;
mod rules;
mod scanner;

pub use deps::{Dependency, DependencySource};
pub use rules::{Confidence, Finding, Rule, RuleId, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub input: std::path::PathBuf,
    pub input_kind: InputKind,
    pub files_scanned: usize,
    pub rules_run: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanErrorEntry>,
    /// npm dependencies extracted from `package-lock.json` (preferred) or
    /// `package.json` bundled with the app. Empty for non-Node apps.
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Asar,
    Directory,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanErrorEntry {
    pub file: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("input path not found: {0}")]
    NotFound(std::path::PathBuf),
    #[error("input path is neither an .asar file nor a directory: {0}")]
    UnsupportedInput(std::path::PathBuf),
    #[error("asar read error: {0}")]
    Asar(#[from] asar::AsarError),
    #[error("io error on {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Scan either an ASAR archive or a directory of source, auto-detected.
pub fn scan(input: &Path) -> Result<Report, ScanError> {
    if !input.exists() {
        return Err(ScanError::NotFound(input.to_path_buf()));
    }
    if input.is_file() {
        match input.extension().and_then(|e| e.to_str()) {
            Some("asar") => scan_asar(input),
            _ => Err(ScanError::UnsupportedInput(input.to_path_buf())),
        }
    } else if input.is_dir() {
        scan_directory(input)
    } else {
        Err(ScanError::UnsupportedInput(input.to_path_buf()))
    }
}

/// Scan an `app.asar` archive.
pub fn scan_asar(path: &Path) -> Result<Report, ScanError> {
    let archive = asar::Archive::open(path)?;
    let ruleset = rules::catalog();
    let mut files_scanned = 0usize;
    let mut errors = Vec::new();
    let mut findings = Vec::new();

    let mut corpus: Vec<scanner::FileContent> = Vec::new();
    for file in archive.files() {
        if !scanner::interesting_extension(&file.path) {
            continue;
        }
        match archive.read(file) {
            Ok(bytes) => {
                corpus.push(scanner::FileContent {
                    path: file.path.clone(),
                    bytes,
                });
                files_scanned += 1;
            }
            Err(err) => errors.push(ScanErrorEntry {
                file: file.path.clone(),
                message: err.to_string(),
            }),
        }
    }

    scanner::run_rules(&ruleset, &corpus, &mut findings);

    // Try root-of-archive first, then the common Electron layout
    // (`app/package.json` — when a wrapper app packages a child app.asar).
    let lock = archive
        .read_path("package-lock.json")
        .or_else(|| archive.read_path("app/package-lock.json"));
    let pkg = archive
        .read_path("package.json")
        .or_else(|| archive.read_path("app/package.json"));
    let dependencies = deps::parse(lock.as_deref(), pkg.as_deref());

    Ok(Report {
        input: path.to_path_buf(),
        input_kind: InputKind::Asar,
        files_scanned,
        rules_run: ruleset.len(),
        findings,
        errors,
        dependencies,
    })
}

/// Scan a directory tree of source files.
pub fn scan_directory(path: &Path) -> Result<Report, ScanError> {
    let ruleset = rules::catalog();
    let mut files_scanned = 0usize;
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut corpus: Vec<scanner::FileContent> = Vec::new();

    scanner::walk_directory(path, &mut |rel_path, read_result| match read_result {
        Ok(bytes) => {
            corpus.push(scanner::FileContent {
                path: rel_path.to_string(),
                bytes,
            });
            files_scanned += 1;
        }
        Err(err) => errors.push(ScanErrorEntry {
            file: rel_path.to_string(),
            message: err.to_string(),
        }),
    })
    .map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    scanner::run_rules(&ruleset, &corpus, &mut findings);

    let lock = std::fs::read(path.join("package-lock.json")).ok();
    let pkg = std::fs::read(path.join("package.json")).ok();
    let dependencies = deps::parse(lock.as_deref(), pkg.as_deref());

    Ok(Report {
        input: path.to_path_buf(),
        input_kind: InputKind::Directory,
        files_scanned,
        rules_run: ruleset.len(),
        findings,
        errors,
        dependencies,
    })
}
