//! Shared vulnerability record type. All sources normalise into this shape
//! so the UI can render one list regardless of provenance.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Canonical source of an advisory.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Query to <https://api.osv.dev/v1/query> (npm, crates.io, …).
    Osv,
    /// NVD REST API keyed by CPE.
    Nvd,
    /// ENISA EU Vulnerability Database (<https://euvd.enisa.europa.eu>).
    Euvd,
    /// GitHub Global Security Advisories (requires PAT).
    Ghsa,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl FromStr for Severity {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "LOW" => Ok(Self::Low),
            "MODERATE" | "MEDIUM" => Ok(Self::Medium),
            "HIGH" => Ok(Self::High),
            "CRITICAL" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

/// Bucket a CVSS base score (0.0–10.0) into [`Severity`].
pub fn severity_from_cvss(score: f64) -> Option<Severity> {
    match score {
        s if s <= 0.0 => None,
        s if s < 4.0 => Some(Severity::Low),
        s if s < 7.0 => Some(Severity::Medium),
        s if s < 9.0 => Some(Severity::High),
        _ => Some(Severity::Critical),
    }
}

/// Normalised advisory record returned by every source. Shape is stable —
/// the UI & Tauri frontend depend on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// Primary identifier — CVE-* when available, GHSA-* or similar otherwise.
    pub id: String,
    pub source: Source,
    pub summary: String,
    pub severity: Option<Severity>,
    /// First patched version we could infer. Best-effort: multi-range CVEs
    /// may report the fix from the first applicable range.
    pub fixed_in: Option<String>,
    /// Other identifiers the advisory is known by.
    pub aliases: Vec<String>,
    /// ISO-8601 publication timestamp, if the source provides one.
    pub published: Option<String>,
    pub references: Vec<String>,
}
