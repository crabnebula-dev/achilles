//! User-configurable settings for CVE sources.
//!
//! Stored as JSON at `dirs::config_dir()/achilles/settings.json`, with
//! file mode `0600` on Unix (tokens may be present). A missing file yields
//! [`Settings::default`].
//!
//! Defaults: OSV + NVD on (both unauthenticated); EUVD + GHSA off. Users
//! opt in explicitly — GHSA because it requires a PAT, EUVD because it
//! queries EU-CNA data that might not be wanted by default.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub sources: SourceSettings,
    pub filters: FilterSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            sources: SourceSettings::default(),
            filters: FilterSettings::default(),
        }
    }
}

/// Post-lookup filtering applied to every [`crate::CveReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterSettings {
    /// Drop advisories whose `published` year is older than `N` years
    /// before the current year. `None` disables the filter. Default: 5.
    ///
    /// Wide-net CPEs (Safari, Java, Qt, …) otherwise return decades of
    /// irrelevant history — a Safari 1.x CVE from 2005 isn't a signal for
    /// someone running Safari 26. Advisories with no `published` date are
    /// kept regardless, to avoid silently dropping newer records that
    /// happen to lack timestamps.
    pub max_age_years: Option<u32>,
}

impl Default for FilterSettings {
    fn default() -> Self {
        Self {
            max_age_years: Some(5),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceSettings {
    pub osv: OsvSettings,
    pub nvd: NvdSettings,
    pub euvd: EuvdSettings,
    pub ghsa: GhsaSettings,
}

impl Default for SourceSettings {
    fn default() -> Self {
        Self {
            // EUVD leads the feed — ENISA-run, unauthenticated, EU-CNA
            // coverage that the US-centric NVD misses.
            euvd: EuvdSettings { enabled: true },
            osv: OsvSettings { enabled: true },
            nvd: NvdSettings {
                enabled: true,
                api_key: None,
            },
            ghsa: GhsaSettings {
                enabled: false,
                token: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdSettings {
    pub enabled: bool,
    /// Optional API key. 5 req/30s without, 50 req/30s with.
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuvdSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhsaSettings {
    pub enabled: bool,
    /// Required for any GHSA query — unauth rate limit (60/h) is too low to
    /// be useful.
    pub token: Option<String>,
}

/// Path where settings are stored. `None` if the OS couldn't provide a
/// config dir (shouldn't happen on macOS/Windows/Linux).
pub fn settings_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("achilles").join("settings.json"))
}

pub fn load() -> Settings {
    let Some(path) = settings_path() else {
        return Settings::default();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Settings::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(settings: &Settings) -> std::io::Result<()> {
    let path = settings_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine config directory",
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, bytes)?;

    // Tighten permissions on unix — tokens may be stored here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}
