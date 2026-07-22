//! Fleet-inventory reporting.
//!
//! When enabled, the app periodically re-discovers installed applications and
//! their detected runtime versions and POSTs a compact **inventory** report to
//! a configurable collector (HTTPS + bearer token). This is opt-in: nothing is
//! sent until a collector URL is configured and reporting is switched on.
//!
//! The payload is intentionally small — app name/version/framework per device,
//! plus device identity, a fleet id, and a timestamp. No CVE/audit/static-scan
//! data is gathered here, so reassessment is fast and fully offline up to the
//! single POST. See `docs/collector-schema.md` for the wire contract.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use scan::ScanEvent;

/// Persisted reporting configuration. All fields default so a partial or
/// missing file still deserialises; reporting stays off until explicitly
/// enabled with a non-empty collector URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    /// Master switch. Reporting is a no-op while `false`.
    pub enabled: bool,
    /// Collector endpoint, e.g. `https://collector.example.com/v1/reports`.
    pub collector_url: String,
    /// Bearer token sent as `Authorization: Bearer <token>` (omitted if empty).
    pub token: String,
    /// Groups this device's reports on the collector.
    pub fleet_id: String,
    /// Seconds between scheduled reassessments. Floored to 60 by the scheduler.
    pub interval_secs: u64,
    /// Whether the app should launch at login. Mirrors the OS login-item state.
    pub autostart: bool,

    // --- Trusted-host VDB snapshot ---
    /// Source CVE data from a trusted host's downloadable snapshot instead of
    /// querying NVD/OSV/EUVD live (with live fallback for anything uncovered).
    pub vdb_enabled: bool,
    /// Snapshot bundle URL on the trusted host.
    pub vdb_url: String,
    /// Bearer token for the VDB host. Falls back to `token` when empty.
    pub vdb_token: String,
    /// Seconds between snapshot refreshes.
    pub vdb_refresh_secs: u64,
    /// A cached snapshot older than this is deleted on a failed refresh so the
    /// CVE lookups fall back to the public sources rather than serve stale data.
    pub vdb_max_age_secs: u64,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            collector_url: String::new(),
            token: String::new(),
            fleet_id: String::new(),
            interval_secs: 21_600, // 6 hours
            autostart: false,
            vdb_enabled: false,
            vdb_url: String::new(),
            vdb_token: String::new(),
            vdb_refresh_secs: 86_400,          // daily
            vdb_max_age_secs: 14 * 86_400,     // two weeks
        }
    }
}

/// Directory holding app config (`reporting.json`, `device-id`), created if
/// necessary. Sits beside the journal under the platform data/config dir.
fn config_dir() -> std::io::Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine config directory",
        )
    })?;
    let dir = base.join("achilles");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn config_file() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("reporting.json"))
}

/// Load the saved config, falling back to defaults when the file is absent or
/// unreadable/garbage — reporting should never fail to start over a bad file.
pub fn load() -> ReportingConfig {
    let Ok(path) = config_file() else {
        return ReportingConfig::default();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => ReportingConfig::default(),
    }
}

/// Persist the config atomically (temp file + rename).
pub fn save(config: &ReportingConfig) -> std::io::Result<()> {
    let path = config_file()?;
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Where the config file lives, for display in the UI.
pub fn path() -> Option<String> {
    config_file().ok().map(|p| p.to_string_lossy().into_owned())
}

/// Stable per-device identifier. Generated once (UUID v4) and persisted to
/// `device-id` in the config dir; reused on every subsequent run.
fn device_id() -> String {
    let file = match config_dir() {
        Ok(dir) => dir.join("device-id"),
        Err(_) => return uuid::Uuid::new_v4().to_string(),
    };
    if let Ok(existing) = std::fs::read_to_string(&file) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    // Best effort: if the write fails we still return a usable id this run.
    let _ = std::fs::write(&file, &id);
    id
}

/// Identity of the reporting device.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub app_version: String,
}

impl Device {
    fn current() -> Self {
        Self {
            id: device_id(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// One installed app's inventory line.
#[derive(Debug, Clone, Serialize)]
pub struct AppInventory {
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub bundle_version: Option<String>,
    pub framework: String,
    /// Detected runtime versions, only the ones present (e.g. `electron`,
    /// `chromium`, `node`, `cef`, …).
    pub runtimes: BTreeMap<String, String>,
}

/// The full report POSTed to the collector.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub generated_at: u64,
    pub generated_at_iso: String,
    pub fleet_id: String,
    pub device: Device,
    pub apps: Vec<AppInventory>,
}

/// Status pushed to the frontend after each reassessment attempt.
#[derive(Debug, Clone, Serialize)]
struct ReassessStatus {
    ok: bool,
    /// Number of apps in the inventory (when a report was built).
    count: usize,
    /// `true` when reporting is disabled / unconfigured, so the UI can show
    /// "inventory built but not sent" distinctly from a send failure.
    skipped: bool,
    error: Option<String>,
    at: u64,
    at_iso: String,
}

/// Serialise a [`detect::Framework`] to its lowercase wire string.
fn framework_str(framework: detect::Framework) -> String {
    serde_json::to_value(framework)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Collapse a [`detect::Versions`] into a map of only the populated runtimes.
fn runtimes_of(v: &detect::Versions) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut put = |key: &str, val: &Option<String>| {
        if let Some(s) = val {
            m.insert(key.to_string(), s.clone());
        }
    };
    put("electron", &v.electron);
    put("chromium", &v.chromium);
    put("node", &v.node);
    put("tauri", &v.tauri);
    put("deno", &v.deno);
    put("cef", &v.cef);
    put("nwjs", &v.nwjs);
    put("flutter", &v.flutter);
    put("qt", &v.qt);
    put("react_native", &v.react_native);
    put("wails", &v.wails);
    put("sciter", &v.sciter);
    put("java", &v.java);
    put("webkit", &v.webkit);
    m
}

/// Version-based risk rating for a detected app. This is the Rust counterpart of
/// the UI's `versionRisk` heuristic — offline and cheap (no CVE lookups), so it
/// can run in the background scheduler to keep the tray informed. It only
/// downgrades frameworks with a defensible version cutoff; everything else is
/// treated as unremarkable (`Ok`).
fn version_risk(framework: detect::Framework, v: &detect::Versions) -> Risk {
    use detect::Framework;
    let major = |s: &Option<String>| {
        s.as_deref()
            .and_then(|x| x.split('.').next())
            .and_then(|m| m.parse::<u32>().ok())
    };
    match framework {
        Framework::Electron => match major(&v.electron) {
            Some(m) if m < 35 => Risk::Bad,
            Some(m) if m < 40 => Risk::Warn,
            _ => Risk::Ok,
        },
        Framework::Tauri => match major(&v.tauri) {
            Some(m) if m < 1 => Risk::Warn,
            _ => Risk::Ok,
        },
        Framework::Cef => match major(&v.cef) {
            Some(m) if m < 130 => Risk::Warn,
            _ => Risk::Ok,
        },
        _ => Risk::Ok,
    }
}

/// A coarse risk rating; only `Warn`/`Bad` count as "needs attention".
#[derive(Clone, Copy)]
enum Risk {
    Ok,
    Warn,
    Bad,
}

/// Tallies risky apps across an inventory run, for the tray summary.
#[derive(Debug, Clone, Copy, Default)]
pub struct RiskSummary {
    /// Apps assessed (all detected apps, not just the reported inventory).
    pub total: usize,
    /// Apps on a runtime old enough to warrant a look.
    pub warn: usize,
    /// Apps on a runtime old enough to be a clear concern.
    pub bad: usize,
}

/// Discover installed apps and detect each, returning a compact inventory plus a
/// version-based [`RiskSummary`] over *every* detected app. Reuses the same
/// discovery + concurrent-detection path the UI scan uses, but only keeps the
/// lightweight inventory fields. Apps with no identifiable framework
/// (`Framework::Unknown`) are dropped from the reported inventory — they add
/// noise, not signal — but still counted in the risk total.
async fn collect_inventory() -> Result<(Vec<AppInventory>, RiskSummary), String> {
    let apps = scan::discover_applications().await.map_err(|e| e.to_string())?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(scan::scan(apps, 8, tx));

    let mut inventory = Vec::new();
    let mut risk = RiskSummary::default();
    while let Some(event) = rx.recv().await {
        if let ScanEvent::Detected(detection) = event {
            risk.total += 1;
            match version_risk(detection.framework, &detection.versions) {
                Risk::Warn => risk.warn += 1,
                Risk::Bad => risk.bad += 1,
                Risk::Ok => {}
            }
            if detection.framework == detect::Framework::Unknown {
                continue;
            }
            inventory.push(AppInventory {
                name: detection.display_name.clone(),
                bundle_id: detection.bundle_id.clone(),
                bundle_version: detection.bundle_version.clone(),
                framework: framework_str(detection.framework),
                runtimes: runtimes_of(&detection.versions),
            });
        }
    }
    Ok((inventory, risk))
}

/// POST a report to the collector. Returns `Err` on transport failure or any
/// non-2xx response.
async fn send_report(config: &ReportingConfig, report: &Report) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client.post(&config.collector_url).json(report);
    if !config.token.is_empty() {
        req = req.bearer_auth(&config.token);
    }

    let res = req.send().await.map_err(|e| e.to_string())?;
    let status = res.status();
    if status.is_success() {
        Ok(())
    } else {
        // Body may carry a useful collector error; keep it short.
        let body = res.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(200).collect();
        Err(format!("collector returned {status}: {snippet}"))
    }
}

/// Run a reassessment and report the result. No-op (Ok) when reporting is
/// disabled or no collector URL is set. Emits a `reassess_status` event so the
/// UI can show the last-run outcome regardless of whether the window is open.
///
/// Outcome of one reassessment, summarised for the caller's tray-status line.
#[derive(Debug, Clone, Copy)]
pub struct ReassessSummary {
    /// Apps in the (reportable) inventory.
    pub count: usize,
    /// Whether the inventory was actually POSTed (vs. built-but-not-sent because
    /// reporting is off/unconfigured).
    pub sent: bool,
    /// Version-based risk tally over every detected app.
    pub risk: RiskSummary,
}

/// Run a reassessment and report the result. The inventory + risk tally are
/// always computed (so the tray stays informed); the POST is a no-op when
/// reporting is disabled or no collector URL is set. Emits a `reassess_status`
/// event so the UI can show the last-run outcome regardless of whether the
/// window is open.
pub async fn reassess_and_report(app: AppHandle) -> Result<ReassessSummary, String> {
    let config = load();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let disabled = !config.enabled || config.collector_url.trim().is_empty();

    let result: Result<(usize, RiskSummary), String> = async {
        let (inventory, risk) = collect_inventory().await?;
        let count = inventory.len();
        if disabled {
            return Ok((count, risk));
        }
        let report = Report {
            schema_version: 1,
            generated_at: now,
            generated_at_iso: crate::journal::format_iso(now),
            fleet_id: config.fleet_id.clone(),
            device: Device::current(),
            apps: inventory,
        };
        send_report(&config, &report).await?;
        Ok((count, risk))
    }
    .await;

    let status = match &result {
        Ok((count, _)) => ReassessStatus {
            ok: true,
            count: *count,
            skipped: disabled,
            error: None,
            at: now,
            at_iso: crate::journal::format_iso(now),
        },
        Err(e) => ReassessStatus {
            ok: false,
            count: 0,
            skipped: false,
            error: Some(e.clone()),
            at: now,
            at_iso: crate::journal::format_iso(now),
        },
    };
    let _ = app.emit("reassess_status", status);

    result.map(|(count, risk)| ReassessSummary {
        count,
        sent: !disabled,
        risk,
    })
}

// ---------- trusted-host VDB snapshot ----------

/// On-disk snapshot path. Must match the reader in `cve::sources::snapshot`
/// (`<cache-dir>/achilles/vdb-snapshot.json`).
fn vdb_snapshot_path() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("achilles").join("vdb-snapshot.json"))
}

/// Status pushed to the frontend after a VDB refresh attempt.
#[derive(Debug, Clone, Serialize)]
struct VdbStatus {
    ok: bool,
    skipped: bool,
    /// Number of products in the freshly downloaded snapshot, when successful.
    products: usize,
    error: Option<String>,
    at: u64,
    at_iso: String,
}

/// Minimal view of a snapshot bundle for validation + freshness checks. The
/// authoritative match-time parse lives in `cve::sources::snapshot`.
#[derive(Deserialize)]
struct SnapshotHead {
    #[serde(default)]
    generated_at: u64,
    #[serde(default)]
    products: BTreeMap<String, serde_json::Value>,
}

/// Download the VDB snapshot from the trusted host and cache it locally. No-op
/// when VDB sourcing is disabled or unconfigured. On failure, a cached snapshot
/// older than `vdb_max_age_secs` is deleted so lookups fall back to the public
/// sources instead of serving stale data.
pub async fn refresh_vdb_snapshot(app: AppHandle) -> Result<(), String> {
    let config = load();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let skipped = !config.vdb_enabled || config.vdb_url.trim().is_empty();

    let result: Result<usize, String> = async {
        if skipped {
            return Ok(0);
        }
        let token = if config.vdb_token.is_empty() {
            &config.token
        } else {
            &config.vdb_token
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = client.get(config.vdb_url.trim());
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.map_err(|e| e.to_string())?;
        let status = res.status();
        let bytes = res.bytes().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("VDB host returned {status}"));
        }
        // Validate it parses as a snapshot before overwriting the cache.
        let head: SnapshotHead = serde_json::from_slice(&bytes)
            .map_err(|e| format!("snapshot is not valid JSON: {e}"))?;
        if head.products.is_empty() {
            return Err("snapshot contains no products".to_string());
        }
        let path = vdb_snapshot_path().ok_or("no cache directory")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(head.products.len())
    }
    .await;

    // On failure, drop a stale cached snapshot so the CVE path falls back to
    // the public sources rather than matching against outdated data.
    if result.is_err() && !skipped {
        if let Some(path) = vdb_snapshot_path() {
            let stale = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<SnapshotHead>(&b).ok())
                .map(|h| now.saturating_sub(h.generated_at) > config.vdb_max_age_secs)
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    let status = match &result {
        Ok(products) => VdbStatus {
            ok: true,
            skipped,
            products: *products,
            error: None,
            at: now,
            at_iso: crate::journal::format_iso(now),
        },
        Err(e) => VdbStatus {
            ok: false,
            skipped: false,
            products: 0,
            error: Some(e.clone()),
            at: now,
            at_iso: crate::journal::format_iso(now),
        },
    };
    let _ = app.emit("vdb_status", status);

    result.map(|_| ())
}
