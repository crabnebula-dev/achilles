//! Behaviour watchdog
//!
//! Inventories everything on the machine that runs in the background or
//! bridges into a browser (launchd agents/daemons, native-messaging hosts),
//! checks each program's code signature, attributes it to an installed app,
//! applies the rules in `jev::watchdog`, and diffs against the previous scan.
//! Jev (an on-device Qwen3-1.7B) is optional and only asked "which app does
//! this belong to?" for items the deterministic checks can't attribute.
//!
//! The model is loaded on demand and dropped after [`IDLE_UNLOAD`], so it
//! occupies memory only while a scan runs. It is downloaded only when the UI
//! passes `allow_download`; otherwise a missing model is reported as
//! [`MODEL_NOT_CACHED`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jev::watchdog::change::{self, Change};
use jev::watchdog::{self, InstalledApp, ItemKind, ItemReport, PersistenceItem, Signature, MODEL};
use jev::{Jev, JevError, ModelFiles};
use serde::{Deserialize, Serialize};

/// Error string the UI matches to offer the model download.
pub const MODEL_NOT_CACHED: &str = "jev-model-not-cached";

/// Drop the model after this long without a scan.
pub const IDLE_UNLOAD: Duration = Duration::from_secs(30);

static ENGINE: Mutex<Option<Jev>> = Mutex::new(None);
/// Bumped by every scan; an unload timer only fires if it's unchanged.
static GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JevStatus {
    pub model: &'static str,
    pub cached: bool,
    pub loaded: bool,
}

#[tauri::command]
pub async fn jev_status() -> JevStatus {
    tokio::task::spawn_blocking(|| JevStatus {
        model: MODEL.id(),
        cached: ModelFiles::cached(&MODEL).is_ok(),
        loaded: ENGINE.lock().map(|e| e.is_some()).unwrap_or(false),
    })
    .await
    .unwrap_or(JevStatus {
        model: MODEL.id(),
        cached: false,
        loaded: false,
    })
}

/// An installed app as the UI knows it (from the scan rows).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppArg {
    pub name: String,
    pub bundle_id: Option<String>,
    pub path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchdogReport {
    pub items: Vec<ItemReport>,
    /// Changes since `baseline_at` (empty on the first scan).
    pub changes: Vec<Change>,
    /// Unix seconds of the previous scan, if there was one.
    pub baseline_at: Option<u64>,
    pub scanned_at: u64,
    /// Whether Jev was used for ownership.
    pub model_used: bool,
}

/// Inventory, attribute and assess every background item on the machine.
#[tauri::command]
pub async fn watchdog_scan(apps: Vec<AppArg>, use_model: bool, allow_download: bool) -> Result<WatchdogReport, String> {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    let (items, apps) = tokio::join!(inventory(), installed(apps));

    let items_for_model = items.clone();
    let reports = tokio::task::spawn_blocking(move || -> Result<Vec<ItemReport>, String> {
        // Only load the model if some item actually needs an ownership question.
        let needed = items_for_model.iter().any(|i| watchdog::ownership::needs_model(i, &apps));
        if !use_model || !needed {
            return watchdog::assess(&items_for_model, &apps, None).map_err(|e| e.to_string());
        }
        let mut engine = ENGINE.lock().map_err(|_| "jev engine poisoned".to_string())?;
        if engine.is_none() {
            let files = if allow_download {
                ModelFiles::fetch(&MODEL)
            } else {
                ModelFiles::cached(&MODEL)
            }
            .map_err(|e| match e {
                JevError::NotCached(_) => MODEL_NOT_CACHED.to_string(),
                e => e.to_string(),
            })?;
            *engine = Some(Jev::load(&files).map_err(|e| e.to_string())?);
        }
        watchdog::assess(&items_for_model, &apps, engine.as_mut()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?;
    if use_model {
        schedule_unload(); // harmless when the model was never loaded
    }
    let reports = reports?;

    let previous = baseline::load();
    let changes = previous
        .as_ref()
        .map(|b| change::diff(&b.items, &items))
        .unwrap_or_default();
    let scanned_at = now();
    baseline::save(&baseline::Baseline { at: scanned_at, items });

    Ok(WatchdogReport {
        items: reports,
        changes,
        baseline_at: previous.map(|b| b.at),
        scanned_at,
        model_used: use_model,
    })
}

fn schedule_unload() {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(IDLE_UNLOAD).await;
        if GENERATION.load(Ordering::SeqCst) == generation {
            // try_lock: a scan in flight means we're not idle after all.
            if let Ok(mut engine) = ENGINE.try_lock() {
                *engine = None;
            }
        }
    });
}

/// Every launchd item and native-messaging host, with program signatures.
pub async fn inventory() -> Vec<PersistenceItem> {
    let (launch, bridges) = tokio::task::spawn_blocking(|| (launch_items(), sideeffects::all_native_messaging_hosts()))
        .await
        .unwrap_or_default();

    let mut items: Vec<PersistenceItem> = launch
        .into_iter()
        .chain(bridges.into_iter().map(|h| PersistenceItem {
            kind: ItemKind::BrowserBridge { browser: h.browser },
            source: h.manifest_path.display().to_string(),
            label: Some(h.host_name),
            program_exists: Path::new(&h.target_path).exists(),
            program: h.target_path,
            arguments: vec![],
            run_at_load: false,
            keep_alive: false,
            signature: None,
        }))
        .collect();

    let sigs = futures::future::join_all(items.iter().map(|i| async {
        if i.program_exists {
            Some(signature_of(Path::new(&i.program)).await)
        } else {
            None
        }
    }))
    .await;
    for (item, sig) in items.iter_mut().zip(sigs) {
        item.signature = sig;
    }
    items
}

#[cfg(target_os = "macos")]
fn launch_items() -> Vec<PersistenceItem> {
    sideeffects::all_launch_items()
        .into_iter()
        .map(|e| PersistenceItem {
            kind: match e.scope {
                sideeffects::LaunchScope::GlobalAgent => ItemKind::GlobalAgent,
                sideeffects::LaunchScope::Daemon => ItemKind::Daemon,
                _ => ItemKind::UserAgent,
            },
            source: e.plist_path.display().to_string(),
            label: e.label,
            program_exists: Path::new(&e.program).exists(),
            program: e.program,
            arguments: e.arguments,
            run_at_load: e.run_at_load,
            keep_alive: e.keep_alive,
            signature: None,
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn launch_items() -> Vec<PersistenceItem> {
    Vec::new()
}

/// Installed apps with their signing Team IDs.
async fn installed(apps: Vec<AppArg>) -> Vec<InstalledApp> {
    futures::future::join_all(apps.into_iter().map(|a| async move {
        let sig = signature_of(Path::new(&a.path)).await;
        InstalledApp {
            name: a.name,
            bundle_id: a.bundle_id,
            team_id: sig.team_id,
            path: a.path,
        }
    }))
    .await
}

async fn signature_of(path: &Path) -> Signature {
    let s = app_audit::code_signature(path).await;
    Signature {
        signed: s.signed,
        apple: s
            .authority
            .iter()
            .any(|a| a == "Software Signing" || a == "Apple Mac OS Application Signing"),
        team_id: s.team_identifier.filter(|t| !t.is_empty() && t != "not set"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The previous scan's inventory, for change detection.
mod baseline {
    use super::*;

    #[derive(Serialize, Deserialize)]
    pub struct Baseline {
        pub at: u64,
        pub items: Vec<PersistenceItem>,
    }

    fn path() -> Option<PathBuf> {
        let dir = dirs::data_dir()?.join("achilles").join("watchdog");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join("baseline.json"))
    }

    pub fn load() -> Option<Baseline> {
        serde_json::from_slice(&std::fs::read(path()?).ok()?).ok()
    }

    pub fn save(b: &Baseline) {
        if let (Some(p), Ok(json)) = (path(), serde_json::to_vec(b)) {
            let _ = std::fs::write(p, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live run over this machine's real persistence and /Applications:
    /// `cargo test -p achilles --release watchdog::tests::live -- --ignored --nocapture`
    /// (`JEV_LIVE_MODEL=1` adds Jev ownership.)
    #[test]
    #[ignore]
    fn live() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let apps: Vec<AppArg> = std::fs::read_dir("/Applications")
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "app"))
            .map(|p| AppArg {
                name: p.file_stem().unwrap().to_string_lossy().into_owned(),
                bundle_id: None,
                path: p.display().to_string(),
            })
            .collect();
        let items = rt.block_on(inventory());
        let apps = rt.block_on(installed(apps));
        let needed = items.iter().filter(|i| watchdog::ownership::needs_model(i, &apps)).count();
        println!("{needed} item(s) need an ownership question");
        let mut jev = (std::env::var("JEV_LIVE_MODEL").is_ok() && needed > 0)
            .then(|| Jev::load(&ModelFiles::cached(&MODEL).unwrap()).unwrap());
        let reports = watchdog::assess(&items, &apps, jev.as_mut()).unwrap();
        for r in &reports {
            let codes: Vec<&str> = r.signals.iter().map(|s| s.code).collect();
            println!(
                "{:<13} {:<52} {:<44} {}",
                format!("{:?}", r.verdict),
                r.item.label.as_deref().unwrap_or("?"),
                format!("{:?}", r.owner).chars().take(44).collect::<String>(),
                codes.join(",")
            );
        }
        let flagged = reports.iter().filter(|r| r.verdict != watchdog::Verdict::Normal).count();
        println!("{} items, {flagged} flagged", reports.len());
    }
}
