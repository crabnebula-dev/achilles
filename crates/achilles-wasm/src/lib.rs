//! Browser/WASM entry point for Achilles.
//!
//! The desktop app scans `/Applications`; in the browser the same analysis runs
//! against an in-memory filesystem ([`vfs::MemTree`]) built from one of two
//! sources:
//!
//! * [`Analyzer`] — a streaming builder. The JS side enumerates a directory
//!   the user granted via the File System Access API (`showDirectoryPicker`,
//!   Chrome/Edge), reads each file, and pushes it in with [`Analyzer::add_file`]
//!   before calling [`Analyzer::finish`]. This is the "scan the local
//!   filesystem" path: one `Analyzer` per `.app`, scanned and dropped in turn.
//! * [`analyze_app`] — a one-shot for an uploaded zip of a `.app` or a bare
//!   `app.asar`, the cross-browser fallback (Firefox/Safari, or drag-drop).
//!
//! Both build a [`MemTree`], install it as the ambient filesystem, and run the
//! exact same synchronous `detect` / `app_audit` / `static_scan` crates the
//! desktop build runs. Each returns one JSON object
//! `{ detection, audit, staticScan, notes }` — the shape Tauri's `invoke`
//! delivers — which the UI shim re-splits into per-command results.
//!
//! The whole crate is `wasm32`-only; on native it compiles to an empty lib.
#![cfg(target_arch = "wasm32")]

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use vfs::MemTree;
use wasm_bindgen::prelude::*;

/// Synthetic root the upload/scan is unpacked under. The analysis crates treat
/// this like `/Applications/Foo.app` on the desktop — they never see the
/// difference.
const SCAN_ROOT: &str = "/scan";

/// Combined result of analysing one app. Field names match the keys the UI
/// already uses for its JSON export, so the shim can serve each `invoke(...)`
/// from this single object.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalyzeResult {
    detection: Option<detect::Detection>,
    audit: Option<app_audit::AppAudit>,
    static_scan: Option<static_scan::Report>,
    /// Human-readable notes about what was (or couldn't be) analysed.
    notes: Vec<String>,
}

/// Streaming builder for the File System Access path: one `.app` is assembled
/// file-by-file, then analysed. `app_root` is an absolute path (e.g.
/// `/scan/Foo.app`); every `add_*` path must sit under it.
#[wasm_bindgen]
pub struct Analyzer {
    root: PathBuf,
    tree: MemTree,
}

#[wasm_bindgen]
impl Analyzer {
    #[wasm_bindgen(constructor)]
    pub fn new(app_root: String) -> Analyzer {
        Analyzer {
            root: PathBuf::from(app_root),
            tree: MemTree::new(),
        }
    }

    /// Add one regular file (its bytes copied into wasm memory).
    pub fn add_file(&mut self, path: String, bytes: Vec<u8>) {
        self.tree.insert_file(PathBuf::from(path), bytes);
    }

    /// Record a symlink (`Versions/Current -> A` and friends), so detection
    /// that walks symlinked framework paths resolves correctly.
    pub fn add_symlink(&mut self, path: String, target: String) {
        self.tree
            .insert_symlink(PathBuf::from(path), PathBuf::from(target));
    }

    /// Analyse the app assembled so far and return the result JSON. Consumes
    /// the builder so its (potentially large) tree is freed before the caller
    /// moves on to the next app.
    pub fn finish(self) -> Result<String, JsValue> {
        let root = self.root.clone();
        vfs::set_ambient(self.tree);
        let result = run_analysis(Some(root), false, Vec::new());
        vfs::clear_ambient();
        to_json(&result)
    }
}

/// Analyse an uploaded `.app` (zipped) or bare `app.asar`.
///
/// `bytes` is the raw upload; `filename` disambiguates a bare `.asar` from a
/// zip when the magic is ambiguous. Returns the result JSON (same shape Tauri's
/// `invoke` delivers) or throws an error string.
#[wasm_bindgen]
pub fn analyze_app(bytes: Vec<u8>, filename: String) -> Result<String, JsValue> {
    let mut notes = Vec::new();
    let mut tree = MemTree::new();

    let treat_as_asar = filename.to_ascii_lowercase().ends_with(".asar") || looks_like_asar(&bytes);

    if treat_as_asar {
        // No bundle to inspect — drop the archive where an Electron macOS app
        // keeps it so the static scan can read it.
        tree.insert_file(asar_only_path(), bytes);
        notes.push("Uploaded a bare app.asar: framework/signing detection is unavailable; ran the static rule scan only.".to_string());
    } else if let Err(e) = unzip_into(&bytes, &mut tree) {
        return Err(JsValue::from_str(&format!(
            "could not read the uploaded zip: {e}"
        )));
    }

    vfs::set_ambient(tree);
    let app_path = if treat_as_asar {
        None
    } else {
        let found = find_app_root();
        if found.is_none() {
            notes.push(
                "Could not locate a .app bundle in the upload; analysed what was found."
                    .to_string(),
            );
        }
        found
    };
    let result = run_analysis(app_path, treat_as_asar, notes);
    vfs::clear_ambient();
    to_json(&result)
}

fn to_json(result: &AnalyzeResult) -> Result<String, JsValue> {
    serde_json::to_string(result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Look up CVEs for a set of detected runtime versions (the `detection.versions`
/// object). If `on_update` is given, it's called with each progressively
/// complete report JSON so the UI can paint fast sources (OSV/EUVD) before a
/// slow one finishes; the promise resolves with the final report JSON.
///
/// On the web build OSV + EUVD are queried (both keyless); NVD/GHSA are off by
/// default — see the `cve` crate's wasm settings.
#[wasm_bindgen]
pub async fn cve_lookup(
    versions_json: String,
    on_update: Option<js_sys::Function>,
) -> Result<String, JsValue> {
    let versions: detect::Versions =
        serde_json::from_str(&versions_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client = cve::OsvClient::new();
    let report = client
        .report_for_streaming(&versions, |snapshot| {
            if let Some(cb) = on_update.as_ref() {
                if let Ok(js) = serde_json::to_string(&snapshot) {
                    let _ = cb.call1(&JsValue::NULL, &JsValue::from_str(&js));
                }
            }
        })
        .await;
    serde_json::to_string(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Load one EUVD snapshot shard — the trimmed advisory array for a
/// `(vendor, product)` runtime pair — into the in-memory store the CVE lookup
/// reads. EUVD blocks browser-origin requests (CORS), so the web build reads a
/// pre-fetched same-origin snapshot instead. Called by the JS updater on page
/// load and whenever the SharedWorker broadcasts a fresh dataset.
#[wasm_bindgen]
pub fn euvd_set_shard(vendor: String, product: String, bytes: Vec<u8>) -> Result<(), JsValue> {
    cve::euvd_set_shard(vendor, product, &bytes).map_err(|e| JsValue::from_str(&e))
}

/// Mark the loaded shards as the active snapshot at `version` and clear the
/// session CVE memo so a mid-session update can't serve stale advisories.
#[wasm_bindgen]
pub fn euvd_commit(version: String) {
    cve::euvd_commit(version);
}

/// The currently-loaded EUVD snapshot version, or `None` if none is loaded yet.
/// The UI uses this to tell "snapshot not yet downloaded" apart from "no
/// advisories" — important so a missing snapshot never reads as "all clear".
#[wasm_bindgen]
pub fn euvd_snapshot_version() -> Option<String> {
    cve::euvd_snapshot_version()
}

/// Look up CVEs for bundled npm dependencies (the `dependencies` array of a
/// static-scan `Report`). Resolves with a JSON array of per-package advisories.
#[wasm_bindgen]
pub async fn dependency_scan(deps_json: String) -> Result<String, JsValue> {
    let deps: Vec<static_scan::Dependency> =
        serde_json::from_str(&deps_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if deps.is_empty() {
        return Ok("[]".to_string());
    }
    let npm: Vec<cve::NpmPackage> = deps
        .into_iter()
        .map(|d| cve::NpmPackage {
            name: d.name,
            version: d.version,
        })
        .collect();
    let settings = cve::load_settings();
    let client = cve::OsvClient::new();
    let mut results = client
        .batch_npm(&npm)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    cve::filter_npm_by_age(&mut results, settings.filters.max_age_years);
    serde_json::to_string(&results).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Run detection / audit / static-scan against the now-installed ambient tree.
fn run_analysis(
    app_path: Option<PathBuf>,
    treat_as_asar: bool,
    notes: Vec<String>,
) -> AnalyzeResult {
    let detection = app_path.as_ref().and_then(|p| detect::detect(p).ok());

    // `app_audit::audit` is async on native (it shells out to codesign) but the
    // wasm build compiles it without the `codesign` feature, so it does only
    // synchronous work and resolves on the first poll.
    let audit = app_path
        .as_ref()
        .and_then(|p| drive_to_completion(app_audit::audit(p, p, None)));

    let static_scan = locate_asar(treat_as_asar, app_path.as_deref())
        .and_then(|asar| static_scan::scan_asar(&asar).ok());

    AnalyzeResult {
        detection,
        audit,
        static_scan,
        notes,
    }
}

/// Poll an already-ready future to completion. `app_audit::audit` performs only
/// synchronous work on the no-codesign wasm build, so it never returns Pending.
fn drive_to_completion<F>(fut: F) -> Option<app_audit::AppAudit>
where
    F: std::future::Future<Output = Result<app_audit::AppAudit, app_audit::AuditError>>,
{
    use std::task::{Context, Poll};
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(r) => r.ok(),
        Poll::Pending => None,
    }
}

fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    // Safety: every vtable entry is a no-op or re-creates the same stateless waker.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

fn asar_only_path() -> PathBuf {
    PathBuf::from(SCAN_ROOT).join("App.app/Contents/Resources/app.asar")
}

/// Find the `app.asar` to statically scan.
fn locate_asar(treat_as_asar: bool, app_path: Option<&Path>) -> Option<PathBuf> {
    if treat_as_asar {
        return Some(asar_only_path());
    }
    let app = app_path?;
    for rel in [
        "Contents/Resources/app.asar",
        "Contents/Resources/electron.asar",
        "Contents/Resources/default_app.asar",
    ] {
        let candidate = app.join(rel);
        if vfs::is_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Locate the `.app` bundle root within an unpacked upload (the FSA path knows
/// its root up front and skips this).
fn find_app_root() -> Option<PathBuf> {
    let root = PathBuf::from(SCAN_ROOT);

    // The zip was created from *inside* the `.app` (its `Contents/` sits at the
    // archive root): the scan root itself is the bundle.
    if vfs::is_dir(root.join("Contents")) {
        return Some(root);
    }

    // Otherwise breadth-first search for a `*.app` directory (or any directory
    // holding `Contents/Info.plist`), a few levels deep.
    let mut queue = vec![(root, 0u32)];
    while let Some((dir, depth)) = queue.pop() {
        let Ok(entries) = vfs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let is_dir = matches!(entry.file_type(), Ok(ft) if ft.is_dir());
            if !is_dir {
                continue;
            }
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if name.ends_with(".app") || vfs::is_file(path.join("Contents/Info.plist")) {
                return Some(path);
            }
            if depth < 3 {
                queue.push((path, depth + 1));
            }
        }
    }
    None
}

/// True if `bytes` looks like an ASAR archive: the pickle outer size (first LE
/// u32) is 4. A zip would start with `PK\x03\x04` instead.
fn looks_like_asar(bytes: &[u8]) -> bool {
    bytes.len() >= 16 && u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == 4
}

/// Unpack a zip archive into `tree` under [`SCAN_ROOT`], preserving unix modes
/// and symlinks (macOS frameworks rely on `Versions/Current -> A`).
fn unzip_into(bytes: &[u8], tree: &mut MemTree) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let base = PathBuf::from(SCAN_ROOT);
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        // `enclosed_name` rejects path-traversal (`..`) entries.
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let dest = base.join(rel);
        if entry.is_dir() {
            tree.insert_dir(dest);
            continue;
        }
        let mode = entry.unix_mode().unwrap_or(0o644);
        // S_IFLNK
        if mode & 0o170000 == 0o120000 {
            let mut target = String::new();
            entry
                .read_to_string(&mut target)
                .map_err(|e| e.to_string())?;
            tree.insert_symlink(dest, PathBuf::from(target));
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        tree.insert_file_with_mode(dest, buf, mode);
    }
    Ok(())
}
