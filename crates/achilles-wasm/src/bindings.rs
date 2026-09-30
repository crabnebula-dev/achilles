//! Browser/WASM entry point for Achilles.
//!
//! The desktop app scans the machine it runs on; in the browser the same
//! analysis runs against an in-memory filesystem ([`vfs::MemTree`]) built from
//! one of two sources:
//!
//! * [`Analyzer`] — a streaming builder. The JS side enumerates a directory
//!   the user granted via the File System Access API (`showDirectoryPicker`,
//!   Chrome/Edge), reads each file, and pushes it in with [`Analyzer::add_file`]
//!   before calling [`Analyzer::finish`]. This is the "scan the local
//!   filesystem" path: one `Analyzer` per app, scanned and dropped in turn.
//! * [`analyze_app`] — a one-shot for an uploaded zip of an app directory, a
//!   bare executable, or a bare `app.asar` — the cross-browser fallback
//!   (Firefox/Safari, or drag-drop).
//!
//! Unlike the desktop, the browser has no host OS to infer a layout from: the
//! upload may be a macOS `.app`, a Windows install directory, or a Linux app
//! tree. So each job first works out which ([`upload::sniff_platform`], or an
//! explicit override from JS), declares it with [`vfs::set_platform`], and only
//! then runs the exact same synchronous `detect` / `app_audit` / `static_scan`
//! crates the desktop build runs — those dispatch on the ambient platform.
//!
//! Each entry point returns one JSON object
//! `{ detection, audit, staticScan, platform, notes }` — the shape Tauri's
//! `invoke` delivers — which the UI shim re-splits into per-command results.

use std::io::{Cursor, Read};
use std::path::PathBuf;

use detect::DiscoveredApp;
use vfs::{MemTree, Platform};
use wasm_bindgen::prelude::*;

use crate::upload;

/// Synthetic root the upload/scan is unpacked under. The analysis crates treat
/// this like `/Applications/Foo.app` on the desktop — they never see the
/// difference.
const SCAN_ROOT: &str = "/scan";

/// How far a Linux package may expand inside the wasm heap. Packages are
/// compressed, so unlike a folder upload the size on disk says little about the
/// size in memory; this matches the folder path's own ceiling so a package and
/// a directory of the same app are treated alike, and turns a decompression
/// bomb into a message rather than an out-of-memory trap.
const MAX_PACKAGE_BYTES: u64 = 2 << 30;

/// Combined result of analysing one app. Field names match the keys the UI
/// already uses for its JSON export, so the shim can serve each `invoke(...)`
/// from this single object.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalyzeResult {
    detection: Option<detect::Detection>,
    audit: Option<app_audit::AppAudit>,
    static_scan: Option<static_scan::Report>,
    /// Which platform's layout the upload was read as — sniffed unless the
    /// caller said otherwise. Surfaced so the UI can show (and correct) it.
    platform: Platform,
    /// Human-readable notes about what was (or couldn't be) analysed.
    notes: Vec<String>,
}

/// Streaming builder for the File System Access path: one app is assembled
/// file-by-file, then analysed. `app_root` is an absolute path (e.g.
/// `/scan/Foo.app`); every `add_*` path must sit under it.
#[wasm_bindgen]
pub struct Analyzer {
    root: PathBuf,
    /// Explicit platform from JS, if the caller knows better than the sniffer.
    platform: Option<Platform>,
    tree: MemTree,
}

#[wasm_bindgen]
impl Analyzer {
    /// `platform` is optional: `"macos"` / `"windows"` / `"linux"` to force a
    /// layout, or omitted to infer it from the files pushed in.
    #[wasm_bindgen(constructor)]
    pub fn new(app_root: String, platform: Option<String>) -> Analyzer {
        Analyzer {
            root: PathBuf::from(app_root),
            platform: platform.as_deref().and_then(Platform::parse),
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
        let forced = self.platform;
        vfs::set_ambient(self.tree);

        let platform = forced.unwrap_or_else(|| upload::sniff_platform(&root));
        vfs::set_platform(platform);

        let app = upload::find_app(&root, platform);
        let notes = match (&app, platform.is_bundle()) {
            (Some(_), _) => Vec::new(),
            (None, true) => vec!["No .app bundle found in this folder.".to_string()],
            (None, false) => vec![format!(
                "No {} application found in this folder — it holds no executable.",
                platform.as_str()
            )],
        };
        let result = run_analysis(app, platform, notes);
        vfs::clear_ambient();
        to_json(&result)
    }
}

/// Analyse an uploaded app: a zipped app directory (`.app`, a Windows install
/// folder, a Linux app tree), a Linux package (AppImage, snap, `.deb`, `.rpm`,
/// tarball), a bare executable, or a bare `app.asar`.
///
/// `bytes` is the raw upload; `filename` disambiguates a bare `.asar` from a
/// zip when the magic is ambiguous, and names the tarball spellings that have
/// no magic of their own. `platform` optionally forces the layout (`"macos"` /
/// `"windows"` / `"linux"`) instead of inferring it. Returns the result JSON
/// (same shape Tauri's `invoke` delivers) or throws an error string.
#[wasm_bindgen]
pub fn analyze_app(
    bytes: Vec<u8>,
    filename: String,
    platform: Option<String>,
) -> Result<String, JsValue> {
    let forced = platform.as_deref().and_then(Platform::parse);
    let mut notes = Vec::new();
    let mut tree = MemTree::new();
    let base = PathBuf::from(SCAN_ROOT);

    let Some(kind) = Upload::classify(&bytes, &filename) else {
        return Err(JsValue::from_str(unsupported_message(&bytes)));
    };
    match kind {
        Upload::Asar => {
            // No bundle to inspect — drop the archive where an Electron app
            // keeps it so the static scan can read it.
            tree.insert_file(asar_only_path(), bytes);
            notes.push("Uploaded a bare app.asar: framework/signing detection is unavailable; ran the static rule scan only.".to_string());
        }
        Upload::Binary(_) => {
            tree.insert_file(base.join(binary_name(&filename)), bytes);
            notes.push(
                "Uploaded a single executable: only what the binary itself carries \
                 (imports and embedded version strings) could be analysed — no sibling \
                 runtime files to inspect."
                    .to_string(),
            );
        }
        Upload::Zip => {
            if let Err(e) = unzip_into(&bytes, &mut tree) {
                return Err(JsValue::from_str(&format!(
                    "could not read the uploaded zip: {e}"
                )));
            }
        }
        Upload::Package(format) => {
            let mut sink = TreeSink(&mut tree);
            match pkg::unpack_with_limit(&bytes, format, &base, &mut sink, MAX_PACKAGE_BYTES) {
                Ok(summary) => {
                    notes.push(format!(
                        "Unpacked a {} ({} files, {:.0} MB) and analysed the application inside it.",
                        summary.format,
                        summary.files,
                        summary.bytes as f64 / (1024.0 * 1024.0),
                    ));
                    notes.extend(summary.warnings);
                }
                Err(e) => {
                    return Err(JsValue::from_str(&format!(
                        "could not read this {format}: {e}"
                    )))
                }
            }
        }
    }

    vfs::set_ambient(tree);

    // The bare-asar case has no tree to sniff and no layout that matters: the
    // archive sits where a macOS Electron app keeps it, so read it that way.
    let platform = match (forced, kind) {
        (Some(p), _) => p,
        (None, Upload::Asar) => Platform::Macos,
        (None, Upload::Binary(p)) => p,
        // Every format `pkg` reads is a Linux one; there is nothing to sniff.
        (None, Upload::Package(_)) => Platform::Linux,
        (None, Upload::Zip) => upload::sniff_platform(&base),
    };
    vfs::set_platform(platform);

    let app = match kind {
        Upload::Asar => None,
        Upload::Binary(_) => Some(upload::single_binary(&base.join(binary_name(&filename)))),
        Upload::Zip | Upload::Package(_) => {
            let found = if matches!(kind, Upload::Package(_)) {
                upload::find_app_in_payload(&base)
            } else {
                upload::find_app(&base, platform)
            };
            if found.is_none() {
                notes.push(format!(
                    "Could not locate a {} application in the upload; analysed what was found.",
                    platform.as_str()
                ));
            }
            found
        }
    };

    let result = run_analysis(app, platform, notes);
    vfs::clear_ambient();
    to_json(&result)
}

/// What the raw upload actually is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Upload {
    /// A zip archive of an application directory.
    Zip,
    /// A bare `app.asar`.
    Asar,
    /// A single executable, with the platform its magic implies.
    Binary(Platform),
    /// A Linux application package to unpack first — see the [`pkg`] crate.
    Package(pkg::Format),
}

impl Upload {
    /// `None` when the bytes match nothing we can analyse — the caller reports
    /// [`unsupported_message`] rather than guessing, since the UI accepts any
    /// extension-less file (a Linux app binary has no extension to check).
    fn classify(bytes: &[u8], filename: &str) -> Option<Upload> {
        let lower = filename.to_ascii_lowercase();
        if lower.ends_with(".asar") || looks_like_asar(bytes) {
            return Some(Upload::Asar);
        }
        // Packages come before the bare-binary check below: an AppImage is an
        // ELF as well, and reading it as a lone executable would find only the
        // runtime stub — never the application in the filesystem behind it.
        if let Some(format) = pkg::sniff(bytes, filename) {
            return Some(Upload::Package(format));
        }
        if bytes.starts_with(b"PK\x03\x04") || lower.ends_with(".zip") {
            return Some(Upload::Zip);
        }
        // A lone executable identifies its own platform: a PE is a Windows app,
        // an ELF a Linux one. (A Mach-O doesn't qualify — it's the inner binary
        // of a `.app`, and on its own carries no bundle to audit.)
        if bytes.starts_with(b"MZ") {
            return Some(Upload::Binary(Platform::Windows));
        }
        if bytes.starts_with(b"\x7fELF") {
            return Some(Upload::Binary(Platform::Linux));
        }
        None
    }
}

/// Adapts [`pkg`]'s unpack sink to the in-memory tree the analysis reads.
struct TreeSink<'a>(&'a mut MemTree);

impl pkg::Sink for TreeSink<'_> {
    fn dir(&mut self, path: &std::path::Path) -> Result<(), pkg::PkgError> {
        self.0.insert_dir(path.to_path_buf());
        Ok(())
    }

    fn file(
        &mut self,
        path: &std::path::Path,
        data: Vec<u8>,
        mode: u32,
    ) -> Result<(), pkg::PkgError> {
        self.0.insert_file_with_mode(path.to_path_buf(), data, mode);
        Ok(())
    }

    fn symlink(
        &mut self,
        path: &std::path::Path,
        target: &std::path::Path,
    ) -> Result<(), pkg::PkgError> {
        self.0
            .insert_symlink(path.to_path_buf(), target.to_path_buf());
        Ok(())
    }
}

/// Mach-O headers, in both widths and both byte orders, plus the universal
/// ("fat") wrappers. Only used to tell the user they uploaded the binary from
/// *inside* a `.app` instead of the bundle.
const MACHO_MAGICS: &[&[u8]] = &[
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
];

/// Why an upload couldn't be read, phrased as the next thing to try.
fn unsupported_message(bytes: &[u8]) -> &'static str {
    if MACHO_MAGICS.iter().any(|m| bytes.starts_with(m)) {
        return "this is a Mach-O binary — the executable from inside a .app, which \
                on its own carries no bundle to analyse. Zip the whole .app and \
                upload that instead.";
    }
    "unrecognised file: expected a zipped app (.zip), a Linux package \
     (.AppImage, .snap, .deb, .rpm, .tar.gz), a Windows .exe, a Linux \
     executable, or an app.asar."
}

/// Where a single uploaded binary lands. Falls back to a fixed name so a
/// filename with path separators can't escape the scan root.
fn binary_name(filename: &str) -> String {
    let name = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() || name == "." || name == ".." {
        "app-binary".to_string()
    } else {
        name
    }
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
/// The ambient platform must already be set — every one of these dispatches on
/// it.
fn run_analysis(
    app: Option<DiscoveredApp>,
    platform: Platform,
    notes: Vec<String>,
) -> AnalyzeResult {
    let detection = app.as_ref().and_then(|a| detect::detect_app(a).ok());

    // Prefer detection's resolved root / executable over the ones we guessed:
    // it applies the same corrections the desktop scanner does (a Windows
    // Squirrel stub redirects to the real versioned app dir, macOS resolves
    // `CFBundleExecutable`), and the audit and static scan must follow it.
    let root = detection
        .as_ref()
        .map(|d| d.root.clone())
        .or_else(|| app.as_ref().map(|a| a.root.clone()));
    let executable = detection
        .as_ref()
        .and_then(|d| d.executable.clone())
        .or_else(|| app.as_ref().and_then(|a| a.executable.clone()));

    // `app_audit::audit` is async on native (it shells out to codesign) but the
    // wasm build compiles it without the `codesign` feature, so it does only
    // synchronous work and resolves on the first poll.
    let audit = app.as_ref().zip(root.as_ref()).and_then(|(a, root)| {
        drive_to_completion(app_audit::audit(&a.path, root, executable.as_deref()))
    });

    let static_scan =
        scan_target(root.as_deref(), platform).and_then(|t| static_scan::scan(&t).ok());

    AnalyzeResult {
        detection,
        audit,
        static_scan,
        platform,
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

/// What the static rule scan should read: the app's `app.asar` (or unpacked
/// `app/` directory), or the standalone archive of a bare `.asar` upload.
fn scan_target(root: Option<&std::path::Path>, platform: Platform) -> Option<PathBuf> {
    match root {
        Some(root) => upload::locate_scan_target(root, platform),
        // No app means the bare-asar upload, which we parked at a known path.
        None => vfs::is_file(asar_only_path()).then(asar_only_path),
    }
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
