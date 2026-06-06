//! Windows discovery via Start Menu shortcuts plus per-user `Programs`
//! installs.
//!
//! A Start Menu `.lnk` is the natural "this is a GUI app the user launches"
//! signal, so resolving those shortcuts to their target `.exe` gives a clean,
//! low-noise list. We additionally scan `%LOCALAPPDATA%\Programs` because the
//! popular Electron apps (VS Code, Discord, Slack, …) install per-user there
//! and don't always leave an all-users shortcut.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use detect::DiscoveredApp;

use crate::ScanError;

pub fn discover() -> Result<Vec<DiscoveredApp>, ScanError> {
    let mut apps: Vec<DiscoveredApp> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for dir in start_menu_dirs() {
        collect_shortcuts(&dir, &mut apps, &mut seen);
    }
    for dir in program_dirs() {
        collect_programs(&dir, &mut apps, &mut seen);
    }

    apps.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(apps)
}

fn start_menu_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(pd) = std::env::var_os("ProgramData") {
        dirs.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Some(ad) = std::env::var_os("APPDATA") {
        dirs.push(PathBuf::from(ad).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    dirs
}

fn program_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        dirs.push(PathBuf::from(local).join("Programs"));
    }
    dirs
}

/// Recursively resolve every `.lnk` under `dir` to its target executable.
fn collect_shortcuts(dir: &Path, apps: &mut Vec<DiscoveredApp>, seen: &mut HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_shortcuts(&path, apps, seen);
            continue;
        }
        if path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("lnk"))
            .unwrap_or(false)
        {
            if let Some(target) = resolve_shortcut(&path) {
                let name = path.file_stem().map(|s| s.to_string_lossy().into_owned());
                push_app(target, name, apps, seen);
            }
        }
    }
}

/// Resolve a `.lnk` to the `.exe` it points at, if any.
fn resolve_shortcut(lnk_path: &Path) -> Option<PathBuf> {
    let link = lnk::ShellLink::open(lnk_path).ok()?;

    // Prefer the absolute local target recorded in the link info.
    if let Some(info) = link.link_info() {
        if let Some(base) = info.local_base_path() {
            let p = PathBuf::from(base);
            if is_app_exe(&p) {
                return Some(p);
            }
        }
    }

    // Fall back to the relative path resolved against the shortcut's folder.
    if let Some(rel) = link.relative_path() {
        let base = lnk_path.parent().unwrap_or_else(|| Path::new("."));
        if let Ok(p) = normalise(&base.join(rel)) {
            if is_app_exe(&p) {
                return Some(p);
            }
        }
    }

    None
}

/// Scan `%LOCALAPPDATA%\Programs\<app>\` for a primary executable.
fn collect_programs(dir: &Path, apps: &mut Vec<DiscoveredApp>, seen: &mut HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let app_dir = entry.path();
        if !app_dir.is_dir() {
            continue;
        }
        let dir_name = app_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        // Prefer `<dirname>.exe`, else the first top-level `.exe`.
        let primary = dir_name
            .as_ref()
            .map(|n| app_dir.join(format!("{n}.exe")))
            .filter(|p| p.is_file())
            .or_else(|| first_exe(&app_dir));
        if let Some(exe) = primary {
            if is_app_exe(&exe) {
                push_app(exe, dir_name, apps, seen);
            }
        }
    }
}

fn first_exe(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if is_app_exe(&path) {
            return Some(path);
        }
    }
    None
}

fn push_app(
    exe: PathBuf,
    name: Option<String>,
    apps: &mut Vec<DiscoveredApp>,
    seen: &mut HashSet<String>,
) {
    let key = exe.to_string_lossy().to_ascii_lowercase();
    if !seen.insert(key) {
        return;
    }
    let root = exe
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| exe.clone());
    apps.push(DiscoveredApp {
        path: exe.clone(),
        root,
        executable: Some(exe),
        name,
    });
}

/// True for an existing `.exe` that isn't an obvious installer / updater /
/// uninstaller helper — those aren't the GUI app itself.
fn is_app_exe(path: &Path) -> bool {
    if path
        .extension()
        .map(|e| !e.eq_ignore_ascii_case("exe"))
        .unwrap_or(true)
    {
        return false;
    }
    if !path.is_file() {
        return false;
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    const SKIP: &[&str] = &[
        "unins",
        "uninstall",
        "setup",
        "update",
        "updater",
        "installer",
        "crashpad_handler",
    ];
    !SKIP.iter().any(|s| stem.contains(s))
}

/// Best-effort path normalisation without touching the filesystem layout.
fn normalise(path: &Path) -> std::io::Result<PathBuf> {
    // `canonicalize` would resolve symlinks and verify existence; for a target
    // that may not exist we just clean it up lexically.
    Ok(path.components().collect())
}
