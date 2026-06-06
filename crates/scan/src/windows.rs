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
///
/// Resolution goes through the Windows Shell COM API (`IShellLinkW`) so the OS
/// itself parses the link. This avoids third-party `.lnk` parsers that panic on
/// non-standard files (e.g. a shortcut whose `ConsoleDataBlock` carries an
/// un-terminated console face name), and it correctly handles relative targets,
/// environment-variable expansion, and target relocation for free.
fn resolve_shortcut(lnk_path: &Path) -> Option<PathBuf> {
    let target = shell::resolve_link_target(lnk_path)?;
    if is_app_exe(&target) {
        Some(target)
    } else {
        None
    }
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

/// Resolve `.lnk` shortcuts through the Windows Shell COM API.
mod shell {
    use std::cell::Cell;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED, STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    thread_local! {
        /// COM must be initialised once per thread before any shell object is
        /// created. We never call `CoUninitialize` — the apartment lives for the
        /// thread's lifetime, which is fine for our short-lived worker threads.
        static COM_READY: Cell<bool> = const { Cell::new(false) };
    }

    fn ensure_com() {
        COM_READY.with(|ready| {
            if !ready.get() {
                // Ignore the result: `S_FALSE` (already initialised) and
                // `RPC_E_CHANGED_MODE` (thread already in a different apartment)
                // both still leave COM usable for in-proc shell objects.
                unsafe {
                    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
                }
                ready.set(true);
            }
        });
    }

    /// Ask the OS to resolve a `.lnk` to its target path. Returns `None` on any
    /// COM failure or when the link has no filesystem target.
    pub fn resolve_link_target(lnk_path: &Path) -> Option<PathBuf> {
        ensure_com();

        let wide: Vec<u16> = lnk_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let target = unsafe {
            let link: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
            let persist: IPersistFile = link.cast().ok()?;
            persist.Load(PCWSTR(wide.as_ptr()), STGM_READ).ok()?;

            // Flags `0`: return the fully resolved target with any environment
            // strings expanded, so the result is a concrete path we can stat.
            let mut buf = [0u16; 260]; // MAX_PATH
            link.GetPath(&mut buf, std::ptr::null_mut(), 0).ok()?;

            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            String::from_utf16_lossy(&buf[..len])
        };

        if target.is_empty() {
            return None;
        }
        Some(PathBuf::from(target))
    }
}
