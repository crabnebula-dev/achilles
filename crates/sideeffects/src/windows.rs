//! Windows side-effects backend.
//!
//! Maps the macOS conventions onto Windows: sibling `.exe`s in the install
//! dir, browser native-messaging hosts registered via the registry, auto-start
//! `Run` keys + Startup-folder shortcuts + Task Scheduler tasks, and the app's
//! `%LOCALAPPDATA%` / `%APPDATA%` data dir.

use std::path::{Path, PathBuf};

use winreg::enums::*;
use winreg::RegKey;

use crate::types::{BundleHelper, LaunchEntry, LaunchScope, NativeMessagingHost};
use crate::SideEffects;

pub fn analyse(app_path: &Path, bundle_id: Option<&str>, executable: Option<&Path>) -> SideEffects {
    let install_dir = executable.and_then(Path::parent);
    let exe_stem = executable
        .and_then(|e| e.file_stem())
        .map(|s| s.to_string_lossy().to_ascii_lowercase());

    let helpers = install_dir
        .map(|dir| sibling_helpers(dir, executable))
        .unwrap_or_default();
    let native_messaging_hosts = native_messaging_hosts(install_dir, exe_stem.as_deref());
    let mut launch_entries = run_keys(install_dir, executable, exe_stem.as_deref());
    launch_entries.extend(startup_shortcuts(install_dir, exe_stem.as_deref()));
    launch_entries.extend(scheduled_tasks(install_dir, exe_stem.as_deref()));
    let log_dir = data_dir(bundle_id, exe_stem.as_deref());

    SideEffects {
        app_path: app_path.to_path_buf(),
        helpers,
        plugins: Vec::new(),
        xpc_services: Vec::new(),
        native_messaging_hosts,
        launch_entries,
        log_dir,
    }
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

/// Sibling `.exe`s next to the main binary (helper procs, updaters, …).
fn sibling_helpers(dir: &Path, main: Option<&Path>) -> Vec<BundleHelper> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .map(|e| !e.eq_ignore_ascii_case("exe"))
            .unwrap_or(true)
        {
            continue;
        }
        if Some(path.as_path()) == main {
            continue;
        }
        let size = entry.metadata().ok().map(|m| m.len());
        let name = entry.file_name().to_string_lossy().into_owned();
        out.push(BundleHelper {
            name,
            path,
            size_bytes: size,
            bundle_id: None,
            version: None,
            is_bundle: false,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Browser native-messaging hosts registered under
/// `…\<Browser>\NativeMessagingHosts\<name>` (default value → manifest path).
fn native_messaging_hosts(
    install_dir: Option<&Path>,
    exe_stem: Option<&str>,
) -> Vec<NativeMessagingHost> {
    const BROWSERS: &[(&str, &str)] = &[
        ("Chrome", r"Software\Google\Chrome\NativeMessagingHosts"),
        ("Chromium", r"Software\Chromium\NativeMessagingHosts"),
        ("Edge", r"Software\Microsoft\Edge\NativeMessagingHosts"),
        (
            "Brave",
            r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
        ),
        ("Firefox", r"Software\Mozilla\NativeMessagingHosts"),
    ];

    let mut out = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        for (browser, sub) in BROWSERS {
            let Ok(key) = root.open_subkey(sub) else {
                continue;
            };
            for host_name in key.enum_keys().flatten() {
                let Ok(host_key) = key.open_subkey(&host_name) else {
                    continue;
                };
                let Ok(manifest_path) = host_key.get_value::<String, _>("") else {
                    continue;
                };
                if let Some(host) =
                    parse_manifest(browser, Path::new(&manifest_path), install_dir, exe_stem)
                {
                    out.push(host);
                }
            }
        }
    }
    out
}

fn parse_manifest(
    browser: &str,
    path: &Path,
    install_dir: Option<&Path>,
    exe_stem: Option<&str>,
) -> Option<NativeMessagingHost> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let target_path = value.get("path")?.as_str()?.to_string();

    let references_app = install_dir
        .map(|d| Path::new(&target_path).starts_with(d))
        .unwrap_or(false)
        || exe_stem
            .map(|stem| target_path.to_ascii_lowercase().contains(stem))
            .unwrap_or(false);
    if !references_app {
        return None;
    }

    let host_name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let allowed_origins = value
        .get("allowed_origins")
        .or_else(|| value.get("allowed_extensions"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Some(NativeMessagingHost {
        browser: browser.to_string(),
        manifest_path: path.to_path_buf(),
        host_name,
        target_path,
        allowed_origins,
        created_at: None,
        modified_at: None,
    })
}

/// `HKCU` / `HKLM` `…\Run` values whose command references the app.
fn run_keys(
    install_dir: Option<&Path>,
    executable: Option<&Path>,
    exe_stem: Option<&str>,
) -> Vec<LaunchEntry> {
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let mut out = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let Ok(key) = RegKey::predef(hive).open_subkey(RUN) else {
            continue;
        };
        for (name, value) in key.enum_values().flatten() {
            let cmd = value.to_string();
            if references(&cmd, install_dir, executable, exe_stem) {
                out.push(LaunchEntry {
                    scope: LaunchScope::RunKey,
                    plist_path: PathBuf::from(format!(r"{RUN}\{name}")),
                    label: Some(name),
                    program: cmd,
                    run_at_load: true,
                    keep_alive: false,
                    modified_at: None,
                });
            }
        }
    }
    out
}

/// `.lnk` shortcuts in the per-user / all-users Startup folders.
fn startup_shortcuts(install_dir: Option<&Path>, exe_stem: Option<&str>) -> Vec<LaunchEntry> {
    let mut dirs = Vec::new();
    if let Some(appdata) = env_path("APPDATA") {
        dirs.push(appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Some(pd) = env_path("ProgramData") {
        dirs.push(pd.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }

    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map(|e| !e.eq_ignore_ascii_case("lnk"))
                .unwrap_or(true)
            {
                continue;
            }
            let Some(target) = resolve_lnk(&path) else {
                continue;
            };
            if references(&target.to_string_lossy(), install_dir, None, exe_stem) {
                out.push(LaunchEntry {
                    scope: LaunchScope::StartupFolder,
                    plist_path: path.clone(),
                    label: path.file_stem().map(|s| s.to_string_lossy().into_owned()),
                    program: target.to_string_lossy().into_owned(),
                    run_at_load: true,
                    keep_alive: false,
                    modified_at: None,
                });
            }
        }
    }
    out
}

/// Resolve a `.lnk` to its target path via the Windows Shell COM API
/// (`IShellLinkW`), letting the OS parse the link. This avoids third-party
/// `.lnk` parsers that panic on non-standard files (e.g. a shortcut carrying an
/// un-terminated console face name in its `ConsoleDataBlock`).
fn resolve_lnk(path: &Path) -> Option<PathBuf> {
    use std::cell::Cell;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED, STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    thread_local! {
        // COM must be initialised once per thread before any shell object is
        // created. We never call `CoUninitialize`; the apartment lives for the
        // thread's lifetime, which is fine for our short-lived worker threads.
        static COM_READY: Cell<bool> = const { Cell::new(false) };
    }
    COM_READY.with(|ready| {
        if !ready.get() {
            // `S_FALSE` (already initialised) and `RPC_E_CHANGED_MODE` (thread
            // already in another apartment) both leave COM usable in-proc.
            unsafe {
                let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            }
            ready.set(true);
        }
    });

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let target = unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let persist: IPersistFile = link.cast().ok()?;
        persist.Load(PCWSTR(wide.as_ptr()), STGM_READ).ok()?;

        // Flags `0`: fully resolved target with environment strings expanded.
        let mut buf = [0u16; 260]; // MAX_PATH
        link.GetPath(&mut buf, std::ptr::null_mut(), 0).ok()?;

        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    };

    if target.is_empty() {
        None
    } else {
        Some(PathBuf::from(target))
    }
}

/// Task Scheduler tasks (XML files under `System32\Tasks`) whose `<Command>`
/// references the app — read as plain XML, no COM.
fn scheduled_tasks(install_dir: Option<&Path>, exe_stem: Option<&str>) -> Vec<LaunchEntry> {
    let Some(windir) = env_path("WINDIR").or_else(|| env_path("SystemRoot")) else {
        return Vec::new();
    };
    let tasks_root = windir.join(r"System32\Tasks");

    let mut out = Vec::new();
    let mut stack = vec![tasks_root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(cmd) = xml_tag(&text, "Command") {
                if references(&cmd, install_dir, None, exe_stem) {
                    out.push(LaunchEntry {
                        scope: LaunchScope::ScheduledTask,
                        plist_path: path.clone(),
                        label: path.file_name().map(|s| s.to_string_lossy().into_owned()),
                        program: cmd,
                        run_at_load: false,
                        keep_alive: false,
                        modified_at: None,
                    });
                }
            }
        }
    }
    out
}

fn xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].trim().to_string())
}

fn references(
    cmd: &str,
    install_dir: Option<&Path>,
    executable: Option<&Path>,
    exe_stem: Option<&str>,
) -> bool {
    let cmd_l = cmd.to_ascii_lowercase();
    if let Some(exe) = executable {
        if cmd_l.contains(&*exe.to_string_lossy().to_ascii_lowercase()) {
            return true;
        }
    }
    if let Some(dir) = install_dir {
        if cmd_l.contains(&*dir.to_string_lossy().to_ascii_lowercase()) {
            return true;
        }
    }
    if let Some(stem) = exe_stem {
        if stem.len() >= 4 && cmd_l.contains(stem) {
            return true;
        }
    }
    false
}

fn data_dir(bundle_id: Option<&str>, exe_stem: Option<&str>) -> Option<crate::LogDirectory> {
    let mut names: Vec<String> = Vec::new();
    if let Some(id) = bundle_id {
        names.push(id.to_string());
        if let Some(tail) = id.rsplit('.').next() {
            names.push(tail.to_string());
        }
    }
    if let Some(stem) = exe_stem {
        names.push(stem.to_string());
    }

    let mut bases = Vec::new();
    if let Some(local) = env_path("LOCALAPPDATA") {
        bases.push(local);
    }
    if let Some(roaming) = env_path("APPDATA") {
        bases.push(roaming);
    }

    for base in bases {
        for name in &names {
            let candidate = base.join(name);
            if candidate.is_dir() {
                if let Some(stats) = crate::dir_stats(&candidate) {
                    return Some(stats);
                }
            }
        }
    }
    None
}
