//! Linux side-effects backend.
//!
//! Maps the macOS launchd / `~/Library` conventions onto their freedesktop
//! equivalents: sibling binaries in the install dir, browser native-messaging
//! hosts under `~/.config` / `~/.mozilla`, autostart `.desktop` entries +
//! systemd user units, and the app's `~/.config` / `~/.local/share` data dir.

use std::path::{Path, PathBuf};

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
    let launch_entries = launch_entries(install_dir, executable, exe_stem.as_deref());
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

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".config")))
}

/// Executable files sitting next to the main binary (Electron helper procs,
/// updaters, crash handlers, …) — the Linux analog of `Contents/Helpers`.
fn sibling_helpers(dir: &Path, main: Option<&Path>) -> Vec<BundleHelper> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        if Some(path.as_path()) == main {
            continue;
        }
        if !is_executable(&meta) {
            continue;
        }
        // Helper *processes*, not the shared libraries / data files that sit in
        // the same dir — those aren't "side effects", they're the runtime.
        let is_helper_exe = matches!(
            path.extension().and_then(|e| e.to_str()),
            None | Some("exe")
        );
        if !is_helper_exe {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        out.push(BundleHelper {
            name,
            path,
            size_bytes: Some(meta.len()),
            bundle_id: None,
            version: None,
            is_bundle: false,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Chromium + Firefox native-messaging host manifests that point back into the
/// app's install dir.
fn native_messaging_hosts(
    install_dir: Option<&Path>,
    exe_stem: Option<&str>,
) -> Vec<NativeMessagingHost> {
    let Some(cfg) = config_home() else {
        return Vec::new();
    };
    let home = home();

    // (display name, manifest directory).
    let mut dirs: Vec<(String, PathBuf)> = vec![
        (
            "Chrome".into(),
            cfg.join("google-chrome/NativeMessagingHosts"),
        ),
        ("Chromium".into(), cfg.join("chromium/NativeMessagingHosts")),
        (
            "Brave".into(),
            cfg.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        ),
        (
            "Edge".into(),
            cfg.join("microsoft-edge/NativeMessagingHosts"),
        ),
        ("Vivaldi".into(), cfg.join("vivaldi/NativeMessagingHosts")),
        ("Opera".into(), cfg.join("opera/NativeMessagingHosts")),
    ];
    if let Some(h) = &home {
        dirs.push(("Firefox".into(), h.join(".mozilla/native-messaging-hosts")));
    }

    let mut out = Vec::new();
    for (browser, dir) in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "json").unwrap_or(true) {
                continue;
            }
            if let Some(host) = parse_manifest(&browser, &path, install_dir, exe_stem) {
                out.push(host);
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

    // Only report manifests whose native binary points back into this app.
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

    let (created_at, modified_at) = file_times(path);
    Some(NativeMessagingHost {
        browser: browser.to_string(),
        manifest_path: path.to_path_buf(),
        host_name,
        target_path,
        allowed_origins,
        created_at,
        modified_at,
    })
}

/// Autostart `.desktop` entries and systemd user units that launch this app.
fn launch_entries(
    install_dir: Option<&Path>,
    executable: Option<&Path>,
    exe_stem: Option<&str>,
) -> Vec<LaunchEntry> {
    let mut out = Vec::new();
    let refers = |cmd: &str| references(cmd, install_dir, executable, exe_stem);

    // ~/.config/autostart + /etc/xdg/autostart.
    let mut autostart_dirs = Vec::new();
    if let Some(cfg) = config_home() {
        autostart_dirs.push(cfg.join("autostart"));
    }
    autostart_dirs.push(PathBuf::from("/etc/xdg/autostart"));
    for dir in autostart_dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "desktop").unwrap_or(true) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let exec = ini_value(&text, "Exec");
            if let Some(exec) = exec {
                if refers(&exec) {
                    out.push(LaunchEntry {
                        scope: LaunchScope::Autostart,
                        plist_path: path.clone(),
                        label: ini_value(&text, "Name"),
                        program: exec,
                        run_at_load: true,
                        keep_alive: false,
                        modified_at: file_times(&path).1,
                    });
                }
            }
        }
    }

    // ~/.config/systemd/user/*.service.
    if let Some(cfg) = config_home() {
        let dir = cfg.join("systemd/user");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e != "service").unwrap_or(true) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if let Some(exec) = ini_value(&text, "ExecStart") {
                    if refers(&exec) {
                        out.push(LaunchEntry {
                            scope: LaunchScope::SystemdUser,
                            plist_path: path.clone(),
                            label: path.file_stem().map(|s| s.to_string_lossy().into_owned()),
                            program: exec,
                            run_at_load: text.contains("WantedBy="),
                            keep_alive: text.to_lowercase().contains("restart=always"),
                            modified_at: file_times(&path).1,
                        });
                    }
                }
            }
        }
    }

    out
}

fn references(
    cmd: &str,
    install_dir: Option<&Path>,
    executable: Option<&Path>,
    exe_stem: Option<&str>,
) -> bool {
    let cmd_l = cmd.to_ascii_lowercase();
    if let Some(exe) = executable {
        if cmd.contains(&*exe.to_string_lossy()) {
            return true;
        }
    }
    if let Some(dir) = install_dir {
        if cmd.contains(&*dir.to_string_lossy()) {
            return true;
        }
    }
    // Avoid matching very short/generic stems that would over-match.
    if let Some(stem) = exe_stem {
        if stem.len() >= 4 && cmd_l.contains(stem) {
            return true;
        }
    }
    false
}

/// The app's out-of-place data directory under `~/.config` or
/// `~/.local/share`.
fn data_dir(bundle_id: Option<&str>, exe_stem: Option<&str>) -> Option<crate::LogDirectory> {
    let home = home()?;
    let cfg = config_home()?;
    let share = home.join(".local/share");

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

    for base in [cfg, share] {
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

/// Read a flat `Key=Value` from a `.desktop` / unit file's first matching line.
fn ini_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// `(created, modified)` epoch seconds, best effort.
fn file_times(path: &Path) -> (Option<u64>, Option<u64>) {
    use std::time::UNIX_EPOCH;
    let Ok(meta) = std::fs::metadata(path) else {
        return (None, None);
    };
    let to_secs = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    };
    (to_secs(meta.created()), to_secs(meta.modified()))
}
