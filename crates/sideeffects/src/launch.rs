//! `launchd` agent / daemon audit.
//!
//! Scan the three standard plist directories and return every entry whose
//! `Program` or `ProgramArguments[0]` points back into the app bundle or
//! references the main executable.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LaunchScope {
    /// `~/Library/LaunchAgents/` — runs on user login.
    UserAgent,
    /// `/Library/LaunchAgents/` — runs on every user's login (needs admin).
    GlobalAgent,
    /// `/Library/LaunchDaemons/` — runs as root at boot.
    Daemon,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchEntry {
    pub scope: LaunchScope,
    /// The plist file on disk.
    pub plist_path: PathBuf,
    /// `Label` key — the reverse-DNS identifier used by `launchctl`.
    pub label: Option<String>,
    /// The executable path referenced. Either `Program` or
    /// `ProgramArguments[0]`.
    pub program: String,
    /// `RunAtLoad` — runs immediately on registration?
    pub run_at_load: bool,
    /// `KeepAlive` set to true — resurrects if it dies?
    pub keep_alive: bool,
    pub modified_at: Option<u64>,
}

pub fn scan(app_path: &Path, executable: Option<&Path>) -> Vec<LaunchEntry> {
    let app_str = app_path.to_string_lossy().into_owned();
    let exe_str = executable.map(|p| p.to_string_lossy().into_owned());

    let mut dirs: Vec<(LaunchScope, PathBuf)> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        dirs.push((
            LaunchScope::UserAgent,
            PathBuf::from(&home).join("Library/LaunchAgents"),
        ));
    }
    dirs.push((LaunchScope::GlobalAgent, PathBuf::from("/Library/LaunchAgents")));
    dirs.push((LaunchScope::Daemon, PathBuf::from("/Library/LaunchDaemons")));

    let mut out = Vec::new();
    for (scope, dir) in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("plist") {
                continue;
            }
            let Ok(plist_value) = plist::Value::from_file(&path) else {
                continue;
            };
            let Some(dict) = plist_value.as_dictionary() else {
                continue;
            };

            let program = extract_program(dict);
            let Some(program) = program else {
                continue;
            };
            // Match if the program path is inside the app bundle or equals
            // the bundle's main executable.
            let inside_bundle = program.starts_with(&app_str);
            let equals_main = exe_str.as_deref().is_some_and(|e| program == e);
            if !inside_bundle && !equals_main {
                continue;
            }

            let label = dict
                .get("Label")
                .and_then(|v| v.as_string())
                .map(str::to_owned);
            let run_at_load = dict
                .get("RunAtLoad")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);
            let keep_alive = matches!(
                dict.get("KeepAlive"),
                Some(plist::Value::Boolean(true))
                    | Some(plist::Value::Dictionary(_)) /* dict-form = conditional KeepAlive */
            );
            let modified_at = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            out.push(LaunchEntry {
                scope,
                plist_path: path,
                label,
                program,
                run_at_load,
                keep_alive,
                modified_at,
            });
        }
    }

    out
}

fn extract_program(dict: &plist::Dictionary) -> Option<String> {
    // `Program` is a single string; `ProgramArguments` is an array and the
    // first element is the executable path.
    if let Some(s) = dict.get("Program").and_then(|v| v.as_string()) {
        return Some(s.to_owned());
    }
    if let Some(array) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        if let Some(first) = array.first().and_then(|v| v.as_string()) {
            return Some(first.to_owned());
        }
    }
    None
}
