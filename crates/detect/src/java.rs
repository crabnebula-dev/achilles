//! Java / OpenJDK probe for bundled JREs.
//!
//! JVM apps on macOS stash the runtime in several conventional places:
//!
//! - `Contents/PlugIns/<vendor>.jdk/Contents/Home/release` — jpackage default
//! - `Contents/PlugIns/jre/Contents/Home/release` — older pattern
//! - `Contents/Runtime/Contents/Home/release` — some installers
//! - `Contents/Resources/Java/jre/release` — legacy / rare
//!
//! We scan those locations for a `release` file and parse `JAVA_VERSION="…"`
//! out of it — that's the authoritative version string the runtime ships.
//!
//! If none of the known locations match but the app declares its executable
//! as `JavaAppLauncher` or similar, we still flag it as Java with an
//! unknown version.

use std::path::{Path, PathBuf};

/// `release` file locations we probe, in preference order.
const RELEASE_PATHS: &[&str] = &[
    "Contents/Runtime/Contents/Home/release",
    "Contents/Resources/Java/jre/release",
];

pub struct Detection {
    pub version: Option<String>,
}

pub fn detect(app_path: &Path, executable: Option<&Path>) -> Option<Detection> {
    // Fixed paths first.
    for rel in RELEASE_PATHS {
        let release = app_path.join(rel);
        if let Some(v) = parse_release_file(&release) {
            return Some(Detection { version: Some(v) });
        }
    }

    // Wildcard paths: any `*.jdk/Contents/Home/release` or `jre/Contents/Home/release`
    // under `Contents/PlugIns/`.
    let plugins = app_path.join("Contents/PlugIns");
    if let Ok(entries) = std::fs::read_dir(&plugins) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if !(name_s.ends_with(".jdk") || name_s == "jre" || name_s.ends_with(".jre")) {
                continue;
            }
            let release = entry.path().join("Contents/Home/release");
            if let Some(v) = parse_release_file(&release) {
                return Some(Detection { version: Some(v) });
            }
        }
    }

    // Last-ditch: executable name hints at Java.
    if let Some(exe) = executable {
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            if is_java_launcher(name) {
                return Some(Detection {
                    version: Some("unknown".to_string()),
                });
            }
        }
    }

    None
}

fn is_java_launcher(name: &str) -> bool {
    matches!(
        name,
        "JavaAppLauncher" | "JavaApplicationStub" | "java"
    )
}

fn parse_release_file(path: &PathBuf) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("JAVA_VERSION=")?;
        // Value is quoted like `"24.0.1"`.
        return Some(rest.trim_matches('"').to_owned());
    }
    None
}
