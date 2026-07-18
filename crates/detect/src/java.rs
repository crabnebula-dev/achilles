//! Java / OpenJDK probe for bundled JREs.
//!
//! JVM apps bundle a runtime whose `release` file carries `JAVA_VERSION="…"` —
//! the authoritative version. We probe the conventional locations per platform
//! and parse that line.
//!
//! * **macOS**: `Contents/PlugIns/<vendor>.jdk/Contents/Home/release`,
//!   `Contents/Runtime/Contents/Home/release`, and older variants.
//! * **Windows / Linux** (jpackage app-image): `runtime/release`,
//!   `jre/release`, `lib/runtime/release`.
//!
//! If no `release` file matches but the launcher name looks like a JVM stub we
//! still flag the app as Java with an unknown version.

use std::path::Path;

use crate::app::Layout;

pub struct Detection {
    pub version: Option<String>,
}

pub fn detect(layout: &Layout) -> Option<Detection> {
    let root = &layout.root;

    // Platform-conventional fixed `release` locations.
    #[cfg(macos_layout)]
    let fixed: &[&str] = &[
        "Contents/Runtime/Contents/Home/release",
        "Contents/Resources/Java/jre/release",
    ];
    #[cfg(not(macos_layout))]
    let fixed: &[&str] = &["runtime/release", "jre/release", "lib/runtime/release"];

    for rel in fixed {
        if let Some(v) = parse_release_file(&root.join(rel)) {
            return Some(Detection { version: Some(v) });
        }
    }

    // macOS also stashes JREs under `Contents/PlugIns/*.jdk` / `jre`.
    #[cfg(macos_layout)]
    {
        let plugins = root.join("Contents/PlugIns");
        if let Ok(entries) = vfs::read_dir(&plugins) {
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
    }

    // Last-ditch: executable name hints at Java.
    if let Some(exe) = layout.executable.as_deref() {
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
        "JavaAppLauncher" | "JavaApplicationStub" | "java" | "javaw" | "java.exe" | "javaw.exe"
    )
}

fn parse_release_file(path: &Path) -> Option<String> {
    let bytes = vfs::read(path).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("JAVA_VERSION=") {
            // Value is quoted like `"24.0.1"`.
            return Some(rest.trim_matches('"').to_owned());
        }
    }
    None
}
