//! macOS discovery: Spotlight (`mdfind`) enumeration of `.app` bundles, with a
//! filesystem-walk fallback over the standard install roots.

use std::path::{Path, PathBuf};

use detect::DiscoveredApp;

use crate::ScanError;

/// Ask Spotlight for every application bundle on the system and narrow to
/// bundles installed in standard user-facing locations.
pub async fn discover() -> Result<Vec<DiscoveredApp>, ScanError> {
    let from_spotlight = spotlight_apps().await.unwrap_or_default();
    let mut paths = if from_spotlight.is_empty() {
        filesystem_walk_apps()
    } else {
        from_spotlight
    };
    paths.retain(|p| is_top_level_app(p) && in_standard_location(p));
    paths.sort();
    paths.dedup();
    Ok(paths
        .into_iter()
        .map(|p| DiscoveredApp {
            root: p.clone(),
            path: p,
            // The executable is resolved by `detect` from `CFBundleExecutable`.
            executable: None,
            name: None,
        })
        .collect())
}

async fn spotlight_apps() -> Result<Vec<PathBuf>, ScanError> {
    let output = tokio::process::Command::new("mdfind")
        .arg("-0")
        .arg("kMDItemContentType == 'com.apple.application-bundle'")
        .output()
        .await
        .map_err(ScanError::Spawn)?;

    if !output.status.success() {
        return Err(ScanError::Mdfind(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let text = std::str::from_utf8(&output.stdout).map_err(|_| ScanError::NotUtf8)?;
    Ok(text
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn filesystem_walk_apps() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in standard_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "app").unwrap_or(false) {
                out.push(path);
            }
        }
    }
    out
}

fn standard_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    if let Some(home) = home_dir() {
        roots.push(home.join("Applications"));
    }
    roots
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Return true only if the path is a top-level `.app` — the *last* path
/// component ends in `.app` and no earlier component does. This rejects
/// helper apps embedded inside Xcode, 1Password, etc.
fn is_top_level_app(path: &Path) -> bool {
    let components: Vec<_> = path.components().collect();
    if components.is_empty() {
        return false;
    }

    let last_is_app = components
        .last()
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.ends_with(".app"))
        .unwrap_or(false);
    if !last_is_app {
        return false;
    }

    components[..components.len() - 1]
        .iter()
        .all(|c| !c.as_os_str().to_string_lossy().ends_with(".app"))
}

fn in_standard_location(path: &Path) -> bool {
    standard_roots().iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_accepts_simple_app() {
        assert!(is_top_level_app(Path::new("/Applications/Safari.app")));
    }

    #[test]
    fn top_level_rejects_nested_app() {
        assert!(!is_top_level_app(Path::new(
            "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app"
        )));
    }

    #[test]
    fn top_level_rejects_non_app() {
        assert!(!is_top_level_app(Path::new("/Applications/Safari")));
    }

    #[test]
    fn standard_location_accepts_applications() {
        assert!(in_standard_location(Path::new("/Applications/Safari.app")));
        assert!(in_standard_location(Path::new(
            "/System/Applications/Calculator.app"
        )));
    }

    #[test]
    fn standard_location_rejects_elsewhere() {
        assert!(!in_standard_location(Path::new("/opt/Foo.app")));
        assert!(!in_standard_location(Path::new("/tmp/Foo.app")));
    }
}
