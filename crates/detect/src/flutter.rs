//! Flutter (Dart) desktop-app probe.
//!
//! Apps built with `flutter build macos` ship `FlutterMacOS.framework` under
//! `Contents/Frameworks/`. The engine version lives in the framework's
//! Info.plist as `CFBundleShortVersionString` (the Flutter-engine commit SHA
//! is usually appended to `CFBundleVersion`).

use std::path::Path;

const FRAMEWORK_REL: &str = "Contents/Frameworks/FlutterMacOS.framework";

/// Return the Flutter engine version string if this is a Flutter app.
pub fn detect(app_path: &Path) -> Option<String> {
    let framework_dir = app_path.join(FRAMEWORK_REL);
    if !framework_dir.is_dir() {
        return None;
    }
    for rel in &[
        "Versions/A/Resources/Info.plist",
        "Resources/Info.plist",
    ] {
        let plist = framework_dir.join(rel);
        if !plist.exists() {
            continue;
        }
        if let Some(v) = read_version(&plist) {
            return Some(v);
        }
    }
    // Framework present but Info.plist didn't yield a version — surface
    // "unknown" so callers can still flag the bundle as Flutter.
    Some("unknown".to_string())
}

fn read_version(plist_path: &Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
