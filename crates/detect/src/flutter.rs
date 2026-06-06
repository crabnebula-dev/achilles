//! Flutter (Dart) desktop-app probe.
//!
//! * **macOS**: `Contents/Frameworks/FlutterMacOS.framework`; the engine
//!   version lives in its Info.plist `CFBundleShortVersionString`.
//! * **Windows**: `flutter_windows.dll` beside the executable.
//! * **Linux**: `lib/libflutter_linux_gtk.so` (or imported by the binary).
//!
//! Off macOS there's no on-disk version to read, so we report `"unknown"` and
//! still flag the app as Flutter.

use crate::app::Layout;

/// Return the Flutter engine version string if this is a Flutter app.
pub fn detect(layout: &Layout) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let framework_dir = layout.frameworks_dir().join("FlutterMacOS.framework");
        if !framework_dir.is_dir() {
            return None;
        }
        for rel in &["Versions/A/Resources/Info.plist", "Resources/Info.plist"] {
            let plist = framework_dir.join(rel);
            if !plist.exists() {
                continue;
            }
            if let Some(v) = read_version(&plist) {
                return Some(v);
            }
        }
        Some("unknown".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        if layout.has_library("flutter_windows") || layout.has_library("flutter_linux") {
            Some("unknown".to_string())
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn read_version(plist_path: &std::path::Path) -> Option<String> {
    let value = plist::Value::from_file(plist_path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(str::to_owned)
}
