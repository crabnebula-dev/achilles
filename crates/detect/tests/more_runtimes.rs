//! Synthetic-fixture tests for the Flutter / Qt / NW.js / Chromium-browser /
//! React Native / Wails / Sciter / Java detectors.
//!
//! We build a minimal directory structure per runtime in a temp dir,
//! satisfy just enough of each probe's expectations to trigger a positive
//! verdict, then assert.

use std::fs;
use std::path::{Path, PathBuf};

use detect::{detect, Framework};

fn tempdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "detect-more-{}-{}-{}",
        name,
        std::process::id(),
        rand_u32()
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
}

/// Common Info.plist at Contents/Info.plist — just enough to let
/// `bundle::read` succeed.
fn write_bundle_plist(app: &Path, bundle_id: &str, exec_name: &str) {
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{bundle_id}</string>
<key>CFBundleExecutable</key><string>{exec_name}</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
</dict></plist>
"#
    );
    fs::write(app.join("Contents/Info.plist"), plist).unwrap();
    // Empty executable so `bundle.executable` resolves to Some(..).
    fs::write(app.join("Contents/MacOS").join(exec_name), b"").unwrap();
}

fn write_framework_plist(dir: &Path, version: &str) {
    fs::create_dir_all(dir).unwrap();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleShortVersionString</key><string>{version}</string>
</dict></plist>
"#
    );
    fs::write(dir.join("Info.plist"), plist).unwrap();
}

#[test]
fn flutter_fixture() {
    let app = tempdir("flutter").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    let fw = app.join("Contents/Frameworks/FlutterMacOS.framework/Versions/A/Resources");
    write_framework_plist(&fw, "3.19.0");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Flutter);
    assert_eq!(d.versions.flutter.as_deref(), Some("3.19.0"));
}

#[test]
fn qt_fixture() {
    let app = tempdir("qt").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    let fw = app.join("Contents/Frameworks/QtCore.framework/Versions/A/Resources");
    write_framework_plist(&fw, "6.6.0");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Qt);
    assert_eq!(d.versions.qt.as_deref(), Some("6.6.0"));
    assert!(d.versions.chromium.is_none()); // no QtWebEngine in fixture
}

#[test]
fn nwjs_fixture() {
    let app = tempdir("nwjs").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    let fw = app.join("Contents/Frameworks/nwjs Framework.framework/Versions/A/Resources");
    write_framework_plist(&fw, "0.83.0");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::NwJs);
    assert_eq!(d.versions.nwjs.as_deref(), Some("0.83.0"));
}

#[test]
fn chromium_browser_fixture() {
    let app = tempdir("chrome").join("Chrome.app");
    write_bundle_plist(&app, "com.google.Chrome", "Google Chrome");
    let fw = app.join(
        "Contents/Frameworks/Google Chrome Framework.framework/Versions/A/Resources",
    );
    write_framework_plist(&fw, "147.0.7727.101");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::ChromiumBrowser);
    assert_eq!(d.versions.chromium.as_deref(), Some("147.0.7727.101"));
}

#[test]
fn react_native_fixture_with_hermes() {
    let app = tempdir("rn").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    let fw = app.join("Contents/Frameworks/hermes.framework/Versions/A/Resources");
    write_framework_plist(&fw, "0.74.3");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::ReactNative);
    assert_eq!(d.versions.react_native.as_deref(), Some("0.74.3"));
}

#[test]
fn wails_fixture() {
    let app = tempdir("wails").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    // Dump a Go-build-info-style string into the fake executable.
    let exe = app.join("Contents/MacOS/Foo");
    fs::write(
        &exe,
        b"\x00\x00some padding github.com/wailsapp/wails/v2@v2.9.2 more padding\x00",
    )
    .unwrap();

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Wails);
    assert_eq!(d.versions.wails.as_deref(), Some("2.9.2"));
}

#[test]
fn sciter_fixture() {
    let app = tempdir("sciter").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "Foo");
    let fw = app.join("Contents/Frameworks/Sciter.framework/Versions/A/Resources");
    write_framework_plist(&fw, "6.0.0.12");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Sciter);
    assert_eq!(d.versions.sciter.as_deref(), Some("6.0.0.12"));
}

#[test]
fn java_fixture_with_release_file() {
    let app = tempdir("java").join("Foo.app");
    write_bundle_plist(&app, "dev.example.foo", "JavaAppLauncher");
    let home = app.join("Contents/PlugIns/adoptium-21.jdk/Contents/Home");
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("release"),
        "JAVA_VERSION=\"21.0.2\"\nIMPLEMENTOR=\"Adoptium\"\n",
    )
    .unwrap();

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Java);
    assert_eq!(d.versions.java.as_deref(), Some("21.0.2"));
}

#[test]
fn safari_fixture_by_bundle_id() {
    let app = tempdir("safari").join("Safari.app");
    // Bundle-id is the determining signal for Safari.
    write_bundle_plist(&app, "com.apple.Safari", "Safari");
    // Override the bundle plist to also include a CFBundleShortVersionString
    // we control (write_bundle_plist already sets "1.0"; fine for test).

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Safari);
    assert_eq!(d.versions.webkit.as_deref(), Some("1.0"));
}

#[test]
fn java_fixture_launcher_only() {
    let app = tempdir("javalauncher").join("Foo.app");
    // Executable named JavaAppLauncher but no release file anywhere — the
    // detector should still flag it as Java but with version "unknown".
    write_bundle_plist(&app, "dev.example.foo", "JavaAppLauncher");

    let d = detect(&app).unwrap();
    assert_eq!(d.framework, Framework::Java);
    assert_eq!(d.versions.java.as_deref(), Some("unknown"));
}
