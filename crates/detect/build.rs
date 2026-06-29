//! Emit the `macos_layout` cfg when detection should use the macOS `.app`
//! bundle layout (Info.plist + `Contents/Frameworks`) rather than the portable
//! import-table path.
//!
//! Active when building for macOS, or when the `macos-bundle` feature is on.
//! The wasm build enables the feature so an uploaded `.app` is analysed with
//! the bundle-layout probes; it also lets the macOS detectors be type-checked
//! on a non-macOS host (`--features macos-bundle`).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(macos_layout)");
    let is_macos = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    // wasm has no import-table backend (no goblin) and only ever analyses an
    // uploaded `.app`, so the bundle layout is the only sensible mode there —
    // force it on regardless of the feature, so crates that depend on `detect`
    // without enabling `macos-bundle` (e.g. `cve`) still build for wasm.
    let is_wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let bundle_feature = std::env::var("CARGO_FEATURE_MACOS_BUNDLE").is_ok();
    if is_macos || is_wasm || bundle_feature {
        println!("cargo::rustc-cfg=macos_layout");
    }
}
