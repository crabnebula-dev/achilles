//! Emit the `macos_layout` cfg when the audit should use the macOS `.app`
//! bundle backend (Info.plist hardening flags + `ElectronAsarIntegrity`).
//!
//! Active when building for macOS, or when the `macos-bundle` feature is on
//! (the wasm build sets it so an uploaded `.app` is audited with the macOS
//! backend; it also lets that backend be type-checked on a non-macOS host).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(macos_layout)");
    let is_macos = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    // wasm only ever audits an uploaded `.app`, so force the macOS bundle
    // backend on there regardless of the feature (keeps crates that depend on
    // `app-audit` without `macos-bundle` building for wasm).
    let is_wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let bundle_feature = std::env::var("CARGO_FEATURE_MACOS_BUNDLE").is_ok();
    if is_macos || is_wasm || bundle_feature {
        println!("cargo::rustc-cfg=macos_layout");
    }
}
