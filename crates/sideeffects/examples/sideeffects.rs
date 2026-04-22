//! `cargo run -p sideeffects --example sideeffects -- <path-to-.app>`

use std::path::PathBuf;

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: sideeffects <path-to-.app>");

    // Quick Info.plist parse for bundle_id + executable so we don't need
    // the full detect crate just for an example.
    let plist_path = path.join("Contents/Info.plist");
    let (bundle_id, executable) = plist::Value::from_file(&plist_path)
        .ok()
        .and_then(|v| v.into_dictionary())
        .map(|d| {
            let id = d
                .get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(str::to_owned);
            let exe = d
                .get("CFBundleExecutable")
                .and_then(|v| v.as_string())
                .map(|e| path.join("Contents/MacOS").join(e));
            (id, exe)
        })
        .unwrap_or((None, None));

    let report = sideeffects::analyse(&path, bundle_id.as_deref(), executable.as_deref())
        .expect("analyse failed");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize")
    );
}
