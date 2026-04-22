//! React Native (macOS) probe.
//!
//! RN-macOS apps typically ship one of two JS engines:
//!
//! 1. **Hermes** as a bundled framework — `Contents/Frameworks/hermes.framework/`
//!    with a version in its Info.plist. This is the strong signal.
//! 2. **System JavaScriptCore**, in which case there's no framework to find
//!    and we fall back to scanning the main binary / Resources for
//!    unmistakable RN strings (`react-native`, `RCTBridge`, `facebook/react-native`).
//!
//! We prefer the Hermes framework signal when available. The string-based
//! fallback returns a generic `"unknown"` version since there's no runtime
//! version to read off disk — but it still lets us flag the bundle as RN.

use std::path::Path;

use crate::strings;

const HERMES_FRAMEWORK_REL: &str = "Contents/Frameworks/hermes.framework";

pub struct Detection {
    pub version: Option<String>,
}

pub fn detect(app_path: &Path, executable: Option<&Path>) -> Result<Option<Detection>, crate::DetectError> {
    let hermes_dir = app_path.join(HERMES_FRAMEWORK_REL);
    if hermes_dir.is_dir() {
        let version = read_hermes_version(&hermes_dir).or(Some("unknown".to_string()));
        return Ok(Some(Detection { version }));
    }

    // No Hermes framework — fall back to string-scanning the main executable
    // for RN-specific symbols.
    if let Some(exe) = executable {
        if exe.exists()
            && (strings::contains(exe, b"facebook::react").unwrap_or(false)
                || strings::contains(exe, b"RCTBridge").unwrap_or(false)
                || strings::contains(exe, b"RCTRootView").unwrap_or(false))
        {
            return Ok(Some(Detection {
                version: Some("unknown".to_string()),
            }));
        }
    }

    Ok(None)
}

fn read_hermes_version(framework_dir: &Path) -> Option<String> {
    for rel in &[
        "Versions/A/Resources/Info.plist",
        "Resources/Info.plist",
    ] {
        let plist = framework_dir.join(rel);
        if !plist.exists() {
            continue;
        }
        let value = plist::Value::from_file(&plist).ok()?;
        let dict = value.as_dictionary()?;
        if let Some(v) = dict
            .get("CFBundleShortVersionString")
            .or_else(|| dict.get("CFBundleVersion"))
            .and_then(|v| v.as_string())
        {
            return Some(v.to_owned());
        }
    }
    None
}
