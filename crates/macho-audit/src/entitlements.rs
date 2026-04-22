//! Extract hardened-runtime entitlements from a signed macOS bundle.
//!
//! `codesign -d --entitlements - --xml <path>` emits the XML property list
//! for the app's entitlements on every current macOS. Older SDKs used
//! `--entitlements :-` which is still accepted on recent macOS but noisy;
//! we try the modern form first, fall back to the legacy form.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Entitlements {
    /// Whether `codesign` returned any entitlements at all.
    pub present: bool,
    /// Every entitlement key/value pair parsed from the plist, JSON-coerced.
    pub raw: BTreeMap<String, serde_json::Value>,

    pub allow_jit: bool,
    pub allow_unsigned_executable_memory: bool,
    pub disable_executable_page_protection: bool,
    pub allow_dyld_environment_variables: bool,
    pub disable_library_validation: bool,
    pub get_task_allow: bool,
}

pub async fn read(app_path: &Path) -> Entitlements {
    let xml = run_codesign(app_path, &["-d", "--entitlements", "-", "--xml"]).await;
    let xml = match xml {
        Some(b) if !b.is_empty() => b,
        _ => run_codesign(app_path, &["-d", "--entitlements", ":-"])
            .await
            .unwrap_or_default(),
    };

    if xml.is_empty() {
        return Entitlements::default();
    }

    match plist::Value::from_reader_xml(std::io::Cursor::new(&xml)) {
        Ok(value) => parse(value),
        Err(_) => {
            // Some macOS versions emit binary plist when asked via `:-`.
            match plist::Value::from_reader(std::io::Cursor::new(&xml)) {
                Ok(value) => parse(value),
                Err(_) => Entitlements::default(),
            }
        }
    }
}

async fn run_codesign(app_path: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let mut cmd = tokio::process::Command::new("codesign");
    cmd.args(args).arg(app_path);
    let output = cmd.output().await.ok()?;
    // Some entitlements plists are emitted on stdout, some on stderr.
    // Concatenating both is safer than picking one.
    let mut combined = output.stdout;
    if combined.is_empty() {
        combined = output.stderr;
    }
    Some(combined)
}

fn parse(value: plist::Value) -> Entitlements {
    let Some(dict) = value.into_dictionary() else {
        return Entitlements::default();
    };

    let flag = |key: &str, d: &plist::Dictionary| {
        d.get(key).and_then(|v| v.as_boolean()).unwrap_or(false)
    };

    let mut raw = BTreeMap::new();
    for (k, v) in &dict {
        raw.insert(k.clone(), plist_to_json(v.clone()));
    }

    Entitlements {
        present: true,
        allow_jit: flag("com.apple.security.cs.allow-jit", &dict),
        allow_unsigned_executable_memory: flag(
            "com.apple.security.cs.allow-unsigned-executable-memory",
            &dict,
        ),
        disable_executable_page_protection: flag(
            "com.apple.security.cs.disable-executable-page-protection",
            &dict,
        ),
        allow_dyld_environment_variables: flag(
            "com.apple.security.cs.allow-dyld-environment-variables",
            &dict,
        ),
        disable_library_validation: flag(
            "com.apple.security.cs.disable-library-validation",
            &dict,
        ),
        get_task_allow: flag("com.apple.security.get-task-allow", &dict),
        raw,
    }
}

fn plist_to_json(value: plist::Value) -> serde_json::Value {
    match value {
        plist::Value::Boolean(b) => serde_json::Value::Bool(b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(serde_json::Value::from)
            .or_else(|| i.as_unsigned().map(serde_json::Value::from))
            .unwrap_or(serde_json::Value::Null),
        plist::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        plist::Value::String(s) => serde_json::Value::String(s),
        plist::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(plist_to_json).collect())
        }
        plist::Value::Dictionary(d) => serde_json::Value::Object(
            d.into_iter()
                .map(|(k, v)| (k, plist_to_json(v)))
                .collect(),
        ),
        plist::Value::Data(d) => serde_json::Value::String(format!("<{} bytes>", d.len())),
        plist::Value::Date(d) => serde_json::Value::String(format!("{d:?}")),
        plist::Value::Uid(u) => serde_json::Value::Number(u.get().into()),
        _ => serde_json::Value::Null,
    }
}
