//! Deterministic signals for a background item. Each names a pattern that
//! documented macOS malware uses for persistence and that legitimate software
//! rarely needs; each is explainable on its own.

use serde::Serialize;

use super::ownership::Owner;
use super::{ItemKind, PersistenceItem, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    /// Stable identifier, e.g. `script_launcher`.
    pub code: &'static str,
    pub severity: Severity,
    pub text: String,
}

/// Interpreters a launchd job can use to run a script payload.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "python", "python2", "python3", "perl", "ruby", "osascript",
    "node", "php", "curl", "wget", "env",
];
const SCRIPT_EXTENSIONS: &[&str] = &[".sh", ".py", ".pl", ".rb", ".command", ".js", ".scpt", ".php"];
/// World-writable or scratch locations nothing should persist from.
const TEMP_DIRS: &[&str] = &["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"];

pub fn evaluate(item: &PersistenceItem, owner: &Owner) -> Vec<Signal> {
    let mut s = Vec::new();
    let mut push = |code, severity, text: String| s.push(Signal { code, severity, text });
    let program_name = basename(&item.program);

    if let Some(script) = script_payload(item) {
        push(
            "script_launcher",
            Severity::High,
            format!("Runs a script rather than a signed program: {script}."),
        );
    }
    if let Some(dir) = TEMP_DIRS.iter().find(|d| item.program.starts_with(**d)) {
        push(
            "temp_location",
            Severity::High,
            format!("Runs a program from a shared or temporary folder ({dir})."),
        );
    }
    if let Some(component) = hidden_component(&item.program) {
        push(
            "hidden_location",
            Severity::High,
            format!("Runs a program from a hidden folder ({component})."),
        );
    }
    // An Apple-signed interpreter (osascript, sh) vouches for nothing it runs.
    let apple_program = item.signature.as_ref().is_some_and(|sig| sig.apple) && script_payload(item).is_none();
    if let Some(label) = &item.label {
        if label.starts_with("com.apple.") && !apple_program && !item.source.starts_with("/System/") {
            push(
                "apple_impersonation",
                Severity::High,
                format!("Uses an Apple-style name ({label}) but isn't Apple software."),
            );
        }
        if let Some(token) = random_token(label) {
            push(
                "random_label",
                Severity::Medium,
                format!("Its name contains a random-looking token ({token})."),
            );
        }
    }
    match (&item.signature, item.program_exists) {
        (_, false) => push(
            "missing_program",
            Severity::Info,
            format!("Points at {program_name}, which no longer exists — likely left behind by an uninstalled app."),
        ),
        (Some(sig), true) if !sig.signed => push(
            "unsigned_program",
            if owner.is_proven() { Severity::Medium } else { Severity::High },
            format!("Its program ({program_name}) is not code-signed."),
        ),
        (Some(sig), true) if !sig.identified() => push(
            "adhoc_program",
            // Normal for package-manager builds and in-bundle helpers.
            if owner.is_proven() { Severity::Info } else { Severity::Medium },
            format!("Its program ({program_name}) is only ad-hoc signed, so no developer vouches for it."),
        ),
        _ => {}
    }
    // The model tied it to an app whose developer didn't sign it: the
    // classic impersonation (e.g. "com.google.Chrome.update" from elsewhere).
    if let Owner::Model {
        app,
        team_id: Some(team), ..
    } = owner
    {
        let item_team = item.signature.as_ref().and_then(|s| s.team_id.as_ref());
        if item_team != Some(team) {
            push(
                "team_mismatch",
                Severity::High,
                format!("Looks like part of {app}, but isn't signed by {app}'s developer."),
            );
        }
    }
    // An orphan that still runs is the core persistence red flag; a dangling
    // entry whose program is gone can't run anything.
    if item.program_exists && !owner.is_known() {
        push(
            "orphan",
            Severity::Medium,
            "No installed application could be tied to it.".to_string(),
        );
    }
    if item.keep_alive && matches!(item.kind, ItemKind::Daemon) && !owner.is_proven() {
        push(
            "root_keepalive",
            Severity::Info,
            "Runs as root and is relaunched whenever it exits.".to_string(),
        );
    }
    s
}

/// Any High signal → bad; any Medium → questionable.
pub fn verdict(signals: &[Signal]) -> Verdict {
    match signals.iter().map(|s| s.severity).max() {
        Some(Severity::High) => Verdict::Bad,
        Some(Severity::Medium) => Verdict::Questionable,
        _ => Verdict::Normal,
    }
}

/// The script an item really runs, if its program is an interpreter or a
/// script file.
fn script_payload(item: &PersistenceItem) -> Option<String> {
    let name = basename(&item.program);
    let lower = item.program.to_ascii_lowercase();
    if SCRIPT_EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
        return Some(item.program.clone());
    }
    if INTERPRETERS.contains(&name.as_str()) {
        let payload = item.arguments.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
        return Some(if payload.is_empty() {
            item.program.clone()
        } else {
            format!("{} {}", name, truncate(&payload, 120))
        });
    }
    None
}

/// The first dot-prefixed directory in the path (`.app` bundles excluded).
fn hidden_component(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    // The last part is the program itself.
    parts[..parts.len().saturating_sub(1)]
        .iter()
        .find(|p| p.len() > 1 && p.starts_with('.') && **p != ".." && !p.ends_with(".app"))
        .map(|p| (*p).to_string())
}

/// A label token that looks machine-generated: long, and either hex-like or
/// mixing letters and digits with few vowels.
fn random_token(label: &str) -> Option<String> {
    label
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|t| {
            if t.len() < 8 {
                return false;
            }
            let lower = t.to_ascii_lowercase();
            let digits = lower.chars().filter(|c| c.is_ascii_digit()).count();
            let hex = lower.chars().all(|c| c.is_ascii_hexdigit());
            let vowels = lower.chars().filter(|c| "aeiou".contains(*c)).count();
            let letters = lower.len() - digits;
            (hex && digits >= 2) || (digits >= 2 && letters >= 2 && vowels * 5 < letters)
        })
        .map(str::to_string)
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens() {
        assert_eq!(random_token("com.a3f9c2e1d7.agent").as_deref(), Some("a3f9c2e1d7"));
        assert_eq!(random_token("com.xk9q2vtm7.helper").as_deref(), Some("xk9q2vtm7"));
        // Real labels from a developer Mac must not trip it.
        for ok in [
            "com.google.GoogleUpdater.wake",
            "com.microsoft.OneDriveStandaloneUpdaterDaemon",
            "com.cloudflare.1dot1dot1dot1.macos.warp.daemon",
            "homebrew.mxcl.postgresql@16",
            "at.obdev.littlesnitch.daemon",
            "us.zoom.ZoomDaemon",
            "com.microsoft.office.licensingV2.helper",
        ] {
            assert_eq!(random_token(ok), None, "{ok}");
        }
    }

    #[test]
    fn hidden_components() {
        assert_eq!(
            hidden_component("/Users/x/Library/Application Support/.helperd/run").as_deref(),
            Some(".helperd")
        );
        assert_eq!(hidden_component("/Applications/Foo.app/Contents/MacOS/Foo"), None);
        assert_eq!(hidden_component("/Users/x/.local/bin/thing").as_deref(), Some(".local"));
    }
}
