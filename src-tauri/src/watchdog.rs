//! Behaviour watchdog (LOCAL ONLY until November): turns the evidence Achilles
//! already gathers about an app — persistence, browser bridges, signing,
//! entitlements, network destinations — into plain-language facts and asks
//! Jev (an on-device Qwen3-4B classifier, see [`jev::watchdog::MODEL`]) whether the app is behaving badly.
//!
//! The model is loaded lazily on first use and kept for the process lifetime.
//! It is only ever downloaded when the UI passes `allow_download` (the user
//! clicked through a size warning); otherwise a missing model is reported as
//! [`MODEL_NOT_CACHED`] so the UI can ask.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use app_audit::{AppAudit, MacosAudit};
use jev::watchdog::{self, Assessment, Subject};
use jev::watchdog::MODEL;
use jev::{Jev, JevError, ModelFiles};
use serde::Serialize;
use sideeffects::{LaunchScope, SideEffects};

/// Error string the UI matches to offer the model download.
pub const MODEL_NOT_CACHED: &str = "jev-model-not-cached";

/// Loaded once, reused across assessments (loading takes seconds).
static ENGINE: Mutex<Option<Jev>> = Mutex::new(None);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JevStatus {
    pub model: &'static str,
    pub cached: bool,
    pub loaded: bool,
}

#[tauri::command]
pub async fn jev_status() -> JevStatus {
    tokio::task::spawn_blocking(|| JevStatus {
        model: MODEL,
        cached: ModelFiles::cached(MODEL).is_ok(),
        loaded: ENGINE.lock().map(|e| e.is_some()).unwrap_or(false),
    })
    .await
    .unwrap_or(JevStatus {
        model: MODEL,
        cached: false,
        loaded: false,
    })
}

/// Gather evidence for one app and ask Jev for a verdict. `destinations` are
/// `host:port` labels from a network capture the UI already holds, if any.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn jev_assess(
    path: PathBuf,
    root: PathBuf,
    bundle_id: Option<String>,
    executable: Option<PathBuf>,
    name: String,
    framework: Option<String>,
    destinations: Option<Vec<String>>,
    allow_download: bool,
) -> Result<Assessment, String> {
    let audit = app_audit::audit(&path, &root, executable.as_deref()).await.ok();
    tokio::task::spawn_blocking(move || {
        let side = sideeffects::analyse(&path, bundle_id.as_deref(), executable.as_deref()).ok();
        let facts = collect_facts(&path, audit.as_ref(), side.as_ref(), destinations.as_deref().unwrap_or(&[]));
        let subject = Subject {
            name: &name,
            framework: framework.as_deref().filter(|f| *f != "unknown"),
            facts,
        };

        let mut engine = ENGINE.lock().map_err(|_| "jev engine poisoned".to_string())?;
        if engine.is_none() {
            let files = if allow_download {
                ModelFiles::fetch(MODEL)
            } else {
                ModelFiles::cached(MODEL)
            }
            .map_err(|e| match e {
                JevError::NotCached(_) => MODEL_NOT_CACHED.to_string(),
                e => e.to_string(),
            })?;
            *engine = Some(Jev::load(&files).map_err(|e| e.to_string())?);
        }
        let jev = engine.as_mut().expect("engine loaded above");
        watchdog::assess(jev, &subject).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Every fact, most significant first (the prompt truncates from the end).
pub fn collect_facts(
    app_path: &Path,
    audit: Option<&AppAudit>,
    side: Option<&SideEffects>,
    destinations: &[String],
) -> Vec<String> {
    let mut facts = Vec::new();
    if let Some(side) = side {
        facts.extend(launch_facts(app_path, side));
    }
    if let Some(AppAudit::Macos(m)) = audit {
        facts.extend(macos_hardening_facts(m));
    }
    if let Some(side) = side {
        facts.extend(browser_bridge_facts(side));
    }
    if let Some(AppAudit::Macos(m)) = audit {
        facts.extend(macos_capability_facts(m));
    }
    if !destinations.is_empty() {
        facts.push(format!(
            "During a recorded session it contacted {} network destination(s): {}.",
            destinations.len(),
            list_some(destinations, 12)
        ));
    }
    if let Some(side) = side {
        let helpers: Vec<String> = side
            .helpers
            .iter()
            .chain(&side.plugins)
            .chain(&side.xpc_services)
            .map(|h| h.name.clone())
            .collect();
        if !helpers.is_empty() {
            facts.push(format!(
                "Ships {} helper executable(s) or plug-in(s): {}.",
                helpers.len(),
                list_some(&helpers, 4)
            ));
        }
    }
    facts
}

fn launch_facts(app_path: &Path, side: &SideEffects) -> Vec<String> {
    side.launch_entries
        .iter()
        .map(|e| {
            let what = match e.scope {
                LaunchScope::UserAgent => "a launch agent for the current user",
                LaunchScope::GlobalAgent => "a launch agent for every user on the machine",
                LaunchScope::Daemon => "a launch daemon that runs as root at boot",
                LaunchScope::RunKey => "a Run registry entry that starts it at sign-in",
                LaunchScope::StartupFolder => "a Startup-folder shortcut that starts it at sign-in",
                LaunchScope::ScheduledTask => "a scheduled task",
                LaunchScope::Service => "a Windows service",
                LaunchScope::Autostart => "an autostart entry that starts it at login",
                LaunchScope::SystemdUser => "a systemd user service",
            };
            let program = Path::new(&e.program);
            let mut s = format!("Registers {what} running {}", file_name(program));
            if !program.starts_with(app_path) && program.is_absolute() {
                s.push_str(&format!(" (located outside the app, at {})", e.program));
            }
            if e.run_at_load {
                s.push_str(", started automatically");
            }
            if e.keep_alive {
                s.push_str(", relaunched whenever it exits");
            }
            s.push('.');
            s
        })
        .collect()
}

fn browser_bridge_facts(side: &SideEffects) -> Vec<String> {
    side.native_messaging_hosts
        .iter()
        .map(|h| {
            format!(
                "Installed a native-messaging bridge \"{}\" into {} that lets {} browser extension(s) run its code.",
                h.host_name,
                h.browser,
                h.allowed_origins.len()
            )
        })
        .collect()
}

fn macos_hardening_facts(m: &MacosAudit) -> Vec<String> {
    let mut f = Vec::new();
    let sig = &m.code_signature;
    // No notarization fact: `notarized` only means a ticket is *stapled*, and
    // Gatekeeper accepts unstapled notarized apps online — too many false alarms.
    if !sig.signed {
        f.push("Is not code-signed, so its origin cannot be verified.".to_string());
    } else if !sig.hardened_runtime && !apple_signed(sig) {
        // Apple's own and App Store apps are protected by other means.
        f.push("Does not enable the hardened runtime.".to_string());
    }
    let e = &m.entitlements;
    if e.get_task_allow {
        f.push("Lets other processes attach a debugger to it (get-task-allow), normally only seen in development builds.".into());
    }
    if e.disable_library_validation {
        f.push("Disables library validation, so it will load code libraries not signed by its developer.".into());
    }
    if e.allow_dyld_environment_variables {
        f.push("Honours DYLD environment variables, which allows code injection.".into());
    }
    if e.allow_unsigned_executable_memory {
        f.push("Allows unsigned executable memory.".into());
    }
    if e.disable_executable_page_protection {
        f.push("Disables executable memory page protection.".into());
    }
    f
}

/// Entitlements that grant access to people's data or to other software.
const SENSITIVE_ENTITLEMENTS: &[(&str, &str)] = &[
    ("com.apple.security.device.camera", "the camera"),
    ("com.apple.security.device.audio-input", "the microphone"),
    ("com.apple.security.device.microphone", "the microphone"),
    ("com.apple.security.personal-information.location", "location"),
    ("com.apple.security.personal-information.addressbook", "contacts"),
    ("com.apple.security.personal-information.calendars", "calendars"),
    ("com.apple.security.personal-information.photos-library", "the photo library"),
    ("com.apple.security.automation.apple-events", "controlling other apps via Apple Events"),
    ("com.apple.security.cs.debugger", "debugging other processes"),
    ("com.apple.developer.endpoint-security.client", "monitoring all system activity (Endpoint Security)"),
    ("com.apple.developer.system-extension.install", "installing system extensions"),
    ("com.apple.developer.networking.networkextension", "intercepting network traffic (Network Extension)"),
];

fn macos_capability_facts(m: &MacosAudit) -> Vec<String> {
    let mut f = Vec::new();
    let mut granted: Vec<&str> = SENSITIVE_ENTITLEMENTS
        .iter()
        .filter(|(key, _)| m.entitlements.raw.get(*key).is_some_and(truthy))
        .map(|(_, what)| *what)
        .collect();
    granted.dedup();
    if !granted.is_empty() {
        f.push(format!("Holds entitlements for {}.", granted.join(", ")));
    }
    let p = &m.info_plist;
    if p.allows_arbitrary_loads {
        f.push("Disables App Transport Security, allowing unencrypted HTTP to any server.".into());
    }
    let insecure: Vec<String> = p
        .tls_exceptions
        .iter()
        .filter(|t| t.allows_insecure_http)
        .map(|t| t.domain.clone())
        .collect();
    if !insecure.is_empty() {
        f.push(format!("Allows unencrypted HTTP to: {}.", list_some(&insecure, 5)));
    }
    if !p.url_schemes.is_empty() {
        f.push(format!(
            "Registers URL scheme(s) other apps and websites can open it with: {}.",
            list_some(&p.url_schemes, 5)
        ));
    }
    f
}

/// Signed by Apple itself or re-signed by the Mac App Store.
fn apple_signed(sig: &app_audit::CodeSignature) -> bool {
    sig.authority
        .iter()
        .any(|a| a == "Software Signing" || a == "Apple Mac OS Application Signing")
}

fn truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Null => false,
        _ => true,
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// "a, b, c (+4 more)"
fn list_some(items: &[String], max: usize) -> String {
    let mut s = items.iter().take(max).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > max {
        s.push_str(&format!(" (+{} more)", items.len() - max));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use sideeffects::{LaunchEntry, NativeMessagingHost};

    fn empty_side(app: &Path) -> SideEffects {
        SideEffects {
            app_path: app.to_path_buf(),
            helpers: vec![],
            plugins: vec![],
            xpc_services: vec![],
            native_messaging_hosts: vec![],
            launch_entries: vec![],
            log_dir: None,
        }
    }

    /// Calibration run over real installed apps (needs the model cached):
    /// `cargo test -p achilles --release watchdog::tests::calibrate -- --ignored --nocapture`
    /// Prints one column per candidate prompt: N(ormal) / q(uestionable) / B(ad)
    /// and P(bad).
    #[test]
    #[ignore]
    fn calibrate() {
        // Candidate 0 is what ships; add alternatives here to compare.
        let candidates: Vec<(&str, [&str; 3])> = vec![(watchdog::SYSTEM, watchdog::CHOICES)];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let model = std::env::var("JEV_MODEL").unwrap_or_else(|_| MODEL.to_string());
        let files = ModelFiles::cached(&model).expect("model cached");
        let mut jev = Jev::load(&files).unwrap();
        println!("model: {model}");
        let mut apps: Vec<PathBuf> = std::fs::read_dir("/Applications")
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "app"))
            .collect();
        apps.sort();
        let subjects: Vec<(String, Vec<String>)> = apps
            .iter()
            .map(|app| {
                let audit = rt.block_on(app_audit::audit(app, app, None)).ok();
                let side = sideeffects::analyse(app, None, None).ok();
                (file_name(app), collect_facts(app, audit.as_ref(), side.as_ref(), &[]))
            })
            .collect();
        let mut tally = vec![[0usize; 3]; candidates.len()];
        for (name, facts) in &subjects {
            let mut line = format!("{name:<32} {:>2}f ", facts.len());
            for (ci, (system, choices)) in candidates.iter().enumerate() {
                let subject = Subject { name, framework: None, facts: facts.clone() };
                let a = watchdog::assess_with(&mut jev, system, choices, &subject).unwrap();
                let v = a.verdict as usize;
                tally[ci][v] += 1;
                line.push_str(&format!(" | {} {:.2}", ["N", "q", "B"][v], a.probabilities[2]));
            }
            println!("{line}");
        }
        for (ci, t) in tally.iter().enumerate() {
            println!("candidate {ci}: normal {} questionable {} bad {}", t[0], t[1], t[2]);
        }
    }

    #[test]
    fn nothing_observed_yields_no_facts() {
        let app = Path::new("/Applications/Calc.app");
        assert!(collect_facts(app, None, Some(&empty_side(app)), &[]).is_empty());
    }

    #[test]
    fn launch_daemon_outside_the_app_is_described() {
        let app = Path::new("/Applications/Foo.app");
        let mut side = empty_side(app);
        side.launch_entries.push(LaunchEntry {
            scope: LaunchScope::Daemon,
            plist_path: "/Library/LaunchDaemons/com.foo.updater.plist".into(),
            label: Some("com.foo.updater".into()),
            program: "/Library/PrivilegedHelperTools/com.foo.updater".into(),
            run_at_load: true,
            keep_alive: true,
            modified_at: None,
        });
        let facts = collect_facts(app, None, Some(&side), &[]);
        assert_eq!(
            facts,
            ["Registers a launch daemon that runs as root at boot running com.foo.updater (located outside the app, at /Library/PrivilegedHelperTools/com.foo.updater), started automatically, relaunched whenever it exits."]
        );
    }

    #[test]
    fn launch_agent_inside_the_app_omits_location() {
        let app = Path::new("/Applications/Foo.app");
        let mut side = empty_side(app);
        side.launch_entries.push(LaunchEntry {
            scope: LaunchScope::UserAgent,
            plist_path: "~/Library/LaunchAgents/com.foo.plist".into(),
            label: None,
            program: "/Applications/Foo.app/Contents/MacOS/Foo Helper".into(),
            run_at_load: false,
            keep_alive: false,
            modified_at: None,
        });
        let facts = collect_facts(app, None, Some(&side), &[]);
        assert_eq!(facts, ["Registers a launch agent for the current user running Foo Helper."]);
    }

    #[test]
    fn bridges_and_destinations() {
        let app = Path::new("/Applications/Foo.app");
        let mut side = empty_side(app);
        side.native_messaging_hosts.push(NativeMessagingHost {
            browser: "Google Chrome".into(),
            manifest_path: "/x.json".into(),
            host_name: "com.foo.bridge".into(),
            target_path: "/Applications/Foo.app/Contents/MacOS/bridge".into(),
            allowed_origins: vec!["chrome-extension://abc/".into()],
            created_at: None,
            modified_at: None,
        });
        let dests: Vec<String> = (0..14).map(|i| format!("h{i}.example:443")).collect();
        let facts = collect_facts(app, None, Some(&side), &dests);
        assert_eq!(facts.len(), 2);
        assert!(facts[0].contains("\"com.foo.bridge\" into Google Chrome"));
        assert!(facts[1].starts_with("During a recorded session it contacted 14 network destination(s): h0.example:443"));
        assert!(facts[1].ends_with("(+2 more)."));
    }
}
