//! Who does a background item belong to?
//!
//! Deterministic evidence first — it can't be argued with: the program lives
//! inside an app's bundle, or carries the same code-signing Team ID as an
//! installed app, or is signed by Apple. Only what's left goes to Jev, as a
//! SemIf-style candidate selection over the most name-similar installed apps
//! plus "none of these". A model-assigned owner is marked as such and never
//! clears a rule on its own (see [`super::rules`]).

use serde::Serialize;

use super::{InstalledApp, PersistenceItem};
use crate::{Jev, Opt, Result};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "by")]
pub enum Owner {
    /// The program is inside this app's bundle.
    Bundle { app: String },
    /// The program is signed by the same Team ID as this app.
    Team { app: String, team_id: String },
    /// Signed by Apple (system or App Store software).
    Apple,
    /// Installed by a package manager (the program lives in its prefix).
    PackageManager { manager: String },
    /// Jev picked this app from the candidates. `team_id` is the app's —
    /// the item *should* be signed by it (see `rules::team_mismatch`).
    Model {
        app: String,
        confidence: f32,
        team_id: Option<String>,
    },
    /// No installed app could be tied to it.
    Unknown,
}

impl Owner {
    pub fn is_known(&self) -> bool {
        !matches!(self, Owner::Unknown)
    }

    /// Attributed by evidence rather than by the model.
    pub fn is_proven(&self) -> bool {
        matches!(
            self,
            Owner::Bundle { .. } | Owner::Team { .. } | Owner::Apple | Owner::PackageManager { .. }
        )
    }
}

/// Package-manager install prefixes → manager name.
const PACKAGE_PREFIXES: &[(&str, &str)] = &[
    ("/opt/homebrew/", "Homebrew"),
    ("/usr/local/Cellar/", "Homebrew"),
    ("/usr/local/opt/", "Homebrew"),
    ("/opt/local/", "MacPorts"),
    ("/nix/store/", "Nix"),
];

/// How many candidate apps Jev chooses between (plus "none of these").
pub const MAX_CANDIDATES: usize = 6;

/// Below this, a model pick is treated as "don't know".
pub const MIN_CONFIDENCE: f32 = 0.5;

pub fn attribute(item: &PersistenceItem, apps: &[InstalledApp], jev: Option<&mut Jev>) -> Result<Owner> {
    if let Some(owner) = deterministic(item, apps) {
        return Ok(owner);
    }
    match jev {
        Some(jev) => ask(jev, item, apps),
        None => Ok(Owner::Unknown),
    }
}

/// Whether [`attribute`] would ask the model about this item: no evidence
/// ties it to an owner, but some installed app shares a name with it. Lets
/// callers skip loading the model entirely when nothing needs it.
pub fn needs_model(item: &PersistenceItem, apps: &[InstalledApp]) -> bool {
    deterministic(item, apps).is_none() && !candidates(item, apps).is_empty()
}

fn deterministic(item: &PersistenceItem, apps: &[InstalledApp]) -> Option<Owner> {
    if let Some(app) = apps.iter().find(|a| inside(&item.program, &a.path)) {
        return Some(Owner::Bundle { app: app.name.clone() });
    }
    if let Some((_, manager)) = PACKAGE_PREFIXES.iter().find(|(p, _)| item.program.starts_with(p)) {
        return Some(Owner::PackageManager {
            manager: (*manager).to_string(),
        });
    }
    if let Some(sig) = &item.signature {
        if sig.apple {
            return Some(Owner::Apple);
        }
        if let Some(team) = &sig.team_id {
            let same_team: Vec<&InstalledApp> = apps.iter().filter(|a| a.team_id.as_ref() == Some(team)).collect();
            // Several apps can share a team (Office); name the most similar.
            if let Some(app) = same_team.iter().max_by_key(|a| similarity(item, a)) {
                return Some(Owner::Team {
                    app: app.name.clone(),
                    team_id: team.clone(),
                });
            }
        }
    }
    None
}

/// Ask Jev which candidate app (if any) the item belongs to.
fn ask(jev: &mut Jev, item: &PersistenceItem, apps: &[InstalledApp]) -> Result<Owner> {
    ask_among(jev, item, &candidates(item, apps))
}

fn ask_among(jev: &mut Jev, item: &PersistenceItem, candidates: &[&InstalledApp]) -> Result<Owner> {
    if candidates.is_empty() {
        return Ok(Owner::Unknown);
    }
    let evidence = serde_json::json!({
        "backgroundItem": {
            "label": item.label,
            "program": item.program,
            "registeredBy": item.source,
            "signingTeam": item.signature.as_ref().and_then(|s| s.team_id.clone()),
        },
        "installedApplications": candidates.iter().map(|a| serde_json::json!({
            "name": a.name,
            "bundleId": a.bundle_id,
            "signingTeam": a.team_id,
        })).collect::<Vec<_>>(),
    });
    let descriptions: Vec<String> = candidates
        .iter()
        .map(|a| format!("It belongs to {}.", a.name))
        .chain(std::iter::once(
            "It belongs to none of the listed applications.".to_string(),
        ))
        .collect();
    let ids: Vec<String> = (0..descriptions.len()).map(|i| i.to_string()).collect();
    let options: Vec<Opt<'_>> = ids
        .iter()
        .zip(&descriptions)
        .map(|(id, description)| Opt { id, description })
        .collect();
    let r = jev.decide(
        &evidence,
        "Which installed application does this background item belong to, judging by its label, program path and signing team?",
        &options,
    )?;
    let best = r.best();
    let idx: usize = best.choice.parse().unwrap_or(usize::MAX);
    Ok(match candidates.get(idx) {
        Some(app) if best.probability >= MIN_CONFIDENCE => Owner::Model {
            app: app.name.clone(),
            confidence: best.probability,
            team_id: app.team_id.clone(),
        },
        _ => Owner::Unknown,
    })
}

/// The most name-similar apps, best first; apps sharing no token are dropped.
pub fn candidates<'a>(item: &PersistenceItem, apps: &'a [InstalledApp]) -> Vec<&'a InstalledApp> {
    let mut scored: Vec<(usize, &InstalledApp)> = apps
        .iter()
        .map(|a| (similarity(item, a), a))
        .filter(|(s, _)| *s > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
    scored.into_iter().take(MAX_CANDIDATES).map(|(_, a)| a).collect()
}

/// Shared distinctive tokens between the item (label, program path) and the
/// app (name, bundle id).
fn similarity(item: &PersistenceItem, app: &InstalledApp) -> usize {
    let item_tokens = tokens(&format!("{} {}", item.label.as_deref().unwrap_or(""), item.program));
    let app_tokens = tokens(&format!("{} {}", app.name, app.bundle_id.as_deref().unwrap_or("")));
    item_tokens.iter().filter(|t| app_tokens.contains(t)).count()
}

/// Lower-cased alphanumeric tokens, minus filler that every path shares.
fn tokens(s: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "com", "app", "apps", "contents", "macos", "library", "application", "support", "applications", "users",
        "agent", "daemon", "helper", "helpers", "launchagents", "launchdaemons", "resources", "privilegedhelpertools",
        "plist", "bin", "usr", "local", "opt", "the", "inc", "ltd", "llc", "updater", "update", "service", "mac", "macos",
    ];
    let mut out: Vec<String> = s
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|t| t.len() >= 3 && !STOP.contains(&t.as_str()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `program` lies inside the bundle at `app_path` (path-component aware).
fn inside(program: &str, app_path: &str) -> bool {
    let app = app_path.trim_end_matches('/');
    program.len() > app.len() && program.starts_with(app) && program.as_bytes()[app.len()] == b'/'
}

#[cfg(test)]
mod tests {
    use super::super::{ItemKind, Signature};
    use super::*;

    fn app(name: &str, bundle: &str, path: &str, team: Option<&str>) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            bundle_id: Some(bundle.into()),
            path: path.into(),
            team_id: team.map(Into::into),
        }
    }

    fn item(label: &str, program: &str, sig: Option<Signature>) -> PersistenceItem {
        PersistenceItem {
            kind: ItemKind::UserAgent,
            source: format!("/Library/LaunchAgents/{label}.plist"),
            label: Some(label.into()),
            program: program.into(),
            arguments: vec![],
            run_at_load: true,
            keep_alive: false,
            program_exists: true,
            signature: sig,
        }
    }

    fn apps() -> Vec<InstalledApp> {
        vec![
            app("Zoom", "us.zoom.xos", "/Applications/zoom.us.app", Some("BJ4HAAB9B3")),
            app("Microsoft Word", "com.microsoft.Word", "/Applications/Microsoft Word.app", Some("UBF8T346G9")),
            app("Microsoft Excel", "com.microsoft.Excel", "/Applications/Microsoft Excel.app", Some("UBF8T346G9")),
            app("Zoomit", "com.example.zoomit", "/Applications/Zoomit.app", None),
        ]
    }

    #[test]
    fn inside_bundle_wins() {
        let i = item("us.zoom.updater", "/Applications/zoom.us.app/Contents/Library/ZoomUpdater", None);
        assert_eq!(attribute(&i, &apps(), None).unwrap(), Owner::Bundle { app: "Zoom".into() });
    }

    #[test]
    fn bundle_prefix_must_end_at_a_component() {
        assert!(!inside("/Applications/zoom.us.application/x", "/Applications/zoom.us.app"));
        assert!(inside("/Applications/zoom.us.app/x", "/Applications/zoom.us.app/"));
    }

    #[test]
    fn same_team_attributes_to_most_similar_app() {
        let sig = Signature {
            signed: true,
            team_id: Some("UBF8T346G9".into()),
            apple: false,
        };
        let i = item(
            "com.microsoft.excel.helper",
            "/Library/PrivilegedHelperTools/com.microsoft.excel.helper",
            Some(sig),
        );
        assert_eq!(
            attribute(&i, &apps(), None).unwrap(),
            Owner::Team {
                app: "Microsoft Excel".into(),
                team_id: "UBF8T346G9".into()
            }
        );
    }

    #[test]
    fn homebrew_is_a_package_manager() {
        let i = item("homebrew.mxcl.postgresql@16", "/opt/homebrew/opt/postgresql@16/bin/postgres", None);
        assert_eq!(
            attribute(&i, &apps(), None).unwrap(),
            Owner::PackageManager { manager: "Homebrew".into() }
        );
    }

    #[test]
    fn unattributable_without_model_is_unknown() {
        let i = item("com.qwlkx.agent", "/Users/x/Library/Application Support/.qwlkx/run", None);
        assert_eq!(attribute(&i, &apps(), None).unwrap(), Owner::Unknown);
    }

    #[test]
    fn candidates_rank_by_shared_tokens() {
        let i = item("us.zoom.ZoomDaemon", "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon", None);
        let apps = apps();
        let c = candidates(&i, &apps);
        assert_eq!(c.first().map(|a| a.name.as_str()), Some("Zoom"));
        assert!(c.iter().all(|a| !a.name.starts_with("Microsoft")));
    }
}

/// Ownership accuracy on `eval/ownership.json`, against a no-model baseline
/// (top name-token candidate) — `cargo test -p jev --release
/// watchdog::ownership::eval -- --ignored --nocapture`. Compare with Laya via
/// the Python harness noted in the commit history.
#[cfg(test)]
mod eval {
    use super::super::{ItemKind, Signature};
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        apps: Vec<InstalledApp>,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        label: String,
        program: String,
        source: String,
        signing_team: Option<String>,
        accept: Vec<Option<String>>,
    }

    fn item(c: &Case) -> PersistenceItem {
        PersistenceItem {
            kind: ItemKind::UserAgent,
            source: c.source.clone(),
            label: Some(c.label.clone()),
            program: c.program.clone(),
            arguments: vec![],
            run_at_load: false,
            keep_alive: false,
            program_exists: true,
            signature: Some(Signature {
                signed: true,
                team_id: c.signing_team.clone(),
                apple: false,
            }),
        }
    }

    fn name(o: &Owner) -> Option<String> {
        match o {
            Owner::Model { app, .. } => Some(app.clone()),
            _ => None,
        }
    }

    #[test]
    #[ignore]
    fn eval() {
        let f: Fixture = serde_json::from_str(include_str!("../../eval/ownership.json")).unwrap();
        let mut jev = Jev::load(&crate::ModelFiles::cached(&super::super::MODEL).expect("model cached")).unwrap();
        let (mut base, mut pipe, mut all, mut calls) = (0, 0, 0, 0);
        let t = std::time::Instant::now();
        for c in &f.cases {
            let it = item(c);
            let cands = candidates(&it, &f.apps);
            // Baseline: no model, take the top-ranked candidate (or none).
            let b = cands.first().map(|a| a.name.clone());
            // Pipeline: ask Jev only when there are candidates.
            let p = if cands.is_empty() {
                None
            } else {
                calls += 1;
                name(&ask(&mut jev, &it, &f.apps).unwrap())
            };
            // Hard mode: every installed app is a candidate.
            let all_apps: Vec<InstalledApp> = f.apps.clone();
            let a = name(&ask_among(&mut jev, &it, &all_apps.iter().collect::<Vec<_>>()).unwrap());
            let ok = |x: &Option<String>| c.accept.contains(x);
            base += ok(&b) as usize;
            pipe += ok(&p) as usize;
            all += ok(&a) as usize;
            println!(
                "{:<46} base {:<4} jev {:<4} jev-all {:<4}  (jev said {:?})",
                c.label,
                if ok(&b) { "✓" } else { "✗" },
                if ok(&p) { "✓" } else { "✗" },
                if ok(&a) { "✓" } else { "✗" },
                p
            );
        }
        let n = f.cases.len();
        println!(
            "baseline {base}/{n} · jev pipeline {pipe}/{n} ({calls} calls) · jev all-apps {all}/{n} · {:.0?} total",
            t.elapsed()
        );
    }
}
