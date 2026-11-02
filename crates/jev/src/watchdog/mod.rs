//! Behaviour watchdog: what on this machine runs in the background, who does
//! it belong to, and does anything about it look like misbehaviour?
//!
//! Malware on macOS almost always persists the same way legitimate software
//! does — a launchd agent/daemon or a browser native-messaging bridge — but
//! unlike legitimate software it rarely points back into an installed app's
//! bundle. So the watchdog starts from the machine-wide persistence inventory,
//! not from apps:
//!
//! 1. **Ownership** ([`ownership`]): attribute each item to an installed app —
//!    deterministically when the program sits inside a bundle or is signed by
//!    the same Team ID, otherwise by asking Jev to pick the owning app from a
//!    short candidate list (an evidence-contained question small models handle
//!    well).
//! 2. **Rules** ([`rules`]): deterministic, explainable signals — script
//!    launchers, hidden/temporary paths, `com.apple.*` impersonation, unsigned
//!    programs, random-looking labels, orphans.
//! 3. **Change** ([`change`]): what appeared or changed since the last scan.
//!
//! Calibrated against `eval/persistence.json` (labelled benign and malicious
//! items modelled on documented macOS malware families) and the live machine.

pub mod change;
pub mod ownership;
pub mod rules;

use serde::{Deserialize, Serialize};

use crate::{Jev, ModelSource, Result};

/// The model Jev uses for ownership questions, when enabled (~1.1 GB file).
/// Picking among candidate apps by name/label/path is evidence-contained, so
/// the small model is the starting point; see the eval for its accuracy.
pub const MODEL: ModelSource = ModelSource::Gguf {
    repo: "unsloth/Qwen3-1.7B-GGUF",
    file: "Qwen3-1.7B-Q4_K_M.gguf",
    tokenizer_repo: "Qwen/Qwen3-1.7B",
};

/// `codesign` facts about a program.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub signed: bool,
    /// Developer Team ID; `None` for ad-hoc and Apple platform signatures.
    pub team_id: Option<String>,
    /// Signed by Apple itself ("Software Signing") or the Mac App Store.
    pub apple: bool,
}

impl Signature {
    /// Signed by an identifiable developer or Apple (not ad-hoc).
    pub fn identified(&self) -> bool {
        self.signed && (self.apple || self.team_id.is_some())
    }
}

/// An installed application, as a candidate owner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApp {
    pub name: String,
    pub bundle_id: Option<String>,
    /// Bundle path, e.g. `/Applications/Foo.app`.
    pub path: String,
    pub team_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ItemKind {
    /// `~/Library/LaunchAgents` — runs at the user's login.
    UserAgent,
    /// `/Library/LaunchAgents` — runs at every user's login.
    GlobalAgent,
    /// `/Library/LaunchDaemons` — runs as root at boot.
    Daemon,
    /// A native-messaging host manifest in a browser profile.
    BrowserBridge { browser: String },
}

/// One thing that runs in the background or bridges into a browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistenceItem {
    pub kind: ItemKind,
    /// The plist / manifest that registers it.
    pub source: String,
    /// launchd label or native-messaging host name.
    pub label: Option<String>,
    /// The executable it runs.
    pub program: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub run_at_load: bool,
    #[serde(default)]
    pub keep_alive: bool,
    #[serde(default = "yes")]
    pub program_exists: bool,
    /// `None` when it couldn't be checked (e.g. the program is missing).
    pub signature: Option<Signature>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Normal,
    Questionable,
    Bad,
}

/// Everything the watchdog concluded about one item.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemReport {
    pub item: PersistenceItem,
    pub owner: ownership::Owner,
    pub signals: Vec<rules::Signal>,
    pub verdict: Verdict,
}

/// Assess every item. `jev` enables model-based ownership for items the
/// deterministic checks can't attribute; without it they stay unattributed.
pub fn assess(items: &[PersistenceItem], apps: &[InstalledApp], mut jev: Option<&mut Jev>) -> Result<Vec<ItemReport>> {
    items
        .iter()
        .map(|item| {
            let owner = ownership::attribute(item, apps, jev.as_deref_mut())?;
            let signals = rules::evaluate(item, &owner);
            Ok(ItemReport {
                verdict: rules::verdict(&signals),
                item: item.clone(),
                owner,
                signals,
            })
        })
        .collect()
}

#[cfg(test)]
mod eval {
    //! The labelled set in `eval/persistence.json`. Rules-only runs in every
    //! `cargo test`; the Jev variant needs the model:
    //! `cargo test -p jev --release watchdog::eval -- --ignored --nocapture`

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
        #[serde(default)]
        family: Option<String>,
        // Fixture keys are camelCase.
        note: String,
        item: PersistenceItem,
        expect: Verdict,
        /// Only reachable with Jev ownership (impersonation): rules alone
        /// are expected to stop at `Questionable`.
        #[serde(default)]
        needs_jev: bool,
        #[serde(default)]
        hard: bool,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../eval/persistence.json")).expect("valid fixture")
    }

    /// Print the table; return the cases that missed their expected verdict.
    fn run(jev: Option<&mut Jev>) -> Vec<String> {
        let with_jev = jev.is_some();
        let f = fixture();
        let items: Vec<PersistenceItem> = f.cases.iter().map(|c| c.item.clone()).collect();
        let reports = assess(&items, &f.apps, jev).unwrap();
        let mut misses = Vec::new();
        let (mut tp, mut fn_, mut fp, mut tn) = (0, 0, 0, 0);
        for (c, r) in f.cases.iter().zip(&reports) {
            let flagged = r.verdict != Verdict::Normal;
            match (c.label == "malicious", flagged) {
                (true, true) => tp += 1,
                (true, false) => fn_ += 1,
                (false, true) => fp += 1,
                (false, false) => tn += 1,
            }
            let want = if c.needs_jev && !with_jev { Verdict::Questionable } else { c.expect };
            let ok = r.verdict == want;
            if !ok && !c.hard {
                misses.push(format!("{}: got {:?}, want {:?}", c.item.source, r.verdict, want));
            }
            let codes: Vec<&str> = r.signals.iter().map(|s| s.code).collect();
            println!(
                "{} {:<9} {:<13} {:<26} owner={:<40} {}",
                if ok { "✓" } else if c.hard { "~" } else { "✗" },
                c.label,
                format!("{:?}", r.verdict),
                c.family.as_deref().unwrap_or(&c.note[..c.note.len().min(26)]),
                format!("{:?}", r.owner),
                codes.join(",")
            );
        }
        println!("malicious flagged {tp}/{} · benign flagged {fp}/{}", tp + fn_, fp + tn);
        misses
    }

    #[test]
    fn rules_only() {
        let misses = run(None);
        assert!(misses.is_empty(), "{misses:#?}");
    }

    #[test]
    #[ignore]
    fn with_jev_ownership() {
        let files = crate::ModelFiles::fetch(&MODEL).expect("model");
        let mut jev = Jev::load(&files).unwrap();
        let misses = run(Some(&mut jev));
        println!("misses: {misses:#?}");
    }
}
