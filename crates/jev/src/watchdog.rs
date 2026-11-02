//! Behaviour watchdog: is an application "behaving badly"?
//!
//! Follows SemIf/OpenJev's decomposition rather than asking one holistic
//! question. The caller groups plain-language facts about an app into
//! [`Evidence`] (persistence, code integrity, browser integration, privacy
//! access, network, bundled components); every aspect that has facts gets its
//! own narrow criterion — "does its background activity go beyond what an app
//! of this kind needs?" — answered `concern` / `fine` / `insufficient` via
//! [`Jev::decide`]. Code, not the model, combines those answers into a
//! [`Verdict`], so every flag names the criterion that raised it.
//!
//! The whole app profile is the shared evidence for each criterion (so the
//! model can judge fit-for-purpose), and it comes first in the prompt so a
//! prefix-caching backend could prefill it once.

use serde::Serialize;

use crate::{Jev, ModelSource, Opt, Result};

/// Models the watchdog can run, smallest first. Chosen by calibration on the
/// apps installed on a developer Mac (see `src-tauri/src/watchdog.rs`).
pub const MODELS: [ModelSource; 2] = [
    // ~1.1 GB
    ModelSource::Gguf {
        repo: "unsloth/Qwen3-1.7B-GGUF",
        file: "Qwen3-1.7B-Q4_K_M.gguf",
        tokenizer_repo: "Qwen/Qwen3-1.7B",
    },
    // ~2.5 GB
    ModelSource::Gguf {
        repo: "unsloth/Qwen3-4B-Instruct-2507-GGUF",
        file: "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
        tokenizer_repo: "Qwen/Qwen3-4B-Instruct-2507",
    },
];

/// The model the watchdog ships with.
pub const MODEL: ModelSource = MODELS[1];

/// Facts beyond this per aspect are dropped to keep prompts short.
pub const MAX_FACTS_PER_ASPECT: usize = 8;

/// What the caller observed about one app, one sentence per fact.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub application: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// Login items, launch agents/daemons, services, keep-alive.
    pub background_activity: Vec<String>,
    /// Signing, hardened runtime, library validation, memory protections.
    pub code_integrity: Vec<String>,
    /// Native-messaging bridges into browsers.
    pub browser_integration: Vec<String>,
    /// Privacy and system-level entitlements, URL schemes, insecure transport.
    pub privacy_access: Vec<String>,
    /// Hosts contacted during a recorded session.
    pub network_destinations: Vec<String>,
    /// Bundled helpers / plug-ins (context only — no criterion of its own).
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Aspect {
    BackgroundActivity,
    CodeIntegrity,
    BrowserIntegration,
    PrivacyAccess,
    NetworkDestinations,
}

struct Criterion {
    aspect: Aspect,
    question: &'static str,
    concern: &'static str,
    fine: &'static str,
}

const CRITERIA: [Criterion; 5] = [
    Criterion {
        aspect: Aspect::BackgroundActivity,
        question: "Does the application keep code running in the background, at login or with root privileges beyond what an application of this kind needs?",
        concern: "Its background activity goes beyond what its purpose needs.",
        fine: "Its background activity fits its purpose.",
    },
    Criterion {
        aspect: Aspect::CodeIntegrity,
        question: "Does the application weaken the operating system's code-integrity protections without a clear need for an application of this kind?",
        concern: "It weakens code-integrity protections without a clear need.",
        fine: "Its code-integrity settings are reasonable for its purpose.",
    },
    Criterion {
        aspect: Aspect::BrowserIntegration,
        question: "Does the application's integration with web browsers go beyond what an application of this kind needs?",
        concern: "Its browser integration goes beyond what its purpose needs.",
        fine: "Its browser integration fits its purpose.",
    },
    Criterion {
        aspect: Aspect::PrivacyAccess,
        question: "Do the application's privacy-sensitive permissions, deep system access and ways to be opened by other software go beyond what an application of this kind needs?",
        concern: "Its privacy access goes beyond what its purpose needs.",
        fine: "Its privacy access fits its purpose.",
    },
    Criterion {
        aspect: Aspect::NetworkDestinations,
        question: "Did the application contact network destinations that are unrelated to its purpose?",
        concern: "It contacted destinations unrelated to its purpose.",
        fine: "The destinations fit its purpose.",
    },
];

const INSUFFICIENT: &str = "The evidence is insufficient to decide.";

impl Evidence {
    fn facts(&self, aspect: Aspect) -> &[String] {
        match aspect {
            Aspect::BackgroundActivity => &self.background_activity,
            Aspect::CodeIntegrity => &self.code_integrity,
            Aspect::BrowserIntegration => &self.browser_integration,
            Aspect::PrivacyAccess => &self.privacy_access,
            Aspect::NetworkDestinations => &self.network_destinations,
        }
    }

    /// The JSON state every criterion sees: the whole profile, truncated.
    pub fn to_json(&self) -> serde_json::Value {
        let mut e = self.clone();
        for v in [
            &mut e.background_activity,
            &mut e.code_integrity,
            &mut e.browser_integration,
            &mut e.privacy_access,
            &mut e.network_destinations,
            &mut e.components,
        ] {
            v.truncate(MAX_FACTS_PER_ASPECT);
        }
        serde_json::to_value(e).expect("evidence is plain data")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Normal,
    Questionable,
    Bad,
}

/// One criterion's answer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub aspect: Aspect,
    pub question: String,
    /// The facts this criterion is about.
    pub facts: Vec<String>,
    pub concern: f32,
    pub fine: f32,
    pub insufficient: f32,
    /// `concern` is the most likely answer.
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub verdict: Verdict,
    /// One per aspect that had facts, in criterion order.
    pub findings: Vec<Finding>,
    /// Bundled components, shown to the model as context.
    pub components: Vec<String>,
}

/// Ask each applicable criterion about `evidence` and combine the answers.
pub fn assess(jev: &mut Jev, evidence: &Evidence) -> Result<Assessment> {
    let state = evidence.to_json();
    let mut findings = Vec::new();
    for c in &CRITERIA {
        let facts = evidence.facts(c.aspect);
        if facts.is_empty() {
            continue;
        }
        let options = [
            Opt { id: "concern", description: c.concern },
            Opt { id: "fine", description: c.fine },
            Opt { id: "insufficient", description: INSUFFICIENT },
        ];
        // Small models lean hard toward whichever option is listed first
        // (calibration saw concern = 1.00 everywhere when it was always "A"),
        // so ask once per cyclic rotation and average by option id.
        let mut sum = [0f32; 3];
        for shift in 0..options.len() {
            let rotated: Vec<Opt<'_>> = (0..options.len()).map(|i| options[(i + shift) % options.len()]).collect();
            let r = jev.decide(&state, c.question, &rotated)?;
            for (i, o) in options.iter().enumerate() {
                sum[i] += r.probability(o.id).unwrap_or(0.0);
            }
        }
        let [concern, fine, insufficient] = sum.map(|p| p / options.len() as f32);
        findings.push(Finding {
            aspect: c.aspect,
            question: c.question.to_string(),
            facts: facts.iter().take(MAX_FACTS_PER_ASPECT).cloned().collect(),
            concern,
            fine,
            insufficient,
            flagged: concern > fine && concern > insufficient,
        });
    }
    Ok(Assessment {
        verdict: verdict_of(&findings),
        findings,
        components: evidence.components.iter().take(MAX_FACTS_PER_ASPECT).cloned().collect(),
    })
}

/// One flagged aspect is worth a look; two or more independent ones together
/// are the pattern we call "behaving badly".
fn verdict_of(findings: &[Finding]) -> Verdict {
    match findings.iter().filter(|f| f.flagged).count() {
        0 => Verdict::Normal,
        1 => Verdict::Questionable,
        _ => Verdict::Bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(flagged: bool) -> Finding {
        Finding {
            aspect: Aspect::CodeIntegrity,
            question: String::new(),
            facts: vec![],
            concern: 0.0,
            fine: 0.0,
            insufficient: 0.0,
            flagged,
        }
    }

    #[test]
    fn verdict_counts_flagged_aspects() {
        assert_eq!(verdict_of(&[]), Verdict::Normal);
        assert_eq!(verdict_of(&[finding(false), finding(true)]), Verdict::Questionable);
        assert_eq!(verdict_of(&[finding(true), finding(true)]), Verdict::Bad);
    }

    #[test]
    fn evidence_json_truncates_and_omits_missing_framework() {
        let e = Evidence {
            application: "Foo".into(),
            code_integrity: (0..MAX_FACTS_PER_ASPECT + 3).map(|i| format!("f{i}")).collect(),
            ..Default::default()
        };
        let j = e.to_json();
        assert_eq!(j["application"], "Foo");
        assert!(j.get("framework").is_none());
        assert_eq!(j["codeIntegrity"].as_array().unwrap().len(), MAX_FACTS_PER_ASPECT);
        assert_eq!(j["backgroundActivity"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn every_aspect_has_a_criterion() {
        for a in [
            Aspect::BackgroundActivity,
            Aspect::CodeIntegrity,
            Aspect::BrowserIntegration,
            Aspect::PrivacyAccess,
            Aspect::NetworkDestinations,
        ] {
            assert_eq!(CRITERIA.iter().filter(|c| c.aspect == a).count(), 1);
        }
    }
}

/// Probe one case across weight formats and prompt variants (needs models cached):
/// `cargo test -p jev --release watchdog::probe -- --ignored --nocapture`
#[cfg(test)]
mod probe {
    use super::*;
    use crate::ModelFiles;

    const CONTEXT: &str = "Most legitimate apps request camera or microphone access, register URL schemes, ship helper extensions, start at login, or install an updater. Only behaviour beyond what the app's purpose needs, hidden from the user, or resembling malware is a concern.";

    #[test]
    #[ignore]
    fn probe() {
        let models = [
            ModelSource::Safetensors { repo: "Qwen/Qwen3-4B-Instruct-2507" },
            MODELS[1],
        ];
        let cases = [
            ("Keynote", "privacyAccess", "Holds entitlements for the camera, the microphone, contacts, the photo library.", false),
            ("Safari", "codeIntegrity", "Allows unsigned executable memory.", false),
            ("SuperCleaner Pro", "backgroundActivity", "Registers a launch daemon that runs as root at boot running cleanerd (located outside the app, at /Library/PrivilegedHelperTools/cleanerd), started automatically, relaunched whenever it exits.", true),
            ("PDF Viewer", "codeIntegrity", "Honours DYLD environment variables, which allows code injection.", true),
        ];
        for source in models {
            let mut jev = Jev::load(&ModelFiles::cached(&source).expect("cached")).unwrap();
            println!("\n== {}", source.id());
            for (app, aspect, fact, expect_concern) in cases {
                let plain = serde_json::json!({ "application": app, aspect: [fact] });
                let with_ctx = serde_json::json!({ "context": CONTEXT, "application": app, aspect: [fact] });
                let variants: [(&str, &serde_json::Value, &str, [Opt<'_>; 3]); 3] = [
                    ("leading", &plain, "Does this go beyond what an application of this kind needs?", [
                        Opt { id: "concern", description: "It goes beyond what its purpose needs." },
                        Opt { id: "fine", description: "It fits its purpose." },
                        Opt { id: "insufficient", description: INSUFFICIENT },
                    ]),
                    ("context", &with_ctx, "Does this go beyond what an application of this kind needs?", [
                        Opt { id: "concern", description: "It goes beyond what its purpose needs." },
                        Opt { id: "fine", description: "It fits its purpose." },
                        Opt { id: "insufficient", description: INSUFFICIENT },
                    ]),
                    ("typical", &with_ctx, "Is this typical for an application of this kind?", [
                        Opt { id: "fine", description: "Yes, it is typical for this kind of application." },
                        Opt { id: "concern", description: "No, it is unusual and worth a closer look." },
                        Opt { id: "insufficient", description: INSUFFICIENT },
                    ]),
                ];
                let mut line = format!("{app:<18} want {:<7}", if expect_concern { "concern" } else { "fine" });
                for (name, ev, q, opts) in &variants {
                    let mut sum = [0f32; 3];
                    for shift in 0..3 {
                        let rot: Vec<Opt<'_>> = (0..3).map(|i| opts[(i + shift) % 3]).collect();
                        let r = jev.decide(ev, q, &rot).unwrap();
                        for (i, id) in ["concern", "fine", "insufficient"].iter().enumerate() {
                            sum[i] += r.probability(id).unwrap();
                        }
                    }
                    line.push_str(&format!(" | {name}: c {:.2} f {:.2} i {:.2}", sum[0] / 3.0, sum[1] / 3.0, sum[2] / 3.0));
                }
                println!("{line}");
            }
        }
    }
}
