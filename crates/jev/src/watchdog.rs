//! Behaviour watchdog: ask Jev whether an application is "behaving badly",
//! given plain-language facts about what it does to the system.
//!
//! Collecting the facts is the caller's job (Achilles maps its side-effect,
//! signing and network evidence into sentences); this module owns the prompt
//! and the scoring so the wording stays in one place and is testable without
//! a model.
//!
//! Small models are sensitive to where an option sits in the list, so
//! [`assess`] scores every cyclic rotation of the choices and averages the
//! per-choice probabilities. That costs one forward pass per choice (~3 ×
//! 100 ms) and removes most of the positional bias.

use serde::Serialize;

use crate::{Jev, Result};

/// The model the watchdog needs. Calibrated against the apps installed on a
/// developer Mac (48 apps): Qwen3-0.6B called 31–45 of them "bad" whatever the
/// prompt (Safari, Signal and Keynote included), while the 4B instruct model
/// with the prompt below flagged 4 and called 6 "unusual". ~7.5 GB download,
/// ~1.2 s per forward pass on Apple silicon.
pub const MODEL: &str = "Qwen/Qwen3-4B-Instruct-2507";

/// Telling the model what *normal* looks like matters most: without it, every
/// listed fact reads as an accusation.
pub const SYSTEM: &str = "You are a security analyst reviewing desktop applications. Most legitimate apps request camera or microphone access, register URL schemes, ship helper extensions, start at login, or install an updater. An app is behaving badly only when its behaviour goes beyond what its purpose needs, hides from the user, or looks like malware. Choose one option.";

/// The verdicts, from benign to bad. Index order is relied on by [`Verdict`].
pub const CHOICES: [&str; 3] = [
    "Expected for this kind of app",
    "Unusual, worth a closer look",
    "Looks malicious or abusive",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Normal,
    Questionable,
    Bad,
}

/// What the caller knows about one app.
#[derive(Debug, Clone, Default)]
pub struct Subject<'a> {
    pub name: &'a str,
    /// Framework / runtime, e.g. "Electron". Optional context for the model.
    pub framework: Option<&'a str>,
    /// One plain sentence per observation, e.g. "Registers a launch daemon
    /// that runs as root at boot." Order roughly by importance — the prompt
    /// keeps at most [`MAX_FACTS`].
    pub facts: Vec<String>,
}

/// Facts beyond this are dropped: Qwen3-0.6B's judgement degrades on long
/// prompts and we want the forward pass to stay well under a second.
pub const MAX_FACTS: usize = 24;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub verdict: Verdict,
    /// Averaged probabilities, aligned with [`CHOICES`].
    pub probabilities: [f32; 3],
    /// The facts the model actually saw (after truncation).
    pub facts: Vec<String>,
    pub facts_dropped: usize,
}

/// The user turn: who the app is and what it was seen doing.
pub fn subject_text(subject: &Subject<'_>) -> String {
    let mut s = format!("Application: {}", subject.name);
    if let Some(fw) = subject.framework {
        s.push_str(&format!(" ({fw})"));
    }
    s.push_str("\nObserved behaviour:\n");
    if subject.facts.is_empty() {
        s.push_str("- Nothing unusual was observed.\n");
    }
    for fact in subject.facts.iter().take(MAX_FACTS) {
        s.push_str("- ");
        s.push_str(fact);
        s.push('\n');
    }
    s.push_str("\nIs this application behaving badly?");
    s
}

/// Score `subject` with every rotation of [`CHOICES`] and average.
pub fn assess(jev: &mut Jev, subject: &Subject<'_>) -> Result<Assessment> {
    assess_with(jev, SYSTEM, &CHOICES, subject)
}

/// [`assess`] with a custom instruction and verdict wording (benign → bad),
/// for calibrating prompts.
pub fn assess_with(jev: &mut Jev, system: &str, choices: &[&str; 3], subject: &Subject<'_>) -> Result<Assessment> {
    let text = subject_text(subject);
    let n = choices.len();
    let mut sum = [0f32; 3];
    for shift in 0..n {
        let rotated: Vec<&str> = (0..n).map(|i| choices[(i + shift) % n]).collect();
        let result = jev.classify(system, &text, &rotated)?;
        for (i, choice) in choices.iter().enumerate() {
            sum[i] += result.probability(choice).unwrap_or(0.0);
        }
    }
    let probabilities = sum.map(|p| p / n as f32);
    Ok(Assessment {
        verdict: verdict_of(&probabilities),
        probabilities,
        facts: subject.facts.iter().take(MAX_FACTS).cloned().collect(),
        facts_dropped: subject.facts.len().saturating_sub(MAX_FACTS),
    })
}

fn verdict_of(p: &[f32; 3]) -> Verdict {
    let best = (0..3).max_by(|&a, &b| p[a].total_cmp(&p[b])).unwrap_or(0);
    [Verdict::Normal, Verdict::Questionable, Verdict::Bad][best]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_text_lists_facts() {
        let s = subject_text(&Subject {
            name: "Example",
            framework: Some("Electron"),
            facts: vec!["Starts at login.".into(), "Ships 2 helper executables.".into()],
        });
        assert_eq!(
            s,
            "Application: Example (Electron)\nObserved behaviour:\n- Starts at login.\n- Ships 2 helper executables.\n\nIs this application behaving badly?"
        );
    }

    #[test]
    fn subject_text_without_facts_says_so() {
        let s = subject_text(&Subject {
            name: "Calculator",
            ..Default::default()
        });
        assert!(s.contains("- Nothing unusual was observed.\n"));
    }

    #[test]
    fn subject_text_truncates() {
        let facts = (0..MAX_FACTS + 5).map(|i| format!("fact {i}")).collect();
        let s = subject_text(&Subject {
            name: "X",
            framework: None,
            facts,
        });
        assert!(s.contains(&format!("fact {}", MAX_FACTS - 1)));
        assert!(!s.contains(&format!("fact {MAX_FACTS}")));
    }

    #[test]
    fn verdict_picks_the_max() {
        assert_eq!(verdict_of(&[0.2, 0.7, 0.1]), Verdict::Questionable);
        assert_eq!(verdict_of(&[0.1, 0.2, 0.7]), Verdict::Bad);
    }
}
