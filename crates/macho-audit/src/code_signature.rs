//! Summarise a bundle's code signature using `codesign -dv`.
//!
//! `codesign` writes its report to stderr in a stable line-oriented format
//! that's easy to parse with substring matches. We only extract what the
//! audit actually needs: team identifier, authority chain, hardened-runtime
//! flag, and notarization-staple presence.

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CodeSignature {
    pub signed: bool,
    pub hardened_runtime: bool,
    pub notarized: bool,
    pub team_identifier: Option<String>,
    pub authority: Vec<String>,
    /// Raw `codesign -dvvv` stderr. Handy for surfacing to users when our
    /// parser misses something.
    pub raw: String,
}

pub async fn read(app_path: &Path) -> CodeSignature {
    let Ok(output) = tokio::process::Command::new("codesign")
        .arg("-dvvv")
        .arg(app_path)
        .output()
        .await
    else {
        return CodeSignature::default();
    };

    // codesign writes the summary to stderr regardless of status.
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // "code object is not signed" → unsigned.
    let signed = !stderr.contains("not signed at all")
        && !stderr.contains("is not signed")
        && stderr.contains("Identifier=");

    let mut sig = CodeSignature {
        signed,
        raw: stderr.clone(),
        ..Default::default()
    };

    if !signed {
        return sig;
    }

    // Hardened runtime: flag on CodeDirectory line is `flags=0x10000(runtime)`
    // or includes `(runtime)` in the bitmask pretty-print.
    sig.hardened_runtime = stderr
        .lines()
        .any(|l| l.starts_with("CodeDirectory") && l.contains("(runtime)"));

    sig.notarized = stderr.contains("Notarization Ticket=stapled");

    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            let id = rest.trim().trim_matches('"').to_owned();
            if id != "not set" && !id.is_empty() {
                sig.team_identifier = Some(id);
            }
        } else if let Some(rest) = line.strip_prefix("Authority=") {
            sig.authority.push(rest.trim().to_owned());
        }
    }

    sig
}
