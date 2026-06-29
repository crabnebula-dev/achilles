//! `cargo run -p fixtures --bin assess -- <detect.json> <static.json> <audit.json> <expected.json>`
//!
//! Compares the JSON emitted by the `detect`, `static-scan`, and `audit`
//! analyzers (run against the fixture) to the human-verified expected-findings
//! manifest. Prints a PASS/FAIL line per expectation and exits non-zero if any
//! expectation is missing — the assessment gate for the fixture workflow.
//!
//! Deliberately compares *plain JSON* (it has no dependency on the analysis
//! crates), so it never affects their feature resolution. The expectation is a
//! lower bound: a fresh run must still surface everything listed, but may also
//! surface more.

use std::process::ExitCode;

use serde_json::Value;

fn load(path: &str) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

struct Report {
    pass: usize,
    fail: usize,
}

impl Report {
    fn check(&mut self, label: impl AsRef<str>, ok: bool) {
        if ok {
            self.pass += 1;
            println!("  \u{2713} {}", label.as_ref());
        } else {
            self.fail += 1;
            println!("  \u{2717} {}", label.as_ref());
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        eprintln!("usage: assess <detect.json> <static.json> <audit.json> <expected.json>");
        return ExitCode::from(2);
    }
    let detect = load(&args[0]);
    let static_scan = load(&args[1]);
    let audit = load(&args[2]);
    let exp = load(&args[3]);

    let mut r = Report { pass: 0, fail: 0 };

    // ---- detection ----------------------------------------------------------
    println!("detection:");
    let ed = &exp["detection"];
    r.check("framework", detect["framework"] == ed["framework"]);
    if !ed["confidence"].is_null() {
        r.check("confidence", detect["confidence"] == ed["confidence"]);
    }
    if let Some(versions) = ed["versions"].as_object() {
        for (key, want) in versions {
            r.check(format!("version.{key}"), detect["versions"][key] == *want);
        }
    }

    // ---- static-scan findings ----------------------------------------------
    println!("static findings:");
    let found: Vec<&str> = static_scan["findings"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f["rule_id"].as_str()).collect())
        .unwrap_or_default();
    for rule in exp["staticFindings"].as_array().into_iter().flatten() {
        let id = rule.as_str().unwrap_or("");
        r.check(id, found.contains(&id));
    }

    // ---- bundled dependencies ----------------------------------------------
    println!("dependencies:");
    let deps = static_scan["dependencies"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for dep in exp["dependencies"].as_array().into_iter().flatten() {
        let name = dep["name"].as_str().unwrap_or("");
        let version = dep["version"].as_str().unwrap_or("");
        let hit = deps
            .iter()
            .any(|d| d["name"] == dep["name"] && d["version"] == dep["version"]);
        r.check(format!("{name}@{version}"), hit);
    }

    // ---- audit (Info.plist + ASAR integrity) -------------------------------
    println!("audit:");
    let ea = &exp["audit"];
    let info = &audit["info_plist"];
    if let Some(want) = ea["infoPlist"]["allowsArbitraryLoads"].as_bool() {
        r.check(
            "infoPlist.allowsArbitraryLoads",
            info["allows_arbitrary_loads"].as_bool() == Some(want),
        );
    }
    for scheme in ea["infoPlist"]["urlSchemes"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let got = info["url_schemes"]
            .as_array()
            .map(|a| a.contains(scheme))
            .unwrap_or(false);
        r.check(
            format!("infoPlist.urlScheme {}", scheme.as_str().unwrap_or("")),
            got,
        );
    }
    for domain in ea["infoPlist"]["tlsExceptionDomains"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let got = info["tls_exceptions"]
            .as_array()
            .map(|a| a.iter().any(|e| e["domain"] == *domain))
            .unwrap_or(false);
        r.check(
            format!("infoPlist.tlsException {}", domain.as_str().unwrap_or("")),
            got,
        );
    }
    let want_key = &ea["asarIntegrity"]["archiveKey"];
    let want_match = ea["asarIntegrity"]["matches"].as_bool().unwrap_or(true);
    let asar_ok = audit["asar_integrity"]
        .as_array()
        .map(|a| {
            a.iter().any(|c| {
                c["archive_key"] == *want_key && c["matches"].as_bool() == Some(want_match)
            })
        })
        .unwrap_or(false);
    r.check(
        format!(
            "asarIntegrity {} matches={want_match}",
            want_key.as_str().unwrap_or("")
        ),
        asar_ok,
    );

    // ---- summary ------------------------------------------------------------
    println!("\n{} passed, {} failed", r.pass, r.fail);
    if r.fail == 0 {
        println!("assessment OK — results line up with the expected manifest");
        ExitCode::SUCCESS
    } else {
        eprintln!("assessment FAILED — analyzer output diverged from the expected manifest");
        ExitCode::FAILURE
    }
}
