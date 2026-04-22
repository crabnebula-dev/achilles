//! Integration tests against synthetic and real fixtures.


use static_scan::RuleId;

#[test]
fn detects_sandbox_false_in_js() {
    let tmp = tempdir();
    let src = r#"
        new BrowserWindow({
            webPreferences: {
                sandbox: false,
                contextIsolation: true,
            },
        });
    "#;
    std::fs::write(tmp.join("main.js"), src).unwrap();

    let report = static_scan::scan_directory(&tmp).unwrap();
    let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id).collect();
    assert!(ids.contains(&RuleId::SandboxJsCheck), "findings: {ids:?}");
    assert!(!ids.contains(&RuleId::ContextIsolationJsCheck));
}

#[test]
fn detects_minified_booleans() {
    let tmp = tempdir();
    // Terser-style: `false` → `!1`, `true` → `!0`.
    let src = r#"new BrowserWindow({webPreferences:{sandbox:!1,nodeIntegration:!0}});"#;
    std::fs::write(tmp.join("bundle.js"), src).unwrap();

    let report = static_scan::scan_directory(&tmp).unwrap();
    let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id).collect();
    assert!(ids.contains(&RuleId::SandboxJsCheck));
    assert!(ids.contains(&RuleId::NodeIntegrationJsCheck));
}

#[test]
fn csp_absent_in_html_fires() {
    let tmp = tempdir();
    std::fs::write(
        tmp.join("index.html"),
        r#"<!doctype html><html><head><title>x</title></head><body></body></html>"#,
    )
    .unwrap();

    let report = static_scan::scan_directory(&tmp).unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::CspGlobalCheck));
}

#[test]
fn csp_present_suppresses_finding() {
    let tmp = tempdir();
    std::fs::write(
        tmp.join("index.html"),
        r#"<!doctype html><html><head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        </head><body></body></html>"#,
    )
    .unwrap();

    let report = static_scan::scan_directory(&tmp).unwrap();
    assert!(!report
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::CspGlobalCheck));
}

#[test]
fn clean_code_produces_no_findings() {
    let tmp = tempdir();
    std::fs::write(
        tmp.join("main.js"),
        r#"
        new BrowserWindow({
            webPreferences: {
                sandbox: true,
                contextIsolation: true,
                nodeIntegration: false,
            }
        });
        "#,
    )
    .unwrap();
    std::fs::write(
        tmp.join("index.html"),
        r#"<!doctype html><html><head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        </head></html>"#,
    )
    .unwrap();

    let report = static_scan::scan_directory(&tmp).unwrap();
    assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
}

/// If a real Electron-app bundle is available locally (path supplied via
/// the `ACHILLES_TESTAPP_BUNDLE` env var), run against its ASAR and make
/// sure the scan completes without errors. We don't assert on specific
/// findings because the ASAR content varies between apps and builds.
#[test]
fn testapp_asar_scans_cleanly() {
    const BUNDLE_ENV: &str = "ACHILLES_TESTAPP_BUNDLE";
    let Some(bundle) = std::env::var_os(BUNDLE_ENV) else {
        eprintln!("skipping: ${BUNDLE_ENV} not set");
        return;
    };
    let asar = std::path::PathBuf::from(bundle).join("Contents/Resources/app.asar");
    if !asar.exists() {
        eprintln!("skipping: {} not present", asar.display());
        return;
    }
    let report = static_scan::scan_asar(&asar).expect("scan should succeed");
    assert!(report.rules_run > 0);
    assert!(report.files_scanned > 0);
    eprintln!(
        "testapp: {} files scanned, {} findings, {} errors",
        report.files_scanned,
        report.findings.len(),
        report.errors.len(),
    );
}

fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "static-scan-test-{}-{}",
        std::process::id(),
        rand_u32(),
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
}
