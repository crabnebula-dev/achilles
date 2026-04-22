//! Rule catalogue. Each rule has a stable `id` (matching the corresponding
//! Electronegativity check name where applicable), a severity/confidence
//! pair, a set of file extensions it applies to, and a [`Matcher`].
//!
//! Adding a rule:
//!  1. Add a `RuleId` variant.
//!  2. Append a `Rule { … }` entry to [`catalog`].
//!  3. Add a fixture test in `tests/` if the pattern isn't already covered.

use std::sync::LazyLock;

use regex::bytes::Regex;
use serde::Serialize;

use crate::ast::{AstMatch, BoolPropertyVisitor, OpenExternalVisitor};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

/// Canonical string id for a rule. We mirror Electronegativity's
/// `SANDBOX_JS_CHECK`-style names so findings stay portable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleId {
    CspGlobalCheck,
    SandboxJsCheck,
    NodeIntegrationJsCheck,
    ContextIsolationJsCheck,
    WebSecurityJsCheck,
    AllowRunningInsecureContentJsCheck,
    ExperimentalFeaturesJsCheck,
    OpenExternalJsCheck,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub description: &'static str,
    pub help_url: &'static str,
    pub file: String,
    /// 1-based line number. `0` for rules that don't attach to a specific
    /// location (e.g. CSP-absent).
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
    pub sample: String,
    /// Optional extra note attached by an AST rule (e.g. whether an
    /// `openExternal` call had a literal URL argument).
    pub note: Option<&'static str>,
}

pub struct Rule {
    pub id: RuleId,
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub help_url: &'static str,
    pub file_extensions: &'static [&'static str],
    pub matcher: Matcher,
}

pub enum Matcher {
    /// JS/TS AST walker. The function takes a parsed oxc `Program`, returns
    /// every hit with its source span.
    AstJs(AstMatcher),
    /// Emit one finding if *no* file of the matching extension contains
    /// the regex pattern (byte-level). Used for "is CSP declared anywhere?"
    RegexAbsentFromAll {
        pattern: &'static LazyLock<Regex>,
        fallback_path: &'static str,
    },
}

/// Boxed function so we can store heterogeneous AST visitors in the same
/// catalogue. The function takes a parsed program and returns matches.
pub type AstMatcher = fn(&oxc_ast::ast::Program) -> Vec<AstMatch>;

// ---------- AST matchers --------------------------------------------------

fn match_sandbox_false(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(program, "sandbox", false, "sandbox: false")
}
fn match_node_integration_true(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(program, "nodeIntegration", true, "nodeIntegration: true")
}
fn match_context_isolation_false(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(program, "contextIsolation", false, "contextIsolation: false")
}
fn match_web_security_false(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(program, "webSecurity", false, "webSecurity: false")
}
fn match_allow_insecure_content(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(
        program,
        "allowRunningInsecureContent",
        true,
        "allowRunningInsecureContent: true",
    )
}
fn match_experimental_features(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    run_bool_prop(
        program,
        "experimentalFeatures",
        true,
        "experimentalFeatures: true",
    )
}
fn match_open_external(program: &oxc_ast::ast::Program) -> Vec<AstMatch> {
    use oxc_ast_visit::Visit;
    let mut v = OpenExternalVisitor {
        matches: Vec::new(),
    };
    v.visit_program(program);
    v.matches
}

fn run_bool_prop(
    program: &oxc_ast::ast::Program,
    key: &str,
    value: bool,
    note: &'static str,
) -> Vec<AstMatch> {
    use oxc_ast_visit::Visit;
    let mut v = BoolPropertyVisitor {
        target_key: key,
        target_value: value,
        matches: Vec::new(),
        note,
    };
    v.visit_program(program);
    v.matches
}

// ---------- regex patterns ------------------------------------------------

static CSP_META: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta[^>]+http-equiv\s*=\s*["']?content-security-policy"#).unwrap()
});

const HTML_EXTS: &[&str] = &["html", "htm"];
const JS_EXTS: &[&str] = &["js", "mjs", "cjs", "ts", "tsx", "jsx"];

pub fn catalog() -> Vec<Rule> {
    vec![
        Rule {
            id: RuleId::CspGlobalCheck,
            description:
                "No Content-Security-Policy meta tag found in any HTML entry point. \
                 Any XSS in the renderer becomes a fast path to the preload bridge.",
            severity: Severity::High,
            confidence: Confidence::Firm,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/CSP_GLOBAL_CHECK",
            file_extensions: HTML_EXTS,
            matcher: Matcher::RegexAbsentFromAll {
                pattern: &CSP_META,
                fallback_path: "(no html files)",
            },
        },
        Rule {
            id: RuleId::SandboxJsCheck,
            description:
                "`sandbox: false` disables the Chromium renderer sandbox. Combined \
                 with any renderer XSS, the attacker can reach preload/Node APIs.",
            severity: Severity::High,
            confidence: Confidence::Firm,
            help_url: "https://github.com/doyensec/electronegativity/wiki/SANDBOX_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_sandbox_false),
        },
        Rule {
            id: RuleId::NodeIntegrationJsCheck,
            description:
                "`nodeIntegration: true` exposes Node.js globals (require, process) \
                 to the renderer. Any renderer XSS becomes trivial RCE.",
            severity: Severity::High,
            confidence: Confidence::Firm,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/NODE_INTEGRATION_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_node_integration_true),
        },
        Rule {
            id: RuleId::ContextIsolationJsCheck,
            description:
                "`contextIsolation: false` merges preload and renderer JS contexts, \
                 letting renderer code reach any Node API the preload pulled in.",
            severity: Severity::Critical,
            confidence: Confidence::Firm,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/CONTEXT_ISOLATION_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_context_isolation_false),
        },
        Rule {
            id: RuleId::WebSecurityJsCheck,
            description:
                "`webSecurity: false` disables same-origin policy in the renderer. \
                 Any loaded resource can read from any other origin.",
            severity: Severity::High,
            confidence: Confidence::Firm,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/WEB_SECURITY_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_web_security_false),
        },
        Rule {
            id: RuleId::AllowRunningInsecureContentJsCheck,
            description:
                "`allowRunningInsecureContent: true` lets HTTP resources load into an \
                 HTTPS renderer. Any network attacker can alter injected script.",
            severity: Severity::High,
            confidence: Confidence::Firm,
            help_url: "https://github.com/doyensec/electronegativity/wiki/\
                       ALLOW_RUNNING_INSECURE_CONTENT_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_allow_insecure_content),
        },
        Rule {
            id: RuleId::ExperimentalFeaturesJsCheck,
            description:
                "`experimentalFeatures: true` enables Chromium features that haven't \
                 completed security review and may have additional attack surface.",
            severity: Severity::Medium,
            confidence: Confidence::Firm,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/EXPERIMENTAL_FEATURES_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_experimental_features),
        },
        Rule {
            id: RuleId::OpenExternalJsCheck,
            description:
                "`shell.openExternal(...)` with unvalidated input can launch arbitrary \
                 URL handlers. Verify the URL is allowlisted before opening.",
            severity: Severity::Medium,
            confidence: Confidence::Tentative,
            help_url:
                "https://github.com/doyensec/electronegativity/wiki/OPEN_EXTERNAL_JS_CHECK",
            file_extensions: JS_EXTS,
            matcher: Matcher::AstJs(match_open_external),
        },
    ]
}
