//! Apply a [`Rule`] catalogue against a corpus of files.
//!
//! JS/TS rules are driven by oxc-parsed ASTs. HTML/text rules fall back to
//! regex against the file bytes. Files larger than [`MAX_BYTES_PER_FILE`]
//! are skipped (some renderer bundles and source-maps are gigabytes; we
//! refuse to allocate that much memory for what's at best a noisy match).

use std::path::Path;

use crate::ast::ParsedProgram;
use crate::rules::{Finding, Matcher, Rule};

const SAMPLE_CONTEXT: usize = 120;
const MAX_BYTES_PER_FILE: usize = 16 * 1024 * 1024;

pub struct FileContent {
    pub path: String,
    pub bytes: Vec<u8>,
}

pub fn interesting_extension(path: &str) -> bool {
    extension_of(path).map_or(false, |ext| {
        matches!(
            ext,
            "js" | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "html"
                | "htm"
                | "json"
        )
    })
}

pub fn walk_directory(
    root: &Path,
    visitor: &mut dyn FnMut(&str, Result<Vec<u8>, std::io::Error>),
) -> std::io::Result<()> {
    fn recurse(
        root: &Path,
        current: &Path,
        visitor: &mut dyn FnMut(&str, Result<Vec<u8>, std::io::Error>),
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(current)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if name_s.starts_with('.') || name_s == "node_modules" {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                recurse(root, &path, visitor)?;
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if !interesting_extension(&rel) {
                    continue;
                }
                visitor(&rel, std::fs::read(&path));
            }
        }
        Ok(())
    }
    recurse(root, root, visitor)
}

pub fn run_rules(ruleset: &[Rule], corpus: &[FileContent], findings: &mut Vec<Finding>) {
    for rule in ruleset {
        match &rule.matcher {
            Matcher::AstJs(matcher_fn) => run_ast_rule(rule, *matcher_fn, corpus, findings),
            Matcher::RegexAbsentFromAll {
                pattern,
                fallback_path,
            } => run_absent_regex(rule, pattern, fallback_path, corpus, findings),
        }
    }
}

fn run_ast_rule(
    rule: &Rule,
    matcher: crate::rules::AstMatcher,
    corpus: &[FileContent],
    findings: &mut Vec<Finding>,
) {
    for file in corpus_for_rule(rule, corpus) {
        if file.bytes.len() > MAX_BYTES_PER_FILE {
            continue;
        }
        let Ok(source) = std::str::from_utf8(&file.bytes) else {
            continue;
        };
        let source_type = source_type_for(&file.path);
        let allocator = oxc_allocator::Allocator::default();
        let parsed = ParsedProgram::parse(&allocator, source, source_type);
        for m in matcher(&parsed.program) {
            let start = m.span.start as usize;
            let end = m.span.end as usize;
            let (line, column) = line_col(&file.bytes, start);
            findings.push(Finding {
                rule_id: rule.id,
                severity: rule.severity,
                confidence: rule.confidence,
                description: rule.description,
                help_url: rule.help_url,
                file: file.path.clone(),
                line,
                column,
                sample: context(&file.bytes, start, end),
                note: Some(m.note).filter(|s| !s.is_empty()),
            });
        }
    }
}

fn run_absent_regex(
    rule: &Rule,
    pattern: &std::sync::LazyLock<regex::bytes::Regex>,
    fallback_path: &str,
    corpus: &[FileContent],
    findings: &mut Vec<Finding>,
) {
    let relevant: Vec<&FileContent> = corpus_for_rule(rule, corpus).collect();
    if relevant.is_empty() {
        findings.push(finding_without_location(rule, fallback_path.to_string()));
        return;
    }
    let any_match = relevant
        .iter()
        .any(|f| f.bytes.len() <= MAX_BYTES_PER_FILE && pattern.is_match(&f.bytes));
    if !any_match {
        let first = relevant[0];
        findings.push(finding_without_location(rule, first.path.clone()));
    }
}

fn finding_without_location(rule: &Rule, file: String) -> Finding {
    Finding {
        rule_id: rule.id,
        severity: rule.severity,
        confidence: rule.confidence,
        description: rule.description,
        help_url: rule.help_url,
        file,
        line: 0,
        column: 0,
        sample: String::new(),
        note: None,
    }
}

fn corpus_for_rule<'a>(
    rule: &'a Rule,
    corpus: &'a [FileContent],
) -> impl Iterator<Item = &'a FileContent> {
    corpus.iter().filter(|f| {
        extension_of(&f.path).map_or(false, |ext| rule.file_extensions.iter().any(|e| *e == ext))
    })
}

fn source_type_for(path: &str) -> oxc_span::SourceType {
    // `SourceType::from_path` infers via extension; gives us JSX/TS/ESM.
    oxc_span::SourceType::from_path(Path::new(path)).unwrap_or_default()
}

fn extension_of(path: &str) -> Option<&str> {
    let dot = path.rfind('.')?;
    Some(&path[dot + 1..])
}

fn line_col(bytes: &[u8], offset: usize) -> (usize, usize) {
    let clamped = offset.min(bytes.len());
    let prefix = &bytes[..clamped];
    let mut line = 1usize;
    let mut last_newline: i64 = -1;
    for (i, b) in prefix.iter().enumerate() {
        if *b == b'\n' {
            line += 1;
            last_newline = i as i64;
        }
    }
    let column = (clamped as i64 - last_newline) as usize;
    (line, column)
}

fn context(bytes: &[u8], start: usize, end: usize) -> String {
    let half = SAMPLE_CONTEXT / 2;
    let from = start.saturating_sub(half);
    let to = (end + half).min(bytes.len());
    let slice = &bytes[from..to];
    let mut s: String = slice
        .iter()
        .map(|b| match *b {
            0x09 | 0x20..=0x7e => *b as char,
            _ => '·',
        })
        .collect();
    s = s.replace('\n', " ").replace('\r', " ");
    s.truncate(SAMPLE_CONTEXT);
    s
}
