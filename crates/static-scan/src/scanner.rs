//! Apply a [`Rule`] catalogue against a corpus of files.
//!
//! JS/TS rules are driven by oxc-parsed ASTs. HTML/text rules fall back to
//! regex against the file bytes. Files larger than [`MAX_BYTES_PER_FILE`]
//! are skipped (some renderer bundles and source-maps are gigabytes; we
//! refuse to allocate that much memory for what's at best a noisy match).

use std::path::{Path, PathBuf};

use crate::ast::ParsedProgram;
use crate::par::*;
use crate::rules::{Finding, Matcher, Rule};

const SAMPLE_CONTEXT: usize = 120;
const MAX_BYTES_PER_FILE: usize = 16 * 1024 * 1024;

pub struct FileContent {
    pub path: String,
    pub bytes: Vec<u8>,
}

pub fn interesting_extension(path: &str) -> bool {
    extension_of(path).is_some_and(|ext| {
        matches!(
            ext,
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "html" | "htm" | "json"
        )
    })
}

/// One file selected for scanning: its POSIX-relative path (used as the
/// finding location) alongside the absolute path to read from.
pub struct SourcePath {
    pub rel: String,
    pub abs: PathBuf,
}

/// Recursively enumerate interesting source files under `root`. This walks
/// directory metadata only (cheap, latency-bound); the expensive byte reads
/// are deferred to [`read_corpus`] so they can run in parallel.
pub fn collect_source_files(root: &Path) -> std::io::Result<Vec<SourcePath>> {
    fn recurse(root: &Path, current: &Path, out: &mut Vec<SourcePath>) -> std::io::Result<()> {
        for entry in vfs::read_dir(current)? {
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
                recurse(root, &path, out)?;
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if !interesting_extension(&rel) {
                    continue;
                }
                out.push(SourcePath { rel, abs: path });
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    recurse(root, root, &mut out)?;
    Ok(out)
}

/// Read the bytes for every enumerated file in parallel. Each entry resolves
/// to either its [`FileContent`] or a `(path, message)` read error; the
/// caller partitions the two. Order matches `files` so the resulting corpus
/// is deterministic.
pub fn read_corpus(files: &[SourcePath]) -> Vec<Result<FileContent, (String, String)>> {
    files
        .par_iter()
        .map(|f| {
            vfs::read(&f.abs)
                .map(|bytes| FileContent {
                    path: f.rel.clone(),
                    bytes,
                })
                .map_err(|err| (f.rel.clone(), err.to_string()))
        })
        .collect()
}

pub fn run_rules(ruleset: &[Rule], corpus: &[FileContent], findings: &mut Vec<Finding>) {
    // Two families of rule need different parallelism strategies:
    //  * AST rules parse a JS/TS file and walk it. Parsing dominates the cost,
    //    so we parse each file *once* and run every applicable AST matcher on
    //    that single parse — instead of re-parsing per rule — then fan the
    //    files out across a rayon pool.
    //  * Absent-regex rules ask "does *any* file contain this pattern?", a
    //    corpus-wide reduction. We evaluate each such rule independently and
    //    parallelise the inner scan.
    let ast_rules: Vec<&Rule> = ruleset
        .iter()
        .filter(|r| matches!(r.matcher, Matcher::AstJs(_)))
        .collect();
    let absent_rules: Vec<&Rule> = ruleset
        .iter()
        .filter(|r| matches!(r.matcher, Matcher::RegexAbsentFromAll { .. }))
        .collect();

    // rayon's indexed `collect` preserves corpus order, keeping output stable.
    let ast_findings: Vec<Finding> = corpus
        .par_iter()
        .flat_map_iter(|file| scan_file_ast(&ast_rules, file))
        .collect();

    let absent_findings: Vec<Finding> = absent_rules
        .par_iter()
        .filter_map(|rule| eval_absent_rule(rule, corpus))
        .collect();

    findings.extend(ast_findings);
    findings.extend(absent_findings);
}

/// Parse one file once and run every AST matcher whose extension filter
/// admits it, collecting the resulting findings.
fn scan_file_ast(ast_rules: &[&Rule], file: &FileContent) -> Vec<Finding> {
    let mut out = Vec::new();
    if file.bytes.len() > MAX_BYTES_PER_FILE {
        return out;
    }
    let Some(ext) = extension_of(&file.path) else {
        return out;
    };
    // Skip files no AST rule cares about before paying for a parse.
    if !ast_rules.iter().any(|r| r.file_extensions.contains(&ext)) {
        return out;
    }
    let Ok(source) = std::str::from_utf8(&file.bytes) else {
        return out;
    };
    let source_type = source_type_for(&file.path);
    let allocator = oxc_allocator::Allocator::default();
    let parsed = ParsedProgram::parse(&allocator, source, source_type);

    for rule in ast_rules {
        if !rule.file_extensions.contains(&ext) {
            continue;
        }
        let Matcher::AstJs(matcher) = &rule.matcher else {
            continue;
        };
        for m in matcher(&parsed.program) {
            let start = m.span.start as usize;
            let end = m.span.end as usize;
            let (line, column) = line_col(&file.bytes, start);
            out.push(Finding {
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
    out
}

fn eval_absent_rule(rule: &Rule, corpus: &[FileContent]) -> Option<Finding> {
    let Matcher::RegexAbsentFromAll {
        pattern,
        fallback_path,
    } = &rule.matcher
    else {
        return None;
    };
    let relevant: Vec<&FileContent> = corpus_for_rule(rule, corpus).collect();
    if relevant.is_empty() {
        return Some(finding_without_location(rule, fallback_path.to_string()));
    }
    let any_match = relevant
        .par_iter()
        .any(|f| f.bytes.len() <= MAX_BYTES_PER_FILE && pattern.is_match(&f.bytes));
    if any_match {
        None
    } else {
        Some(finding_without_location(rule, relevant[0].path.clone()))
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
    corpus
        .iter()
        .filter(|f| extension_of(&f.path).is_some_and(|ext| rule.file_extensions.contains(&ext)))
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
    s = s.replace(['\n', '\r'], " ");
    s.truncate(SAMPLE_CONTEXT);
    s
}
