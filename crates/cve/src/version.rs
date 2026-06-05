//! Version comparison and free-text relevance helpers shared across sources.
//!
//! Runtime versions in this domain (Chromium's `148.0.7778.216`, Node's
//! `20.11.1`) are dotted-numeric but *not* strict semver, so we can't lean on
//! the `semver` crate — we compare component-by-component as integers.
//!
//! On top of raw comparison this module extracts two signals that let us drop
//! advisories that don't actually apply to the running build:
//!
//!   * a "fixed ceiling" parsed from advisory prose ("prior to X", "before
//!     X") — when the scanned version is at or past that ceiling, the build is
//!     already patched, and
//!   * an OS scope ("on Android", "Windows only") — when an advisory is
//!     explicitly scoped to a platform other than the one we're auditing.

use std::cmp::Ordering;

/// Compare two dotted-numeric version strings (e.g. `148.0.7778.216` vs
/// `148.0.7778.215`). Missing trailing components and unparseable components
/// both count as 0, so `148.0` == `148.0.0.0`.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.trim().split('.');
    let mut bi = b.trim().split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (a, b) => {
                let av: u64 = a.unwrap_or("0").trim().parse().unwrap_or(0);
                let bv: u64 = b.unwrap_or("0").trim().parse().unwrap_or(0);
                match av.cmp(&bv) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
        }
    }
}

/// `true` when `shipped` is the same as, or newer than, `reference`.
pub fn at_or_above(shipped: &str, reference: &str) -> bool {
    matches!(cmp(shipped, reference), Ordering::Equal | Ordering::Greater)
}

/// Phrases that introduce the first *unaffected* (fixed) version in CVE prose.
/// Order matters only for readability; all are tried.
const CEILING_PHRASES: &[&str] = &[
    "prior to ",
    "before ",
    "earlier than ",
    "older than ",
    "up to but not including ",
    "versions below ",
    "fixed in ",
];

/// Extract the "fixed in / not affected from" version a description points at.
///
/// Two prose shapes are handled:
///   * Chromium/Node style — `"… Google Chrome prior to 148.0.7778.216 …"` →
///     `Some("148.0.7778.216")`, found via the ceiling phrase.
///   * Apple style — `"… is fixed in Safari 26.5, iOS 18.7.9 …"`, where each
///     product carries its own version. When `product` is given (e.g.
///     `"Safari"`) we take the version that follows *that* product name, so we
///     compare against the right one rather than whichever appears first.
///
/// Returns `None` when nothing version-looking is found, so callers stay
/// conservative (keep the advisory) when the text doesn't clearly state a fix.
pub fn fixed_ceiling_from_text(text: &str, product: Option<&str>) -> Option<String> {
    // Most specific: the version immediately following the product we scanned.
    if let Some(p) = product {
        if let Some(v) = version_after_keyword(text, p) {
            return Some(v);
        }
    }

    let lower = text.to_ascii_lowercase();
    for phrase in CEILING_PHRASES {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(phrase) {
            let start = from + rel + phrase.len();
            // Allow a couple of product-name words between the phrase and the
            // version ("fixed in Safari 26.5") before giving up.
            if let Some(v) = first_version_token(&text[start..], 3) {
                return Some(v);
            }
            from = start;
        }
    }
    None
}

/// Find `keyword` (case-insensitive) and return the first version token within
/// the next two words — e.g. `version_after_keyword("fixed in Safari 26.5", "Safari")`
/// is `Some("26.5")`.
fn version_after_keyword(text: &str, keyword: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let kw = keyword.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(&kw) {
        let start = from + rel + kw.len();
        if let Some(v) = first_version_token(&text[start..], 2) {
            return Some(v);
        }
        from = start;
    }
    None
}

/// Scan up to `max_tokens` whitespace-separated tokens from the start of `s`
/// and return the first that looks like a dotted-numeric version.
fn first_version_token(s: &str, max_tokens: usize) -> Option<String> {
    s.split_whitespace()
        .take(max_tokens)
        .find_map(version_from_token)
}

/// Pull a dotted-numeric version out of a single token, stripping surrounding
/// punctuation (`"26.5,"` → `"26.5"`, `"v2.3"` → `"2.3"`). Requires at least
/// one dot so bare numbers ("before 2 releases") aren't mistaken for versions.
fn version_from_token(tok: &str) -> Option<String> {
    let t = tok.trim_matches(|c: char| !c.is_ascii_digit());
    if t.contains('.') && t.chars().all(|c| c.is_ascii_digit() || c == '.') {
        Some(t.to_string())
    } else {
        None
    }
}

/// Operating systems an advisory can be scoped to in prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Macos,
    Windows,
    Linux,
    Android,
    Ios,
    ChromeOs,
}

/// The OS this binary is auditing — advisories scoped exclusively to a
/// *different* OS don't apply. Defaults to macOS for the (unlisted) targets
/// this tool currently ships on.
pub fn current_os() -> Os {
    #[cfg(target_os = "windows")]
    {
        Os::Windows
    }
    #[cfg(target_os = "linux")]
    {
        Os::Linux
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Os::Macos
    }
}

/// Scope phrases per OS. We only treat an advisory as platform-scoped when it
/// uses one of these explicit constructions — incidental mentions ("ported
/// from Android") must not trigger a drop.
fn os_phrases(os: Os) -> &'static [&'static str] {
    match os {
        Os::Macos => &["on macos", "on mac os", "on os x", "on mac ", "macos only", "for macos"],
        Os::Windows => &["on windows", "windows only", "for windows"],
        Os::Linux => &["on linux", "linux only", "for linux"],
        Os::Android => &["on android", "android only", "for android", "(android"],
        Os::Ios => &["on ios", "ios only", "for ios", "(ios"],
        Os::ChromeOs => &["on chrome os", "on chromeos", "chromeos only"],
    }
}

const ALL_OSES: &[Os] = &[
    Os::Macos,
    Os::Windows,
    Os::Linux,
    Os::Android,
    Os::Ios,
    Os::ChromeOs,
];

fn mentions_os(lower: &str, os: Os) -> bool {
    os_phrases(os).iter().any(|p| lower.contains(p))
}

/// `true` when `summary` is explicitly scoped to one or more operating systems
/// and `current` is not among them — i.e. the advisory is about somebody
/// else's platform. Untyped, cross-platform descriptions return `false` (keep).
pub fn scoped_to_other_os(summary: &str, current: Os) -> bool {
    let lower = summary.to_ascii_lowercase();
    if mentions_os(&lower, current) {
        return false; // our platform is named — definitely relevant
    }
    ALL_OSES
        .iter()
        .any(|&os| os != current && mentions_os(&lower, os))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_is_numeric_not_lexicographic() {
        assert_eq!(cmp("148.0.7778.216", "148.0.7778.216"), Ordering::Equal);
        assert_eq!(cmp("148.0.7778.100", "148.0.7778.99"), Ordering::Greater);
        assert_eq!(cmp("148.0", "148.0.0.0"), Ordering::Equal);
    }

    #[test]
    fn at_or_above_covers_boundary() {
        assert!(at_or_above("148.0.7778.216", "148.0.7778.216"));
        assert!(at_or_above("148.0.7778.217", "148.0.7778.216"));
        assert!(!at_or_above("148.0.7778.215", "148.0.7778.216"));
    }

    #[test]
    fn extracts_ceiling_from_chrome_prose() {
        let s = "Use after free in PDFium in Google Chrome prior to 148.0.7778.216 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file.";
        assert_eq!(
            fixed_ceiling_from_text(s, None).as_deref(),
            Some("148.0.7778.216")
        );
    }

    #[test]
    fn extracts_ceiling_from_before_phrasing() {
        assert_eq!(
            fixed_ceiling_from_text("Affected versions before 20.11.1 are vulnerable.", None)
                .as_deref(),
            Some("20.11.1")
        );
    }

    #[test]
    fn ignores_bare_numbers() {
        assert_eq!(fixed_ceiling_from_text("removed before 2 releases", None), None);
        assert_eq!(fixed_ceiling_from_text("no version info here", None), None);
    }

    #[test]
    fn extracts_safari_version_from_apple_multi_product_list() {
        // Apple lists every fixed product; for the Safari bucket we must pick
        // Safari's version, not whichever number appears first.
        let s = "The issue was addressed with improved memory handling. This issue is fixed in Safari 26.5, iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. Processing maliciously crafted web content may lead to an unexpected process crash.";
        assert_eq!(
            fixed_ceiling_from_text(s, Some("Safari")).as_deref(),
            Some("26.5")
        );
        // The reported false positive: Safari 26.5 ⇒ already patched.
        assert!(at_or_above("26.5", "26.5"));
    }

    #[test]
    fn android_scoped_dropped_on_macos() {
        let s = "Inappropriate implementation in Google Chrome on Android prior to 149.0 allowed …";
        assert!(scoped_to_other_os(s, Os::Macos));
    }

    #[test]
    fn cross_platform_kept_on_macos() {
        let s = "Use after free in PDFium in Google Chrome prior to 148.0.7778.216 allowed …";
        assert!(!scoped_to_other_os(s, Os::Macos));
    }

    #[test]
    fn macos_named_kept() {
        let s = "Issue affecting Safari on macOS prior to 17.0 …";
        assert!(!scoped_to_other_os(s, Os::Macos));
    }

    #[test]
    fn multi_os_including_current_kept() {
        let s = "Affected on Windows and on macOS only in certain configs.";
        assert!(!scoped_to_other_os(s, Os::Macos));
    }
}
