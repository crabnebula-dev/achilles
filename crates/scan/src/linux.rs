//! Linux discovery via freedesktop `.desktop` entries.
//!
//! The desktop menu is the natural "installed GUI apps" list: every entry is a
//! `Type=Application` launcher, and we drop the ones explicitly hidden from
//! menus (`NoDisplay` / `Hidden`) or that run in a terminal (`Terminal=true`).
//! Each surviving entry's `Exec=` is resolved to a real binary; the binary's
//! directory becomes the app root for sibling-library detection.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use detect::DiscoveredApp;

use crate::ScanError;

pub fn discover() -> Result<Vec<DiscoveredApp>, ScanError> {
    let mut apps = Vec::new();
    let mut seen_ids = HashSet::new();
    let mut seen_launchers = HashSet::new();

    for dir in application_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "desktop").unwrap_or(true) {
                continue;
            }
            // `.desktop` IDs are unique by basename, earlier dirs winning.
            let id = path.file_name().map(|n| n.to_owned());
            if let Some(id) = &id {
                if !seen_ids.insert(id.clone()) {
                    continue;
                }
            }

            let Some(app) = parse_desktop_entry(&path) else {
                continue;
            };

            // Dedup by the app's own launcher path (its identity), NOT the
            // resolved binary — several apps legitimately share one system
            // Electron runtime (`/usr/lib/electronNN/electron`) yet are
            // distinct applications.
            if !seen_launchers.insert(app.path.clone()) {
                continue;
            }
            apps.push(app);
        }
    }

    apps.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(apps)
}

/// The XDG application directories, in precedence order, plus flatpak / snap
/// exports.
fn application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let home = std::env::var_os("HOME").map(PathBuf::from);

    // $XDG_DATA_HOME/applications (default ~/.local/share/applications).
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/share")));
    if let Some(d) = data_home {
        dirs.push(d.join("applications"));
    }

    // $XDG_DATA_DIRS/applications (default /usr/local/share:/usr/share).
    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    for d in data_dirs.split(':').filter(|s| !s.is_empty()) {
        dirs.push(Path::new(d).join("applications"));
    }

    // Flatpak + snap exported entries.
    dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    if let Some(home) = &home {
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    dirs.push(PathBuf::from("/var/lib/snapd/desktop/applications"));

    dirs
}

/// Parse one `.desktop` file, returning a [`DiscoveredApp`] if it's a visible
/// GUI application we could resolve to a binary.
fn parse_desktop_entry(path: &Path) -> Option<DiscoveredApp> {
    let text = std::fs::read_to_string(path).ok()?;

    let mut in_entry = false;
    let mut name = None;
    let mut exec = None;
    let mut type_app = false;
    let mut no_display = false;
    let mut hidden = false;
    let mut terminal = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            // Only the `[Desktop Entry]` group matters; stop at the first
            // action group (`[Desktop Action ...]`).
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // Take the unlocalised key only (ignore `Name[de]` etc.).
        match key.trim() {
            "Name" => name = Some(value.trim().to_string()),
            "Exec" => exec = Some(value.trim().to_string()),
            "Type" => type_app = value.trim() == "Application",
            "NoDisplay" => no_display = value.trim().eq_ignore_ascii_case("true"),
            "Hidden" => hidden = value.trim().eq_ignore_ascii_case("true"),
            "Terminal" => terminal = value.trim().eq_ignore_ascii_case("true"),
            _ => {}
        }
    }

    if !type_app || no_display || hidden || terminal {
        return None;
    }
    let exec = exec?;
    // The `Exec=` target (often a `/usr/bin` wrapper) is the app's stable
    // identity. Follow any launcher shell-script to the real ELF it execs
    // (Chrome, VS Code, shared Electron runtimes, …) for version scanning, but
    // key the app on the launcher so runtime-sharing apps stay distinct.
    let launcher = resolve_exec(&exec)?;
    let real = follow_wrapper(&launcher, 0).unwrap_or_else(|| launcher.clone());
    let root = real
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| real.clone());

    Some(DiscoveredApp {
        path: launcher,
        root,
        executable: Some(real),
        name,
    })
}

/// If `path` is a launcher shell-script, follow the binary it ultimately
/// `exec`s; otherwise return `path` unchanged. Resolves the handful of variable
/// forms these wrappers use in practice (`$HERE`/`$0` → the script's dir,
/// `${name}` → the script's basename). Bounded recursion guards against loops.
fn follow_wrapper(path: &Path, depth: u8) -> Option<PathBuf> {
    if depth >= 5 {
        return Some(path.to_path_buf());
    }
    let bytes = std::fs::read(path).ok()?;
    if !bytes.starts_with(b"#!") {
        // A real binary (ELF), not a script — we're done.
        return Some(path.to_path_buf());
    }
    let text = String::from_utf8_lossy(&bytes);
    let script_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Seed common wrapper variables, then let explicit literal assignments in
    // the script override them.
    let dir = script_dir.to_string_lossy().into_owned();
    let mut vars: std::collections::HashMap<String, String> = [
        ("name", stem.clone()),
        ("HERE", dir.clone()),
        ("DIR", dir.clone()),
        ("here", dir.clone()),
        ("dir", dir.clone()),
        ("APPDIR", dir.clone()),
        ("0", path.to_string_lossy().into_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();

    let mut target: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        // Skip comments — a `#` line mentioning `exec` must not be mistaken for
        // the launch line.
        if line.starts_with('#') {
            continue;
        }
        // Record `VAR=value` assignments whose value is a plain literal.
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.chars().all(|c| c.is_alphanumeric() || c == '_') && !key.is_empty() {
                let value = value.trim().trim_matches(['"', '\'']);
                if !value.is_empty() && !value.contains(['$', '`', ' ']) {
                    vars.insert(key.to_string(), value.to_string());
                    continue;
                }
            }
        }
        // The launch line — `exec` may follow env-assignments
        // (`FOO=1 exec /path`), so find it as a token, not a line prefix.
        let mut toks = line.split_whitespace();
        if toks.any(|t| t == "exec") {
            if let Some(t) = first_exec_target(toks) {
                target = Some(t);
                break;
            }
        }
    }

    let resolved = substitute(&target?, &vars)?;
    let resolved = if Path::new(&resolved).is_absolute() {
        PathBuf::from(resolved)
    } else {
        script_dir.join(resolved)
    };
    if resolved.exists() {
        follow_wrapper(&resolved, depth + 1)
    } else {
        None
    }
}

/// Pick the executable token from the tokens following `exec`, skipping
/// redirections, env-assignments, the `-a name` bashism, and `$0`.
fn first_exec_target<'a>(tokens: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut tokens = tokens.peekable();
    while let Some(tok) = tokens.next() {
        if tok == "-a" {
            tokens.next(); // drop the alias argument
            continue;
        }
        // A redirection (`2>`, `>(...)`, `<`, `>&2`) means this is a
        // descriptor-setup `exec` (`exec 2> log`) with no command — abandon
        // this line so the caller scans the next `exec` for the real launch.
        if tok.contains('>') || tok.contains('<') {
            return None;
        }
        // env VAR=value prefix.
        if tok.contains('=') && !tok.contains('/') {
            continue;
        }
        let tok = tok.trim_matches(['"', '\'']);
        if tok.is_empty() || tok == "$0" || tok == "${0}" {
            continue;
        }
        return Some(tok.to_string());
    }
    None
}

/// Substitute `$VAR` / `${VAR}` against `vars`; fail if any reference is
/// unknown (we can't safely guess a path).
fn substitute(input: &str, vars: &std::collections::HashMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_alphanumeric() || c == '_' {
                name.push(c);
                chars.next();
            } else {
                break;
            }
        }
        if braced {
            // Drop modifiers like `${0%/*}` we don't model, up to the `}`.
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
            }
        }
        out.push_str(vars.get(&name)?);
    }
    Some(out)
}

/// Resolve a `.desktop` `Exec=` line to an absolute binary path.
///
/// Strips field codes (`%U`, `%f`, …), an optional `env VAR=val` prefix, and
/// quoting, then resolves via absolute path or `$PATH`. Flatpak/snap wrapper
/// invocations resolve to the wrapper binary (`flatpak`/`snap`), which is still
/// a real executable we can string-scan as a fallback.
fn resolve_exec(exec: &str) -> Option<PathBuf> {
    let mut tokens = exec.split_whitespace().filter(|t| {
        // Drop field codes and env-assignment prefixes.
        !t.starts_with('%') && !(t.contains('=') && !t.contains('/'))
    });

    // Skip a leading `env` wrapper.
    let mut first = tokens.next()?;
    if first == "env" {
        first = tokens.next()?;
    }
    let first = first.trim_matches('"');

    let candidate = Path::new(first);
    if candidate.is_absolute() {
        return candidate.exists().then(|| candidate.to_path_buf());
    }
    which_in_path(first)
}

/// Minimal `$PATH` lookup (avoids pulling in a `which` dependency).
fn which_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
