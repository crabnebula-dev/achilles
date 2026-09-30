//! Resolve a sandboxed app's launcher to the binary it actually runs.
//!
//! Snap and flatpak entries in the desktop menu don't point at an application:
//! they point at the *runner* (`/snap/bin/signal-desktop`, itself a symlink to
//! `/usr/bin/snap`; `/usr/bin/flatpak run com.spotify.Client`). Taken at face
//! value, every snap on the machine detects as the same `snap` binary and every
//! flatpak as `flatpak` — one Go program and one C program, no Electron in
//! sight.
//!
//! The payload is on disk in both cases, unpacked and readable without entering
//! the sandbox: `/snap/<name>/current` and
//! `<flatpak install>/app/<id>/current/active/files`. This module maps an
//! `Exec=` line to that tree and to the binary inside it.

use std::path::{Path, PathBuf};

/// A sandboxed app, located on the host.
pub(super) struct Sandboxed {
    /// Stable per-app identity. Never the runner: `/usr/bin/flatpak` is the
    /// launcher for *every* flatpak installed, so keying on it would collapse
    /// them into a single entry.
    pub path: PathBuf,
    pub root: PathBuf,
    /// `None` for an app with no native binary of its own — a GJS or Python
    /// app whose interpreter comes from the runtime. The tree is still worth
    /// listing and analysing; there is simply no executable to scan.
    pub executable: Option<PathBuf>,
}

/// Locate the application a sandboxed `Exec=` line ultimately runs.
///
/// `None` when the line isn't a snap/flatpak invocation, or when the payload
/// isn't installed where it should be — the caller then keeps the runner it
/// already resolved, which at least names the app correctly.
pub(super) fn resolve(exec: &str) -> Option<Sandboxed> {
    let tokens: Vec<&str> = exec.split_whitespace().collect();
    if let Some((snap, app)) = snap_name(&tokens) {
        return snap_app(&snap, app.as_deref());
    }
    if let Some((id, command)) = flatpak_target(&tokens) {
        return flatpak_app(&id, command.as_deref());
    }
    None
}

/// Describe a payload, given the application binary if one was found.
///
/// With a binary, the app is rooted where it sits — beside its `.so`s and
/// `resources/`, as any other Linux app. Without one, the payload root is both
/// the root and the identity: it exists (unlike a launcher symlink pointing
/// into the sandbox), it's unique per app, and it's the tree to analyse.
fn describe(payload: PathBuf, binary: Option<PathBuf>) -> Sandboxed {
    match binary {
        Some(binary) => Sandboxed {
            root: binary
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| payload.clone()),
            path: binary.clone(),
            executable: Some(binary),
        },
        None => Sandboxed {
            path: payload.clone(),
            root: payload,
            executable: None,
        },
    }
}

/// Where snapd mounts installed snaps.
///
/// Ubuntu uses `/snap`; every other distribution uses `/var/lib/snapd/snap`,
/// with `/snap` as a symlink *if* the packaging chose to create one — on Arch
/// it doesn't exist at all. Assuming the Ubuntu path finds nothing anywhere
/// else, so both are probed.
const SNAP_ROOTS: &[&str] = &["/snap", "/var/lib/snapd/snap"];

/// The snap an `Exec=` line runs, as `(snap, app)`.
///
/// Recognises the runner invoked directly (`snap run foo`) and the per-app shim
/// snapd generates (`<mount>/bin/foo`, `<mount>/bin/foo.bar`). The `app` half
/// names which of the snap's entry points is wanted — `firefox.geckodriver`
/// lives in the `firefox` snap but is not the browser.
fn snap_name(tokens: &[&str]) -> Option<(String, Option<String>)> {
    let mut tokens = tokens.iter().copied().skip_while(|t| *t == "env");
    let first = tokens.next()?;
    let command = Path::new(first).file_name()?.to_string_lossy().into_owned();

    if command == "snap" {
        // `snap run [--options] <name>[.<app>]`
        let mut rest = tokens.skip_while(|t| *t != "run").skip(1);
        let name = rest.find(|t| !t.starts_with('-'))?;
        return Some(split_instance(name));
    }
    // The generated shim sits in the mount root's own `bin/`.
    if SNAP_ROOTS
        .iter()
        .any(|root| first.starts_with(&format!("{root}/bin/")))
    {
        return Some(split_instance(&command));
    }
    None
}

/// `firefox.geckodriver` → the `firefox` snap, its `geckodriver` app.
fn split_instance(name: &str) -> (String, Option<String>) {
    match name.split_once('.') {
        Some((snap, app)) => (snap.to_string(), Some(app.to_string())),
        None => (name.to_string(), None),
    }
}

/// The flatpak application id, plus the `--command=` override if one is given.
fn flatpak_target(tokens: &[&str]) -> Option<(String, Option<String>)> {
    let mut tokens = tokens.iter().copied().skip_while(|t| *t == "env");
    let first = tokens.next()?;
    if Path::new(first).file_name()?.to_string_lossy() != "flatpak" {
        return None;
    }
    let mut rest = tokens.skip_while(|t| *t != "run").skip(1).peekable();

    let mut command = None;
    let mut id = None;
    for token in rest.by_ref() {
        if let Some(value) = token.strip_prefix("--command=") {
            command = Some(value.to_string());
            continue;
        }
        if token.starts_with('-') || token.starts_with('%') {
            continue;
        }
        id = Some(token.to_string());
        break;
    }
    Some((id?, command))
}

/// Where an installed snap's files are mounted, and the binary inside.
fn snap_app(name: &str, app: Option<&str>) -> Option<Sandboxed> {
    let root = SNAP_ROOTS
        .iter()
        .map(|r| Path::new(r).join(name).join("current"))
        .find(|p| p.is_dir())?;

    // The snap declares its own entry point, which is nearly always a shell
    // script that sets the sandbox environment up before exec'ing the real
    // binary — so follow it, with `$SNAP` pointing at this tree.
    let declared = snap_command(&root, app)
        .map(|command| root.join(command))
        .filter(|p| p.is_file())
        .and_then(|entry| super::follow_wrapper_in(&entry, 0, Some(&root)))
        .filter(|p| detect::is_app_binary(p));

    let binary = declared.or_else(|| {
        // No usable declaration: try the conventional homes, then search.
        [
            root.join(name),
            root.join("bin").join(name),
            root.join("usr/bin").join(name),
            root.join("usr/lib").join(name).join(name),
            root.join("usr/share").join(name).join(name),
            root.join("opt").join(name).join(name),
        ]
        .into_iter()
        .find(|p| detect::is_app_binary(p))
        .or_else(|| detect::payload_executable(&root))
    });

    Some(describe(root, binary))
}

/// The `command:` a snap declares for `app` in `meta/snap.yaml`, or for its
/// first app when none is named.
///
/// Parsed by indentation rather than with a YAML crate: the shape is fixed
/// (`apps:` → an app name at one level in → `command:` at the next) and this is
/// the only field read, so a parser dependency would buy nothing.
fn snap_command(root: &Path, want: Option<&str>) -> Option<String> {
    let text = std::fs::read_to_string(root.join("meta/snap.yaml")).ok()?;
    let indent = |line: &str| line.len() - line.trim_start().len();

    let mut in_apps = false;
    let mut current: Option<String> = None;
    let mut first: Option<String> = None;

    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // A top-level key ends the `apps:` block.
        if indent(line) == 0 {
            in_apps = line.trim_end() == "apps:";
            current = None;
            continue;
        }
        if !in_apps {
            continue;
        }
        let trimmed = line.trim();
        // `  <app>:` — the name of one of the snap's entry points.
        if let Some(app) = trimmed.strip_suffix(':') {
            current = Some(app.to_string());
            continue;
        }
        let Some(command) = trimmed.strip_prefix("command:") else {
            continue;
        };
        // `command: bin/foo --flag` — the path is the first token.
        let Some(command) = command.split_whitespace().next() else {
            continue;
        };
        match (&current, want) {
            (Some(app), Some(want)) if app == want => return Some(command.to_string()),
            _ => first.get_or_insert_with(|| command.to_string()),
        };
    }
    first
}

/// Where an installed flatpak's files are, and the binary inside.
fn flatpak_app(id: &str, command: Option<&str>) -> Option<Sandboxed> {
    let installs = flatpak_installations();
    let files = installs
        .iter()
        .map(|base| base.join("app").join(id).join("current/active/files"))
        .find(|p| p.is_dir())?;

    // `--command=` names a binary in the sandbox's `/app/bin`, which is this
    // `files/bin`. Without one, the app's `metadata` declares it.
    let command = command
        .map(str::to_string)
        .or_else(|| files.parent().and_then(metadata_command));
    let binary = command
        .map(|c| files.join("bin").join(c))
        .and_then(|entry| resolve_entry(&entry, &files, 0))
        .filter(|p| detect::is_app_binary(p))
        // No declared entry point, or one that isn't a native binary: the app
        // may still ship one (and if it doesn't — a GJS or Python app — this
        // finds nothing, which is the right answer).
        .or_else(|| detect::payload_executable(&files));

    Some(describe(files, binary))
}

/// Follow a flatpak entry point to the file it actually is.
///
/// The entry is rarely the binary: it is a symlink or a wrapper script, and
/// either way it refers to the app through absolute `/app/...` paths, because
/// inside the sandbox that is where the tree is mounted. From the host those
/// paths are dangling — which is why `files/bin/<command>` so often reads as a
/// broken symlink — until the prefix is rewritten to the real `files` root.
fn resolve_entry(entry: &Path, files: &Path, depth: u8) -> Option<PathBuf> {
    if depth >= 5 {
        return None;
    }
    // `symlink_metadata` so a link into the sandbox is seen as a link rather
    // than as a missing file.
    if entry.symlink_metadata().ok()?.file_type().is_symlink() {
        let target = std::fs::read_link(entry).ok()?;
        let target = if target.is_absolute() {
            super::map_sandbox_path(&target, files).unwrap_or(target)
        } else {
            entry.parent()?.join(target)
        };
        return resolve_entry(&target, files, depth + 1);
    }
    if !entry.is_file() {
        return None;
    }
    // A wrapper script resolves to what it execs. One that execs nothing is
    // the entry point itself — a GJS or Python app is its own launcher — so
    // report that rather than losing the symlink we just followed. Whether it
    // is a *binary* is the caller's question, not this one's.
    Some(super::follow_wrapper_in(entry, 0, Some(files)).unwrap_or_else(|| entry.to_path_buf()))
}

/// System and per-user flatpak installations, system first (the same order
/// flatpak itself resolves them in).
fn flatpak_installations() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/var/lib/flatpak")];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".local/share/flatpak"));
    }
    roots
}

/// `command=` from a flatpak app's `metadata` file — the binary it starts when
/// the desktop entry doesn't say.
fn metadata_command(app_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(app_dir.join("metadata")).ok()?;
    let mut in_application = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_application = line == "[Application]";
            continue;
        }
        if in_application {
            if let Some(value) = line.strip_prefix("command=") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_snap_name_from_both_launcher_spellings() {
        let snap = snap_name;
        assert_eq!(
            snap(&["/snap/bin/signal-desktop", "%U"]),
            Some(("signal-desktop".into(), None))
        );
        assert_eq!(
            snap(&["snap", "run", "signal-desktop"]),
            Some(("signal-desktop".into(), None))
        );
        assert_eq!(
            snap(&["/usr/bin/snap", "run", "--shell", "code"]),
            Some(("code".into(), None))
        );
        // The shim lives in the mount root's `bin/`, which is NOT `/snap` on
        // any distribution but Ubuntu.
        assert_eq!(
            snap(&["/var/lib/snapd/snap/bin/chromium", "%U"]),
            Some(("chromium".into(), None))
        );
        // A per-app shim: the `firefox` snap, its `geckodriver` app.
        assert_eq!(
            snap(&["/snap/bin/firefox.geckodriver"]),
            Some(("firefox".into(), Some("geckodriver".into())))
        );
        assert_eq!(snap(&["/usr/bin/obsidian"]), None);
    }

    #[test]
    fn reads_the_flatpak_id_and_command() {
        let exec = [
            "/usr/bin/flatpak",
            "run",
            "--branch=stable",
            "--arch=x86_64",
            "--command=spotify",
            "com.spotify.Client",
        ];
        assert_eq!(
            flatpak_target(&exec),
            Some(("com.spotify.Client".into(), Some("spotify".into())))
        );

        // No `--command=`: the id is still the first non-flag token.
        assert_eq!(
            flatpak_target(&["flatpak", "run", "org.gimp.GIMP"]),
            Some(("org.gimp.GIMP".into(), None))
        );
        assert_eq!(flatpak_target(&["/usr/bin/spotify"]), None);
    }

    #[test]
    fn a_plain_launcher_resolves_to_nothing_here() {
        assert!(resolve("/usr/bin/obsidian %U").is_none());
        assert!(resolve("code --unity-launch %F").is_none());
    }

    #[test]
    fn reads_the_command_out_of_flatpak_metadata() {
        let dir = std::env::temp_dir().join(format!("scan-flatpak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("metadata"),
            "[Application]\nname=com.spotify.Client\ncommand=spotify\n\n[Context]\ncommand=nope\n",
        )
        .unwrap();

        assert_eq!(metadata_command(&dir).as_deref(), Some("spotify"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a flatpak-shaped `files/` tree in a temp dir.
    fn flatpak_files(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scan-flatpak-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        dir
    }

    /// The entry point is a symlink to `/app/...`, which resolves only *inside*
    /// the sandbox — from the host it is a dangling link until the prefix is
    /// rewritten. GNOME's GJS apps are all shaped this way.
    #[cfg(unix)]
    #[test]
    fn an_entry_symlinked_into_the_sandbox_is_followed_to_the_real_file() {
        let files = flatpak_files("symlink");
        std::fs::create_dir_all(files.join("share/org.gnome.Characters")).unwrap();
        let real = files.join("share/org.gnome.Characters/org.gnome.Characters");
        std::fs::write(&real, b"#!/usr/bin/gjs-console\n").unwrap();

        let entry = files.join("bin/gnome-characters");
        std::os::unix::fs::symlink(
            "/app/share/org.gnome.Characters/org.gnome.Characters",
            &entry,
        )
        .unwrap();
        // The premise: from the host, that link points at nothing.
        assert!(!entry.exists(), "the link should be dangling on the host");

        assert_eq!(
            resolve_entry(&entry, &files, 0).as_deref(),
            Some(real.as_path())
        );
        let _ = std::fs::remove_dir_all(&files);
    }

    /// The other shape: a wrapper script that `exec`s an `/app` path (Spotify,
    /// and most repackaged proprietary apps).
    #[test]
    fn a_wrapper_execing_an_app_path_is_followed_into_the_payload() {
        let files = flatpak_files("wrapper");
        std::fs::create_dir_all(files.join("extra/Spotify")).unwrap();
        let real = files.join("extra/Spotify/spotify");
        std::fs::write(&real, b"\x7fELF").unwrap();

        let entry = files.join("bin/spotify");
        std::fs::write(
            &entry,
            b"#!/bin/sh\nexec /app/extra/Spotify/spotify \"$@\"\n",
        )
        .unwrap();

        assert_eq!(
            resolve_entry(&entry, &files, 0).as_deref(),
            Some(real.as_path())
        );
        let _ = std::fs::remove_dir_all(&files);
    }

    /// Identity must be per-app. Keying on the launcher would make every
    /// flatpak `/usr/bin/flatpak`, and discovery dedups on it — so all but the
    /// first would vanish from the scan.
    #[test]
    fn identity_is_the_payload_never_the_shared_runner() {
        let a = describe(
            PathBuf::from("/f/app/A/files"),
            Some("/f/app/A/files/bin/a".into()),
        );
        let b = describe(
            PathBuf::from("/f/app/B/files"),
            Some("/f/app/B/files/bin/b".into()),
        );
        assert_ne!(a.path, b.path);
        assert_eq!(a.root, Path::new("/f/app/A/files/bin"));
        assert_eq!(
            a.executable.as_deref(),
            Some(Path::new("/f/app/A/files/bin/a"))
        );
    }

    /// An app with no native binary (GJS, Python) still gets a distinct
    /// identity and a tree to analyse — just no executable to scan.
    #[test]
    fn an_app_without_a_native_binary_still_resolves_to_its_own_payload() {
        let a = describe(PathBuf::from("/f/app/A/files"), None);
        let b = describe(PathBuf::from("/f/app/B/files"), None);
        assert_ne!(a.path, b.path);
        assert_eq!(a.root, Path::new("/f/app/A/files"));
        assert_eq!(a.executable, None);
    }

    /// A snap declares its entry point in `meta/snap.yaml`, and it is nearly
    /// always a launcher script rather than the binary.
    #[test]
    fn reads_the_declared_command_for_the_right_app() {
        let dir = std::env::temp_dir().join(format!("scan-snapyaml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("meta")).unwrap();
        std::fs::write(
            dir.join("meta/snap.yaml"),
            "name: chromium\nversion: 150.0\napps:\n  chromium:\n    command: bin/chromium.launcher\n    plugs:\n      - network\n  daemon:\n    command: bin/daemon.wrapper --flag\nplugs:\n  command: not-an-app\n",
        )
        .unwrap();

        assert_eq!(
            snap_command(&dir, Some("chromium")).as_deref(),
            Some("bin/chromium.launcher")
        );
        // Arguments are not part of the path.
        assert_eq!(
            snap_command(&dir, Some("daemon")).as_deref(),
            Some("bin/daemon.wrapper")
        );
        // No app named: the first one. A `command:` under a *different*
        // top-level key must not be mistaken for an app's.
        assert_eq!(
            snap_command(&dir, None).as_deref(),
            Some("bin/chromium.launcher")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snap's launcher finds its own files through `$SNAP`, which only means
    /// anything inside the sandbox. Without seeding it, the exec line resolves
    /// to nothing and the app falls back to the runner.
    #[test]
    fn a_launcher_using_the_snap_variable_is_followed_to_the_binary() {
        let root = std::env::temp_dir().join(format!("scan-snapvar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("usr/lib/chromium-browser")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let real = root.join("usr/lib/chromium-browser/chrome");
        std::fs::write(&real, b"\x7fELF").unwrap();

        let launcher = root.join("bin/chromium.launcher");
        std::fs::write(
            &launcher,
            b"#!/bin/sh\nexport GROFF=$SNAP/usr/share/groff\nexec \"$SNAP/usr/lib/chromium-browser/chrome\" $FLAGS \"$@\"\n",
        )
        .unwrap();

        assert_eq!(
            super::super::follow_wrapper_in(&launcher, 0, Some(&root)).as_deref(),
            Some(real.as_path())
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
