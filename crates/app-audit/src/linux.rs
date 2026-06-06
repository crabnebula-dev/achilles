//! Linux audit backend.
//!
//! Linux has no system code-signing, so the analog of macOS's hardened-runtime
//! flags is the ELF's own exploit-mitigation posture — PIE, RELRO, NX, and
//! stack-canary instrumentation — read straight from the binary. For
//! flatpak/snap apps we additionally surface the declared sandbox permissions,
//! which are the closest thing to entitlements on Linux.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::asar::{self, AsarInfo};

#[derive(Debug, Clone, Serialize)]
pub struct LinuxAudit {
    pub path: PathBuf,
    pub hardening: ElfHardening,
    /// Sandbox permissions for flatpak / snap apps, if applicable.
    pub sandbox: Option<SandboxInfo>,
    /// Informational ASAR hash for Electron apps (no signed baseline on Linux).
    pub asar: Option<AsarInfo>,
}

/// ELF exploit-mitigation flags, read from the main executable.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfHardening {
    /// Parsed an ELF at all. `false` ⇒ the rest are meaningless.
    pub is_elf: bool,
    /// Position-independent executable (`ET_DYN` + interpreter).
    pub pie: bool,
    /// GNU_RELRO state — `none` / `partial` / `full`.
    pub relro: RelroKind,
    /// Non-executable stack (`PT_GNU_STACK` without the execute flag).
    pub nx: bool,
    /// Compiled with stack-smashing protection (`__stack_chk_fail`).
    pub stack_canary: bool,
    /// `_FORTIFY_SOURCE` instrumentation (`*_chk` libc symbols).
    pub fortify_source: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelroKind {
    #[default]
    None,
    Partial,
    Full,
}

/// Declared sandbox permissions for a containerised app.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxInfo {
    /// `"flatpak"` or `"snap"`.
    pub kind: String,
    /// Notable granted permissions (e.g. `filesystem=host`, `network`,
    /// `device=all`).
    pub permissions: Vec<String>,
}

pub fn audit(path: &Path, root: &Path, executable: Option<&Path>) -> LinuxAudit {
    let hardening = executable.map(elf_hardening).unwrap_or_default();
    let sandbox = detect_sandbox(root, executable);
    let asar = asar::info(root);

    LinuxAudit {
        path: path.to_path_buf(),
        hardening,
        sandbox,
        asar,
    }
}

fn elf_hardening(exe: &Path) -> ElfHardening {
    use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1};
    use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP};

    // mmap rather than read the whole file — these binaries can be 100s of MB
    // (Electron), and goblin only touches the headers + symbol tables, so we
    // avoid copying the entire executable into the heap.
    let Ok(file) = std::fs::File::open(exe) else {
        return ElfHardening::default();
    };
    // SAFETY: read-only mapping; a concurrent modification could only skew the
    // parsed flags, no worse than racing any other reader.
    let Ok(mmap) = (unsafe { memmap2::Mmap::map(&file) }) else {
        return ElfHardening::default();
    };
    let Ok(elf) = goblin::elf::Elf::parse(&mmap) else {
        return ElfHardening::default();
    };

    let has_interp = elf.program_headers.iter().any(|ph| ph.p_type == PT_INTERP);
    // `ET_DYN` (3) + an interpreter ⇒ PIE (a bare `ET_DYN` with no interp is a
    // shared library).
    let pie = elf.header.e_type == goblin::elf::header::ET_DYN && has_interp;

    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().is_some_and(|dyns| {
        dyns.dyns.iter().any(|d| match d.d_tag {
            DT_BIND_NOW => true,
            DT_FLAGS => d.d_val & DF_BIND_NOW != 0,
            DT_FLAGS_1 => d.d_val & DF_1_NOW != 0,
            _ => false,
        })
    });
    let relro = match (has_relro, bind_now) {
        (true, true) => RelroKind::Full,
        (true, false) => RelroKind::Partial,
        (false, _) => RelroKind::None,
    };

    // NX: a GNU_STACK segment without the execute flag. Absence of the segment
    // historically means an executable stack, so we treat that as NX off.
    let nx = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK)
        .is_some_and(|ph| ph.p_flags & PF_X == 0);

    let mut stack_canary = false;
    let mut fortify_source = false;
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" {
                stack_canary = true;
            }
            if name.ends_with("_chk") && name != "__stack_chk_fail" {
                fortify_source = true;
            }
        }
    }

    ElfHardening {
        is_elf: true,
        pie,
        relro,
        nx,
        stack_canary,
        fortify_source,
    }
}

/// Detect a flatpak / snap sandbox by walking up from the app's files for a
/// flatpak `metadata` file or a snap `meta/snap.yaml`, and extract the notable
/// permissions.
fn detect_sandbox(root: &Path, executable: Option<&Path>) -> Option<SandboxInfo> {
    let probe = executable.unwrap_or(root);
    let s = probe.to_string_lossy();

    if s.contains("/flatpak/") {
        // flatpak app trees carry a `metadata` file at `.../<id>/current/active/`.
        for anc in probe.ancestors() {
            let meta = anc.join("metadata");
            if meta.is_file() {
                return parse_flatpak_metadata(&meta);
            }
        }
        return Some(SandboxInfo {
            kind: "flatpak".into(),
            permissions: Vec::new(),
        });
    }

    if s.contains("/snap/") {
        return Some(SandboxInfo {
            kind: "snap".into(),
            permissions: Vec::new(),
        });
    }

    None
}

fn parse_flatpak_metadata(meta: &Path) -> Option<SandboxInfo> {
    let text = std::fs::read_to_string(meta).ok()?;
    let mut permissions = Vec::new();
    let mut in_context = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_context = line == "[Context]";
            continue;
        }
        if !in_context {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            // `shared=network;ipc;`, `filesystems=host;`, `devices=all;`, …
            for item in value.split(';').filter(|v| !v.trim().is_empty()) {
                permissions.push(format!("{}={}", key.trim(), item.trim()));
            }
        }
    }
    Some(SandboxInfo {
        kind: "flatpak".into(),
        permissions,
    })
}
