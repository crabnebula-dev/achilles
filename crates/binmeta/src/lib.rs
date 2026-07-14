//! Object-file header inspection.
//!
//! Parses a binary's headers with `goblin` and returns structured, UI-friendly
//! metadata: format, architecture(s), file kind, notable header flags (PIE / NX
//! / ASLR / CFG / …), linked libraries, and segment/section names. Covers
//! Mach-O (incl. fat/universal), ELF, and PE.

use std::path::Path;

use goblin::Object;
use memmap2::Mmap;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("unrecognized object file")]
    Unknown,
}

/// Headers of one binary. Fat/universal Mach-O binaries yield multiple [`Arch`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryMeta {
    pub path: String,
    /// `mach-o` | `fat-mach-o` | `elf` | `pe`.
    pub format: String,
    pub arches: Vec<Arch>,
}

/// One architecture slice's header metadata.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Arch {
    pub arch: String,
    /// executable | shared-library | object | bundle | core | dynamic-linker | unknown
    pub kind: String,
    pub bits: u8,
    /// `little` | `big`.
    pub endianness: String,
    pub entry: Option<String>,
    /// Notable header attributes (format-specific), e.g. `PIE`, `NX`, `ASLR`.
    pub flags: Vec<String>,
    /// ELF program interpreter (dynamic loader).
    pub interpreter: Option<String>,
    /// ELF `SONAME`.
    pub soname: Option<String>,
    /// PE subsystem (`GUI` / `console` / …).
    pub subsystem: Option<String>,
    /// PE link timestamp (unix seconds), when non-zero.
    pub timestamp: Option<u32>,
    /// Mach-O load-command count.
    pub load_commands: Option<u32>,
    pub linked_libraries: Vec<LinkedLib>,
    /// Mach-O segment names / ELF+PE section names.
    pub segments: Vec<String>,
}

/// A dynamically-linked library and its recorded version.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedLib {
    pub name: String,
    /// Mach-O `current_version` from the load command (link-time version).
    pub version: Option<String>,
}

/// Inspect the headers of the binary at `path`.
pub fn inspect(path: &Path) -> Result<BinaryMeta, Error> {
    let file = std::fs::File::open(path)?;
    // Safety: read-only mapping, never aliased mutably.
    let mmap = unsafe { Mmap::map(&file)? };
    let obj = Object::parse(&mmap).map_err(|e| Error::Parse(e.to_string()))?;
    let path = path.to_string_lossy().into_owned();

    match obj {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => Ok(BinaryMeta {
            path,
            format: "mach-o".into(),
            arches: vec![mach_arch(&macho)],
        }),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            let mut arches = Vec::new();
            let count = fat.arches().map(|a| a.len()).unwrap_or(0);
            for i in 0..count {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(i) {
                    arches.push(mach_arch(&macho));
                }
            }
            Ok(BinaryMeta {
                path,
                format: "fat-mach-o".into(),
                arches,
            })
        }
        Object::Elf(elf) => Ok(BinaryMeta {
            path,
            format: "elf".into(),
            arches: vec![elf_arch(&elf)],
        }),
        Object::PE(pe) => Ok(BinaryMeta {
            path,
            format: "pe".into(),
            arches: vec![pe_arch(&pe)],
        }),
        _ => Err(Error::Unknown),
    }
}


// --- Mach-O -------------------------------------------------------------

fn mach_arch(macho: &goblin::mach::MachO) -> Arch {
    use goblin::mach::header;
    let h = &macho.header;

    let arch = goblin::mach::cputype::get_arch_name_from_types(h.cputype, h.cpusubtype)
        .map(str::to_string)
        .unwrap_or_else(|| {
            use goblin::mach::cputype::*;
            match h.cputype {
                CPU_TYPE_X86_64 => "x86_64",
                CPU_TYPE_X86 => "x86",
                CPU_TYPE_ARM64 => "arm64",
                CPU_TYPE_ARM64_32 => "arm64_32",
                CPU_TYPE_ARM => "arm",
                CPU_TYPE_POWERPC64 => "ppc64",
                CPU_TYPE_POWERPC => "ppc",
                _ => "unknown",
            }
            .to_string()
        });

    let kind = match h.filetype {
        header::MH_EXECUTE => "executable",
        header::MH_DYLIB => "shared-library",
        header::MH_BUNDLE => "bundle",
        header::MH_OBJECT => "object",
        header::MH_CORE => "core",
        header::MH_DYLINKER => "dynamic-linker",
        _ => "unknown",
    }
    .to_string();

    let mut flags = Vec::new();
    let f = h.flags;
    if f & header::MH_PIE != 0 {
        flags.push("PIE".into());
    }
    if f & header::MH_TWOLEVEL != 0 {
        flags.push("two-level namespace".into());
    }
    if f & header::MH_NO_HEAP_EXECUTION != 0 {
        flags.push("no-heap-execution".into());
    }
    if f & header::MH_ALLOW_STACK_EXECUTION != 0 {
        flags.push("allow-stack-execution".into());
    }
    if f & header::MH_WEAK_DEFINES != 0 {
        flags.push("weak-defines".into());
    }

    let segments = macho
        .segments
        .iter()
        .filter_map(|seg| seg.name().ok().map(str::to_owned))
        .collect();

    // Pair each linked dylib name with the `current_version` recorded in its
    // load command. `libs` and the dylib-loading commands are in the same order;
    // if they don't align (e.g. an odd binary), fall back to names-only.
    use goblin::mach::load_command::CommandVariant;
    let versions: Vec<Option<String>> = macho
        .load_commands
        .iter()
        .filter_map(|lc| match &lc.command {
            CommandVariant::LoadDylib(d)
            | CommandVariant::LoadWeakDylib(d)
            | CommandVariant::ReexportDylib(d)
            | CommandVariant::LoadUpwardDylib(d)
            | CommandVariant::LazyLoadDylib(d) => Some(mach_version(d.dylib.current_version)),
            _ => None,
        })
        .collect();
    // `libs[0]` is a "self" placeholder for the binary itself, not a dependency.
    let names: Vec<&str> = macho.libs.iter().copied().filter(|l| *l != "self").collect();
    let linked_libraries = if names.len() == versions.len() {
        names
            .iter()
            .zip(versions)
            .map(|(name, version)| LinkedLib {
                name: name.to_string(),
                version,
            })
            .collect()
    } else {
        names
            .iter()
            .map(|name| LinkedLib {
                name: name.to_string(),
                version: None,
            })
            .collect()
    };

    Arch {
        arch,
        kind,
        bits: if macho.is_64 { 64 } else { 32 },
        endianness: if macho.little_endian { "little" } else { "big" }.into(),
        entry: Some(format!("0x{:x}", macho.entry)),
        flags,
        load_commands: Some(h.ncmds as u32),
        linked_libraries,
        segments,
        ..Default::default()
    }
}

/// Mach-O 32-bit packed version `X.Y.Z` → `"X.Y.Z"`, or `None` for `0`.
fn mach_version(v: u32) -> Option<String> {
    if v == 0 {
        return None;
    }
    Some(format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff))
}

// --- ELF ----------------------------------------------------------------

fn elf_arch(elf: &goblin::elf::Elf) -> Arch {
    use goblin::elf::header;
    use goblin::elf::program_header;

    let arch = match elf.header.e_machine {
        header::EM_X86_64 => "x86_64",
        header::EM_386 => "x86",
        header::EM_AARCH64 => "arm64",
        header::EM_ARM => "arm",
        header::EM_RISCV => "riscv",
        header::EM_PPC64 => "ppc64",
        _ => "unknown",
    }
    .to_string();

    let is_dyn = elf.header.e_type == header::ET_DYN;
    let kind = match elf.header.e_type {
        header::ET_EXEC => "executable",
        header::ET_DYN if elf.interpreter.is_some() => "executable", // PIE
        header::ET_DYN => "shared-library",
        header::ET_REL => "object",
        header::ET_CORE => "core",
        _ => "unknown",
    }
    .to_string();

    let mut flags = Vec::new();
    if is_dyn && elf.interpreter.is_some() {
        flags.push("PIE".into());
    }
    // NX: a PT_GNU_STACK header that is not executable.
    if let Some(gs) = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == program_header::PT_GNU_STACK)
    {
        if gs.p_flags & program_header::PF_X == 0 {
            flags.push("NX".into());
        } else {
            flags.push("executable-stack".into());
        }
    }
    // RELRO: PT_GNU_RELRO present (partial); full if BIND_NOW is set.
    if elf
        .program_headers
        .iter()
        .any(|p| p.p_type == program_header::PT_GNU_RELRO)
    {
        let bind_now = elf
            .dynamic
            .as_ref()
            .map(|d| {
                d.info.flags & goblin::elf::dynamic::DF_BIND_NOW != 0
                    || d.info.flags_1 & goblin::elf::dynamic::DF_1_NOW != 0
            })
            .unwrap_or(false);
        flags.push(if bind_now { "full-RELRO".into() } else { "partial-RELRO".into() });
    }

    let sections = elf
        .section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name).map(str::to_owned))
        .filter(|n| !n.is_empty())
        .collect();

    Arch {
        arch,
        kind,
        bits: if elf.is_64 { 64 } else { 32 },
        endianness: if elf.little_endian { "little" } else { "big" }.into(),
        entry: Some(format!("0x{:x}", elf.entry)),
        flags,
        interpreter: elf.interpreter.map(str::to_owned),
        soname: elf.soname.map(str::to_owned),
        linked_libraries: elf
            .libraries
            .iter()
            .map(|s| LinkedLib {
                name: s.to_string(),
                version: None,
            })
            .collect(),
        segments: sections,
        ..Default::default()
    }
}

// --- PE -----------------------------------------------------------------

fn pe_arch(pe: &goblin::pe::PE) -> Arch {
    use goblin::pe::characteristic;

    let machine = pe.header.coff_header.machine;
    let arch = match machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xAA64 => "arm64",
        0x01c0 | 0x01c4 => "arm",
        _ => "unknown",
    }
    .to_string();

    let opt = pe.header.optional_header;
    let mut flags = Vec::new();
    let mut subsystem = None;
    if let Some(opt) = opt {
        let dll = opt.windows_fields.dll_characteristics;
        // IMAGE_DLLCHARACTERISTICS_* bits.
        if dll & 0x0040 != 0 {
            flags.push("ASLR".into());
        }
        if dll & 0x0020 != 0 {
            flags.push("high-entropy-ASLR".into());
        }
        if dll & 0x0100 != 0 {
            flags.push("DEP/NX".into());
        }
        if dll & 0x4000 != 0 {
            flags.push("CFG".into());
        }
        if dll & 0x0080 != 0 {
            flags.push("force-integrity".into());
        }
        if dll & 0x0400 != 0 {
            flags.push("no-SEH".into());
        }
        subsystem = Some(
            match opt.windows_fields.subsystem {
                2 => "GUI",
                3 => "console",
                9 => "Windows CE GUI",
                _ => "other",
            }
            .to_string(),
        );
    }
    if pe.header.coff_header.characteristics & characteristic::IMAGE_FILE_DLL != 0 {
        flags.push("DLL".into());
    }

    let timestamp = pe.header.coff_header.time_date_stamp;

    let sections = pe
        .sections
        .iter()
        .filter_map(|s| s.name().ok().map(|n| n.to_string()))
        .collect();

    Arch {
        arch,
        kind: if pe.is_lib { "shared-library" } else { "executable" }.into(),
        bits: if pe.is_64 { 64 } else { 32 },
        endianness: "little".into(),
        entry: Some(format!("0x{:x}", pe.entry)),
        flags,
        subsystem,
        timestamp: (timestamp != 0).then_some(timestamp),
        linked_libraries: pe
            .libraries
            .iter()
            .map(|s| LinkedLib {
                name: s.to_string(),
                version: None,
            })
            .collect(),
        segments: sections,
        ..Default::default()
    }
}
