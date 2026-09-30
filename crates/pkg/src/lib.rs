//! Read Linux application package formats into a file tree.
//!
//! Achilles analyses an *installed* application: a directory of files it can
//! walk. Linux ships applications as single-file packages instead — an
//! AppImage, a snap, a `.deb`, an `.rpm`, a vendor tarball — so before any of
//! that analysis can run, the payload has to come out.
//!
//! That's all this crate does: given the bytes of a package, work out what it
//! is ([`sniff`]) and stream its payload to a [`Sink`] ([`unpack`]). The sink
//! decides where the files land — an in-memory [`vfs::MemTree`] in the browser,
//! a cache directory on the desktop — so the crate itself needs no filesystem
//! and compiles unchanged for `wasm32-unknown-unknown`.
//!
//! ```no_run
//! # fn ex(bytes: &[u8]) -> Result<(), pkg::PkgError> {
//! use std::path::Path;
//!
//! let format = pkg::sniff(bytes, "Foo-1.2.3.AppImage").ok_or(pkg::PkgError::Unrecognised)?;
//! let mut entries = pkg::Collector::default();
//! let summary = pkg::unpack(bytes, format, Path::new("/scan"), &mut entries)?;
//! println!("{} files from a {}", summary.files, summary.format);
//! # Ok(())
//! # }
//! ```
//!
//! Every reader here is a from-scratch parser over a byte slice. The formats
//! are simple containers (ar, tar, cpio, squashfs) and the alternative — the
//! established crates for each — pulls in C decompressors that cannot link on
//! wasm. Nothing is executed and nothing is written outside the sink, which
//! matters when the input is an untrusted package a user dropped on the page.

use std::fmt;
use std::path::{Component, Path, PathBuf};

mod appimage;
mod ar;
mod cpio;
mod decompress;
mod rpm;
mod squashfs;
mod tar;

pub use decompress::Codec;

// Writing to a real filesystem — and therefore caching an expanded package on
// one — only exists off wasm, where the browser build keeps everything in
// memory instead.
#[cfg(not(target_arch = "wasm32"))]
mod cache;
#[cfg(not(target_arch = "wasm32"))]
mod dir_sink;
#[cfg(not(target_arch = "wasm32"))]
pub use cache::{default_cache_root, extract_cached, extract_cached_in, is_expandable};
#[cfg(not(target_arch = "wasm32"))]
pub use dir_sink::DirSink;

/// Largest payload we will expand. A package is compressed, so a small upload
/// can decompress to an unbounded tree ("zip bomb"); this caps the damage on a
/// malicious input while sitting far above any real application (the largest
/// Electron AppImages land around 700 MB expanded).
pub const MAX_PAYLOAD_BYTES: u64 = 4 << 30;

/// A Linux application package format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Type-2 AppImage: an ELF runtime stub with a squashfs image appended.
    AppImage,
    /// A snap: a bare squashfs image.
    Snap,
    /// A Debian package: an `ar` archive whose `data.tar.*` member is the payload.
    Deb,
    /// An RPM package: a header stack followed by a compressed cpio payload.
    Rpm,
    /// A tarball, optionally compressed (`.tar`, `.tar.gz`, `.tar.xz`, …).
    Tarball,
}

impl Format {
    /// The extension-style name used in user-facing messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::AppImage => "AppImage",
            Format::Snap => "snap",
            Format::Deb => ".deb",
            Format::Rpm => ".rpm",
            Format::Tarball => "tarball",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PkgError {
    #[error("not a package format we recognise")]
    Unrecognised,
    /// The container was identified but its structure didn't parse.
    #[error("malformed {0}: {1}")]
    Malformed(&'static str, String),
    #[error("{0} decompression failed: {1}")]
    Decompress(&'static str, String),
    #[error("{0}-compressed payloads are not supported")]
    UnsupportedCompression(&'static str),
    /// A type-1 AppImage (ISO 9660), or any other variant we don't read.
    #[error("{0}")]
    Unsupported(String),
    #[error("the payload expands past the {} GiB limit for this scan", *.0 as f64 / (1 << 30) as f64)]
    TooLarge(u64),
    /// Only produced by sinks that touch a real filesystem.
    #[error("writing the unpacked payload failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Where an unpacked payload goes.
///
/// Paths handed to a sink are already joined onto the caller's base and
/// guaranteed not to escape it. Symlink targets are passed through as the
/// package recorded them, except that absolute targets are re-rooted onto the
/// base — inside a package `/usr/lib/libfoo.so` means the packaged copy, not
/// the host's.
pub trait Sink {
    fn dir(&mut self, path: &Path) -> Result<(), PkgError>;
    fn file(&mut self, path: &Path, data: Vec<u8>, mode: u32) -> Result<(), PkgError>;
    fn symlink(&mut self, path: &Path, target: &Path) -> Result<(), PkgError>;
}

/// One unpacked entry, as collected by [`Collector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Dir(PathBuf),
    File {
        path: PathBuf,
        data: Vec<u8>,
        mode: u32,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

impl Entry {
    pub fn path(&self) -> &Path {
        match self {
            Entry::Dir(p) => p,
            Entry::File { path, .. } => path,
            Entry::Symlink { path, .. } => path,
        }
    }
}

/// A [`Sink`] that keeps everything in a `Vec` — for tests and small payloads.
#[derive(Debug, Default)]
pub struct Collector {
    pub entries: Vec<Entry>,
}

impl Sink for Collector {
    fn dir(&mut self, path: &Path) -> Result<(), PkgError> {
        self.entries.push(Entry::Dir(path.to_path_buf()));
        Ok(())
    }

    fn file(&mut self, path: &Path, data: Vec<u8>, mode: u32) -> Result<(), PkgError> {
        self.entries.push(Entry::File {
            path: path.to_path_buf(),
            data,
            mode,
        });
        Ok(())
    }

    fn symlink(&mut self, path: &Path, target: &Path) -> Result<(), PkgError> {
        self.entries.push(Entry::Symlink {
            path: path.to_path_buf(),
            target: target.to_path_buf(),
        });
        Ok(())
    }
}

/// What [`unpack`] produced.
#[derive(Debug, Clone)]
pub struct Unpacked {
    pub format: Format,
    /// Regular files written (directories and symlinks excluded).
    pub files: usize,
    /// Total uncompressed bytes of those files.
    pub bytes: u64,
    /// The payload root inside the base — where the application tree starts.
    /// A `.deb` unpacks its `data.tar` at the base, an AppImage its squashfs
    /// root; both are the base itself today, but the field keeps callers
    /// honest about which directory to analyse.
    pub root: PathBuf,
    /// Non-fatal problems: entries skipped, a member we couldn't read. Worth
    /// showing, never worth failing the whole unpack over.
    pub warnings: Vec<String>,
    /// The expansion cap this unpack is running under, in bytes.
    limit: u64,
}

impl Unpacked {
    pub(crate) fn new(format: Format, root: &Path, limit: u64) -> Unpacked {
        Unpacked {
            format,
            files: 0,
            bytes: 0,
            root: root.to_path_buf(),
            warnings: Vec::new(),
            limit,
        }
    }
}

/// Identify a package from its magic bytes, with `filename` as a tie-breaker.
///
/// Magic decides wherever there is one. `filename` only matters for the two
/// ambiguous cases: a tarball (a `.tar` has no magic at offset 0, and a bare
/// gzip stream might be anything) and an AppImage whose runtime stub predates
/// the type-2 magic bytes.
pub fn sniff(bytes: &[u8], filename: &str) -> Option<Format> {
    let lower = filename.to_ascii_lowercase();

    if rpm::is_rpm(bytes) {
        return Some(Format::Rpm);
    }
    if ar::is_ar(bytes) {
        // `.deb` is by far the common ar archive; a static library is the other
        // one, and it holds no application.
        return ar::looks_like_deb(bytes).then_some(Format::Deb);
    }
    if squashfs::is_squashfs(bytes) {
        return Some(Format::Snap);
    }
    if appimage::is_appimage(bytes, &lower) {
        return Some(Format::AppImage);
    }
    if tar::is_tar(bytes) {
        return Some(Format::Tarball);
    }
    // A compressed stream is a tarball if it's named like one, or if what's
    // under the compression turns out to be a tar. Checking the content means
    // decompressing, so only the name is used here — `unpack` reports a clear
    // error if the name lied.
    if decompress::Codec::sniff(bytes).is_some() && is_tarball_name(&lower) {
        return Some(Format::Tarball);
    }
    None
}

/// True for the tarball spellings that actually appear on download pages.
fn is_tarball_name(lower: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.xz",
        ".txz",
        ".tar.bz2",
        ".tbz2",
        ".tbz",
        ".tar.zst",
        ".tzst",
        ".tar.lz4",
        ".tar.lzma",
    ];
    SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Unpack `bytes` under `base`, pushing every entry to `sink`.
///
/// `format` comes from [`sniff`]; passing one that doesn't match the bytes
/// yields [`PkgError::Malformed`] rather than garbage.
pub fn unpack(
    bytes: &[u8],
    format: Format,
    base: &Path,
    sink: &mut dyn Sink,
) -> Result<Unpacked, PkgError> {
    unpack_with_limit(bytes, format, base, sink, MAX_PAYLOAD_BYTES)
}

/// [`unpack`] with an explicit cap on how much the payload may expand to.
///
/// The browser build sets this well below [`MAX_PAYLOAD_BYTES`]: wasm has a
/// 4 GiB address space that also has to hold the upload itself and every binary
/// the analysis parses out of it, so the useful failure there is a message, not
/// an out-of-memory trap.
pub fn unpack_with_limit(
    bytes: &[u8],
    format: Format,
    base: &Path,
    sink: &mut dyn Sink,
    limit: u64,
) -> Result<Unpacked, PkgError> {
    let mut out = Unpacked::new(format, base, limit);
    sink.dir(base)?;

    match format {
        Format::AppImage => {
            let image = appimage::payload(bytes)?;
            squashfs::unpack(image, base, sink, &mut out)?;
        }
        Format::Snap => squashfs::unpack(bytes, base, sink, &mut out)?,
        Format::Deb => {
            let (data, codec) = ar::data_member(bytes)?;
            let tarball = decompress::decompress(codec, data, None)?;
            tar::unpack(&tarball, base, sink, &mut out)?;
        }
        Format::Rpm => {
            let (payload, codec) = rpm::payload(bytes)?;
            let raw = decompress::decompress(codec, payload, None)?;
            cpio::unpack(&raw, base, sink, &mut out)?;
        }
        Format::Tarball => {
            let codec = decompress::Codec::sniff(bytes).unwrap_or(decompress::Codec::None);
            let raw = decompress::decompress(codec, bytes, None)?;
            tar::unpack(&raw, base, sink, &mut out)?;
        }
    }

    Ok(out)
}

/// Join a package-relative path onto `base`, refusing anything that would
/// escape it.
///
/// Package payloads are absolute by convention (`./usr/bin/foo`, `/usr/bin/foo`),
/// so the leading root is stripped rather than rejected. `..` is the one
/// rejection: no legitimate payload needs it, and honouring it is the classic
/// archive-traversal write-anywhere bug.
///
/// A name that normalises away to nothing — `.`, `./`, `/` — is the payload
/// root itself, which `tar -C src .` puts at the front of every archive it
/// writes, and maps to `base`.
pub(crate) fn join_safe(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/');
    let mut out = base.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            // `./` and a leading `/` are noise in archive member names.
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => return None,
        }
    }
    Some(out)
}

/// Re-root an absolute symlink target onto the payload: inside a package,
/// `/usr/lib/libfoo.so` names the packaged file, not the host's.
pub(crate) fn link_target(base: &Path, target: &str) -> PathBuf {
    if target.starts_with('/') {
        join_safe(base, target).unwrap_or_else(|| base.to_path_buf())
    } else {
        PathBuf::from(target)
    }
}

/// Account for a file about to be written, enforcing the unpack's limit.
pub(crate) fn account(out: &mut Unpacked, len: usize) -> Result<(), PkgError> {
    out.files += 1;
    out.bytes += len as u64;
    if out.bytes > out.limit {
        return Err(PkgError::TooLarge(out.limit));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_safe_strips_leading_root_and_curdir() {
        let base = Path::new("/scan");
        assert_eq!(
            join_safe(base, "./usr/bin/foo").unwrap(),
            Path::new("/scan/usr/bin/foo")
        );
        assert_eq!(
            join_safe(base, "/usr/bin/foo").unwrap(),
            Path::new("/scan/usr/bin/foo")
        );
    }

    #[test]
    fn join_safe_rejects_traversal() {
        let base = Path::new("/scan");
        assert!(join_safe(base, "../etc/passwd").is_none());
        assert!(join_safe(base, "usr/../../etc/passwd").is_none());
    }

    #[test]
    fn the_archive_root_entry_maps_to_the_base() {
        // `tar -C src .` writes this member; it is not a traversal attempt.
        let base = Path::new("/scan");
        assert_eq!(join_safe(base, "./").unwrap(), base);
        assert_eq!(join_safe(base, "/").unwrap(), base);
    }

    #[test]
    fn absolute_link_targets_are_rerooted() {
        let base = Path::new("/scan");
        assert_eq!(
            link_target(base, "/usr/lib/libfoo.so"),
            Path::new("/scan/usr/lib/libfoo.so")
        );
        assert_eq!(
            link_target(base, "../lib/libfoo.so"),
            Path::new("../lib/libfoo.so")
        );
    }
}
