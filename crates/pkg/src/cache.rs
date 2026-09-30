//! Expand a package once and keep it, so the rest of Achilles can walk it.
//!
//! An AppImage is a single file: there is no installed directory to analyse,
//! and the application inside it is compressed, so nothing short of expanding
//! it reveals which framework it bundles. The desktop build therefore unpacks
//! one to a cache directory the first time it sees it, and every later scan
//! reuses that.
//!
//! The cache key covers the file's identity *and* its size and mtime, so a
//! replaced or updated package expands again rather than being read as its
//! predecessor. Extraction goes to a `.partial` directory that is renamed into
//! place only on success, so an interrupted run can never leave a half-tree
//! that looks complete.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{DirSink, Format, PkgError};

/// Expand `file` into the shared cache and return the directory holding its
/// payload. A package already expanded there is returned untouched.
pub fn extract_cached(file: &Path) -> Result<PathBuf, PkgError> {
    let root = default_cache_root().ok_or_else(|| {
        PkgError::Io(std::io::Error::other(
            "no cache directory available on this system",
        ))
    })?;
    extract_cached_in(file, &root)
}

/// [`extract_cached`] against an explicit cache root.
pub fn extract_cached_in(file: &Path, cache_root: &Path) -> Result<PathBuf, PkgError> {
    let metadata = fs::metadata(file)?;
    let dest = cache_root.join(cache_key(file, &metadata));
    if dest.is_dir() {
        return Ok(dest);
    }

    let bytes = fs::read(file)?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let format = crate::sniff(&bytes, &name).ok_or(PkgError::Unrecognised)?;

    // Extract beside the destination so the rename that publishes it stays
    // within one filesystem.
    fs::create_dir_all(cache_root)?;
    let partial = cache_root.join(format!(
        "{}.partial-{}",
        dest.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&partial);

    let result = (|| -> Result<(), PkgError> {
        let mut sink = DirSink::new(&partial)?;
        crate::unpack(&bytes, format, &partial, &mut sink)?;
        sink.finish()
    })();
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&partial);
        return Err(e);
    }

    match fs::rename(&partial, &dest) {
        Ok(()) => Ok(dest),
        // Another process published the same package while we were working;
        // theirs is as good as ours.
        Err(_) if dest.is_dir() => {
            let _ = fs::remove_dir_all(&partial);
            Ok(dest)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&partial);
            Err(PkgError::Io(e))
        }
    }
}

/// Where expanded packages live: `<cache>/achilles/packages`.
pub fn default_cache_root() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("achilles/packages"))
}

/// True for a package this crate expands to a directory rather than reads in
/// place — i.e. one that discovery may hand over as a single file.
pub fn is_expandable(path: &Path) -> bool {
    matches!(
        crate::sniff(&read_prefix(path), &file_name(path)),
        Some(Format::AppImage) | Some(Format::Snap)
    )
}

/// A directory name that is stable for one version of one file, and different
/// for any other. The stem keeps the cache browsable by a human; the rest
/// distinguishes same-named packages and catches in-place updates.
fn cache_key(file: &Path, metadata: &fs::Metadata) -> String {
    use std::time::UNIX_EPOCH;

    let stem: String = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "package".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(48)
        .collect();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{stem}-{:016x}-{:x}-{:x}",
        fnv1a(file.to_string_lossy().as_bytes()),
        metadata.len(),
        mtime
    )
}

/// FNV-1a over the absolute path. Not a security boundary — it only has to
/// separate two packages that share a name, size, and mtime.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// Enough of a file to sniff its format, without reading a 300 MB AppImage to
/// answer "is this an AppImage?".
fn read_prefix(path: &Path) -> Vec<u8> {
    use std::io::Read;

    let mut buf = vec![0u8; 512];
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    match file.read(&mut buf) {
        Ok(read) => {
            buf.truncate(read);
            buf
        }
        Err(_) => Vec::new(),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pkg-cache-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A tar standing in for a package, so the test needs no external tools.
    fn tarball() -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[.."app".len()].copy_from_slice(b"app");
        header[100..108].copy_from_slice(b"0000755\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", 4).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        let mut out = header;
        out.extend_from_slice(b"BODY");
        out.extend(std::iter::repeat(0).take(512 - 4));
        out.extend(std::iter::repeat(0).take(1024));
        out
    }

    #[test]
    fn expands_once_and_reuses_the_result() {
        let dir = temp("reuse");
        let file = dir.join("fixture.tar");
        fs::write(&file, tarball()).unwrap();
        let cache = dir.join("cache");

        let first = extract_cached_in(&file, &cache).unwrap();
        assert_eq!(fs::read(first.join("app")).unwrap(), b"BODY");

        // Mark the extraction so a second call reusing it is observable.
        fs::write(first.join("marker"), b"kept").unwrap();
        let second = extract_cached_in(&file, &cache).unwrap();
        assert_eq!(first, second);
        assert!(second.join("marker").is_file(), "should have been reused");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_file_expands_to_a_new_directory() {
        let dir = temp("changed");
        let file = dir.join("fixture.tar");
        fs::write(&file, tarball()).unwrap();
        let cache = dir.join("cache");
        let first = extract_cached_in(&file, &cache).unwrap();

        // Same name, different content: a new size means a new key.
        let mut bigger = tarball();
        bigger.extend(std::iter::repeat(0).take(512));
        fs::write(&file, bigger).unwrap();
        let second = extract_cached_in(&file, &cache).unwrap();

        assert_ne!(
            first, second,
            "an updated package must not reuse the old tree"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_a_package_leaves_nothing_behind() {
        let dir = temp("bogus");
        let file = dir.join("notes.txt");
        fs::write(&file, b"just some text").unwrap();
        let cache = dir.join("cache");

        assert!(matches!(
            extract_cached_in(&file, &cache),
            Err(PkgError::Unrecognised)
        ));
        let leftovers = fs::read_dir(&cache).map(|d| d.count()).unwrap_or(0);
        assert_eq!(leftovers, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
