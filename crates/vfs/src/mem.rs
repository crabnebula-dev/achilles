//! wasm backend: an ambient, thread-local in-memory filesystem.
//!
//! The wasm entry point unpacks an uploaded archive into a [`MemTree`], installs
//! it with [`set_ambient`], runs the (unchanged, synchronous) analysis, then
//! calls [`clear_ambient`]. Lookups resolve symlinks component-by-component so
//! that macOS framework layouts (`Versions/Current -> A`) behave like a real
//! disk.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const MAX_SYMLINK_DEPTH: usize = 16;

#[derive(Clone)]
enum Node {
    File {
        bytes: Arc<Vec<u8>>,
        #[allow(dead_code)] // reserved for WS5 re-zip fidelity
        mode: u32,
    },
    Dir,
    Symlink {
        target: PathBuf,
    },
}

/// An in-memory directory tree populated from an uploaded archive. Keys are the
/// exact paths the analysis will query (the wasm entry builds the tree and
/// drives `detect`/`static_scan`/`app_audit` with the same root prefix).
#[derive(Default, Clone)]
pub struct MemTree {
    nodes: BTreeMap<PathBuf, Node>,
}

impl MemTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a regular file (default mode `0o644`), creating parent dirs.
    pub fn insert_file(&mut self, path: PathBuf, bytes: Vec<u8>) {
        self.insert_file_with_mode(path, bytes, 0o644);
    }

    /// Insert a regular file with an explicit unix mode, creating parent dirs.
    pub fn insert_file_with_mode(&mut self, path: PathBuf, bytes: Vec<u8>, mode: u32) {
        self.ensure_parents(&path);
        self.nodes.insert(
            path,
            Node::File {
                bytes: Arc::new(bytes),
                mode,
            },
        );
    }

    /// Insert (or ensure) a directory, creating parent dirs.
    pub fn insert_dir(&mut self, path: PathBuf) {
        self.ensure_parents(&path);
        self.nodes.entry(path).or_insert(Node::Dir);
    }

    /// Insert a symlink with the given (possibly relative) target.
    pub fn insert_symlink(&mut self, path: PathBuf, target: PathBuf) {
        self.ensure_parents(&path);
        self.nodes.insert(path, Node::Symlink { target });
    }

    /// Number of nodes (files + dirs + symlinks). Useful for diagnostics.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn ensure_parents(&mut self, path: &Path) {
        let mut cur = path.parent();
        while let Some(p) = cur {
            if p.as_os_str().is_empty() {
                break;
            }
            self.nodes.entry(p.to_path_buf()).or_insert(Node::Dir);
            cur = p.parent();
        }
    }

    /// Resolve `path` to a canonical key, following symlink components.
    fn resolve(&self, path: &Path, depth: usize) -> Option<PathBuf> {
        if depth > MAX_SYMLINK_DEPTH {
            return None;
        }
        let mut acc = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Prefix(_) => {}
                Component::RootDir => acc = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    acc.pop();
                }
                Component::Normal(c) => {
                    acc.push(c);
                    if let Some(Node::Symlink { target }) = self.nodes.get(&acc) {
                        let base = acc.parent().map(Path::to_path_buf).unwrap_or_default();
                        let joined = if target.is_absolute() {
                            target.clone()
                        } else {
                            base.join(target)
                        };
                        acc = self.resolve(&joined, depth + 1)?;
                    }
                }
            }
        }
        Some(acc)
    }

    /// Look up a node, following symlinks (used by the symlink-following calls).
    fn get_resolved(&self, path: &Path) -> Option<&Node> {
        let key = self.resolve(path, 0)?;
        self.nodes.get(&key)
    }
}

thread_local! {
    static AMBIENT: RefCell<Option<MemTree>> = const { RefCell::new(None) };
}

/// Install `tree` as the ambient filesystem for the current thread.
pub fn set_ambient(tree: MemTree) {
    AMBIENT.with(|a| *a.borrow_mut() = Some(tree));
}

/// Remove the ambient filesystem for the current thread.
pub fn clear_ambient() {
    AMBIENT.with(|a| *a.borrow_mut() = None);
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("vfs: no such path: {}", path.display()),
    )
}

fn with_ambient<R>(f: impl FnOnce(&MemTree) -> io::Result<R>, path: &Path) -> io::Result<R> {
    AMBIENT.with(|a| match a.borrow().as_ref() {
        Some(tree) => f(tree),
        None => Err(not_found(path)),
    })
}

pub fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    with_ambient(
        |tree| match tree.get_resolved(path) {
            Some(Node::File { bytes, .. }) => Ok((**bytes).clone()),
            _ => Err(not_found(path)),
        },
        path,
    )
}

pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    let bytes = read(path)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
    let path = path.as_ref();
    with_ambient(
        |tree| {
            let dir = tree.resolve(path, 0).ok_or_else(|| not_found(path))?;
            match tree.nodes.get(&dir) {
                Some(Node::Dir) => {}
                // `ErrorKind::NotADirectory` is only stable since 1.83; the
                // workspace MSRV is 1.80, so use a generic error with a message.
                _ => {
                    return Err(io::Error::other(format!(
                        "vfs: not a directory: {}",
                        path.display()
                    )))
                }
            }
            let entries: Vec<DirEntry> = tree
                .nodes
                .iter()
                .filter(|(k, _)| k.parent() == Some(dir.as_path()))
                .map(|(k, node)| DirEntry {
                    path: k.clone(),
                    // DirEntry::file_type does NOT follow symlinks (std parity).
                    file_type: FileType::of_node(node),
                })
                .collect();
            Ok(ReadDir {
                entries: entries.into_iter(),
            })
        },
        path,
    )
}

pub fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref();
    with_ambient(
        |tree| {
            // metadata() follows symlinks.
            let node = tree.get_resolved(path).ok_or_else(|| not_found(path))?;
            Ok(match node {
                Node::File { bytes, .. } => Metadata {
                    len: bytes.len() as u64,
                    is_dir: false,
                    is_file: true,
                },
                Node::Dir => Metadata {
                    len: 0,
                    is_dir: true,
                    is_file: false,
                },
                // Unreachable after resolve(), but stay total.
                Node::Symlink { .. } => Metadata {
                    len: 0,
                    is_dir: false,
                    is_file: false,
                },
            })
        },
        path,
    )
}

pub fn is_file(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    AMBIENT.with(|a| {
        a.borrow()
            .as_ref()
            .and_then(|tree| tree.get_resolved(path))
            .map(|n| matches!(n, Node::File { .. }))
            .unwrap_or(false)
    })
}

pub fn is_dir(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    AMBIENT.with(|a| {
        a.borrow()
            .as_ref()
            .and_then(|tree| tree.get_resolved(path))
            .map(|n| matches!(n, Node::Dir))
            .unwrap_or(false)
    })
}

pub fn exists(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    AMBIENT.with(|a| {
        a.borrow()
            .as_ref()
            .and_then(|tree| tree.get_resolved(path))
            .is_some()
    })
}

/// Mirror of `std::fs::DirEntry` (the subset the analysis crates use).
pub struct DirEntry {
    path: PathBuf,
    file_type: FileType,
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn file_name(&self) -> OsString {
        self.path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default()
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        Ok(self.file_type)
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        metadata(&self.path)
    }
}

/// Mirror of `std::fs::ReadDir`: an iterator of `io::Result<DirEntry>`.
pub struct ReadDir {
    entries: std::vec::IntoIter<DirEntry>,
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(Ok)
    }
}

/// Mirror of `std::fs::FileType`.
#[derive(Clone, Copy)]
pub struct FileType {
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
}

impl FileType {
    fn of_node(node: &Node) -> Self {
        match node {
            Node::File { .. } => FileType {
                is_dir: false,
                is_file: true,
                is_symlink: false,
            },
            Node::Dir => FileType {
                is_dir: true,
                is_file: false,
                is_symlink: false,
            },
            Node::Symlink { .. } => FileType {
                is_dir: false,
                is_file: false,
                is_symlink: true,
            },
        }
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    pub fn is_file(&self) -> bool {
        self.is_file
    }

    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

/// Mirror of `std::fs::Metadata` (the subset the analysis crates use).
pub struct Metadata {
    len: u64,
    is_dir: bool,
    is_file: bool,
}

// `len()` here is a byte size (mirroring `std::fs::Metadata::len`), so an
// `is_empty()` would be misleading — std doesn't have one either.
#[allow(clippy::len_without_is_empty)]
impl Metadata {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    pub fn is_file(&self) -> bool {
        self.is_file
    }
}
