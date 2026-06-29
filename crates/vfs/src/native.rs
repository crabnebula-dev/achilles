//! Native backend: thin, inlined forwarders to `std::fs` / `Path`.
//!
//! These compile away to direct `std` calls, so migrating a call site from
//! `std::fs::read(p)` to `vfs::read(p)` is behaviour- and performance-neutral
//! on the desktop build.

use std::io;
use std::path::Path;

pub use std::fs::{DirEntry, FileType, Metadata, ReadDir};

#[inline]
pub fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

#[inline]
pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    std::fs::read_to_string(path)
}

#[inline]
pub fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
    std::fs::read_dir(path)
}

#[inline]
pub fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    std::fs::metadata(path)
}

#[inline]
pub fn is_file(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_file()
}

#[inline]
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

#[inline]
pub fn exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}
