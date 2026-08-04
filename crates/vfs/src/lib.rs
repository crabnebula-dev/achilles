//! A minimal filesystem abstraction shared by the analysis crates
//! (`detect`, `static-scan`, `app-audit`).
//!
//! On native targets every function forwards directly to `std::fs` / `Path`
//! — zero overhead, behaviour identical to calling `std` directly. On
//! `wasm32` — where there is no real filesystem — the same functions read
//! from an ambient, thread-local in-memory tree ([`MemTree`]) that the wasm
//! entry point populates from an uploaded archive before analysis runs.
//!
//! The analysis crates call these free functions instead of `std::fs`
//! directly, so the same synchronous code drives both a real disk walk on the
//! desktop and an in-memory walk in the browser. Because a browser job
//! analyses exactly one upload at a time, a single ambient tree per thread is
//! sufficient and lets the analysis keep its plain `&Path` signatures.
//!
//! Semantics match `std` where it matters:
//! * [`is_file`] / [`is_dir`] / [`exists`] follow symlinks (like `Path::*`).
//! * [`DirEntry::file_type`] does *not* follow symlinks (like `std::fs`).
//! * [`metadata`] follows symlinks.
//!
//! Alongside the tree, `vfs` carries the [`Platform`] whose application layout
//! the analysis should assume. It starts at the host OS on native — the desktop
//! scan, which needs no ceremony — and is settable, because a caller that
//! unpacks a *distribution artifact* rather than an install is handed a layout
//! that has nothing to do with the machine reading it. See [`platform`] and
//! [`with_platform`].

mod platform;
pub use platform::*;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

#[cfg(target_arch = "wasm32")]
mod mem;
#[cfg(target_arch = "wasm32")]
pub use mem::*;
