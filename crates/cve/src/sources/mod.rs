//! Per-source adapters. Each module exposes one or more `lookup*` functions
//! that take a shared `reqwest::Client` + package identifier and return a
//! `Vec<Advisory>` normalised into the shared [`crate::Advisory`] shape.
//!
//! Every lookup is cached on disk by key; see [`crate::cache`].

pub mod euvd;
pub mod ghsa;
pub mod nvd;
pub mod osv;
