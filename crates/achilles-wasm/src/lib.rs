//! Browser/WASM entry point for Achilles. See [`bindings`] for the JS-facing
//! API and the analysis flow.
//!
//! Only the bindings are `wasm32`-only. [`upload`] — working out which
//! platform's layout an uploaded tree follows and where the application sits
//! inside it — is plain [`vfs`] code with no browser dependency, so it builds
//! and is unit-tested natively against real directories.

#[cfg(target_arch = "wasm32")]
mod bindings;
#[cfg(target_arch = "wasm32")]
pub use bindings::*;

// Zip upload unpacking: used by the wasm bindings; built natively only for its tests
// (zip is a wasm-only dependency).
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) mod unzip;

pub mod upload;
