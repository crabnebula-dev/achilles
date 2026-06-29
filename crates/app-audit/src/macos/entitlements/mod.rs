//! Hardened-runtime entitlements of a macOS bundle.
//!
//! The [`Entitlements`] data is always available (so the wasm build can hold and
//! display an imported result), but *reading* it from a bundle means shelling
//! out to `codesign`, which lives in the [`codesign`] submodule behind the
//! `codesign` feature.

use std::collections::BTreeMap;

use serde::Serialize;

#[cfg(feature = "codesign")]
mod codesign;
#[cfg(feature = "codesign")]
pub use codesign::read;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Entitlements {
    /// Whether `codesign` returned any entitlements at all.
    pub present: bool,
    /// Every entitlement key/value pair parsed from the plist, JSON-coerced.
    pub raw: BTreeMap<String, serde_json::Value>,

    pub allow_jit: bool,
    pub allow_unsigned_executable_memory: bool,
    pub disable_executable_page_protection: bool,
    pub allow_dyld_environment_variables: bool,
    pub disable_library_validation: bool,
    pub get_task_allow: bool,
}
