//! Builds a synthetic, deliberately-vulnerable Electron app used as a stable
//! Achilles assessment fixture: a packed `app.asar` and a minimal macOS `.app`
//! bundle whose `Contents/Info.plist` declares a *correct* `ElectronAsarIntegrity`
//! hash (so the integrity check passes) but several weak hardening flags.
//!
//! This crate intentionally depends on **none** of the analysis crates, so
//! making it a workspace member can never pull `macos-bundle`/`codesign` into
//! the unified feature set of a normal `cargo build`. It only packs files and
//! hashes them; the assessment runs the real analyzers as a separate step.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The deliberately-insecure source packed into the fixture.
const PACKAGE_JSON: &str = include_str!("../electron-sample/package.json");
const MAIN_JS: &str = include_str!("../electron-sample/main.js");
const INDEX_HTML: &str = include_str!("../electron-sample/index.html");

/// Versions baked into the fake `Electron Framework` binary / its Info.plist, so
/// detection has something deterministic to report. Kept as constants so the
/// builder and the expected manifest can be cross-checked.
pub const ELECTRON_VERSION: &str = "28.1.0";
pub const CHROMIUM_VERSION: &str = "120.0.6099.109"; // 4-part: matches `Chrome/<v>`
pub const NODE_VERSION: &str = "18.18.2";

pub const ASAR_NAME: &str = "electron-sample.asar";
pub const APP_NAME: &str = "ElectronSample.app";

/// Pack the sample files into a minimal Electron ASAR.
///
/// Layout (little-endian), matching `static-scan`'s reader and
/// `app-audit`'s integrity check:
///
/// ```text
///   [0..4]   = 4              (pickle outer size)
///   [4..8]   = 8 + json_len   (header_size; body_start = 8 + header_size)
///   [8..12]  = json_len + 4   (json pickle size; the reader ignores it)
///   [12..16] = json_len
///   [16..]   = JSON header, then file bodies (no padding)
/// ```
pub fn build_asar() -> Vec<u8> {
    let files: [(&str, &[u8]); 3] = [
        ("package.json", PACKAGE_JSON.as_bytes()),
        ("main.js", MAIN_JS.as_bytes()),
        ("index.html", INDEX_HTML.as_bytes()),
    ];

    let mut entries = serde_json::Map::new();
    let mut bodies: Vec<u8> = Vec::new();
    for (name, body) in files {
        // `offset` is a string because Electron supports archives larger than
        // JS's 2^53 integer range; it is relative to the body region.
        entries.insert(
            name.to_string(),
            serde_json::json!({ "size": body.len(), "offset": bodies.len().to_string() }),
        );
        bodies.extend_from_slice(body);
    }
    let header = serde_json::json!({ "files": entries });
    let json = serde_json::to_vec(&header).expect("serialize asar header");
    let json_len = json.len() as u32;
    let header_size = 8 + json_len;

    let mut out = Vec::with_capacity(16 + json.len() + bodies.len());
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&(json_len + 4).to_le_bytes());
    out.extend_from_slice(&json_len.to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(&bodies);
    out
}

/// SHA-256 of the ASAR header JSON string — the digest macOS declares in
/// `ElectronAsarIntegrity`. See [`build_asar`] for the byte layout.
pub fn asar_header_sha256(asar: &[u8]) -> String {
    let json_len = u32::from_le_bytes(asar[12..16].try_into().unwrap()) as usize;
    let mut hasher = Sha256::new();
    hasher.update(&asar[16..16 + json_len]);
    format!("{:x}", hasher.finalize())
}

/// Write `electron-sample.asar` into `dir`; returns its path.
pub fn write_asar(dir: &Path) -> io::Result<PathBuf> {
    let path = dir.join(ASAR_NAME);
    fs::write(&path, build_asar())?;
    Ok(path)
}

/// Write a minimal macOS `.app` bundle (versioned Electron framework layout)
/// into `dir`; returns the `.app` path.
pub fn build_app(dir: &Path) -> io::Result<PathBuf> {
    let app = dir.join(APP_NAME);
    let contents = app.join("Contents");
    fs::create_dir_all(contents.join("MacOS"))?;
    fs::create_dir_all(contents.join("Resources"))?;
    let framework = contents
        .join("Frameworks")
        .join("Electron Framework.framework")
        .join("Versions")
        .join("A");
    fs::create_dir_all(framework.join("Resources"))?;

    // Resources/app.asar + its declared integrity hash.
    let asar = build_asar();
    fs::write(contents.join("Resources").join("app.asar"), &asar)?;
    let asar_hash = asar_header_sha256(&asar);

    // The main executable referenced by CFBundleExecutable. Detection only
    // needs it to be a regular file; the bundle path reads versions from the
    // framework, not this stub.
    fs::write(
        contents.join("MacOS").join("ElectronSample"),
        b"#!/bin/sh\nexit 0\n".as_slice(),
    )?;

    // The fake framework binary carries the user-agent fingerprints the
    // string-scanner reads: a 4-part `Chrome/<v>` and a `node-v<v>` tarball URL.
    let framework_bin = format!(
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/{CHROMIUM_VERSION} Electron/{ELECTRON_VERSION} Safari/537.36 \
         https://nodejs.org/download/release/v{NODE_VERSION}/node-v{NODE_VERSION}.tar.gz"
    );
    fs::write(
        framework.join("Electron Framework"),
        framework_bin.as_bytes(),
    )?;
    fs::write(
        framework.join("Resources").join("Info.plist"),
        framework_plist(ELECTRON_VERSION),
    )?;

    fs::write(contents.join("Info.plist"), app_plist(&asar_hash))?;
    Ok(app)
}

/// Top-level `Contents/Info.plist`: a correct ASAR-integrity hash plus
/// deliberately weak App Transport Security flags and a registered URL scheme.
fn app_plist(asar_hash: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Electron Sample</string>
	<key>CFBundleIdentifier</key>
	<string>dev.crabnebula.achilles.electron-sample</string>
	<key>CFBundleExecutable</key>
	<string>ElectronSample</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0.0</string>
	<key>CFBundleVersion</key>
	<string>1.0.0</string>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>insecure.example.com</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
				<key>NSExceptionMinimumTLSVersion</key>
				<string>TLSv1.0</string>
			</dict>
		</dict>
	</dict>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>achilles-sample</string>
			</array>
		</dict>
	</array>
	<key>ElectronAsarIntegrity</key>
	<dict>
		<key>Resources/app.asar</key>
		<dict>
			<key>algorithm</key>
			<string>SHA256</string>
			<key>hash</key>
			<string>{asar_hash}</string>
		</dict>
	</dict>
</dict>
</plist>
"#
    )
}

/// The framework's `Info.plist`, whose `CFBundleVersion` is the Electron version.
fn framework_plist(version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Electron Framework</string>
	<key>CFBundleShortVersionString</key>
	<string>{version}</string>
	<key>CFBundleVersion</key>
	<string>{version}</string>
</dict>
</plist>
"#
    )
}
