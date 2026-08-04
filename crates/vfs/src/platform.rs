//! Which OS's application layout the analysis should assume.
//!
//! For the desktop app the answer is simply the host OS: it scans what is
//! installed on this machine, so [`platform`] starts out as [`host_platform`]
//! and nothing ever changes it.
//!
//! Two callers do not have a host OS to appeal to. The wasm entry point
//! analyses whatever the user dropped in, which may be a macOS `.app`, a
//! Windows install directory, or a Linux app tree. A server-side caller — one
//! that unpacks a *distribution artifact* rather than an install, such as the
//! Fleet plugin analysing a released `.app.tar.gz` on a Linux box — is in the
//! same position: the artifact's layout has nothing to do with the machine
//! reading it.
//!
//! So the platform is **ambient state**, on every target: a thread-local the
//! caller sets with [`set_platform`] before analysis runs, alongside the tree
//! it describes. On native it starts at the host OS, which is why the desktop
//! build needs no call at all; in the browser there is no host, so it starts at
//! [`Platform::Macos`] and the entry point states the layout it inferred.
//!
//! Thread-local rather than global because two analyses of different platforms
//! may be in flight at once in a server, and a process-wide switch would let
//! one reinterpret the other's tree halfway through. The corollary is the one
//! rule callers have to keep: **set it on the thread that runs the analysis**.
//! Work moved to a pool (`spawn_blocking`, a rayon fan-out) lands on a thread
//! that still answers with the default, so state it inside that closure —
//! [`with_platform`] does exactly that and puts the previous value back.

/// The application-layout convention the analysis crates should follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// `.app` directory: `Contents/{MacOS,Frameworks,Resources}` + `Info.plist`.
    Macos,
    /// Install directory: `.exe` + sibling `.dll`s + `resources/`.
    Windows,
    /// App directory: ELF binary + sibling `.so`s + `resources/`.
    Linux,
}

impl Platform {
    /// True for the macOS `.app` bundle layout, false for the "executable plus
    /// sibling files" layout Windows and Linux share. The single question most
    /// layout probes actually ask.
    pub const fn is_bundle(self) -> bool {
        matches!(self, Platform::Macos)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Macos => "macos",
            Platform::Windows => "windows",
            Platform::Linux => "linux",
        }
    }

    /// Parse a platform name (`"macos"` / `"windows"` / `"linux"`), as passed
    /// across the JS boundary. Case-insensitive; `None` if unrecognised.
    pub fn parse(name: &str) -> Option<Platform> {
        match name.trim().to_ascii_lowercase().as_str() {
            "macos" | "mac" | "osx" | "darwin" => Some(Platform::Macos),
            "windows" | "win" | "win32" => Some(Platform::Windows),
            "linux" => Some(Platform::Linux),
            _ => None,
        }
    }
}

/// The layout of applications installed on *this* machine. Other unixes
/// analyse like Linux — an ELF binary plus sibling shared objects — which is
/// what the portable path already assumed.
///
/// A compile-time constant, and the value [`platform`] starts at on native.
/// On wasm there is no host to speak of; it answers [`Platform::Macos`] there
/// only so the constant is total, and nothing should read it.
pub const fn host_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_arch = "wasm32") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

/// What [`platform`] answers until [`set_platform`] says otherwise.
///
/// The host OS on native, because the desktop scan is the case that must need
/// no ceremony. [`Platform::Macos`] on wasm, where "the host" is a browser and
/// the entry point always states the layout it inferred from the upload.
const DEFAULT: Platform = if cfg!(target_arch = "wasm32") {
    Platform::Macos
} else {
    host_platform()
};

thread_local! {
    static PLATFORM: std::cell::Cell<Platform> = const { std::cell::Cell::new(DEFAULT) };
}

/// The layout the analysis on this thread should assume.
pub fn platform() -> Platform {
    PLATFORM.with(std::cell::Cell::get)
}

/// Declare the layout of the tree about to be analysed on this thread.
///
/// Set this *before* running detection, next to the tree it describes — which
/// on wasm is [`set_ambient`](crate::set_ambient), and on native is whatever
/// directory the caller unpacked. Prefer [`with_platform`], which cannot leave
/// the thread on someone else's layout.
pub fn set_platform(platform: Platform) {
    PLATFORM.with(|p| p.set(platform));
}

/// Put the thread back on its default layout: the host OS on native, the
/// browser's starting assumption on wasm.
pub fn reset_platform() {
    set_platform(DEFAULT);
}

/// Run `f` with the analysis reading `platform`'s layout, then restore what was
/// there before.
///
/// The scoped form exists because the failure mode of the bare setter is
/// silent: a thread left on `Windows` reads the *next* tree it is handed as a
/// Windows install, and reports a macOS bundle as an app with no executable
/// rather than as an error. Restoring on the way out — including when `f`
/// panics, since the guard's `Drop` runs while unwinding — makes a pooled
/// thread safe to hand back.
pub fn with_platform<T>(platform: Platform, f: impl FnOnce() -> T) -> T {
    struct Restore(Platform);
    impl Drop for Restore {
        fn drop(&mut self) {
            set_platform(self.0);
        }
    }

    let _restore = Restore(self::platform());
    set_platform(platform);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_starts_on_the_default_layout() {
        assert_eq!(platform(), DEFAULT);
    }

    #[test]
    fn the_layout_can_be_stated_and_reset() {
        set_platform(Platform::Windows);
        assert_eq!(platform(), Platform::Windows);

        reset_platform();
        assert_eq!(platform(), DEFAULT);
    }

    /// Two analyses of different platforms may be in flight at once, so one
    /// thread's answer must not be another's.
    #[test]
    fn the_layout_is_per_thread() {
        set_platform(Platform::Windows);

        let elsewhere = std::thread::spawn(|| {
            let before = platform();
            set_platform(Platform::Linux);
            (before, platform())
        })
        .join()
        .unwrap();

        assert_eq!(elsewhere, (DEFAULT, Platform::Linux));
        assert_eq!(platform(), Platform::Windows, "the other thread's set leaked");
        reset_platform();
    }

    #[test]
    fn the_scoped_form_restores_what_was_there() {
        set_platform(Platform::Linux);

        let inside = with_platform(Platform::Macos, platform);

        assert_eq!(inside, Platform::Macos);
        assert_eq!(platform(), Platform::Linux);
        reset_platform();
    }

    /// A pooled thread is handed back after a panic too, so the restore has to
    /// happen while unwinding rather than on the way out of the call.
    #[test]
    fn the_scoped_form_restores_after_a_panic() {
        set_platform(Platform::Linux);

        let panicked = std::panic::catch_unwind(|| {
            with_platform(Platform::Windows, || panic!("analysis blew up"));
        });

        assert!(panicked.is_err());
        assert_eq!(platform(), Platform::Linux);
        reset_platform();
    }

    #[test]
    fn platform_names_round_trip() {
        for platform in [Platform::Macos, Platform::Windows, Platform::Linux] {
            assert_eq!(Platform::parse(platform.as_str()), Some(platform));
        }
        assert_eq!(Platform::parse("  DARWIN "), Some(Platform::Macos));
        assert_eq!(Platform::parse("plan9"), None);
    }
}
