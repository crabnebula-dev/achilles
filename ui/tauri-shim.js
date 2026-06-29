// Web/WASM adapter for the Achilles UI.
//
// The desktop build runs under Tauri, which injects `window.__TAURI__` and
// services the `invoke(...)` calls in Rust. In the browser there is no Tauri,
// so this module installs a `window.__TAURI__` shim that routes the same calls
// into the `achilles-wasm` module instead — letting `main.js` run unchanged.
//
// Loaded as a module *before* `main.js`. It installs `window.__TAURI__`
// SYNCHRONOUSLY (so main.js's top-level destructure of `window.__TAURI__.core`
// succeeds) and loads the wasm in the background; `invoke` awaits a `ready`
// promise before touching it. (A top-level `await` here would not work: the
// browser runs the next module script, main.js, during the suspension.)
//
// On the desktop build this detects real Tauri and does nothing — it never
// even fetches the wasm — so the same `index.html` serves both targets.

if (!window.__TAURI_INTERNALS__ && !window.__TAURI__) {
  installWebShim();
}

function installWebShim() {
  // `wasm` is filled in once the module loads; `ready` gates anything that
  // needs it. main.js can destructure `window.__TAURI__` immediately because
  // we assign it synchronously at the end of this function.
  let wasm = null;
  let markReady;
  const ready = new Promise((resolve) => (markReady = resolve));

  // ---- per-app analysis cache -------------------------------------------
  // `analyze_app` / `Analyzer.finish()` return { detection, audit, staticScan }
  // in one pass, but the UI asks for `audit` / `static_scan` separately per
  // row. Cache each app's result and serve the slices from it.
  const analyzed = new Map(); // detection.path -> { detection, audit, staticScan }
  const rootToPath = new Map(); // detection.root -> detection.path

  function cacheResult(result, fallbackName) {
    let det = result?.detection;
    if (!det?.path) {
      // A bare `app.asar` has no bundle, so detection is null. Synthesize a
      // minimal Electron detection (an .asar is Electron-specific) so its
      // static-scan + dependency results still get a row to live under —
      // otherwise the scan runs but nothing shows in the UI.
      if (!result?.staticScan) return null; // genuinely nothing to show
      const name = fallbackName || "app.asar";
      det = {
        path: name,
        root: name,
        name,
        framework: "electron", // makes the UI run static_scan for this row
        confidence: "low", // inferred from the .asar, not a full bundle detection
        versions: {},
        bundle_id: null,
        executable: null,
      };
      result.detection = det;
    }
    analyzed.set(det.path, result);
    if (det.root) rootToPath.set(det.root, det.path);
    return det;
  }

  // ---- event bus (Tauri `listen` / emit) --------------------------------
  const listeners = new Map(); // event name -> Set<handler>
  function listen(event, handler) {
    let set = listeners.get(event);
    if (!set) listeners.set(event, (set = new Set()));
    set.add(handler);
    return Promise.resolve(() => set.delete(handler));
  }
  function emit(event, payload) {
    for (const h of listeners.get(event) ?? []) {
      try {
        h({ payload });
      } catch (e) {
        console.error("listener error", e);
      }
    }
  }

  // ---- Tauri `Channel` (cve_lookup streaming) ---------------------------
  class Channel {
    onmessage = () => {};
    // The Rust side calls this with each progressively-complete snapshot.
    _send(msg) {
      try {
        this.onmessage(msg);
      } catch (e) {
        console.error("channel onmessage error", e);
      }
    }
  }

  // ---- settings (localStorage; lookups still use OSV+EUVD on the web) ----
  const SETTINGS_KEY = "achilles.settings";
  function defaultSettings() {
    return {
      sources: {
        osv: { enabled: true },
        // NVD/GHSA can't run from the browser (CORS + client-side secrets).
        nvd: { enabled: false, api_key: null },
        euvd: { enabled: true },
        ghsa: { enabled: false, token: null },
      },
      filters: { max_age_years: 5 },
    };
  }
  function loadSettings() {
    try {
      return JSON.parse(localStorage.getItem(SETTINGS_KEY)) ?? defaultSettings();
    } catch {
      return defaultSettings();
    }
  }
  function saveSettings(s) {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
    } catch {
      /* private mode / disabled storage — ignore */
    }
  }

  // ---- the `invoke` surface ---------------------------------------------
  async function invoke(cmd, args = {}) {
    await ready; // wasm is loaded asynchronously; never touch it before it's up
    switch (cmd) {
      case "scan":
        return webScan();
      case "discover":
        return [];
      case "detect_one":
        return analyzed.get(args.path)?.detection ?? null;
      case "audit":
        return analyzed.get(args.path)?.audit ?? { error: "not analysed" };
      case "static_scan": {
        const path = rootToPath.get(args.root);
        return analyzed.get(path)?.staticScan ?? null;
      }
      // Side-effects live on the host filesystem, not in a user-provided bundle.
      case "sideeffects":
        return null;
      case "cve_lookup": {
        const ch = args.onUpdate;
        const onUpdate =
          ch && typeof ch._send === "function"
            ? (snap) => ch._send(JSON.parse(snap))
            : null;
        const json = await wasm.cve_lookup(
          JSON.stringify(args.versions ?? {}),
          onUpdate,
        );
        return JSON.parse(json);
      }
      case "dependency_scan": {
        const json = await wasm.dependency_scan(JSON.stringify(args.deps ?? []));
        return JSON.parse(json);
      }
      case "get_settings":
        return loadSettings();
      case "set_settings":
        saveSettings(args.settings);
        return;
      case "settings_path":
        return null;
      // Journaling is host-side persistence; not wired up in the browser yet.
      case "journal_save":
        return null;
      case "journal_latest":
        return null;
      case "journal_list":
        return [];
      case "journal_path":
        return null;
      case "set_zoom":
        document.body.style.zoom = String(args.factor ?? 1);
        return;
      default:
        console.warn("achilles web shim: unhandled invoke", cmd, args);
        return null;
    }
  }

  // ---- scanning: File System Access (Chromium) or a selected file (any browser) --

  function setStatus(text) {
    const el = document.querySelector("#status");
    if (el) el.textContent = text;
  }

  // `scan` is fired both on boot (no user gesture) and from the Rescan button
  // (a gesture). `showDirectoryPicker` needs transient activation, so only open
  // it when a gesture is active; otherwise just prompt.
  async function webScan() {
    if (window.showDirectoryPicker && navigator.userActivation?.isActive) {
      try {
        await scanViaDirectoryPicker();
      } catch (e) {
        if (e?.name !== "AbortError") {
          console.warn("folder scan failed", e);
          setStatus(`scan failed: ${e}`);
        }
      }
      return;
    }
    setStatus(
      window.showDirectoryPicker
        ? "Click ‘Scan folder’ to choose a directory, or ‘Select file’ for a .app / .asar."
        : "Click ‘Select file’ to choose a .app (zipped) or app.asar — your browser has no folder picker.",
    );
  }

  async function scanViaDirectoryPicker() {
    await ready;
    const dir = await window.showDirectoryPicker({ mode: "read" });

    // Either the picked directory *is* a `.app`, or it contains `.app`s.
    let apps;
    if (dir.name.endsWith(".app")) {
      apps = [dir];
    } else {
      apps = [];
      for await (const [name, handle] of dir.entries()) {
        if (handle.kind === "directory" && name.endsWith(".app")) apps.push(handle);
      }
    }

    if (apps.length === 0) {
      setStatus(`No .app bundles found in ${dir.name}.`);
    }
    emit("scan_event", { event: "started", total: apps.length });
    let count = 0;
    for (const appHandle of apps) {
      try {
        const root = `/scan/${appHandle.name}`;
        const analyzer = new wasm.Analyzer(root);
        await addDirToAnalyzer(appHandle, root, analyzer);
        const result = JSON.parse(analyzer.finish());
        const det = cacheResult(result, appHandle.name);
        if (det) emit("scan_event", { event: "detected", ...det });
        count++;
      } catch (e) {
        console.warn("failed to analyse", appHandle.name, e);
        emit("scan_event", { event: "error", message: String(e) });
      }
    }
    emit("scan_event", { event: "finished", count });
  }

  // Recursively read every file of one `.app` into the streaming Analyzer.
  async function addDirToAnalyzer(dirHandle, basePath, analyzer) {
    for await (const [name, handle] of dirHandle.entries()) {
      const path = `${basePath}/${name}`;
      if (handle.kind === "directory") {
        await addDirToAnalyzer(handle, path, analyzer);
      } else {
        const file = await handle.getFile();
        analyzer.add_file(path, new Uint8Array(await file.arrayBuffer()));
      }
    }
  }

  async function scanViaFile(file) {
    await ready;
    setStatus(`analysing ${file.name}…`);
    emit("scan_event", { event: "started", total: 1 });
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = JSON.parse(wasm.analyze_app(bytes, file.name));
      const det = cacheResult(result, file.name);
      if (det) emit("scan_event", { event: "detected", ...det });
      emit("scan_event", { event: "finished", count: 1 });
    } catch (e) {
      console.warn("failed to analyse file", e);
      emit("scan_event", { event: "error", message: String(e) });
      emit("scan_event", { event: "finished", count: 0 });
    }
  }

  // ---- inject the web-only scan controls into the header ----------------
  function injectControls() {
    const header = document.querySelector("header");
    if (!header) return;
    const anchor = document.querySelector("#rescan") ?? header.lastElementChild;

    if (window.showDirectoryPicker) {
      const scanBtn = document.createElement("button");
      scanBtn.type = "button";
      scanBtn.textContent = "Scan folder";
      scanBtn.title = "Pick a folder (e.g. /Applications) and scan the .app bundles in it";
      scanBtn.addEventListener("click", () => {
        void scanViaDirectoryPicker().catch((e) => {
          if (e?.name !== "AbortError") setStatus(`scan failed: ${e}`);
        });
      });
      header.insertBefore(scanBtn, anchor);
    }

    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.accept = ".zip,.asar,application/zip";
    fileInput.style.display = "none";
    fileInput.id = "achilles-file-input";
    fileInput.addEventListener("change", () => {
      const file = fileInput.files?.[0];
      if (file) void scanViaFile(file);
      fileInput.value = "";
    });
    const selectBtn = document.createElement("button");
    selectBtn.type = "button";
    selectBtn.textContent = "Select file";
    selectBtn.title = "Select a .app (zipped) or a bare app.asar";
    selectBtn.addEventListener("click", () => fileInput.click());
    header.insertBefore(selectBtn, anchor);
    header.appendChild(fileInput);
  }

  // ---- export: native save-dialog + writeTextFile → Blob download -------
  let pendingName = "achilles-export.json";
  async function save(opts) {
    pendingName = opts?.defaultPath || pendingName;
    return pendingName; // non-null so main.js proceeds to writeTextFile
  }
  async function writeTextFile(path, contents) {
    const blob = new Blob([contents], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = path || pendingName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---- install the shim SYNCHRONOUSLY (before main.js evaluates) --------
  window.__TAURI__ = {
    core: { invoke, Channel },
    event: { listen },
    dialog: { save },
    fs: { writeTextFile },
    // The updater/process plugins don't exist on the web; stub the bits the UI
    // touches so `updater?.check` and friends no-op cleanly.
    updater: { check: async () => null },
    process: { relaunch: async () => {} },
  };

  // ---- load the wasm in the background, then enable scanning ------------
  (async () => {
    try {
      const mod = await import("./pkg/achilles_wasm.js");
      await mod.default();
      wasm = mod;
      markReady();
      const inject = () => injectControls();
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", inject, { once: true });
      } else {
        inject();
      }
    } catch (e) {
      console.error("achilles web shim: failed to load wasm", e);
      setStatus(`failed to load analysis engine: ${e}`);
    }
  })();
}
