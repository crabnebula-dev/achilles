// Host seam: the one module that reads `window.__TAURI__`. Everything else
// imports the Tauri-shaped services from here, so the app code stays host
// agnostic (desktop Tauri today, browser via the shim, a mobile shell later).
//
// The shim import comes first: in the browser it installs `window.__TAURI__`
// synchronously during evaluation; under desktop Tauri it is a no-op. The
// module registry evaluates it once even though index.html also loads it via
// a script tag.
import "./tauri-shim.js";

const t = window.__TAURI__;

export const { invoke, Channel } = t.core;
export const { listen } = t.event;
export const { save } = t.dialog;
export const { writeTextFile } = t.fs;
// The web shim stubs these ({ check: async () => null } / no-op relaunch).
export const updater = t.updater;
export const { relaunch } = t.process;

/** The current window, or null where there is no window chrome (browser). */
export function appWindow() {
  return t.window?.getCurrentWindow?.() ?? null;
}

/** What the host can do — components render against this, not the host name. */
export const capabilities = {
  windowChrome: Boolean(t.window?.getCurrentWindow),
  updater: Boolean(t.updater?.check),
};
