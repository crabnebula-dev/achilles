// Achilles frontend — vanilla ES modules, no bundler.
//
// Flow:
//   1. On boot, invoke `scan` which kicks off a background walk of
//      /Applications and emits `scan_event` per bundle.
//   2. Render rows as events arrive.
//   3. Click a row → invoke `audit` + `cve_lookup`, show the detail panel.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const tbody = document.querySelector("#apps tbody");
const statusEl = document.querySelector("#status");
const rescanBtn = document.querySelector("#rescan");
const detailPanel = document.querySelector("#detail-panel");
const detailName = document.querySelector("#detail-name");
const detailBody = document.querySelector("#detail-body");
const closeDetailBtn = document.querySelector("#close-detail");

/** Map from serialised path → { row, detection } so we can update in place. */
const rows = new Map();

/**
 * Per-app detail payloads we've successfully fetched. Populated opportunistically
 * in openDetail(); used by the "Export JSON" action so a global dump reflects
 * whatever sub-queries have already run. Missing entries = user hasn't opened
 * that row yet.
 */
const detailCache = new Map();

/** The currently-open app, for the per-detail "Export" button. */
let currentDetail = null;

function setStatus(text) {
  statusEl.textContent = text;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[c]);
}

function isStale(framework, versions) {
  // Extremely rough heuristic for now — later replaced by CVE-backed scoring.
  if (framework === "electron") {
    const e = versions.electron;
    if (!e) return "unknown";
    const major = parseInt(e.split(".")[0], 10);
    if (major < 35) return "bad";
    if (major < 40) return "warn";
    return "ok";
  }
  if (framework === "tauri") {
    const t = versions.tauri;
    if (!t) return "unknown";
    const major = parseInt(t.split(".")[0], 10);
    if (major < 1) return "warn";
    return "ok";
  }
  if (framework === "cef") {
    // CEF tracks Chromium major versions; reuse the same cutoff.
    const c = versions.cef;
    if (!c) return "unknown";
    const major = parseInt(c.split(".")[0], 10);
    if (major < 130) return "warn";
    return "ok";
  }
  if (framework === "native" || framework === "unknown") return "ok";
  return "unknown";
}

function renderRow(det) {
  const v = det.versions;
  const name = det.display_name || det.bundle_id || det.path;
  const risk = isStale(det.framework, v);

  const tr = document.createElement("tr");
  tr.dataset.path = det.path;
  tr.innerHTML = `
    <td class="name">${escapeHtml(name)}</td>
    <td><span class="framework-tag ${escapeHtml(det.framework)}">${escapeHtml(det.framework)}</span></td>
    <td class="version">${escapeHtml(v.electron ?? "")}</td>
    <td class="version">${escapeHtml(v.chromium ?? "")}</td>
    <td class="version">${escapeHtml(v.node ?? "")}</td>
    <td class="version">${escapeHtml(v.tauri ?? "")}</td>
    <td class="version">${escapeHtml(v.cef ?? "")}</td>
    <td><span class="risk ${risk}">${risk}</span></td>
  `;
  tr.addEventListener("click", () => openDetail(det));
  return tr;
}

function sortRowsInto(container) {
  const sorted = [...container.children].sort((a, b) => {
    // Group by framework, then name.
    const fa = a.children[1].textContent.trim();
    const fb = b.children[1].textContent.trim();
    if (fa !== fb) return fa.localeCompare(fb);
    return a.children[0].textContent.localeCompare(b.children[0].textContent);
  });
  container.replaceChildren(...sorted);
}

function handleDetection(det) {
  const existing = rows.get(det.path);
  const fresh = renderRow(det);
  if (existing) {
    existing.row.replaceWith(fresh);
  } else {
    tbody.appendChild(fresh);
  }
  rows.set(det.path, { row: fresh, detection: det });
}

async function openDetail(det) {
  document
    .querySelectorAll("#apps tbody tr.selected")
    .forEach((r) => r.classList.remove("selected"));
  rows.get(det.path)?.row.classList.add("selected");

  currentDetail = det;
  detailName.textContent = det.display_name || det.bundle_id || det.path;

  // If we've fetched this app before in this session, render from cache
  // first so the panel never flashes blank.
  const prior = detailCache.get(det.path);
  if (prior && (prior.audit || prior.cves || prior.staticScan || prior.sideeffects)) {
    detailBody.innerHTML = renderDetail(
      det,
      prior.audit,
      prior.cves,
      prior.staticScan,
      prior.depAdvisories,
      prior.savedAtIso,
      prior.sideeffects,
    );
  } else {
    detailBody.innerHTML = `<p style="color:var(--fg-2)">loading audit…</p>`;
  }
  detailPanel.hidden = false;

  try {
    const [audit, cves, staticScan, sideeffects] = await Promise.all([
      invoke("audit", { path: det.path }).catch((e) => ({ error: String(e) })),
      invoke("cve_lookup", { versions: det.versions }).catch((e) => ({
        error: String(e),
      })),
      det.framework === "electron"
        ? invoke("static_scan", { path: det.path }).catch((e) => ({
            error: String(e),
          }))
        : Promise.resolve(null),
      invoke("sideeffects", {
        path: det.path,
        bundleId: det.bundle_id ?? null,
        executable: null,
      }).catch((e) => ({ error: String(e) })),
    ]);

    // Dep advisories need the dep list from static_scan. Kick that off only
    // if we got a sane static_scan payload.
    const deps = staticScan && !staticScan.error ? staticScan.dependencies ?? [] : [];
    const depAdvisoriesPromise = deps.length > 0
      ? invoke("dependency_scan", { deps }).catch((e) => ({ error: String(e) }))
      : Promise.resolve([]);

    const firstRender = renderDetail(det, audit, cves, staticScan, null, null, sideeffects);
    detailBody.innerHTML = firstRender;
    // Cache what we have now so the Export button works immediately.
    detailCache.set(det.path, {
      detection: det,
      audit,
      cves,
      staticScan,
      sideeffects,
      depAdvisories: null,
      savedAtIso: null,
    });

    // Let the caller see the main detail immediately, then fill in the
    // dep-CVE section once OSV responds.
    depAdvisoriesPromise.then(async (depAdvisories) => {
      // Patch the cache regardless; patch the DOM only if the same app is
      // still open (prevents stale results rendering over a newer click).
      const cached = detailCache.get(det.path);
      if (cached) cached.depAdvisories = depAdvisories;

      // Persist the fully-populated detail to the journal. Any failure is
      // non-fatal; we just log it.
      const savedAtIso = await persistToJournal(det, {
        detection: det,
        audit,
        cves,
        staticScan,
        sideeffects,
        depAdvisories,
      });
      if (cached && savedAtIso) cached.savedAtIso = savedAtIso;

      if (!detailPanel.hidden && currentDetail?.path === det.path) {
        detailBody.innerHTML = renderDetail(
          det,
          audit,
          cves,
          staticScan,
          depAdvisories,
          savedAtIso,
          sideeffects,
        );
      }
    });
  } catch (err) {
    detailBody.innerHTML = `<p class="bad">error: ${escapeHtml(err)}</p>`;
  }
}

function yesNo(b, { yesClass = "bad", noClass = "ok", yesText = "yes", noText = "no" } = {}) {
  return b
    ? `<span class="${yesClass}">${yesText}</span>`
    : `<span class="${noClass}">${noText}</span>`;
}

function renderStaticScan(staticScan) {
  if (!staticScan) return "";
  if (staticScan.error) {
    return `<h3>Static analysis</h3><p class="warn">${escapeHtml(staticScan.error)}</p>`;
  }

  const parts = [
    `<h3>Static analysis</h3>`,
    `<dl>
      <dt>input</dt><dd>${escapeHtml(staticScan.input_kind)}</dd>
      <dt>files scanned</dt><dd>${staticScan.files_scanned}</dd>
      <dt>rules run</dt><dd>${staticScan.rules_run}</dd>
      <dt>findings</dt><dd>${staticScan.findings.length}</dd>
    </dl>`,
  ];

  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const sorted = [...staticScan.findings].sort(
    (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9),
  );

  for (const f of sorted) {
    const loc = f.line > 0 ? `${escapeHtml(f.file)}:${f.line}:${f.column}` : escapeHtml(f.file);
    parts.push(`<div class="advisory ${escapeHtml(f.severity)}">
      <strong>${escapeHtml(f.rule_id)}</strong>
      <span class="${escapeHtml(f.severity)}">[${escapeHtml(f.severity)}]</span>
      <span style="color:var(--fg-2)">[${escapeHtml(f.confidence)}]</span>
      ${f.note ? `<em style="color:var(--fg-2)"> — ${escapeHtml(f.note)}</em>` : ""}
      <br><span style="color:var(--fg-2)">${escapeHtml(loc)}</span>
      ${f.sample ? `<pre style="margin:4px 0 0;white-space:pre-wrap;color:var(--fg)">${escapeHtml(f.sample)}</pre>` : ""}
      <br><span style="color:var(--fg-2);font-size:11px">${escapeHtml(f.description)}</span>
    </div>`);
  }

  if (staticScan.errors?.length) {
    parts.push(`<p class="warn">${staticScan.errors.length} parse error(s) during scan</p>`);
  }

  return parts.join("");
}

function renderRuntimeCves(cves) {
  if (!cves) return "";
  if (cves.error) {
    return `<h3>Runtime CVEs</h3><p class="warn">${escapeHtml(cves.error)}</p>`;
  }

  const sources = [
    { key: "electron", label: "Electron" },
    { key: "chromium", label: "Chromium" },
    { key: "node", label: "Node.js" },
    { key: "tauri", label: "Tauri" },
    { key: "flutter", label: "Flutter" },
    { key: "qt", label: "Qt" },
    { key: "nwjs", label: "NW.js" },
    { key: "react_native", label: "React Native" },
    { key: "wails", label: "Wails" },
    { key: "sciter", label: "Sciter" },
    { key: "java", label: "Java / JDK" },
    { key: "webkit", label: "Safari / WKWebView (system)" },
  ];

  const parts = [`<h3>Runtime CVEs</h3>`];
  let anyFound = false;

  for (const { key, label } of sources) {
    const list = cves[key] ?? [];
    if (list.length === 0) continue;
    anyFound = true;
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">${escapeHtml(label)} — ${list.length}</p>`);
    for (const a of list) {
      const sev = (a.severity ?? "").toLowerCase();
      parts.push(`<div class="advisory ${escapeHtml(sev)}">
        <strong>${escapeHtml(a.id)}</strong>
        ${a.severity ? `<span class="${escapeHtml(sev)}">[${escapeHtml(a.severity)}]</span>` : ""}
        ${a.fixed_in ? ` — fixed in <code>${escapeHtml(a.fixed_in)}</code>` : ""}
        <br><span style="color:var(--fg-2)">${escapeHtml(a.summary || "")}</span>
      </div>`);
    }
  }

  if (!anyFound) {
    parts.push(`<p class="ok">No advisories matched for any detected runtime.</p>`);
  }

  if ((cves.errors ?? []).length) {
    parts.push(`<p class="warn" style="margin-top:8px">Source errors: ${escapeHtml(cves.errors.join("; "))}</p>`);
  }
  return parts.join("");
}

function renderDepAdvisories(depAdvisories) {
  if (depAdvisories === null) {
    return `<h3>Dependency CVEs</h3><p style="color:var(--fg-2)">checking OSV…</p>`;
  }
  if (depAdvisories?.error) {
    return `<h3>Dependency CVEs</h3><p class="warn">${escapeHtml(depAdvisories.error)}</p>`;
  }
  if (!Array.isArray(depAdvisories) || depAdvisories.length === 0) {
    return "";
  }

  const hits = depAdvisories.filter((x) => (x.advisories ?? []).length > 0);
  const parts = [`<h3>Dependency CVEs</h3>`];
  parts.push(`<p style="color:var(--fg-2)">${depAdvisories.length} deps checked — ${hits.length} with advisories</p>`);

  if (hits.length === 0) {
    parts.push(`<p class="ok">No advisories from OSV.</p>`);
    return parts.join("");
  }

  for (const entry of hits) {
    parts.push(`<div style="margin:6px 0">
      <strong>${escapeHtml(entry.package.name)}</strong>
      <code style="color:var(--fg-2)">@${escapeHtml(entry.package.version)}</code>
    </div>`);
    for (const a of entry.advisories) {
      const sev = (a.severity ?? "").toLowerCase();
      parts.push(`<div class="advisory ${escapeHtml(sev)}">
        <strong>${escapeHtml(a.id)}</strong>
        ${a.severity ? `<span class="${escapeHtml(sev)}">[${escapeHtml(a.severity)}]</span>` : ""}
        ${a.fixed_in ? ` — fixed in <code>${escapeHtml(a.fixed_in)}</code>` : ""}
        <br><span style="color:var(--fg-2)">${escapeHtml(a.summary || "")}</span>
      </div>`);
    }
  }

  return parts.join("");
}

async function persistToJournal(det, dossier) {
  // Avoid flooding the journal with partial results — only save when we
  // actually have something worth keeping.
  const hasContent =
    (dossier.audit && !dossier.audit.error) ||
    (dossier.cves && !dossier.cves.error) ||
    (dossier.staticScan && !dossier.staticScan.error);
  if (!hasContent) return null;

  try {
    const entry = await invoke("journal_save", {
      args: {
        app_path: det.path,
        display_name: det.display_name ?? null,
        bundle_id: det.bundle_id ?? null,
        payload: dossier,
      },
    });
    return entry?.saved_at_iso ?? null;
  } catch (err) {
    console.warn("journal_save failed", err);
    return null;
  }
}

function formatRelativeTime(iso) {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const delta = Math.max(0, (Date.now() - then) / 1000);
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86_400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86_400)}d ago`;
}

function renderSideEffects(sideeffects) {
  if (!sideeffects) return "";
  if (sideeffects.error) {
    return `<h3>Side effects</h3><p class="warn">${escapeHtml(sideeffects.error)}</p>`;
  }

  const parts = [`<h3>System side effects</h3>`];

  const totalInside =
    (sideeffects.helpers?.length ?? 0) +
    (sideeffects.plugins?.length ?? 0) +
    (sideeffects.xpc_services?.length ?? 0);
  const nmh = sideeffects.native_messaging_hosts ?? [];
  const le = sideeffects.launch_entries ?? [];

  // Quick summary row — "n helpers · m browser bridges · k launch items"
  const summaryBits = [];
  if (totalInside > 0)
    summaryBits.push(`${totalInside} bundled helper/plugin/XPC`);
  if (nmh.length > 0)
    summaryBits.push(`<span class="bad">${nmh.length} browser bridge${nmh.length === 1 ? "" : "s"}</span>`);
  if (le.length > 0)
    summaryBits.push(`<span class="warn">${le.length} launch item${le.length === 1 ? "" : "s"}</span>`);
  if (sideeffects.log_dir)
    summaryBits.push(`log directory present`);

  if (summaryBits.length === 0) {
    parts.push(`<p class="ok">No side effects detected outside the bundle.</p>`);
    return parts.join("");
  }
  parts.push(`<p style="color:var(--fg-2)">${summaryBits.join(" · ")}</p>`);

  const renderHelperList = (label, items) => {
    if (!items || items.length === 0) return "";
    const rows = items
      .map(
        (h) =>
          `<li><code>${escapeHtml(h.name)}</code>${h.is_bundle ? ` <span class="muted">(bundle)</span>` : ""}${h.version ? ` <span class="muted">${escapeHtml(h.version)}</span>` : ""}${h.size_bytes != null ? ` <span class="muted">${formatBytes(h.size_bytes)}</span>` : ""}</li>`,
      )
      .join("");
    return `<p style="margin:8px 0 4px;color:var(--fg-2)">${escapeHtml(label)}</p><ul style="margin:0 0 8px 0;padding-left:18px">${rows}</ul>`;
  };
  parts.push(renderHelperList("Contents/Helpers/", sideeffects.helpers));
  parts.push(renderHelperList("Contents/PlugIns/", sideeffects.plugins));
  parts.push(renderHelperList("Contents/XPCServices/", sideeffects.xpc_services));

  if (nmh.length > 0) {
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">Browser native-messaging bridges (installed silently)</p>`);
    for (const h of nmh) {
      const when = h.modified_at
        ? new Date(h.modified_at * 1000).toISOString()
        : "unknown";
      parts.push(`<div class="advisory bad">
        <strong>${escapeHtml(h.browser)}</strong>
        <span class="muted">${escapeHtml(h.host_name)}</span>
        <br><span class="muted">target:</span> <code>${escapeHtml(h.target_path)}</code>
        <br><span class="muted">allowed origins:</span> ${
          h.allowed_origins.length > 0
            ? h.allowed_origins
                .map((o) => `<code>${escapeHtml(o)}</code>`)
                .join(" ")
            : "(none declared)"
        }
        <br><span class="muted">manifest:</span> <code>${escapeHtml(h.manifest_path)}</code>
        <br><span class="muted">last modified:</span> ${escapeHtml(when)}
      </div>`);
    }
  }

  if (le.length > 0) {
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">launchd entries</p>`);
    for (const e of le) {
      parts.push(`<div class="advisory warn">
        <strong>${escapeHtml(e.label ?? "(no Label)")}</strong>
        <span class="muted">[${escapeHtml(e.scope)}]</span>
        ${e.run_at_load ? ` <span class="bad">RunAtLoad</span>` : ""}
        ${e.keep_alive ? ` <span class="bad">KeepAlive</span>` : ""}
        <br><span class="muted">program:</span> <code>${escapeHtml(e.program)}</code>
        <br><span class="muted">plist:</span> <code>${escapeHtml(e.plist_path)}</code>
      </div>`);
    }
  }

  if (sideeffects.log_dir) {
    const l = sideeffects.log_dir;
    const mtime = l.last_modified
      ? new Date(l.last_modified * 1000).toISOString()
      : "unknown";
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">Log directory</p>
      <dl>
        <dt>path</dt><dd><code>${escapeHtml(l.path)}</code></dd>
        <dt>files</dt><dd>${l.file_count} (${formatBytes(l.total_bytes)})</dd>
        <dt>last modified</dt><dd>${escapeHtml(mtime)}</dd>
      </dl>`);
  }

  return parts.join("");
}

function formatBytes(n) {
  if (n == null) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function renderDetail(det, audit, cves, staticScan, depAdvisories, savedAtIso, sideeffects) {
  const v = det.versions;
  const parts = [];

  if (savedAtIso) {
    parts.push(`<p style="margin:0 0 10px;color:var(--fg-2);font-size:11px">
      fetched <span title="${escapeHtml(savedAtIso)}">${escapeHtml(formatRelativeTime(savedAtIso))}</span>
      · <span>${escapeHtml(savedAtIso)}</span> · saved to journal
    </p>`);
  }

  parts.push(`<h3>Runtime</h3>`);

  // Only emit rows for fields that were actually populated — keeps the
  // panel compact when an app only uses one runtime.
  const versionRows = [
    ["electron", v.electron],
    ["chromium", v.chromium],
    ["node", v.node],
    ["tauri", v.tauri],
    ["cef", v.cef],
    ["nwjs", v.nwjs],
    ["flutter", v.flutter],
    ["qt", v.qt],
    ["react native", v.react_native],
    ["wails", v.wails],
    ["sciter", v.sciter],
    ["java", v.java],
    ["webkit (system)", v.webkit],
  ]
    .filter(([, val]) => val != null)
    .map(([k, val]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(val)}</dd>`)
    .join("");

  parts.push(`<dl>
    <dt>framework</dt><dd>${escapeHtml(det.framework)} (confidence: ${escapeHtml(det.confidence)})</dd>
    <dt>bundle id</dt><dd>${escapeHtml(det.bundle_id ?? "—")}</dd>
    <dt>bundle version</dt><dd>${escapeHtml(det.bundle_version ?? "—")}</dd>
    ${versionRows}
  </dl>`);

  if (audit && !audit.error) {
    const e = audit.entitlements;
    const ip = audit.info_plist;
    const cs = audit.code_signature;

    parts.push(`<h3>Code signature</h3>`);
    parts.push(`<dl>
      <dt>signed</dt><dd>${yesNo(cs.signed, { yesClass: "ok", noClass: "bad", yesText: "yes", noText: "no" })}</dd>
      <dt>hardened runtime</dt><dd>${yesNo(cs.hardened_runtime, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
      <dt>notarized</dt><dd>${yesNo(cs.notarized, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
      <dt>team id</dt><dd>${escapeHtml(cs.team_identifier ?? "—")}</dd>
    </dl>`);

    parts.push(`<h3>Hardened-runtime entitlements</h3>`);
    parts.push(`<dl>
      <dt>allow-jit</dt><dd>${yesNo(e.allow_jit, { yesClass: "warn", yesText: "yes", noText: "no" })}</dd>
      <dt>allow-unsigned-executable-memory</dt><dd>${yesNo(e.allow_unsigned_executable_memory)}</dd>
      <dt>disable-executable-page-protection</dt><dd>${yesNo(e.disable_executable_page_protection)}</dd>
      <dt>allow-dyld-environment-variables</dt><dd>${yesNo(e.allow_dyld_environment_variables)}</dd>
      <dt>disable-library-validation</dt><dd>${yesNo(e.disable_library_validation)}</dd>
      <dt>get-task-allow (debug)</dt><dd>${yesNo(e.get_task_allow)}</dd>
    </dl>`);

    parts.push(`<h3>Info.plist hardening</h3>`);
    parts.push(`<dl>
      <dt>allows arbitrary loads</dt><dd>${yesNo(ip.allows_arbitrary_loads)}</dd>
      <dt>url schemes</dt><dd>${ip.url_schemes.length ? ip.url_schemes.map(escapeHtml).join(", ") : "—"}</dd>
      <dt>TLS exceptions</dt><dd>${ip.tls_exceptions.length ? ip.tls_exceptions.map((t) => `${escapeHtml(t.domain)} (insecure HTTP: ${yesNo(t.allows_insecure_http)}, min TLS ${escapeHtml(t.minimum_tls_version ?? "default")})`).join("<br>") : "—"}</dd>
    </dl>`);

    if (audit.asar_integrity) {
      parts.push(`<h3>ASAR integrity</h3>`);
      for (const entry of audit.asar_integrity) {
        parts.push(`<dl>
          <dt>archive</dt><dd>${escapeHtml(entry.archive_key)}</dd>
          <dt>declared</dt><dd>${escapeHtml(entry.declared_hash)}</dd>
          <dt>actual</dt><dd>${escapeHtml(entry.actual_hash ?? "—")}</dd>
          <dt>matches</dt><dd>${yesNo(entry.matches, { yesClass: "ok", noClass: "bad", yesText: "yes", noText: "no" })}</dd>
        </dl>`);
      }
    }
  } else if (audit?.error) {
    parts.push(`<h3>Audit</h3><p class="bad">${escapeHtml(audit.error)}</p>`);
  }

  const runtimeCveParts = renderRuntimeCves(cves);
  if (runtimeCveParts) parts.push(runtimeCveParts);

  const depParts = renderDepAdvisories(depAdvisories);
  if (depParts) parts.push(depParts);

  const staticParts = renderStaticScan(staticScan);
  if (staticParts) parts.push(staticParts);

  const sideParts = renderSideEffects(sideeffects);
  if (sideParts) parts.push(sideParts);

  return parts.join("");
}

closeDetailBtn.addEventListener("click", () => {
  detailPanel.hidden = true;
  currentDetail = null;
  document
    .querySelectorAll("#apps tbody tr.selected")
    .forEach((r) => r.classList.remove("selected"));
});

// ---------- JSON export ----------

/**
 * One entry in an exported document. Any of `audit` / `cves` / `staticScan` /
 * `depAdvisories` may be `null` if the user hasn't opened that app's detail
 * pane yet (we never speculate — only dump what's actually been fetched).
 */
function buildExportEntry(detection) {
  const cached = detailCache.get(detection.path);
  return {
    detection,
    audit: cached?.audit ?? null,
    cves: cached?.cves ?? null,
    staticScan: cached?.staticScan ?? null,
    sideeffects: cached?.sideeffects ?? null,
    depAdvisories: cached?.depAdvisories ?? null,
  };
}

function buildExportDocument(entries) {
  return {
    schema: 1,
    tool: "achilles",
    generatedAt: new Date().toISOString(),
    entryCount: entries.length,
    entries,
  };
}

function slugify(s) {
  return (s ?? "app")
    .toString()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .slice(0, 60) || "app";
}

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "Z");
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke on the next tick to let the browser start the download first.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function exportAll() {
  const entries = [...rows.values()].map((r) => buildExportEntry(r.detection));
  const fetchedCount = entries.filter(
    (e) =>
      e.audit !== null ||
      e.cves !== null ||
      e.staticScan !== null ||
      e.sideeffects !== null,
  ).length;
  const doc = buildExportDocument(entries);
  downloadJson(`achilles-${isoStamp()}.json`, doc);
  setStatus(
    `exported ${entries.length} apps (${fetchedCount} with full detail)`,
  );
}

function exportDetail() {
  if (!currentDetail) return;
  const entry = buildExportEntry(currentDetail);
  const doc = buildExportDocument([entry]);
  const slug = slugify(
    currentDetail.display_name || currentDetail.bundle_id || "app",
  );
  downloadJson(`achilles-${slug}-${isoStamp()}.json`, doc);
}

document.querySelector("#export-all").addEventListener("click", exportAll);
document.querySelector("#export-detail").addEventListener("click", exportDetail);

rescanBtn.addEventListener("click", () => {
  rows.clear();
  tbody.replaceChildren();
  detailPanel.hidden = true;
  startScan();
});

// ---------- settings dialog ----------
const settingsBtn = document.querySelector("#settings");
const settingsDialog = document.querySelector("#settings-dialog");
const settingsForm = document.querySelector("#settings-form");
const settingsPathEl = document.querySelector("#settings-path");
const settingsCloseBtn = document.querySelector("#settings-close");
const settingsCancelBtn = document.querySelector("#settings-cancel");

function formToSettings() {
  const fd = new FormData(settingsForm);
  const trimOrNull = (v) => {
    const t = (v ?? "").toString().trim();
    return t === "" ? null : t;
  };
  const maxAgeRaw = (fd.get("max_age_years") ?? "").toString().trim();
  const maxAgeParsed = maxAgeRaw === "" ? 5 : parseInt(maxAgeRaw, 10);
  const maxAge = Number.isFinite(maxAgeParsed) && maxAgeParsed > 0
    ? maxAgeParsed
    : null; // 0 or NaN → no filter
  return {
    sources: {
      osv: { enabled: fd.has("osv") },
      nvd: {
        enabled: fd.has("nvd"),
        api_key: trimOrNull(fd.get("nvd_api_key")),
      },
      euvd: { enabled: fd.has("euvd") },
      ghsa: {
        enabled: fd.has("ghsa"),
        token: trimOrNull(fd.get("ghsa_token")),
      },
    },
    filters: { max_age_years: maxAge },
  };
}

function applySettingsToForm(s) {
  const src = s?.sources ?? {};
  settingsForm.elements["osv"].checked = src.osv?.enabled ?? true;
  settingsForm.elements["nvd"].checked = src.nvd?.enabled ?? true;
  settingsForm.elements["nvd_api_key"].value = src.nvd?.api_key ?? "";
  settingsForm.elements["euvd"].checked = src.euvd?.enabled ?? false;
  settingsForm.elements["ghsa"].checked = src.ghsa?.enabled ?? false;
  settingsForm.elements["ghsa_token"].value = src.ghsa?.token ?? "";
  const age = s?.filters?.max_age_years;
  settingsForm.elements["max_age_years"].value =
    age == null ? "0" : String(age);
}

async function openSettings() {
  try {
    const [settings, path] = await Promise.all([
      invoke("get_settings"),
      invoke("settings_path").catch(() => null),
    ]);
    applySettingsToForm(settings);
    settingsPathEl.textContent = path ? `stored at: ${path}` : "";
    if (typeof settingsDialog.showModal === "function") {
      settingsDialog.showModal();
    } else {
      settingsDialog.setAttribute("open", "");
    }
  } catch (err) {
    alert(`Couldn't load settings: ${err}`);
  }
}

function closeSettings() {
  if (typeof settingsDialog.close === "function" && settingsDialog.open) {
    settingsDialog.close();
  } else {
    settingsDialog.removeAttribute("open");
  }
}

settingsBtn.addEventListener("click", openSettings);
settingsCloseBtn.addEventListener("click", closeSettings);
settingsCancelBtn.addEventListener("click", (e) => {
  e.preventDefault();
  closeSettings();
});

settingsForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const settings = formToSettings();
  try {
    await invoke("set_settings", { settings });
    closeSettings();
    setStatus("settings saved");
  } catch (err) {
    alert(`Save failed: ${err}`);
  }
});

let seenCount = 0;
let expectedTotal = 0;

listen("scan_event", ({ payload }) => {
  switch (payload.event) {
    case "started":
      expectedTotal = payload.total;
      setStatus(`scanning ${payload.total}…`);
      break;
    case "detected":
      seenCount++;
      handleDetection(payload);
      setStatus(`${seenCount}/${expectedTotal}`);
      sortRowsInto(tbody);
      break;
    case "error":
      console.warn("scan error", payload);
      seenCount++;
      setStatus(`${seenCount}/${expectedTotal} (errors present — see console)`);
      break;
    case "finished":
      setStatus(`done: ${payload.count} bundles`);
      sortRowsInto(tbody);
      break;
  }
});

// ---------- zoom shortcuts (Cmd+= / Cmd+- / Cmd+0) ----------
// Session-only for now — no persistence. Tauri's WebviewWindow::set_zoom
// handles pixel alignment natively; we just track the current factor here
// so the keystrokes stay snappy and we can clamp.
const ZOOM_MIN = 0.5;
const ZOOM_MAX = 3.0;
const ZOOM_STEP = 0.1;
let currentZoom = 1.0;

function clampZoom(n) {
  return Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, Math.round(n * 100) / 100));
}

async function setZoom(factor) {
  const next = clampZoom(factor);
  if (Math.abs(next - currentZoom) < 1e-6) return;
  currentZoom = next;
  try {
    await invoke("set_zoom", { factor: next });
  } catch (err) {
    console.warn("set_zoom failed", err);
    return;
  }
  setStatus(`zoom ${Math.round(next * 100)}%`);
}

document.addEventListener("keydown", (e) => {
  // Only respond to Cmd on macOS (metaKey); ignore on any non-apple platform
  // by falling through when the webview's window doesn't report metaKey.
  if (!e.metaKey) return;

  // Keyboard `key` for shift+'=' is '+' on US layout; accept both.
  if (e.key === "=" || e.key === "+") {
    e.preventDefault();
    void setZoom(currentZoom + ZOOM_STEP);
  } else if (e.key === "-" || e.key === "_") {
    e.preventDefault();
    void setZoom(currentZoom - ZOOM_STEP);
  } else if (e.key === "0") {
    e.preventDefault();
    void setZoom(1.0);
  }
});

async function startScan() {
  seenCount = 0;
  expectedTotal = 0;
  setStatus("discovering…");
  try {
    await invoke("scan");
  } catch (err) {
    setStatus(`scan failed: ${err}`);
  }
}

startScan();
