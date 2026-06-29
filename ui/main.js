// Achilles frontend — vanilla ES modules, no bundler.
//
// Flow:
//   1. On boot, invoke `scan` which kicks off background discovery of
//      installed GUI apps (per-OS) and emits `scan_event` per app.
//   2. Render rows as events arrive.
//   3. Click a row → invoke `audit` + `cve_lookup`, show the detail panel.
1
const { invoke, Channel } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { save } = window.__TAURI__.dialog;
const { writeTextFile } = window.__TAURI__.fs;

const tbody = document.querySelector("#apps tbody");
const theadRow = document.querySelector("#apps thead tr");
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

/** Which CVE tab is showing ("runtime" | "dependencies"). Held here so the
 * choice survives the async repaints that stream CVE data into the panel. */
let activeCveTab = "runtime";

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
  fresh.hidden = !rowMatches(det);
}

// ---------- column filters ----------
// Each column gets a header control: the App column opens a free-text search
// box; the rest open a <select> populated from the distinct values currently
// present in the table. An active filter reveals a "×" to clear it.

const COLUMNS = [
  { key: "name", label: "App", type: "search" },
  { key: "framework", label: "Framework", type: "select" },
  { key: "electron", label: "Electron", type: "select" },
  { key: "chromium", label: "Chromium", type: "select" },
  { key: "node", label: "Node", type: "select" },
  { key: "tauri", label: "Tauri", type: "select" },
  { key: "cef", label: "CEF", type: "select" },
  { key: "risk", label: "Risk", type: "select" },
];

/** Active filters: column key → filter string (substring for search, exact for select). */
const activeFilters = new Map();

/** Header cell handles, keyed by column key, for live state updates. */
const headerCells = new Map();

/** The displayed value for a detection in a given column (matches renderRow). */
function cellValue(det, key) {
  const v = det.versions;
  switch (key) {
    case "name":
      return det.display_name || det.bundle_id || det.path || "";
    case "framework":
      return det.framework || "";
    case "risk":
      return isStale(det.framework, v);
    default:
      return v[key] ?? "";
  }
}

/** Distinct, non-empty values for a column across all known rows, sorted. */
function distinctValues(key) {
  const set = new Set();
  for (const { detection } of rows.values()) {
    const val = cellValue(detection, key);
    if (val !== "" && val != null) set.add(String(val));
  }
  return [...set].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function rowMatches(det) {
  for (const [key, val] of activeFilters) {
    const cell = String(cellValue(det, key) ?? "");
    const col = COLUMNS.find((c) => c.key === key);
    if (col?.type === "search") {
      if (!cell.toLowerCase().includes(val.toLowerCase())) return false;
    } else if (cell !== val) {
      return false;
    }
  }
  return true;
}

function applyFilters() {
  for (const { row, detection } of rows.values()) {
    row.hidden = !rowMatches(detection);
  }
}

function setFilter(key, value) {
  const v = (value ?? "").trim();
  if (v) activeFilters.set(key, v);
  else activeFilters.delete(key);
  updateHeaderState();
  applyFilters();
}

function updateHeaderState() {
  for (const [key, { th, clearBtn }] of headerCells) {
    const active = activeFilters.has(key);
    th.classList.toggle("filtered", active);
    clearBtn.hidden = !active;
  }
}

function closeAllPopovers() {
  for (const { popover } of headerCells.values()) popover.hidden = true;
}

// Anchor the popover just above the trigger button. It's `position: fixed`
// (viewport coordinates) so it can float above the sticky header without being
// clipped by #list-panel's `overflow: auto`.
function positionPopover(popover, anchorBtn) {
  const r = anchorBtn.getBoundingClientRect();
  const pr = popover.getBoundingClientRect();
  const left = Math.max(6, Math.min(r.left, window.innerWidth - pr.width - 6));
  const top = Math.max(6, r.top - pr.height - 4);
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function openPopover(col, popover, anchorBtn) {
  const wasOpen = !popover.hidden;
  closeAllPopovers();
  if (wasOpen) return; // toggle: a second click on the same column closes it

  popover.replaceChildren();
  let field;

  if (col.type === "search") {
    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = "app name…";
    input.value = activeFilters.get(col.key) ?? "";
    input.addEventListener("input", () => setFilter(col.key, input.value));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === "Escape") closeAllPopovers();
    });
    popover.appendChild(input);
    field = input;
  } else {
    const select = document.createElement("select");
    select.appendChild(new Option("(all)", ""));
    for (const val of distinctValues(col.key)) {
      select.appendChild(new Option(val, val));
    }
    select.value = activeFilters.get(col.key) ?? "";
    select.addEventListener("change", () => {
      setFilter(col.key, select.value);
      closeAllPopovers();
    });
    popover.appendChild(select);
    field = select;
  }

  popover.hidden = false;
  positionPopover(popover, anchorBtn);
  field.focus();
}

function buildHeader() {
  theadRow.replaceChildren();
  headerCells.clear();

  for (const col of COLUMNS) {
    const th = document.createElement("th");

    const inner = document.createElement("div");
    inner.className = "th-inner";

    const label = document.createElement("span");
    label.className = "th-label";
    label.textContent = col.label;

    const filterBtn = document.createElement("button");
    filterBtn.type = "button";
    filterBtn.className = "th-filter-btn";
    filterBtn.title = col.type === "search" ? "Search by name" : "Filter";
    filterBtn.textContent = col.type === "search" ? "⌕" : "▾";

    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "th-clear-btn";
    clearBtn.title = "Clear filter";
    clearBtn.textContent = "×";
    clearBtn.hidden = true;

    const popover = document.createElement("div");
    popover.className = "th-popover";
    popover.hidden = true;

    filterBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openPopover(col, popover, filterBtn);
    });
    clearBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      setFilter(col.key, "");
      closeAllPopovers();
    });

    inner.append(label, filterBtn, clearBtn);
    th.append(inner);
    theadRow.appendChild(th);
    // The popover lives on <body>, not inside the th: the sticky header cells
    // each create a `z-index: 1` stacking context, which would otherwise pin
    // the popover beneath the header. As a top-level fixed element it's free to
    // float above everything (positioned by positionPopover()).
    document.body.appendChild(popover);
    headerCells.set(col.key, { th, clearBtn, popover });
  }
}

// Close any open popover when clicking outside it (the trigger/clear buttons
// stop propagation, so their own clicks never reach here).
document.addEventListener("click", (e) => {
  if (!e.target.closest(".th-popover")) closeAllPopovers();
});

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

  // Only repaint the DOM if this same app is still the open one — guards
  // against a slower earlier promise overwriting a newer click.
  const stillOpen = () => !detailPanel.hidden && currentDetail?.path === det.path;

  try {
    // Kick every command off in parallel, but don't await them together: the
    // local audits (audit / static-scan / side-effects) finish in
    // milliseconds, while `cve_lookup` and `dependency_scan` are network-bound
    // (EUVD / OSV / NVD, rate-limited). Paint the local panes first and stream
    // the CVE sections in, so the panel isn't held on the slowest request.
    const auditP = invoke("audit", {
      path: det.path,
      root: det.root,
      executable: det.executable ?? null,
    }).catch((e) => ({ error: String(e) }));
    const staticP =
      det.framework === "electron"
        ? invoke("static_scan", { root: det.root }).catch((e) => ({ error: String(e) }))
        : Promise.resolve(null);
    const sideP = invoke("sideeffects", {
      path: det.path,
      bundleId: det.bundle_id ?? null,
      executable: det.executable ?? null,
    }).catch((e) => ({ error: String(e) }));

    // Single mutable view-state for this pane. Each command writes its own
    // slice as it resolves and repaints independently, so the fast local
    // audits don't wait on the network-bound CVE/dependency lookups. Pending
    // slices render as "loading" placeholders (CVEs / dep advisories) or are
    // simply omitted (audit / static / side-effects) until their data lands.
    const CVES_PENDING = { pending: true };
    const cache = {
      detection: det,
      audit: undefined,
      cves: CVES_PENDING,
      staticScan: undefined,
      sideeffects: undefined,
      depAdvisories: null,
      savedAtIso: null,
    };
    detailCache.set(det.path, cache);

    // Repaint from whatever slices have resolved so far. The stillOpen() guard
    // keeps a slow promise from a previous click out of a newer pane.
    const repaint = () => {
      if (stillOpen()) {
        detailBody.innerHTML = renderDetail(
          det,
          cache.audit,
          cache.cves,
          cache.staticScan,
          cache.depAdvisories,
          cache.savedAtIso,
          cache.sideeffects,
        );
      }
    };

    // First paint — CVEs pending, dep advisories pending, local panes empty.
    repaint();

    auditP.then((audit) => {
      cache.audit = audit;
      repaint();
    });
    sideP.then((sideeffects) => {
      cache.sideeffects = sideeffects;
      repaint();
    });
    // CVE lookups stream in per source over a Channel: each message is a
    // progressively-complete report, so fast sources (EUVD / OSV) paint without
    // waiting on a slow one (e.g. NVD retrying 503s). The resolved promise
    // carries the final, fully-populated report.
    const cveChannel = new Channel();
    cveChannel.onmessage = (snapshot) => {
      cache.cves = snapshot;
      repaint();
    };
    const cvesP = invoke("cve_lookup", {
      versions: det.versions,
      onUpdate: cveChannel,
    }).catch((e) => ({ error: String(e) }));
    cvesP.then((cves) => {
      cache.cves = cves;
      repaint();
    });

    // Dep advisories need the static-scan dep list, so they chain off staticP:
    // paint the static pane as soon as it lands, then kick off the OSV lookup.
    const depAdvisoriesPromise = staticP.then((staticScan) => {
      cache.staticScan = staticScan;
      repaint();
      const deps = staticScan && !staticScan.error ? staticScan.dependencies ?? [] : [];
      return deps.length > 0
        ? invoke("dependency_scan", { deps }).catch((e) => ({ error: String(e) }))
        : [];
    });
    depAdvisoriesPromise.then((depAdvisories) => {
      cache.depAdvisories = depAdvisories;
      repaint();
    });

    // Once every slice has resolved, persist to the journal and stamp the
    // saved time (a final repaint shows the "saved to journal" line).
    const [audit, cves, sideeffects, staticScan, depAdvisories] = await Promise.all([
      auditP,
      cvesP,
      sideP,
      staticP,
      depAdvisoriesPromise,
    ]);
    const savedAtIso = await persistToJournal(det, {
      detection: det,
      audit,
      cves,
      staticScan,
      sideeffects,
      depAdvisories,
    });
    if (savedAtIso) {
      cache.savedAtIso = savedAtIso;
      repaint();
    }
  } catch (err) {
    detailBody.innerHTML = `<p class="bad">error: ${escapeHtml(err)}</p>`;
  }
}

// The web build keeps its EUVD data in a background-updated snapshot. When a
// fresh snapshot lands (see the shim's `euvd_updated` event), re-check the open
// app: if its CVE set actually gained entries, re-render the pane in place —
// keeping expanded advisories open and the scroll position, and flashing the
// newly-added ones. On the desktop build this event never fires.
function cveIds(cves) {
  const ids = new Set();
  if (!cves) return ids;
  for (const [k, v] of Object.entries(cves)) {
    if (k === "errors" || k === "unavailable" || !Array.isArray(v)) continue;
    for (const a of v) if (a?.id) ids.add(a.id);
  }
  return ids;
}

async function refreshOpenDetailCves() {
  if (detailPanel.hidden || !currentDetail) return;
  const det = currentDetail;
  const cache = detailCache.get(det.path);
  if (!cache) return;

  let report;
  try {
    report = await invoke("cve_lookup", { versions: det.versions });
  } catch {
    return; // a failed re-check just leaves the current view in place
  }
  if (detailPanel.hidden || currentDetail?.path !== det.path) return; // navigated away

  const before = cveIds(cache.cves);
  const added = [...cveIds(report)].filter((id) => !before.has(id));
  cache.cves = report; // keep the data fresh regardless
  if (added.length === 0) return; // nothing new for this app — don't disturb it

  const openIds = new Set(
    [...detailBody.querySelectorAll("details.advisory[open]")].map((d) => d.dataset.advisoryId),
  );
  const scroll = detailBody.scrollTop;
  detailBody.innerHTML = renderDetail(
    det,
    cache.audit,
    cache.cves,
    cache.staticScan,
    cache.depAdvisories,
    cache.savedAtIso,
    cache.sideeffects,
  );
  for (const d of detailBody.querySelectorAll("details.advisory")) {
    if (openIds.has(d.dataset.advisoryId)) d.open = true;
    if (added.includes(d.dataset.advisoryId)) d.classList.add("flash-new");
  }
  detailBody.scrollTop = scroll;
}
listen("euvd_updated", () => void refreshOpenDetailCves());

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

// critical → high → medium → low → unrated, so we can sort highest-risk first.
function severityRank(sev) {
  switch ((sev ?? "").toLowerCase()) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}

// Highest severity first; stable for equal severity (preserves source order).
function sortBySeverity(list) {
  return [...list].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

// One advisory, collapsed by default: the summary shows the CVE id (+ severity
// and fix), and the description reveals on expand — these lists get long.
function renderAdvisory(a) {
  const sev = (a.severity ?? "").toLowerCase();
  const badge = a.severity
    ? `<span class="${escapeHtml(sev)}">[${escapeHtml(a.severity)}]</span>`
    : "";
  const fixed = a.fixed_in ? ` — fixed in <code>${escapeHtml(a.fixed_in)}</code>` : "";
  const body = a.summary
    ? escapeHtml(a.summary)
    : `<span class="muted">no description provided</span>`;
  return `<details class="advisory ${escapeHtml(sev)}" data-advisory-id="${escapeHtml(a.id)}">
    <summary><strong>${escapeHtml(a.id)}</strong> ${badge}${fixed}</summary>
    <div class="advisory-body">${body}</div>
  </details>`;
}

// Inner content for the runtime-CVE tab. Returns `null` when there's nothing
// to show at all (no detected runtimes), otherwise `{ count, html }` where
// `count` is the number of advisories (null while pending/errored, so the tab
// label omits a count).
function runtimeCvesContent(cves) {
  if (!cves) return null;
  if (cves.pending) {
    return { count: null, html: `<p style="color:var(--fg-2)">looking up advisories…</p>` };
  }
  if (cves.error) {
    return { count: null, html: `<p class="warn">${escapeHtml(cves.error)}</p>` };
  }

  const sources = [
    { key: "electron", label: "Electron" },
    { key: "chromium", label: "Chromium" },
    { key: "cef", label: "CEF (Chromium)" },
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

  const parts = [];
  let count = 0;

  for (const { key, label } of sources) {
    const list = sortBySeverity(cves[key] ?? []);
    if (list.length === 0) continue;
    count += list.length;
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">${escapeHtml(label)} — ${list.length}</p>`);
    for (const a of list) parts.push(renderAdvisory(a));
  }

  const hasErrors = (cves.errors ?? []).length > 0;
  const unavailable = cves.unavailable ?? [];

  // Only claim "all clear" when every source actually answered. If a lookup
  // failed (NVD 503) or a source was unavailable, count === 0 means "we don't
  // know", not "nothing matched" — the notices below explain it instead.
  if (count === 0 && !hasErrors && unavailable.length === 0) {
    parts.push(`<p class="ok">No advisories matched for any detected runtime.</p>`);
  }

  // Transient unavailability (e.g. NVD rate-limiting) is shown as a concise
  // notice rather than raw error payloads: Chromium advisories come almost
  // entirely from NVD, so a silent failure would read as a clean bill of health.
  if (unavailable.length > 0) {
    // NVD throttles unauthenticated callers hard (5 req/30s); an API key raises
    // it to 50 and is the practical fix when Chromium/Node advisories vanish.
    const nvdHint =
      unavailable.includes("NVD") && !nvdApiKeyConfigured
        ? " Add an NVD API key in Settings to raise the rate limit (5→50 per 30s)."
        : "";
    parts.push(`<p class="warn" style="margin-top:8px">${escapeHtml(unavailable.join(", "))} temporarily unavailable — results may be incomplete.${nvdHint}</p>`);
  }

  if (hasErrors) {
    parts.push(`<p class="warn" style="margin-top:8px">Source errors: ${escapeHtml(cves.errors.join("; "))}</p>`);
  }
  return { count, html: parts.join("") };
}

// Inner content for the dependency-CVE tab. Same `null` / `{ count, html }`
// contract as runtimeCvesContent().
function depCvesContent(depAdvisories) {
  if (depAdvisories === null) {
    return { count: null, html: `<p style="color:var(--fg-2)">checking OSV…</p>` };
  }
  if (depAdvisories?.error) {
    return { count: null, html: `<p class="warn">${escapeHtml(depAdvisories.error)}</p>` };
  }
  if (!Array.isArray(depAdvisories) || depAdvisories.length === 0) {
    return null;
  }

  const hits = depAdvisories.filter((x) => (x.advisories ?? []).length > 0);
  const parts = [
    `<p style="color:var(--fg-2)">${depAdvisories.length} deps checked — ${hits.length} with advisories</p>`,
  ];
  let count = 0;

  if (hits.length === 0) {
    parts.push(`<p class="ok">No advisories from OSV.</p>`);
  } else {
    for (const entry of hits) {
      count += entry.advisories.length;
      parts.push(`<div style="margin:6px 0">
        <strong>${escapeHtml(entry.package.name)}</strong>
        <code style="color:var(--fg-2)">@${escapeHtml(entry.package.version)}</code>
      </div>`);
      for (const a of sortBySeverity(entry.advisories)) parts.push(renderAdvisory(a));
    }
  }

  return { count, html: parts.join("") };
}

// Runtime and dependency CVEs, tabbed. These lists can run to hundreds of
// entries, so we split them across two tabs and only paint one at a time.
// The active tab is held in `activeCveTab` (module-level) so it survives the
// async repaints as CVE/dependency data streams in.
function renderCves(cves, depAdvisories) {
  const tabs = [];
  const runtime = runtimeCvesContent(cves);
  if (runtime) tabs.push({ id: "runtime", label: "Runtime", ...runtime });
  const dep = depCvesContent(depAdvisories);
  if (dep) tabs.push({ id: "dependencies", label: "Dependencies", ...dep });

  if (tabs.length === 0) return "";

  // Fall back to the first available tab if the remembered one isn't present
  // yet (e.g. dependency data hasn't landed).
  let active = activeCveTab;
  if (!tabs.some((t) => t.id === active)) active = tabs[0].id;

  const label = (t) => (t.count == null ? escapeHtml(t.label) : `${escapeHtml(t.label)} (${t.count})`);

  const btns = tabs
    .map(
      (t) =>
        `<button type="button" class="cve-tab${t.id === active ? " active" : ""}" data-cve-tab="${t.id}">${label(t)}</button>`,
    )
    .join("");

  const panels = tabs
    .map(
      (t) =>
        `<div class="cve-panel${t.id === active ? " active" : ""}" data-cve-tab="${t.id}">${t.html}</div>`,
    )
    .join("");

  return `<div class="cve-section">
    <h3>CVEs</h3>
    <div class="cve-tabs">${btns}</div>
    ${panels}
  </div>`;
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

/**
 * Render the platform-tagged audit payload. Returns an array of HTML strings.
 * The `platform` discriminant selects which fields are present.
 */
function renderAudit(audit) {
  switch (audit.platform) {
    case "windows":
      return renderWindowsAudit(audit);
    case "linux":
      return renderLinuxAudit(audit);
    case "macos":
    default:
      return renderMacosAudit(audit);
  }
}

function renderMacosAudit(audit) {
  const parts = [];
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
  return parts;
}

function renderWindowsAudit(audit) {
  const parts = [];
  const sig = audit.signature;
  const h = audit.hardening;
  const m = audit.manifest;

  const trustedDd =
    sig.trusted == null
      ? `<dd class="muted">not evaluated</dd>`
      : `<dd>${yesNo(sig.trusted, { yesClass: "ok", noClass: "bad", yesText: "yes", noText: "no" })}</dd>`;
  parts.push(`<h3>Authenticode signature</h3>`);
  parts.push(`<dl>
    <dt>signed</dt><dd>${yesNo(sig.signed, { yesClass: "ok", noClass: "bad", yesText: "yes", noText: "no" })}</dd>
    <dt>trusted (OS store)</dt>${trustedDd}
    <dt>signer</dt><dd>${escapeHtml(sig.subject ?? "—")}</dd>
    <dt>issuer</dt><dd>${escapeHtml(sig.issuer ?? "—")}</dd>
    ${sig.note ? `<dt>note</dt><dd class="muted">${escapeHtml(sig.note)}</dd>` : ""}
  </dl>`);

  parts.push(`<h3>PE hardening</h3>`);
  parts.push(`<dl>
    <dt>ASLR (DYNAMICBASE)</dt><dd>${yesNo(h.aslr, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>DEP (NXCOMPAT)</dt><dd>${yesNo(h.dep, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>Control Flow Guard</dt><dd>${yesNo(h.cfg, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>high-entropy ASLR</dt><dd>${yesNo(h.high_entropy_va, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
  </dl>`);

  parts.push(`<h3>Manifest</h3>`);
  parts.push(`<dl>
    <dt>requested execution level</dt><dd>${escapeHtml(m.requested_execution_level ?? "—")}</dd>
  </dl>`);

  parts.push(...renderAsarInfo(audit.asar));
  return parts;
}

function renderLinuxAudit(audit) {
  const parts = [];
  const h = audit.hardening;

  parts.push(`<h3>ELF hardening</h3>`);
  parts.push(`<dl>
    <dt>PIE</dt><dd>${yesNo(h.pie, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>RELRO</dt><dd>${escapeHtml(h.relro)}</dd>
    <dt>NX stack</dt><dd>${yesNo(h.nx, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>stack canary</dt><dd>${yesNo(h.stack_canary, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
    <dt>FORTIFY_SOURCE</dt><dd>${yesNo(h.fortify_source, { yesClass: "ok", noClass: "warn", yesText: "yes", noText: "no" })}</dd>
  </dl>`);

  if (audit.sandbox) {
    const s = audit.sandbox;
    parts.push(`<h3>Sandbox (${escapeHtml(s.kind)})</h3>`);
    parts.push(`<dl>
      <dt>permissions</dt><dd>${s.permissions.length ? s.permissions.map((p) => `<code>${escapeHtml(p)}</code>`).join(" ") : "—"}</dd>
    </dl>`);
  }

  parts.push(...renderAsarInfo(audit.asar));
  return parts;
}

/** Informational ASAR hash block for the non-macOS audits. */
function renderAsarInfo(asar) {
  if (!asar) return [];
  return [
    `<h3>ASAR</h3>`,
    `<dl>
      <dt>archive</dt><dd><code>${escapeHtml(asar.archive_path)}</code></dd>
      <dt>header sha-256</dt><dd><code>${escapeHtml(asar.header_sha256 ?? "—")}</code></dd>
    </dl>`,
  ];
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
  parts.push(renderHelperList("Bundled helpers / sibling executables", sideeffects.helpers));
  parts.push(renderHelperList("Plug-ins", sideeffects.plugins));
  parts.push(renderHelperList("XPC services", sideeffects.xpc_services));

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
    parts.push(`<p style="margin:8px 0 4px;color:var(--fg-2)">Auto-start / background entries</p>`);
    for (const e of le) {
      parts.push(`<div class="advisory warn">
        <strong>${escapeHtml(e.label ?? "(unnamed)")}</strong>
        <span class="muted">[${escapeHtml(e.scope)}]</span>
        ${e.run_at_load ? ` <span class="bad">runs at login</span>` : ""}
        ${e.keep_alive ? ` <span class="bad">keep-alive</span>` : ""}
        <br><span class="muted">program:</span> <code>${escapeHtml(e.program)}</code>
        <br><span class="muted">source:</span> <code>${escapeHtml(e.plist_path)}</code>
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
    // The audit payload is platform-tagged (`platform`: macos | windows | linux).
    parts.push(...renderAudit(audit));
  } else if (audit?.error) {
    parts.push(`<h3>Audit</h3><p class="bad">${escapeHtml(audit.error)}</p>`);
  }

  const staticParts = renderStaticScan(staticScan);
  if (staticParts) parts.push(staticParts);

  const sideParts = renderSideEffects(sideeffects);
  if (sideParts) parts.push(sideParts);

  // CVEs last: these lists can run to hundreds of entries, so they live at the
  // bottom of the panel, split across runtime/dependency tabs.
  const cveParts = renderCves(cves, depAdvisories);
  if (cveParts) parts.push(cveParts);

  return parts.join("");
}

closeDetailBtn.addEventListener("click", () => {
  detailPanel.hidden = true;
  currentDetail = null;
  document
    .querySelectorAll("#apps tbody tr.selected")
    .forEach((r) => r.classList.remove("selected"));
});

// Delegated CVE tab switching: the panel's innerHTML is replaced on every async
// repaint, so we listen on the stable container and toggle the active tab in
// place (no full repaint), persisting the choice in `activeCveTab`.
detailBody.addEventListener("click", (e) => {
  const btn = e.target.closest(".cve-tab");
  if (!btn) return;
  const tab = btn.dataset.cveTab;
  activeCveTab = tab;
  const section = btn.closest(".cve-section");
  if (!section) return;
  for (const b of section.querySelectorAll(".cve-tab")) {
    b.classList.toggle("active", b.dataset.cveTab === tab);
  }
  for (const p of section.querySelectorAll(".cve-panel")) {
    p.classList.toggle("active", p.dataset.cveTab === tab);
  }
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

// Prompt for a path with the native save dialog, then write the JSON there.
// Returns the chosen path, or null if the user cancelled.
async function downloadJson(filename, payload) {
  const path = await save({
    defaultPath: filename,
    filters: [{ name: "JSON", extensions: ["json"] }],
  });
  if (!path) return null;
  await writeTextFile(path, JSON.stringify(payload, null, 2));
  return path;
}

async function exportAll() {
  const entries = [...rows.values()].map((r) => buildExportEntry(r.detection));
  const fetchedCount = entries.filter(
    (e) =>
      e.audit !== null ||
      e.cves !== null ||
      e.staticScan !== null ||
      e.sideeffects !== null,
  ).length;
  const doc = buildExportDocument(entries);
  try {
    const path = await downloadJson(`achilles-${isoStamp()}.json`, doc);
    if (!path) return;
    setStatus(
      `exported ${entries.length} apps (${fetchedCount} with full detail)`,
    );
  } catch (e) {
    setStatus(`export failed: ${e}`);
  }
}

async function exportDetail() {
  if (!currentDetail) return;
  const entry = buildExportEntry(currentDetail);
  const doc = buildExportDocument([entry]);
  const slug = slugify(
    currentDetail.display_name || currentDetail.bundle_id || "app",
  );
  try {
    await downloadJson(`achilles-${slug}-${isoStamp()}.json`, doc);
  } catch (e) {
    setStatus(`export failed: ${e}`);
  }
}

document.querySelector("#export-all").addEventListener("click", exportAll);
document.querySelector("#export-detail").addEventListener("click", exportDetail);

rescanBtn.addEventListener("click", () => {
  rows.clear();
  // Drop the per-session detail cache too — otherwise a previously-opened app
  // keeps showing its pre-rescan audit/CVE payload (e.g. an old runtime
  // version and the CVEs that went with it) after the app has been updated.
  detailCache.clear();
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

// Whether an NVD API key is configured. Cached so the runtime-CVE pane can
// suggest adding one when NVD is rate-limited (without re-fetching settings on
// every repaint). Refreshed at boot and after the settings form is saved.
let nvdApiKeyConfigured = false;
async function refreshNvdKeyState() {
  try {
    const s = await invoke("get_settings");
    nvdApiKeyConfigured = Boolean(s?.sources?.nvd?.api_key);
  } catch {
    // Leave the previous value on failure — a missing hint is harmless.
  }
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
    nvdApiKeyConfigured = Boolean(settings?.sources?.nvd?.api_key);
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
      applyFilters();
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

// ---------- auto-update (CrabNebula Cloud) ----------
// Checks the configured updater endpoint on boot. If a newer release is found
// we surface a banner; installing downloads + swaps the bundle and relaunches.
const updater = window.__TAURI__.updater;
const { relaunch } = window.__TAURI__.process;

const updateBanner = document.querySelector("#update-banner");
const updateText = document.querySelector("#update-text");
const updateInstallBtn = document.querySelector("#update-install");
const updateDismissBtn = document.querySelector("#update-dismiss");

let pendingUpdate = null;

async function checkForUpdates() {
  if (!updater?.check) return; // plugin unavailable (e.g. running without globals)
  let update;
  try {
    update = await updater.check();
  } catch (err) {
    console.warn("update check failed", err);
    return;
  }
  if (!update?.available) return;
  pendingUpdate = update;
  updateText.textContent = `Achilles ${update.version} is available.`;
  updateBanner.hidden = false;
}

async function installUpdate() {
  if (!pendingUpdate) return;
  updateInstallBtn.disabled = true;
  updateDismissBtn.disabled = true;
  try {
    let downloaded = 0;
    let total = 0;
    await pendingUpdate.downloadAndInstall((event) => {
      switch (event.event) {
        case "Started":
          total = event.data.contentLength ?? 0;
          updateText.textContent = "Downloading update…";
          break;
        case "Progress":
          downloaded += event.data.chunkLength ?? 0;
          updateText.textContent = total
            ? `Downloading update… ${Math.round((downloaded / total) * 100)}%`
            : "Downloading update…";
          break;
        case "Finished":
          updateText.textContent = "Installing… the app will restart.";
          break;
      }
    });
    await relaunch();
  } catch (err) {
    console.error("update install failed", err);
    updateText.textContent = `Update failed: ${err}`;
    updateInstallBtn.disabled = false;
    updateDismissBtn.disabled = false;
  }
}

updateInstallBtn.addEventListener("click", () => void installUpdate());
updateDismissBtn.addEventListener("click", () => {
  updateBanner.hidden = true;
  pendingUpdate = null;
});

buildHeader();
startScan();
void checkForUpdates();
void refreshNvdKeyState();
