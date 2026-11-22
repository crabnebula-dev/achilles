// Advisory-list helpers shared by main.js and its tests. Kept free of DOM and
// Tauri globals so `node --test ui/*.test.mjs` can import them directly.

// critical → high → medium → low → unrated, so we can sort highest-risk first.
export function severityRank(sev) {
  switch ((sev ?? "").toLowerCase()) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}

// The same CVE often comes back from more than one source. The backend keeps one
// record per source; here we collapse them to one entry per id so the list and
// its counts don't reflect duplicates.
export function uniqueAdvisories(list) {
  const byId = new Map();
  let unkeyed = 0;
  for (const a of list ?? []) {
    // `GHSA-unknown` is a placeholder for advisories with no id at all — those
    // are distinct records, never the same one twice.
    const key =
      a.id === "GHSA-unknown"
        ? `\0${unkeyed++}`
        : [a.id, ...(a.aliases ?? [])].find((x) => x?.startsWith("CVE-")) ?? a.id;
    const prev = byId.get(key);
    if (!prev) {
      // Show the CVE id whenever one is known, whichever sources answered.
      byId.set(key, { ...a, id: key.startsWith("CVE-") ? key : a.id });
      continue;
    }
    if (severityRank(a.severity) > severityRank(prev.severity)) prev.severity = a.severity;
    prev.fixed_in ??= a.fixed_in;
    if ((a.summary ?? "").length > (prev.summary ?? "").length) prev.summary = a.summary;
  }
  return [...byId.values()];
}
