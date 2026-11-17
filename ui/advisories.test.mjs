// Run with `node --test ui/*.test.mjs` (Node 22+, no dependencies).
import { test } from "node:test";
import assert from "node:assert/strict";

import { uniqueAdvisories } from "./advisories.js";

const ids = (list) => list.map((a) => a.id).sort();

test("the same CVE from NVD and EUVD is listed once", () => {
  const out = uniqueAdvisories([
    { id: "CVE-2026-0001", source: "nvd" },
    { id: "CVE-2026-0001", source: "euvd" },
    { id: "CVE-2026-0002", source: "nvd" },
  ]);
  assert.deepEqual(ids(out), ["CVE-2026-0001", "CVE-2026-0002"]);
});

test("an OSV record is matched on its CVE alias and shown under the CVE id", () => {
  const out = uniqueAdvisories([
    { id: "GHSA-28m8-9j7v-x499", source: "osv", aliases: ["CVE-2022-39215"] },
    { id: "CVE-2022-39215", source: "nvd" },
  ]);
  assert.deepEqual(ids(out), ["CVE-2022-39215"]);
});

test("GHSA and RUSTSEC copies of one CVE (as OSV returns for tauri) merge", () => {
  const out = uniqueAdvisories([
    { id: "GHSA-28m8-9j7v-x499", aliases: ["CVE-2022-39215", "RUSTSEC-2022-0088"] },
    { id: "RUSTSEC-2022-0088", aliases: ["CVE-2022-39215", "GHSA-28m8-9j7v-x499"] },
  ]);
  assert.deepEqual(ids(out), ["CVE-2022-39215"]);
});

test("records without a CVE keep their own id", () => {
  const out = uniqueAdvisories([
    { id: "GHSA-aaaa-bbbb-cccc", aliases: [] },
    { id: "EUVD-2026-1234" },
  ]);
  assert.deepEqual(ids(out), ["EUVD-2026-1234", "GHSA-aaaa-bbbb-cccc"]);
});

test("GHSA-unknown placeholders are never merged", () => {
  const out = uniqueAdvisories([
    { id: "GHSA-unknown", summary: "one" },
    { id: "GHSA-unknown", summary: "two" },
  ]);
  assert.equal(out.length, 2);
});

test("the highest severity wins, whichever copy arrives first", () => {
  const medium = { id: "CVE-2026-0001", source: "nvd", severity: "medium" };
  const high = { id: "CVE-2026-0001", source: "euvd", severity: "high" };
  assert.equal(uniqueAdvisories([medium, high])[0].severity, "high");
  assert.equal(uniqueAdvisories([high, medium])[0].severity, "high");
});

test("missing fields are filled from another copy", () => {
  const [a] = uniqueAdvisories([
    { id: "CVE-2026-0001", fixed_in: null, summary: "" },
    { id: "CVE-2026-0001", fixed_in: "26.5", summary: "Memory corruption in WebKit." },
  ]);
  assert.equal(a.fixed_in, "26.5");
  assert.equal(a.summary, "Memory corruption in WebKit.");
});

test("the input records are left untouched", () => {
  const input = [
    { id: "GHSA-28m8-9j7v-x499", aliases: ["CVE-2022-39215"], severity: "low" },
    { id: "CVE-2022-39215", severity: "high" },
  ];
  const before = structuredClone(input);
  uniqueAdvisories(input);
  assert.deepEqual(input, before);
});

test("an empty or missing list gives an empty result", () => {
  assert.deepEqual(uniqueAdvisories([]), []);
  assert.deepEqual(uniqueAdvisories(undefined), []);
});
