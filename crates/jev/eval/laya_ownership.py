# /// script
# requires-python = ">=3.10"
# dependencies = ["laya"]
# ///
"""Laya (https://github.com/NandhaKishorM/laya) on the watchdog's ownership
questions, for comparison with Jev and the no-model baseline in
crates/jev/src/watchdog/ownership.rs (eval test).

    uv run crates/jev/eval/laya_ownership.py crates/jev/eval/ownership.json
"""
import json, re, sys, time, resource
from laya import Router

F = json.load(open(sys.argv[1]))
apps = F["apps"]
QUESTION = "Which installed application does this background item belong to, judging by its label, program path and signing team?"
STOP = set("com app apps contents macos library application support applications users agent daemon helper helpers launchagents launchdaemons resources privilegedhelpertools plist bin usr local opt the inc ltd llc updater update service mac".split())

def tokens(s):
    return sorted({t.lower() for t in re.split(r"[^A-Za-z0-9]", s) if len(t) >= 3 and t.lower() not in STOP})

def candidates(case):
    it = set(tokens(f'{case["label"]} {case["program"]}'))
    scored = []
    for a in apps:
        at = set(tokens(f'{a["name"]} {a.get("bundleId") or ""}'))
        s = len(it & at)
        if s: scored.append((-s, a["name"], a))
    return [a for _, _, a in sorted(scored)[:6]]

router = Router()
def ask(case, cands):
    state = {"backgroundItem": {"label": case["label"], "program": case["program"], "registeredBy": case["source"], "signingTeam": case["signingTeam"]},
             "installedApplications": [{"name": a["name"], "bundleId": a.get("bundleId"), "signingTeam": a.get("teamId")} for a in cands]}
    criteria = {str(i): f'It belongs to {a["name"]}.' for i, a in enumerate(cands)}
    criteria["none"] = "It belongs to none of the listed applications."
    t = time.perf_counter()
    r = router.predict(state, {"owner": {"type": "choice", "instructions": QUESTION, "criteria": criteria}}, model="english")
    dt = time.perf_counter() - t
    ans = r["answers"]["owner"]
    pick = ans["choice"]
    name = None if pick == "none" else cands[int(pick)]["name"]
    return name, dt, ans

for mode in ("A-all-apps", "B-pipeline"):
    ok = 0; times = []
    print(f"\n== Laya ({mode})")
    for c in F["cases"]:
        cands = apps if mode.startswith("A") else candidates(c)
        if not cands:
            name, dt = None, 0.0
        else:
            name, dt, _ = ask(c, cands); times.append(dt)
        good = name in c["accept"]
        ok += good
        print(f'{"✓" if good else "✗"} {c["label"]:<46} got {name!s:<16} want {c["accept"]}')
    print(f"{ok}/{len(F['cases'])} correct; {len(times)} model calls, median {sorted(times)[len(times)//2]*1000 if times else 0:.0f} ms")
print("peak RSS MB", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e6)
