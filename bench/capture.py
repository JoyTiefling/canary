"""Capture GitHub fixtures for every dataset entry that lacks one (online, once).

    python -m bench.capture            # capture only missing fixtures
    python -m bench.capture --force    # re-capture all (refresh snapshots)
    python -m bench.capture o/r#59 ... # capture specific targets

Unauth GitHub allows 60 req/hr; set GITHUB_TOKEN to raise it. A target that the
API can't resolve is REPORTED, never silently labelled — existence is ground
truth we get from the API, not from memory.

A repo the API answers "not visible" for (404/403/451) IS capturable: that answer
is the datum, and the UNKNOWN class exists precisely to cover it. Only a target we
got NO answer about is refused — recording that would freeze a network hiccup into
ground truth. Before this split, the one verdict class the gate can honestly emit
was the one class the benchmark structurally could not hold."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary.github import GitHub, parse_target
from canary.scan import scan
from bench.cassette import Cassette, save_cassette, fixture_path, slug_for
from bench.dataset import load_dataset, FIXTURES_DIR

# GitHub answered, and the answer is "you cannot see this": missing, blocked, or
# taken down (404 covers private repos too, for unauth clients).
ANSWERED_ABSENT = (403, 404, 451)


def capture_one(entry, gh, force=False):
    target = entry["target"]
    path = fixture_path(FIXTURES_DIR, slug_for(target))
    if os.path.exists(path) and not force:
        return "skip", None
    cas = Cassette(real=gh)
    verdict, err = scan(target, gh=cas)
    if err:
        return "error", err
    resolved = any(cas.store.get(k) for k in cas.store if k.startswith("repo:"))
    absent_reason = None
    if not resolved:
        # scan() collapsed the reason (see GitHub.repo_ex). Re-ask keeping the status:
        # only an actual answer may be written to disk as a fixture.
        t = parse_target(target)
        status = gh.repo_ex(t["owner"], t["repo"])[1] if t else None
        if status not in ANSWERED_ABSENT:
            return "unreachable", (f"no answer from API (status={status}) — "
                                   "not recorded; absence of data is not data")
        absent_reason = f"repo not visible via API (HTTP {status})"
    save_cassette(path, target, cas.store, absent_reason=absent_reason)
    if absent_reason:
        return "absent", f"{absent_reason} -> {verdict.verdict if verdict else '?'}"
    return "ok", verdict.verdict if verdict else "?"


def main(argv):
    force = "--force" in argv
    only = [a for a in argv if not a.startswith("--")]
    entries = load_dataset()
    if only:
        entries = [e for e in entries if e["target"] in only]
        for t in only:
            if t not in {e["target"] for e in entries}:
                entries.append({"target": t})
    gh = GitHub()
    rem = gh.remaining()
    print(f"GitHub rate limit remaining: {rem}")
    counts = {}
    for e in entries:
        status, info = capture_one(e, gh, force=force)
        counts[status] = counts.get(status, 0) + 1
        tag = {"ok": "OK ", "skip": "-- ", "error": "ERR",
               "absent": "404", "unreachable": "!! "}.get(status, "???")
        print(f"  {tag} {e['target']:<40} {info if info is not None else ''}")
    print("summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
