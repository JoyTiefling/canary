"""Capture GitHub fixtures for every dataset entry that lacks one (online, once).

    python -m bench.capture            # capture only missing fixtures
    python -m bench.capture --force    # re-capture all (refresh snapshots)
    python -m bench.capture o/r#59 ... # capture specific targets

Unauth GitHub allows 60 req/hr; set GITHUB_TOKEN to raise it. A target that the
API can't resolve is REPORTED, never silently labelled — existence is ground
truth we get from the API, not from memory."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary.github import GitHub
from canary.scan import scan
from bench.cassette import Cassette, save_cassette, fixture_path, slug_for
from bench.dataset import load_dataset, FIXTURES_DIR


def capture_one(entry, gh, force=False):
    target = entry["target"]
    path = fixture_path(FIXTURES_DIR, slug_for(target))
    if os.path.exists(path) and not force:
        return "skip", None
    cas = Cassette(real=gh)
    verdict, err = scan(target, gh=cas)
    if err:
        return "error", err
    if not cas.store.get(next(iter(
            [k for k in cas.store if k.startswith("repo:")]), "repo:")):
        return "unresolved", "repo not reachable via API (path wrong / deleted / private?)"
    save_cassette(path, target, cas.store)
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
        tag = {"ok": "OK ", "skip": "-- ", "error": "ERR", "unresolved": "!! "}.get(status, "???")
        print(f"  {tag} {e['target']:<40} {info if info is not None else ''}")
    print("summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
