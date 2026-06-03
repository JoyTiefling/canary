"""Harness tests — fully offline, no fixtures on disk needed. Run with pytest or
`python bench/test_bench.py`. These guard the benchmark machinery itself: replay
determinism, frozen clock, and the false-green metric."""
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary import github
from canary.scan import scan
from bench.cassette import Cassette, captured_dt, slug_for
from bench.dataset import load_dataset, TRAP_VERDICTS

CLOCK = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _clean_repo_store():
    return {
        "repo:o/r": {"owner": {"login": "o"}, "created_at": "2020-01-01T00:00:00Z",
                     "pushed_at": "2026-05-20T00:00:00Z",
                     "stargazers_count": 5000, "forks_count": 800},
        "user:o": {"created_at": "2015-01-01T00:00:00Z"},
        "releases:o/r": [{"tag_name": "v1.0"}],
    }


def test_replay_is_offline_and_deterministic():
    # real=None => any network attempt would explode; this must not touch the net.
    store = _clean_repo_store()
    github.set_clock(CLOCK)
    try:
        v1, e1 = scan("o/r", gh=Cassette(store=store))
        v2, e2 = scan("o/r", gh=Cassette(store=store))
    finally:
        github.set_clock(None)
    assert e1 is None and e2 is None
    assert v1.verdict == "ENGAGE", (v1.verdict, v1.reasons)
    assert v1.verdict == v2.verdict and abs(v1.risk - v2.risk) < 1e-9


def test_frozen_clock_changes_age_signal():
    github.set_clock(datetime(2026, 6, 1, tzinfo=timezone.utc))
    try:
        old = github.age_days("2026-01-01T00:00:00Z")
    finally:
        github.set_clock(None)
    github.set_clock(datetime(2027, 6, 1, tzinfo=timezone.utc))
    try:
        later = github.age_days("2026-01-01T00:00:00Z")
    finally:
        github.set_clock(None)
    assert later > old and old == 151  # deterministic, not wall-clock


def test_swarmed_bounty_replays_to_avoid():
    store = _clean_repo_store()
    store["issue:o/r#5"] = {"comments": 30, "labels": [], "assignees": []}
    store["comments:o/r#5"] = [{"user": {"login": "algora-pbc[bot]"},
                                "body": "💎 bounty\n" + ("🟢 @x\n" * 20)}]
    store["timeline:o/r#5"] = []
    github.set_clock(CLOCK)
    try:
        v, err = scan("o/r#5", gh=Cassette(store=store))
    finally:
        github.set_clock(None)
    assert err is None and v.verdict == "AVOID", (v.verdict, v.reasons)


def test_missing_key_replays_as_no_data_not_crash():
    # An issue target with no recorded issue must degrade safely (UNKNOWN), not throw.
    github.set_clock(CLOCK)
    try:
        v, err = scan("o/r#9", gh=Cassette(store=_clean_repo_store()))
    finally:
        github.set_clock(None)
    assert err is None and v.verdict in ("UNKNOWN", "AVOID"), v.verdict


def test_captured_dt_parses_z_suffix():
    dt = captured_dt({"captured_at": "2026-06-01T10:00:00Z"})
    assert dt is not None and dt.tzinfo is not None and dt.year == 2026
    assert captured_dt({}) is None


def test_slug_is_filesystem_safe():
    assert slug_for("o/r#59") == "o__r__59"
    assert "/" not in slug_for("a/b#1") and "#" not in slug_for("a/b#1")


def test_dataset_loads_and_is_well_formed():
    ds = load_dataset()
    assert len(ds) >= 5
    for e in ds:
        assert e["target"]
        if "expected" in e:
            assert e["expected"] in ("ENGAGE", "CAUTION", "AVOID", "UNKNOWN")


def test_trap_verdicts_exclude_engage():
    assert "ENGAGE" not in TRAP_VERDICTS  # the whole point of the safety metric


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
