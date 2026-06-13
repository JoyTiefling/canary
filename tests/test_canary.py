"""Pure tests — no network. Run with `pytest` or `python tests/test_canary.py`."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta, timezone

from canary.signals import (SignalResult, parse_algora_attempts, sig_linked_prs,
                            sig_owner_bounty_flood, sig_owner_age, _trajectory)
from canary.score import aggregate
from canary.github import parse_target, set_clock


def S(name, dim, risk, weight=0.5, available=True):
    return SignalResult(name, dim, available, risk, weight, name)


def test_clean_engage():
    v = aggregate([S("a", "authenticity", 0.05), S("b", "responsiveness", 0.05, 0.4),
                   S("c", "contention", 0.1, 0.7)])
    assert v.verdict == "ENGAGE", v.verdict


def test_honeypot_vetoes_to_avoid():
    # even with otherwise-clean signals, a honeypot hit must AVOID
    v = aggregate([S("clean", "authenticity", 0.05, 1.0), S("hp", "honeypot", 0.95, 0.7)])
    assert v.verdict == "AVOID", v.verdict


def test_contention_piranha_vetoes():
    v = aggregate([S("clean", "authenticity", 0.05, 1.0), S("c", "contention", 0.97, 0.7)])
    assert v.verdict == "AVOID", v.verdict


def test_assigned_vetoes_green():
    v = aggregate([S("clean", "authenticity", 0.05, 1.0), S("asg", "availability", 0.85, 0.6)])
    assert v.verdict == "AVOID", v.verdict


def test_missing_data_is_unknown_not_green():
    # only one low-weight signal available -> confidence below threshold -> UNKNOWN
    sigs = [S("a", "authenticity", 0.05, 0.2),
            SignalResult("contention", "contention", False, None, 0.7, "no data"),
            SignalResult("honeypot", "honeypot", False, None, 0.7, "no data")]
    v = aggregate(sigs)
    assert v.verdict == "UNKNOWN", (v.verdict, v.confidence)


def test_mid_risk_is_caution():
    v = aggregate([S("a", "authenticity", 0.5, 1.0), S("b", "responsiveness", 0.4, 1.0)])
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


def test_issue_missing_contention_is_unknown_not_engage():
    # Regression for EdgeChains#286: clean repo signals but no contention data on an
    # issue target must NOT yield ENGAGE — contention is a required dimension.
    repo_only = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4)]
    v = aggregate(repo_only, required_dims=("contention",))
    assert v.verdict == "UNKNOWN", v.verdict
    # but with contention present and clean -> ENGAGE
    v2 = aggregate(repo_only + [S("c", "contention", 0.1, 0.7)], required_dims=("contention",))
    assert v2.verdict == "ENGAGE", v2.verdict


def test_single_hot_signal_blocks_clean_engage():
    # clean repo signals but one elevated signal (e.g. open linked PR) -> CAUTION
    sigs = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4),
            S("linked", "contention", 0.7, 0.6)]
    v = aggregate(sigs)
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


def test_linked_prs_open_is_contention():
    tl = [{"event": "cross-referenced",
           "source": {"issue": {"number": 515, "state": "open",
                                "pull_request": {"url": "https://api.github.com/.../pulls/515"}}}}]
    r = sig_linked_prs(tl)
    assert r.available and r.dimension == "contention" and r.risk >= 0.7, r


def test_linked_prs_none_unavailable():
    assert sig_linked_prs(None).available is False


def test_honeypot_still_vetoes_even_if_required_missing():
    # safety takes precedence: honeypot AVOID beats UNKNOWN-from-missing-required
    v = aggregate([S("hp", "honeypot", 0.95, 0.7)], required_dims=("contention",))
    assert v.verdict == "AVOID", v.verdict


def test_parse_algora_counts_greens():
    comments = [{"user": {"login": "algora-pbc[bot]"},
                 "body": "💎 $200 bounty\nAttempt table\n🟢 @a #1\n🟢 @b WIP\n🔴 @c"}]
    n, found = parse_algora_attempts(comments)
    assert found and n == 3, (found, n)


def test_parse_algora_absent():
    n, found = parse_algora_attempts([{"user": {"login": "someone"}, "body": "hi"}])
    assert not found and n == 0


def test_mcp_to_dict_shapes_verdict():
    from canary.mcp_server import _to_dict
    from canary.score import Verdict
    d = _to_dict("o/r#1", Verdict("AVOID", 0.9, 1.0, ["swarmed"], []))
    assert d["verdict"] == "AVOID" and d["engage"] is False and d["risk"] == 0.9, d
    assert _to_dict("o/r", Verdict("ENGAGE", 0.05, 0.9, [], []))["engage"] is True
    assert _to_dict("o/r", Verdict("UNKNOWN", None, 0.1, [], []))["engage"] is False


def test_owner_flood_none_is_unavailable():
    # no data must never be scored as safe (0)
    assert sig_owner_bounty_flood(None).available is False


def test_owner_flood_normal_is_low_risk():
    r = sig_owner_bounty_flood(2)
    assert r.available and r.dimension == "contention" and r.risk < 0.2, r


def test_owner_flood_industrial_vetoes():
    # 144 (real ritesh-1918 farm) must cross the contention veto -> AVOID
    r = sig_owner_bounty_flood(144)
    assert r.risk >= 0.8, r
    v = aggregate([S("clean", "authenticity", 0.05, 1.0), r])
    assert v.verdict == "AVOID", (v.verdict, v.risk)


def test_owner_flood_heavy_downgrades_not_vetoes():
    # heavy-but-plausible (20) blocks a clean go but does not hard-AVOID
    r = sig_owner_bounty_flood(20)
    assert 0.5 <= r.risk < 0.8, r
    v = aggregate([S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4), r])
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


# ---------- owner_age + trajectory (DESIGN.md §7 / cold-start) ----------

_NOW = datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc)


def _user_aged(days):
    return {"created_at": (_NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")}


def _push_events(commits_per_day, distinct_days, start_offset_days=1):
    """Build a synthetic events list: one PushEvent per distinct day, with
    `commits_per_day` commits in payload. Spread across distinct calendar dates."""
    evs = []
    for i in range(distinct_days):
        day = _NOW - timedelta(days=start_offset_days + i)
        evs.append({
            "type": "PushEvent",
            "created_at": day.isoformat().replace("+00:00", "Z"),
            "payload": {"commits": [{"sha": f"x{i}{j}"} for j in range(commits_per_day)]},
        })
    return evs


def setup_module(_m):  # freeze clock for all owner_age tests in this module
    set_clock(_NOW)


def teardown_module(_m):
    set_clock(None)


def test_trajectory_counts_pushes_and_distinct_days():
    evs = _push_events(commits_per_day=3, distinct_days=5)
    assert _trajectory(evs) == (15, 5)
    # Non-push events are ignored.
    evs += [{"type": "WatchEvent", "created_at": _NOW.isoformat(), "payload": {}}]
    assert _trajectory(evs) == (15, 5)
    assert _trajectory(None) == (0, 0)
    assert _trajectory([]) == (0, 0)


def test_owner_age_under_30_bootstrap_floor():
    # Even with a strong trajectory, <30d cannot ease — pay the days tax.
    r = sig_owner_age(_user_aged(4), _push_events(5, 14))
    assert r.available and r.risk == 0.8, r
    assert "bootstrap floor" in r.detail


def test_owner_age_30_120_strong_trajectory_eases():
    # 60d + 25 commits across 14 days -> band eases below the 0.55 single-block.
    r = sig_owner_age(_user_aged(60), _push_events(2, 14))  # 28c/14d
    assert r.risk == 0.45, r
    assert r.risk < 0.55  # the architectural point: no longer single-blocks


def test_owner_age_30_120_weak_trajectory_holds_default():
    r = sig_owner_age(_user_aged(60), _push_events(2, 5))  # 10c/5d, below thresholds
    assert r.risk == 0.8, r


def test_owner_age_30_120_no_events_holds_default():
    # Backward-compat: if caller didn't fetch events, we keep the strict default.
    r = sig_owner_age(_user_aged(60), None)
    assert r.risk == 0.8, r


def test_owner_age_120_365_lighter_trajectory_eases():
    r = sig_owner_age(_user_aged(200), _push_events(2, 8))  # 16c/8d
    assert r.risk == 0.15, r


def test_owner_age_120_365_default_when_weak():
    r = sig_owner_age(_user_aged(200), _push_events(1, 3))  # 3c/3d
    assert r.risk == 0.4, r


def test_owner_age_established_inert_to_events():
    # ≥365d: age IS the trajectory; events are ignored.
    r = sig_owner_age(_user_aged(800), _push_events(0, 0))
    assert r.risk == 0.05, r


def test_owner_age_unavailable_when_no_user():
    assert sig_owner_age(None).available is False
    assert sig_owner_age({"created_at": None}).available is False


def test_cold_start_unblocked_end_to_end():
    """Regression for the dogfood self-block (#2369/#2413/#2458): a 60d-old owner
    with a real push trajectory and otherwise-clean repo signals must now reach
    ENGAGE — the single-signal-block on owner_age=0.8 was the architectural
    blocker, and the trajectory-eased risk (0.45) no longer trips it."""
    owner_sig = sig_owner_age(_user_aged(60), _push_events(2, 14))  # eased -> 0.45
    clean = [S("releases", "authenticity", 0.05, 0.4),
             S("push_recency", "responsiveness", 0.05, 0.4),
             S("honeypot", "honeypot", 0.05, 0.7)]
    v = aggregate([owner_sig] + clean)
    assert v.verdict == "ENGAGE", (v.verdict, v.risk, [s.risk for s in v.signals])


def test_cold_start_weak_trajectory_still_blocks():
    """Counter-test: a 60d-old owner with weak/no trajectory must still single-block
    a clean ENGAGE. The eased band is *earned*, not granted."""
    owner_sig = sig_owner_age(_user_aged(60), _push_events(1, 2))  # weak -> 0.8
    clean = [S("releases", "authenticity", 0.05, 0.4),
             S("push_recency", "responsiveness", 0.05, 0.4),
             S("honeypot", "honeypot", 0.05, 0.7)]
    v = aggregate([owner_sig] + clean)
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


def test_parse_target_forms():
    assert parse_target("https://github.com/o/r/issues/59") == {"kind": "issue", "owner": "o", "repo": "r", "num": 59}
    assert parse_target("https://github.com/o/r") == {"kind": "repo", "owner": "o", "repo": "r"}
    assert parse_target("o/r#7") == {"kind": "issue", "owner": "o", "repo": "r", "num": 7}
    assert parse_target("o/r") == {"kind": "repo", "owner": "o", "repo": "r"}
    assert parse_target("garbage ::") is None


if __name__ == "__main__":
    # Mimic pytest's module-level setup/teardown so `python tests/test_canary.py`
    # behaves the same as `pytest` (owner_age tests rely on a frozen clock).
    if "setup_module" in globals():
        setup_module(None)
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
    if "teardown_module" in globals():
        teardown_module(None)
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
