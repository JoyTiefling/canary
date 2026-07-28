"""Pure tests — no network. Run with `pytest` or `python tests/test_canary.py`."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta, timezone

from canary.signals import (SignalResult, parse_algora_attempts, sig_linked_prs,
                            sig_owner_bounty_flood, sig_owner_age, _trajectory,
                            sig_fork_swarm, sig_releases)
from canary.score import aggregate
from canary.github import parse_target, set_clock


def S(name, dim, risk, weight=0.5, available=True, hard=True):
    return SignalResult(name, dim, available, risk, weight, name, hard)


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
    # clean repo signals but one elevated HARD signal (e.g. 2 open linked PRs) -> CAUTION
    sigs = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4),
            S("linked", "contention", 0.7, 0.6)]
    v = aggregate(sigs)
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


def test_soft_signal_alone_does_not_single_block():
    # DESIGN §8 (calibrated 2026-07-23): a SOFT (probabilistic) signal at 0.55-0.7
    # with clean peers must NOT single-block a clean ENGAGE. It tilts overall risk;
    # it does not get categorical veto power. This is the fork_swarm/flood fix.
    sigs = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4),
            S("swarm", "swarm", 0.55, 0.4, hard=False)]
    v = aggregate(sigs)
    assert v.verdict == "ENGAGE", (v.verdict, v.risk)


def test_soft_signal_paired_with_hard_still_blocks():
    # The HARD signal fires the single-block rule; the SOFT one contributes the
    # weighted risk that kept us near the boundary. Pairing must still CAUTION.
    sigs = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4),
            S("swarm", "swarm", 0.55, 0.4, hard=False),
            S("linked", "contention", 0.55, 0.3)]
    v = aggregate(sigs)
    assert v.verdict == "CAUTION", (v.verdict, v.risk)
    assert any("single" in r or "categorical" in r for r in v.reasons), v.reasons


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


def test_mcp_to_verdict_output_shapes_verdict():
    from canary.mcp_server import _to_verdict_output, VerdictOutput
    from canary.score import Verdict
    o = _to_verdict_output("o/r#1", Verdict("AVOID", 0.9, 1.0, ["swarmed"], []))
    assert isinstance(o, VerdictOutput)
    assert o.verdict == "AVOID" and o.engage is False and o.risk == 0.9, o
    assert _to_verdict_output("o/r", Verdict("ENGAGE", 0.05, 0.9, [], [])).engage is True
    assert _to_verdict_output("o/r", Verdict("UNKNOWN", None, 0.1, [], [])).engage is False
    # signals absent by default (compact go/no-go form)
    assert _to_verdict_output("o/r", Verdict("ENGAGE", 0.05, 0.9, [], [])).signals is None


def test_mcp_verdict_output_verbose_populates_signals():
    from canary.mcp_server import _to_verdict_output, SignalOutput
    from canary.score import Verdict
    from canary.signals import SignalResult
    sig = SignalResult("s1", "authenticity", True, 0.7, 1.0, "detail")
    o = _to_verdict_output("o/r", Verdict("CAUTION", 0.4, 0.8, [], [sig]), verbose=True)
    assert o.signals is not None and len(o.signals) == 1
    assert isinstance(o.signals[0], SignalOutput)
    assert o.signals[0].name == "s1" and o.signals[0].risk == 0.7


def test_mcp_tool_advertises_output_schema():
    # Structured output: FastMCP must derive an outputSchema from the tool's
    # return type annotation (VerdictOutput). Without it, clients only ever
    # see the text form and lose the typed shape.
    from canary.mcp_server import mcp
    import asyncio
    tools = asyncio.run(mcp.list_tools())
    t = next((t for t in tools if t.name == "canary_check"), None)
    assert t is not None, "canary_check tool not registered"
    assert t.outputSchema is not None, "canary_check must advertise outputSchema"
    props = t.outputSchema.get("properties", {})
    for field in ("target", "verdict", "engage", "risk", "confidence", "reasons", "signals"):
        assert field in props, f"outputSchema missing field: {field}"


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


def test_owner_flood_heavy_is_soft_tilt_not_single_block():
    # DESIGN §8 (calibrated 2026-07-23): the 11-25 dilution band (0.55) is SOFT —
    # a probability tilt that no longer single-blocks a clean go on its own.
    # This is the commaai/opendbc#3426 fix (legit $10k bounty, 10y owner, all
    # other signals clean — used to be dragged to CAUTION by flood alone).
    r = sig_owner_bounty_flood(20)
    assert 0.5 <= r.risk < 0.8 and r.hard is False, r
    v = aggregate([S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4), r])
    assert v.verdict == "ENGAGE", (v.verdict, v.risk)


def test_owner_flood_farm_scale_still_blocks():
    # 26-50 (farm-scale, 0.75) stays HARD: categorical pattern — blocks a clean
    # go via single-block (still below the 0.8 contention veto).
    r = sig_owner_bounty_flood(30)
    assert r.risk == 0.75 and r.hard is True, r
    v = aggregate([S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4), r])
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


# ---------- fork_swarm (repo-level swarm lens on fork:star) ----------
# Dimension is 'swarm', deliberately NOT 'contention': fork_swarm reads the
# repo-level population, not the issue-level fight. Tagging it 'contention'
# used to satisfy the issue-target required-dim gate on repo data alone and
# false-green an issue with no issue data (regression fixed 2026-07-02).

def test_fork_swarm_tiny_repo_unavailable():
    # stars + forks under 20 — too small to read swarm signal
    r = sig_fork_swarm({"stargazers_count": 3, "forks_count": 1})
    assert r.available is False and r.dimension == "swarm", r


def test_fork_swarm_no_stars_unavailable():
    # all-forks-no-stars is ambiguous, let issue-level contention signals decide
    r = sig_fork_swarm({"stargazers_count": 0, "forks_count": 25})
    assert r.available is False, r


def test_fork_swarm_helpdesk_anchor_triggers_clear():
    # HELPDESK.AI live anchor (149f / 90★, 3-mo-old) — the case fake_star punted on.
    # Must hit the 0.55 "hunter swarm" tier as a SOFT signal (DESIGN §8, 2026-07-23):
    # alone on otherwise-clean signals it no longer single-blocks (that shape was the
    # 6/8 tutorial-repo false-positive), but paired with a HARD contention signal —
    # the real HELPDESK shape — it amplifies into CAUTION.
    r = sig_fork_swarm({"stargazers_count": 90, "forks_count": 149})
    assert r.available and r.dimension == "swarm" and r.risk == 0.55, r
    assert r.hard is False, "fork_swarm must be a soft probability tilt (§8)"
    clean = [S("auth", "authenticity", 0.05, 1.0), S("resp", "responsiveness", 0.05, 0.4)]
    # tutorial-repo shape: swarm tilt alone -> no single-block
    assert aggregate(clean + [r]).verdict == "ENGAGE"
    # hunter shape: swarm tilt + hard contention evidence -> CAUTION
    v = aggregate(clean + [r, S("linked", "contention", 0.55, 0.3)])
    assert v.verdict == "CAUTION", (v.verdict, v.risk)


def test_fork_swarm_medium_repo_heavy_tier():
    # 300★ / 350f — ratio 1.17, stars<500: heavy swarm tier (0.3), not single-block
    r = sig_fork_swarm({"stargazers_count": 300, "forks_count": 350})
    assert r.available and 0.25 <= r.risk < 0.55, r


def test_fork_swarm_large_repo_healthy():
    # vue.js-shaped: 200k★ / 35k forks — large repo, ratio 0.18, healthy
    r = sig_fork_swarm({"stargazers_count": 200000, "forks_count": 35000})
    assert r.available and r.risk < 0.1, r


def test_fork_swarm_not_a_hard_veto():
    # Even at clear-swarm tier (0.55), fork_swarm must NOT trip the contention veto (0.8).
    # It's a soft probability tilt — proof of contention still belongs to issue-level signals.
    r = sig_fork_swarm({"stargazers_count": 90, "forks_count": 149})
    assert r.risk < 0.8, "fork_swarm must stay soft — not hard veto"


def test_fork_swarm_does_not_satisfy_issue_contention_gate():
    # Regression sibling of bench test_missing_key_replays_as_no_data_not_crash.
    # A repo-level swarm signal must NOT satisfy the issue-target required=('contention',)
    # gate — otherwise an issue with no fetched issue data false-greens on repo swarm alone.
    swarm = sig_fork_swarm({"stargazers_count": 200000, "forks_count": 35000})  # available, clean
    v = aggregate([S("auth", "authenticity", 0.05, 1.0), swarm],
                  required_dims=("contention",))
    assert v.verdict == "UNKNOWN", (v.verdict, v.reasons)


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


# --- unreachable repo: honest coverage, not a confident AVOID -----------------
class _GHUnreachable:
    """Minimal stub: repo fetch fails, rate limit is fine (so it's not a limit error)."""
    def repo(self, owner, repo):
        return None
    def remaining(self):
        return 42


def test_unreachable_repo_is_unknown_with_honest_confidence():
    from canary.scan import scan
    v, err = scan("someowner/vanished", gh=_GHUnreachable())
    assert err is None
    # Documented contract (mcp_server docstring: "Repo is private ... will be UNKNOWN").
    assert v.verdict == "UNKNOWN", (v.verdict, v.confidence)
    # And the certainty must reflect what we actually covered, not normalise over the
    # single signal we happened to build.
    assert v.confidence < 0.35, v.confidence
    # The risk flag itself is not lost — it stays visible in the reasons.
    assert any("not reachable" in r for r in v.reasons), v.reasons


def test_releases_without_repo_metadata_is_unavailable():
    # Absent created_at means degraded data, not a young repo: asserting
    # "no releases (young repo)" would invent a fact.
    s = sig_releases({}, None)
    assert s.available is False and s.risk is None, (s.available, s.risk)


# --- absence vs emptiness (audit 2026-07-29) --------------------------------
# Follow-up to the false-certainty fix: the same sin one layer lower. A fetcher
# that returns [] on a failed request hands the signal layer a network error
# dressed as a fact, and the honest-absence branches downstream become dead code.

class _DeadAPI:
    """A GitHub client whose every request fails (HTTP 502)."""
    def __init__(self):
        from canary.github import GitHub
        self.gh = GitHub()
        self.gh._get = lambda path: (None, 502)


def test_failed_list_fetch_returns_none_not_empty():
    """[] must mean 'looked, found nothing'; None must mean 'could not look'."""
    gh = _DeadAPI().gh
    assert gh.releases("o", "r") is None
    assert gh.issue_timeline("o", "r", 1) is None
    assert gh.issue_comments("o", "r", 1) is None


def test_failed_timeline_does_not_certify_absence_of_contention():
    """A 502 on the timeline endpoint must not read as 'no linked PRs' (risk 0.05).
    sig_linked_prs always had the `timeline is None -> unavailable` branch; before
    this fix nothing could ever reach it."""
    gh = _DeadAPI().gh
    r = sig_linked_prs(gh.issue_timeline("o", "r", 1))
    assert r.available is False, f"clean bill from a network error: {r.detail}"


def test_failed_comments_fetch_leaves_contention_unknown():
    from canary.signals import sig_contention
    r = sig_contention({"comments": 3}, None)
    assert r.available is False


def test_failed_releases_fetch_is_not_no_releases():
    r = sig_releases({"created_at": "2020-01-01T00:00:00Z"}, None)
    assert r.available is False, f"invented evidence: {r.detail}"


def test_missing_fork_count_does_not_accuse_of_fake_stars():
    """Absent forks_count defaulted to 0 -> ratio 0.000 -> 'fake-star proxy' risk
    0.6. False certainty pointed at the risky side is still false certainty."""
    from canary.signals import sig_fake_star
    r = sig_fake_star({"stargazers_count": 500})
    assert r.available is False, f"accusation manufactured from a missing field: {r.detail}"


def test_partial_issue_payload_buys_no_clean_bill():
    """'no one assigned' / 'no honeypot markers' are green lights on their
    dimensions — they must rest on data we actually read, not on absent keys."""
    from canary.signals import sig_assigned_reserved, sig_honeypot
    assert sig_assigned_reserved({"labels": []}).available is False
    assert sig_honeypot({}, {"labels": []}).available is False


# --- structural gate: honesty as a property, not a coincidence --------------

def _keys_read(fn, param):
    """Keys a signal function reads off `param` via `param.get("...")`, harvested
    from its own source. Self-maintaining: a newly added `.get()` is covered the
    day it is written, with no list here to keep in sync."""
    import ast, inspect, textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == param
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            found.add(node.args[0].value)
    return found


def test_no_signal_changes_its_confident_verdict_because_a_datum_is_absent():
    """The invariant behind every false-green/false-certainty bug found so far:
    removing a datum may only make a signal LESS certain. If knocking out a key
    leaves the signal `available` but with a DIFFERENT risk, that signal inferred
    something from absence — it read silence as a value.

    Fixtures are chosen so each key is load-bearing in at least one of them;
    a signal is exercised across all of them."""
    from canary import signals as SIG

    repos = [
        {"created_at": "2020-01-01T00:00:00Z", "pushed_at": "2026-07-20T00:00:00Z",
         "stargazers_count": 500, "forks_count": 60},                    # healthy
        {"created_at": "2026-06-20T00:00:00Z", "pushed_at": "2026-07-20T00:00:00Z",
         "stargazers_count": 400, "forks_count": 5},                     # fast growth + low ratio
        {"created_at": "2020-01-01T00:00:00Z", "pushed_at": "2020-01-01T00:00:00Z",
         "stargazers_count": 100, "forks_count": 250},                   # swarmed + abandoned
    ]
    issues = [
        {"labels": [{"name": "bounty"}], "user": {"login": "human"},
         "assignees": [], "assignee": None, "comments": 3},              # clean
        {"labels": [{"name": "ai agent friendly"}], "user": {"login": "clanker"},
         "assignees": [{"login": "someone"}], "assignee": None, "comments": 40},  # loaded
    ]
    cases = [
        ("sig_releases",          lambda r, i: SIG.sig_releases(r, []),        "repo",  "repo"),
        ("sig_fast_growth",       lambda r, i: SIG.sig_fast_growth(r),         "repo",  "repo"),
        ("sig_fake_star",         lambda r, i: SIG.sig_fake_star(r),           "repo",  "repo"),
        ("sig_fork_swarm",        lambda r, i: SIG.sig_fork_swarm(r),          "repo",  "repo"),
        ("sig_push_recency",      lambda r, i: SIG.sig_push_recency(r),        "repo",  "repo"),
        ("sig_honeypot",          lambda r, i: SIG.sig_honeypot(r, i),         "issue", "issue"),
        ("sig_assigned_reserved", lambda r, i: SIG.sig_assigned_reserved(i),   "issue", "issue"),
        ("sig_contention",        lambda r, i: SIG.sig_contention(i, []),      "issue", "issue"),
    ]

    violations = []
    for name, call, which, param in cases:
        keys = _keys_read(getattr(SIG, name), param)
        assert keys, f"{name}: probe harvested no keys — the AST walk is broken, not the signal"
        for repo in repos:
            for issue in issues:
                base_in = repo if which == "repo" else issue
                base = call(repo, issue)
                for key in keys:
                    if key not in base_in:
                        continue
                    knocked = {k: v for k, v in base_in.items() if k != key}
                    got = call(knocked if which == "repo" else repo,
                               knocked if which == "issue" else issue)
                    if got.available and base.available and got.risk != base.risk:
                        violations.append(
                            f"{name}: dropping '{key}' kept a confident verdict but moved risk "
                            f"{base.risk} -> {got.risk} ({got.detail})")
    assert not violations, "verdict inferred from absent data:\n  " + "\n  ".join(sorted(set(violations)))
