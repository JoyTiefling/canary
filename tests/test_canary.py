"""Pure tests — no network. Run with `pytest` or `python tests/test_canary.py`."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary.signals import SignalResult, parse_algora_attempts, sig_linked_prs
from canary.score import aggregate
from canary.github import parse_target


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


def test_parse_target_forms():
    assert parse_target("https://github.com/o/r/issues/59") == {"kind": "issue", "owner": "o", "repo": "r", "num": 59}
    assert parse_target("https://github.com/o/r") == {"kind": "repo", "owner": "o", "repo": "r"}
    assert parse_target("o/r#7") == {"kind": "issue", "owner": "o", "repo": "r", "num": 7}
    assert parse_target("o/r") == {"kind": "repo", "owner": "o", "repo": "r"}
    assert parse_target("garbage ::") is None


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
