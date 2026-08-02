"""Rule-coverage gate: which DECISION PATH produced each verdict, read directly.

Companion to test_thresholds.py, and a correction of it. That file measures
coverage by *sensitivity* -- mutate a constant, see whether any row moves -- and
on 2026-08-02 it reported `ENGAGE_MAX` and `CAUTION_MAX` as unexercised. I wrote
the conclusion down as "not one bench verdict is produced by the continuous risk
ladder; every one is categorical". That was false, and this file is how it got
caught: `Verdict.rule` says six of fifteen rows are `ladder:engage`.

Both measurements are correct and they measure different things:

  * sensitivity  — does moving this constant move a verdict? For ENGAGE_MAX: no,
    because every ENGAGE row sits at risk <= 0.098 against a boundary at 0.30.
  * provenance   — which branch decided this verdict? For those same rows: the
    ladder, comfortably inside the ENGAGE band.

The ladder RUNS on most of the bench. What it never does is run NEAR a boundary,
and "exercised" was my one word for both. (Same shape as #3335: the thing I
called a property of the tool was a property of how I measured it.)

So the honest, narrower claim is: no bench row is decided by a ladder BOUNDARY
comparison, and no row at all takes `ladder:caution`, `ladder:avoid`, or
`no_signal`. Those three are listed below with what would close them.

Known gaps are an EQUALITY assertion, like the sibling gate: closing one without
deleting its entry fails too, and an unlisted uncovered rule fails loudly.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary import score
from bench.dataset import load_dataset
from bench.run import evaluate

KNOWN_UNCOVERED = {
    "ladder:caution": (
        "Accumulation CAUTION: weighted risk inside [ENGAGE_MAX, CAUTION_MAX) with "
        "no dimension veto and no hard signal >= SINGLE_BLOCK_MIN -- nothing damning "
        "on its own, damning in sum. The one CAUTION row (JoyTiefling/canary) is a "
        "single_block downgrade at overall risk 0.238, i.e. BELOW ENGAGE_MAX. "
        "Measured spread of `overall` over all 15 rows: 0.044 .. 0.354, and the only "
        "row above 0.30 is already vetoed. Closing it needs a live specimen, not a "
        "hand-built one: a repo that passes every categorical rule yet carries "
        "several mid-risk signals at once."
    ),
    "ladder:avoid": (
        "Every AVOID in the bench is veto-driven; their weighted risk is 0.17..0.35, "
        "nowhere near CAUTION_MAX=0.55. Reaching 0.55 by average means most of the "
        "covered weight sitting at 0.55+ without any dimension crossing 0.80 -- "
        "possible by construction, never observed. Until a specimen exists I do not "
        "know whether this band is empty by accident or unreachable by design, and "
        "that distinction is exactly what the gate must not paper over."
    ),
    "no_signal": (
        "Nothing available at all -> no risk value. Split out of low_confidence on "
        "2026-08-03 so the two UNKNOWN causes stop sharing a name. Currently "
        "unreachable in practice: the unreachable-repo path still builds one "
        "low-weight signal, so it lands in low_confidence. Kept as a named branch "
        "because a future signal set could empty it, and a silent fallthrough into "
        "low_confidence would then report a confidence number computed from nothing."
    ),
}


def _rules():
    """target -> rule, replayed from fixtures."""
    out = {}
    for e in load_dataset():
        pred, _info, rule = evaluate(e)
        out[e["target"]] = (pred, rule)
    return out


def test_every_decision_rule_is_covered_or_declared():
    rows = _rules()
    assert rows, "empty dataset -- nothing to measure"

    # Positive control on the harness: an unreplayed row carries no rule, and a
    # bench that replayed nothing would report every rule uncovered -- which reads
    # identical to a genuine design gap. Refuse that reading, same as the sibling.
    unreplayed = sorted(t for t, (pred, _r) in rows.items() if pred is None)
    assert not unreplayed, (
        "rows did not replay (%s); rule coverage is unmeasurable until they do -- "
        "run `python -m bench.capture`" % unreplayed)

    unnamed = sorted(t for t, (_p, r) in rows.items() if not r)
    assert not unnamed, (
        "verdict produced with no rule recorded: %s -- aggregate() has a branch "
        "that does not name itself" % unnamed)

    bad = sorted({r for _p, r in rows.values()} - set(score.RULES))
    assert not bad, "rule(s) not declared in score.RULES: %s" % bad

    covered = {r for _p, r in rows.values()}
    uncovered = set(score.RULES) - covered
    new = sorted(uncovered - set(KNOWN_UNCOVERED))
    stale = sorted(set(KNOWN_UNCOVERED) - uncovered)
    assert not new, (
        "decision rule(s) no bench row reaches: %s -- the bench scores 15/15 while "
        "these branches have never run. Add a specimen, or declare it in "
        "KNOWN_UNCOVERED with what would close it." % new)
    assert not stale, (
        "%s is now covered by the bench -- delete its KNOWN_UNCOVERED entry. A gap "
        "list that outlives its gap silences the next real one." % stale)


def test_ladder_runs_but_never_near_a_boundary():
    """The finding this file was written to record, as an assertion rather than a
    comment. `ladder:engage` is covered six times over, yet test_thresholds.py
    correctly reports ENGAGE_MAX as unexercised -- because every one of those rows
    sits far below the boundary. If a future specimen lands near it, this test goes
    red and the KNOWN_UNEXERCISED entry for ENGAGE_MAX must go with it."""
    ladder = [t for t, (_p, r) in _rules().items() if r == "ladder:engage"]
    assert ladder, "no ladder verdict at all -- provenance harness is not reaching aggregate()"
    margin = score.ENGAGE_MAX - _max_ladder_risk()
    assert margin > 0.15, (
        "an ENGAGE row now sits within %.3f of ENGAGE_MAX (%s). The ladder is being "
        "exercised near its boundary -- update test_thresholds.KNOWN_UNEXERCISED, "
        "which still declares ENGAGE_MAX unexercised." % (margin, ladder))


def _max_ladder_risk():
    from canary import github
    from canary.scan import scan
    from bench.cassette import Cassette, load_cassette, captured_dt, fixture_path, slug_for
    from bench.dataset import FIXTURES_DIR
    worst = 0.0
    for e in load_dataset():
        payload = load_cassette(fixture_path(FIXTURES_DIR, slug_for(e["target"])))
        github.set_clock(captured_dt(payload))
        try:
            v, err = scan(e["target"], gh=Cassette(store=payload.get("store", {})))
        finally:
            github.set_clock(None)
        if not err and v.rule == "ladder:engage":
            worst = max(worst, v.risk)
    return worst


def test_provenance_comes_from_the_scorer_not_from_the_replay():
    """Negative control. If `rule` were derived by the bench (re-deducing the branch
    from verdict + risk) instead of stamped by aggregate(), this whole file would be
    grading my own re-implementation. Break the scorer's ladder and the reported
    provenance must change with it."""
    before = {t: r for t, (_p, r) in _rules().items()}
    old = score.ENGAGE_MAX
    score.ENGAGE_MAX = 0.0          # nothing can be ladder:engage any more
    try:
        after = {t: r for t, (_p, r) in _rules().items()}
    finally:
        score.ENGAGE_MAX = old
    assert "ladder:engage" in set(before.values())
    assert "ladder:engage" not in set(after.values()), (
        "provenance did not follow the scorer's constants -- `rule` is not coming "
        "from aggregate()")


if __name__ == "__main__":
    test_provenance_comes_from_the_scorer_not_from_the_replay()
    print("negative control ok: provenance comes from the scorer")
    test_every_decision_rule_is_covered_or_declared()
    test_ladder_runs_but_never_near_a_boundary()
    print("rule coverage ok (known gaps: %s)" % sorted(KNOWN_UNCOVERED))
