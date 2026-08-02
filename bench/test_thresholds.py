"""Threshold-coverage gate: every decision constant must be *exercised* by the bench.

A benchmark that scores 15/15 says nothing about a constant no row's verdict
depends on. Measured 2026-08-02: `CAUTION_MAX` could be moved to 0.31 or to 0.99
-- either direction, across most of its range -- and the bench still reported
EXACT MATCH 15/15, FALSE-GREEN 0, gate exit 0. The number that defines the whole
CAUTION/AVOID boundary was a free parameter as far as the harness was concerned.

That is the same defect as the two before it, one layer up: what is not measured
does not complain (empty UNKNOWN class, 9097b41; gate that could not fail on zero
measurements, ed9b3ed). The dataset gate asks "is every verdict CLASS present"
-- which the CAUTION class passes with n=1 -- but a class can be populated by a
route that leaves the threshold untouched. `JoyTiefling/canary` is exactly that:
overall risk 0.238, i.e. BELOW `ENGAGE_MAX`; it is CAUTION via the single-block
downgrade, never via the band. Class coverage and threshold coverage are two
different questions and only the first was asked.

So this file asks the second: mutate each constant, replay the whole bench, and
require that at least one row's verdict move. A constant nothing moves under is
reported by name. Known gaps live in KNOWN_UNEXERCISED with the reason and the
row that would close them -- and the assertion is an EQUALITY, so closing a gap
without deleting its entry fails too. An allowlist that only ever grows is a
second thing that cannot complain.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary import score
from bench.dataset import load_dataset
from bench.run import evaluate

# name -> alternative values a plausible regression (or a careless calibration)
# could introduce. Both directions where the constant has two sides: a threshold
# only nudged one way is half-measured.
MUTATIONS = {
    "MIN_CONFIDENCE": [0.05, 0.90],
    "ENGAGE_MAX": [0.10, 0.50],
    "CAUTION_MAX": [0.31, 0.99],
    "SINGLE_BLOCK_MIN": [0.20, 0.99],
}

# Dimension veto thresholds live in a dict; mutated as a whole (raising every
# veto floor to 0.99 disables the mechanism, lowering to 0.10 fires it everywhere).
VETO_MUTATIONS = [0.10, 0.99]

KNOWN_UNEXERCISED = {
    "ENGAGE_MAX": (
        "Found by this gate on its first run, unpredicted: nothing moves anywhere in "
        "0.10..0.50 (measured sweep 2026-08-02; 0.04 moves six rows, so the harness "
        "does see it). Every ENGAGE row sits at risk <= 0.098 -- a 3x margin below "
        "the boundary -- and nothing sits above it that is not already vetoed. The "
        "bench holds no near-boundary specimen at all. Closing it needs a row whose "
        "overall risk lands in roughly [0.15, 0.30): a repo good enough to pass every "
        "categorical rule yet visibly worse than facebook/react. Same specimen family "
        "as CAUTION_MAX below, one band lower."
    ),
    "CAUTION_MAX": (
        "No bench row's verdict is decided by the CAUTION/AVOID band comparison. "
        "Every AVOID present is veto-driven (max hard signal >= 0.80) and the one "
        "CAUTION is a single-block downgrade at risk 0.238. Closing it needs a live "
        "specimen whose overall weighted risk lands inside [0.30, 0.55) with no "
        "dimension veto and no hard signal >= SINGLE_BLOCK_MIN -- an accumulation "
        "verdict, where no single signal is damning but the sum is. That is the "
        "band CAUTION_MAX names, and the bench has never held one. Capture it, add "
        "the row, then DELETE this entry."
    ),
}

# WRONG, and corrected 2026-08-03 -- kept because the error is instructive:
#
#   "What the two entries above amount to, said once: every verdict this benchmark
#    scores is produced by a CATEGORICAL rule -- a dimension veto, the single-block
#    downgrade, or a required-dimension miss. Not one is produced by the continuous
#    risk ladder."
#
# Six of fifteen rows ARE produced by the ladder (`ladder:engage`); Verdict.rule now
# says so directly. What is true is narrower: no row is decided by a ladder BOUNDARY
# comparison. Every ENGAGE sits at risk <= 0.098 against a boundary at 0.30, so the
# constant can move freely and nothing follows -- which is what this file measures
# and reports correctly. The false step was mine, at the write-up: "no row is
# sensitive to the threshold" became "the ladder never runs", and a sensitivity
# sweep cannot tell those apart. See bench/test_rule_coverage.py, which can.
#
# What survives of the original point, and it is the sharp part: the weighted score
# is the piece of this tool that most looks like judgement, and every verdict it has
# ever produced sits far from the two boundaries that give it meaning.


def _verdict_vector():
    return {e["target"]: evaluate(e)[0] for e in load_dataset()}


def _apply(name, value):
    old = getattr(score, name)
    setattr(score, name, value)
    return old


def test_every_threshold_is_exercised_by_some_row():
    entries = load_dataset()
    baseline = _verdict_vector()

    # Positive control on the harness itself: a baseline that measured nothing
    # would make every constant look unexercised, and this test would then be
    # reporting the absence of fixtures as a design gap. Refuse that reading.
    measured = [t for t, v in baseline.items() if v is not None]
    assert entries, "empty dataset -- nothing to measure"
    assert len(measured) == len(entries), (
        "baseline did not replay every row (%d/%d); threshold coverage is "
        "unmeasurable until it does -- run `python -m bench.capture`"
        % (len(measured), len(entries)))

    unexercised = []
    for name, alts in MUTATIONS.items():
        moved = False
        for alt in alts:
            old = _apply(name, alt)
            try:
                if _verdict_vector() != baseline:
                    moved = True
            finally:
                _apply(name, old)
            if moved:
                break
        if not moved:
            unexercised.append(name)

    moved = False
    for alt in VETO_MUTATIONS:
        old = _apply("VETO", {d: alt for d in score.VETO})
        try:
            if _verdict_vector() != baseline:
                moved = True
        finally:
            _apply("VETO", old)
        if moved:
            break
    if not moved:
        unexercised.append("VETO")

    got, known = set(unexercised), set(KNOWN_UNEXERCISED)
    new = sorted(got - known)
    stale = sorted(known - got)
    assert not new, (
        "threshold(s) no bench row exercises: %s -- the bench cannot tell you if "
        "these are calibrated. Add a row whose verdict depends on each, or record "
        "it in KNOWN_UNEXERCISED with the specimen that would close it." % new)
    assert not stale, (
        "%s is now exercised by the bench -- delete its KNOWN_UNEXERCISED entry. "
        "A gap list that outlives its gap silences the next real one." % stale)


def test_mutation_harness_detects_a_known_live_threshold():
    """Negative control for the test above: if _verdict_vector() were insensitive
    to score's constants (wrong import, cached module, verdicts read from disk),
    every constant would look unexercised and the equality assertion would drift
    to whatever KNOWN_UNEXERCISED happened to say. MIN_CONFIDENCE is known-live:
    dropping it to 0.05 turns the two UNKNOWN rows into confident verdicts."""
    baseline = _verdict_vector()
    old = _apply("MIN_CONFIDENCE", 0.05)
    try:
        mutated = _verdict_vector()
    finally:
        _apply("MIN_CONFIDENCE", old)
    assert mutated != baseline, (
        "monkeypatching canary.score.MIN_CONFIDENCE changed no verdict -- the "
        "mutation harness is not reaching the code under test")


if __name__ == "__main__":
    test_mutation_harness_detects_a_known_live_threshold()
    print("negative control ok: harness reaches the scorer")
    test_every_threshold_is_exercised_by_some_row()
    print("threshold coverage ok (known gaps: %s)" % sorted(KNOWN_UNEXERCISED))
