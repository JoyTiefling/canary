"""Replay the labeled dataset offline and score the gate.

    python -m bench.run            # summary report
    python -m bench.run -v         # + per-entry verdicts and reasons

Reads each entry's fixture, freezes the clock to its capture time, runs the real
scan() pipeline over recorded data, and compares to the ground-truth label.

Metrics, in priority order:
  1. FALSE-GREEN  — predicted ENGAGE on a trap. The one error that hurts a user.
                    Any > 0 makes this exit non-zero (CI gate).
  2. EXACT MATCH  — predicted verdict == expected verdict.
  3. CONFUSION    — full matrix + per-class precision/recall.

Entries without a captured fixture are reported as MISSING and excluded from
scoring (run `python -m bench.capture` first), never counted as passes."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary import github
from canary.scan import scan
from bench.cassette import Cassette, load_cassette, captured_dt, fixture_path, slug_for
from bench.dataset import load_dataset, FIXTURES_DIR, VERDICTS, TRAP_VERDICTS


def evaluate(entry):
    """Replay one entry. Returns (predicted, reasons) or (None, why-missing)."""
    target = entry["target"]
    path = fixture_path(FIXTURES_DIR, slug_for(target))
    if not os.path.exists(path):
        return None, "no fixture"
    payload = load_cassette(path)
    github.set_clock(captured_dt(payload))
    try:
        cas = Cassette(store=payload.get("store", {}))
        verdict, err = scan(target, gh=cas)
    finally:
        github.set_clock(None)
    if err:
        return None, f"scan error: {err}"
    return verdict.verdict, verdict.reasons


def _matrix(rows):
    idx = {v: i for i, v in enumerate(VERDICTS)}
    m = [[0] * len(VERDICTS) for _ in VERDICTS]
    for exp, pred in rows:
        if exp in idx and pred in idx:
            m[idx[exp]][idx[pred]] += 1
    return m


def _prec_recall(m):
    out = {}
    for i, v in enumerate(VERDICTS):
        tp = m[i][i]
        col = sum(m[r][i] for r in range(len(VERDICTS)))   # predicted == v
        row = sum(m[i])                                     # actual == v
        prec = tp / col if col else None
        rec = tp / row if row else None
        out[v] = (prec, rec, row)
    return out


def _fmt(x):
    return "  -- " if x is None else f"{x:5.2f}"


def main(argv):
    verbose = "-v" in argv or "--verbose" in argv
    entries = load_dataset()
    rows, missing, scored = [], [], []
    false_green = []

    for e in entries:
        pred, info = evaluate(e)
        exp = e.get("expected")
        if pred is None:
            missing.append((e["target"], info))
            continue
        scored.append((e, pred))
        if exp:
            rows.append((exp, pred))
            if exp in TRAP_VERDICTS and pred == "ENGAGE":
                false_green.append(e["target"])
        if verbose:
            mark = "ok" if pred == exp else "XX"
            print(f"[{mark}] {e['target']:<38} exp={exp:<8} got={pred:<8} {e.get('trap_type','')}")
            for r in (info or [])[:4]:
                print(f"         - {r}")

    if verbose:
        print()
    n = len(rows)
    exact = sum(1 for a, b in rows if a == b)
    print("=" * 60)
    print(f"BENCHMARK  scored={len(scored)}  labeled={n}  missing_fixtures={len(missing)}")
    if missing:
        for t, why in missing:
            print(f"  MISSING  {t:<40} ({why})")
    print("-" * 60)
    print(f"FALSE-GREEN (ENGAGE on a trap): {len(false_green)}"
          + (f"  -> {false_green}" if false_green else "  [none]"))
    if n:
        print(f"EXACT MATCH: {exact}/{n} = {exact / n:.0%}")
        m = _matrix(rows)
        print("\nconfusion (rows=expected, cols=predicted):")
        print("            " + "".join(f"{v[:6]:>8}" for v in VERDICTS))
        for i, v in enumerate(VERDICTS):
            print(f"  {v:<10}" + "".join(f"{m[i][j]:>8}" for j in range(len(VERDICTS))))
        print("\nper-class   prec  recall   n")
        for v, (p, r, cnt) in _prec_recall(m).items():
            print(f"  {v:<10}{_fmt(p)} {_fmt(r)}  {cnt:>3}")
    print("=" * 60)

    # CI gate: the only hard failure is sending a contributor into a trap.
    return 1 if false_green else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
