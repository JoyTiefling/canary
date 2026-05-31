"""`canary <github-url-or-owner/repo[#n]>` — prints a trust verdict.
JSON with --json. Exit code: 0 ENGAGE, 1 CAUTION, 2 AVOID, 3 UNKNOWN/error."""
import sys, json, argparse
from .scan import scan

_EXIT = {"ENGAGE": 0, "CAUTION": 1, "AVOID": 2, "UNKNOWN": 3}
_TAG = {"ENGAGE": "[ENGAGE]", "CAUTION": "[CAUTION]", "AVOID": "[AVOID]", "UNKNOWN": "[UNKNOWN]"}


def main(argv=None):
    # Be robust on legacy Windows consoles (cp1251 etc.): never crash on output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="canary", description="Trust verdict for an OSS repo/bounty before you engage.")
    ap.add_argument("target", help="github repo/issue URL, or owner/repo[#issue]")
    ap.add_argument("--json", action="store_true", help="machine-readable output (for agents)")
    args = ap.parse_args(argv)

    v, err = scan(args.target)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({
            "verdict": v.verdict,
            "risk": round(v.risk, 3) if v.risk is not None else None,
            "confidence": round(v.confidence, 3),
            "reasons": v.reasons,
            "signals": [
                {"name": s.name, "dimension": s.dimension, "available": s.available,
                 "risk": s.risk, "weight": s.weight, "detail": s.detail}
                for s in v.signals
            ],
        }, ensure_ascii=False, indent=2))
        return _EXIT.get(v.verdict, 3)

    risk = f"{v.risk:.2f}" if v.risk is not None else "n/a"
    print(f"{_TAG.get(v.verdict, v.verdict)}  (risk {risk}, confidence {v.confidence:.2f})")
    for r in v.reasons:
        print(f"   • {r}")
    return _EXIT.get(v.verdict, 3)


if __name__ == "__main__":
    sys.exit(main())
