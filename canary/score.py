"""Pure aggregation: SignalResult[] -> Verdict. No network. The heart of the
'never false-green on missing data' principle lives here."""
from dataclasses import dataclass, field

MIN_CONFIDENCE = 0.35   # below this much signal coverage -> UNKNOWN, never a 'go'
ENGAGE_MAX = 0.30       # overall risk below this -> ENGAGE
CAUTION_MAX = 0.55      # below this -> CAUTION, else AVOID

# A single dimension this risky vetoes a green verdict.
VETO = {"honeypot": 0.8, "contention": 0.8, "availability": 0.8}


@dataclass
class Verdict:
    verdict: str          # ENGAGE | CAUTION | AVOID | UNKNOWN
    risk: float | None    # overall weighted risk of available signals
    confidence: float     # share of total weight that had data
    reasons: list = field(default_factory=list)
    signals: list = field(default_factory=list)


def aggregate(signals, required_dims=()):
    """required_dims: dimensions that MUST have at least one available signal for a
    'go' verdict. For an issue/bounty target, contention is required — if we couldn't
    measure how swarmed it is, we cannot ENGAGE (absence != safe)."""
    avail = [s for s in signals if s.available and s.risk is not None]
    total_w = sum(s.weight for s in signals) or 1.0
    avail_w = sum(s.weight for s in avail)
    confidence = avail_w / total_w
    overall = (sum(s.risk * s.weight for s in avail) / avail_w) if avail_w else None

    reasons = []
    # Hard vetoes first (safe-side: a honeypot/swarm/assigned hit AVOIDs regardless).
    veto_hit = None
    for s in avail:
        thr = VETO.get(s.dimension)
        if thr is not None and s.risk >= thr:
            veto_hit = s
            break

    missing_required = [d for d in required_dims
                        if not any(s.available and s.dimension == d for s in signals)]

    if veto_hit:
        verdict = "AVOID"
        reasons.append(f"veto: {veto_hit.name} ({veto_hit.dimension}) risk={veto_hit.risk:.2f} -- {veto_hit.detail}")
    elif missing_required:
        verdict = "UNKNOWN"
        reasons.append(f"required signal(s) unavailable: {missing_required} -- cannot assert engageability (absence != safe)")
    elif confidence < MIN_CONFIDENCE or overall is None:
        verdict = "UNKNOWN"
        reasons.append(f"insufficient data (confidence {confidence:.2f} < {MIN_CONFIDENCE}); not asserting safety")
    elif overall < ENGAGE_MAX:
        verdict = "ENGAGE"
    elif overall < CAUTION_MAX:
        verdict = "CAUTION"
    else:
        verdict = "AVOID"

    # A single elevated signal blocks a clean ENGAGE — for a trust tool the worst
    # signal matters more than the average (else many low repo signals dilute one
    # real red flag, e.g. an open linked PR on an otherwise-fine repo).
    if verdict == "ENGAGE":
        hot = max((s.risk for s in avail), default=0.0)
        if hot >= 0.55:
            verdict = "CAUTION"
            reasons.append(f"downgraded to CAUTION: a single signal at risk {hot:.2f} blocks a clean go")

    # Surface the top contributing risks for explainability.
    for s in sorted(avail, key=lambda x: (x.risk * x.weight), reverse=True)[:4]:
        if s.risk >= 0.4:
            reasons.append(f"{s.dimension}/{s.name}: {s.detail} (risk {s.risk:.2f})")
    # Note any unavailable high-weight signals (transparency about blind spots).
    blind = [s for s in signals if not s.available and s.weight >= 0.5]
    for s in blind:
        reasons.append(f"blind spot — {s.name}: {s.detail}")

    return Verdict(verdict, overall, confidence, reasons, signals)
