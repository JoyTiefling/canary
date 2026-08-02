"""Pure aggregation: SignalResult[] -> Verdict. No network. The heart of the
'never false-green on missing data' principle lives here."""
from dataclasses import dataclass, field

MIN_CONFIDENCE = 0.35   # below this much signal coverage -> UNKNOWN, never a 'go'
ENGAGE_MAX = 0.30       # overall risk below this -> ENGAGE
CAUTION_MAX = 0.55      # below this -> CAUTION, else AVOID
SINGLE_BLOCK_MIN = 0.55  # one HARD signal this hot downgrades a clean ENGAGE (see below)

# A single dimension this risky vetoes a green verdict.
# `availability` = is this *work item* free to take (assignee/reserved label).
# `engageability` = can a contribution land in this *repo* at all (archived/disabled).
# They are separate dimensions on purpose: required_dims matches by dimension,
# so sharing one would let a live issue satisfy the repo-level requirement.
VETO = {"honeypot": 0.8, "contention": 0.8, "availability": 0.8, "engageability": 0.8}


# Which rule decided the verdict. The verdict class alone does not say this:
# CAUTION can come from the risk ladder (accumulated weighted risk landed in the
# band) or from single_block (one categorical signal downgraded a clean go), and
# AVOID can come from a dimension veto or from the top of the same ladder. Those
# are different code paths with different failure modes, and until 2026-08-03 the
# only way to tell them apart was to mutate a threshold and see whether any row
# moved. Recording provenance makes "which rules has the bench ever exercised"
# answerable from a run instead of from a sweep. See bench/test_thresholds.py.
RULES = (
    "veto",             # a dimension-level hard signal >= VETO[dim]
    "missing_required", # a required dimension had no available signal
    "no_signal",        # nothing available at all -> no risk could be computed
    "low_confidence",   # some data, but too little weight covered to assert safety
    "ladder:engage",    # weighted risk < ENGAGE_MAX
    "ladder:caution",   # ENGAGE_MAX <= weighted risk < CAUTION_MAX
    "ladder:avoid",     # weighted risk >= CAUTION_MAX
    "single_block",     # ladder said ENGAGE, one hard signal >= SINGLE_BLOCK_MIN downgraded it
)


@dataclass
class Verdict:
    verdict: str          # ENGAGE | CAUTION | AVOID | UNKNOWN
    risk: float | None    # overall weighted risk of available signals
    confidence: float     # share of total weight that had data
    reasons: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    rule: str = ""        # one of RULES — which branch produced `verdict`


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
        verdict, rule = "AVOID", "veto"
        reasons.append(f"veto: {veto_hit.name} ({veto_hit.dimension}) risk={veto_hit.risk:.2f} -- {veto_hit.detail}")
    elif missing_required:
        verdict, rule = "UNKNOWN", "missing_required"
        reasons.append(f"required signal(s) unavailable: {missing_required} -- cannot assert engageability (absence != safe)")
    elif overall is None:
        verdict, rule = "UNKNOWN", "no_signal"
        reasons.append("no signal produced a risk value; nothing to assert safety from")
    elif confidence < MIN_CONFIDENCE:
        verdict, rule = "UNKNOWN", "low_confidence"
        reasons.append(f"insufficient data (confidence {confidence:.2f} < {MIN_CONFIDENCE}); not asserting safety")
    elif overall < ENGAGE_MAX:
        verdict, rule = "ENGAGE", "ladder:engage"
    elif overall < CAUTION_MAX:
        verdict, rule = "CAUTION", "ladder:caution"
    else:
        verdict, rule = "AVOID", "ladder:avoid"

    # A single elevated HARD signal blocks a clean ENGAGE — for a trust tool the
    # worst categorical signal matters more than the average (else many low repo
    # signals dilute one real red flag, e.g. two open linked PRs on an otherwise-
    # fine repo). SOFT (probabilistic) signals are scoped OUT of this rule
    # (DESIGN §8, calibrated 2026-07-23): a probability tilt at 0.55 adds weighted
    # risk and can pair with peers into a real CAUTION/AVOID, but cannot veto a
    # clean go on its own. Dimension veto (>= 0.80) above remains signal-agnostic.
    if verdict == "ENGAGE":
        hot = max((s.risk for s in avail if s.hard), default=0.0)
        if hot >= SINGLE_BLOCK_MIN:
            verdict, rule = "CAUTION", "single_block"
            reasons.append(f"downgraded to CAUTION: a single categorical signal at risk {hot:.2f} blocks a clean go")

    # Surface the top contributing risks for explainability.
    for s in sorted(avail, key=lambda x: (x.risk * x.weight), reverse=True)[:4]:
        if s.risk >= 0.4:
            reasons.append(f"{s.dimension}/{s.name}: {s.detail} (risk {s.risk:.2f})")
    # Note any unavailable high-weight signals (transparency about blind spots).
    blind = [s for s in signals if not s.available and s.weight >= 0.5]
    for s in blind:
        reasons.append(f"blind spot — {s.name}: {s.detail}")

    return Verdict(verdict, overall, confidence, reasons, signals, rule)
