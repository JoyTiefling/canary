"""Canary MCP server — exposes the trust verdict as a tool autonomous agents call
*before* engaging an open-source repo or bounty. The whole point of Canary in one
endpoint: a pre-engagement gate so an agent doesn't walk into a trap/dead-end/swarm.

Run:  python -m canary.mcp_server      (stdio transport)
Needs the `mcp` SDK (FastMCP). Core scanning has no third-party deps; only the
server transport does.
"""
from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from .scan import scan
from .score import Verdict

mcp = FastMCP("canary")


def _to_dict(target, v: Verdict, verbose=False):
    d = {
        "target": target,
        "verdict": v.verdict,                 # ENGAGE | CAUTION | AVOID | UNKNOWN
        "engage": v.verdict == "ENGAGE",       # go/no-go gate for an agent
        "risk": round(v.risk, 3) if v.risk is not None else None,
        "confidence": round(v.confidence, 3),
        "reasons": v.reasons,
    }
    if verbose:
        d["signals"] = [
            {"name": s.name, "dimension": s.dimension, "available": s.available,
             "risk": s.risk, "weight": s.weight, "detail": s.detail}
            for s in v.signals
        ]
    return d


@mcp.tool()
def canary_check(
    target: Annotated[
        str,
        Field(
            description=(
                "The GitHub repository or bounty issue to assess. Accepts a full URL "
                "(https://github.com/owner/repo or .../issues/123) or the shorthand "
                "'owner/repo' (repo-level check) / 'owner/repo#123' (bounty/issue-level "
                "check). Issue-level targets additionally require the 'contention' "
                "dimension: if how-contested-the-bounty-is cannot be measured, the "
                "verdict is UNKNOWN rather than a possibly-false ENGAGE."
            ),
        ),
    ],
    verbose: Annotated[
        bool,
        Field(
            description=(
                "When true, include the full per-signal breakdown under 'signals' "
                "(each signal's name, risk dimension, availability, 0..1 risk, weight, "
                "and a human detail). Use to explain or audit a verdict; leave false "
                "for a compact go/no-go answer."
            ),
        ),
    ] = False,
) -> dict:
    """Decide whether to engage a GitHub repo or bounty BEFORE spending effort or tokens.

    Call this as a pre-engagement gate: before attempting a bounty, cloning, depending
    on, or contributing to an unfamiliar repository. Surface trust signals (stars,
    activity, labels) are gameable and increasingly AI-faked; this tool synthesizes
    authenticity, responsiveness, honeypot, availability, and contention signals into a
    single decision so you can avoid scams, swarmed (dead-end) bounties, non-payers, and
    agent honeypots. Reads only public GitHub data; makes no changes.

    Verdict meanings (returned in `verdict`):
        ENGAGE  — signals are clean and sufficient; safe to proceed. `engage` is True.
        CAUTION — proceed only with scrutiny; at least one elevated risk or a downgrade
                  from a single hot signal. Not a hard stop, but do not automate past it.
        AVOID   — a hard red flag fired (honeypot label + bot author, swarmed bounty,
                  already-assigned/reserved, or overall risk in the AVOID band). Do not engage.
        UNKNOWN — not enough data to judge (low confidence, or a required dimension such
                  as contention had no signal). Treat as "NOT cleared" — never as safe.

    Cardinal rule: the tool never returns ENGAGE on missing data. Absence of evidence is
    not evidence of safety, so gaps resolve to UNKNOWN, not a false green.

    Returns a dict:
        target:     the input, echoed back.
        verdict:    "ENGAGE" | "CAUTION" | "AVOID" | "UNKNOWN" (see above).
        engage:     bool — True only when verdict == "ENGAGE". Your direct go/no-go gate.
        risk:       float 0..1 overall weighted risk (higher = more reason to avoid), or
                    null when nothing could be scored.
        confidence: float 0..1 — share of signal weight that had data behind it.
        reasons:    list[str] — human-readable drivers (vetoes, top risks, blind spots).
        signals:    (only when verbose=True) the full per-signal breakdown.

    Tip: set GITHUB_TOKEN in the server environment to raise the GitHub API rate limit.
    """
    v, err = scan(target)
    if err:
        return {"target": target, "verdict": "UNKNOWN", "engage": False,
                "risk": None, "confidence": 0.0, "reasons": [f"error: {err}"]}
    return _to_dict(target, v, verbose)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
