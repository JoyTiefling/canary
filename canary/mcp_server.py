"""Canary MCP server — exposes the trust verdict as a tool autonomous agents call
*before* engaging an open-source repo or bounty. The whole point of Canary in one
endpoint: a pre-engagement gate so an agent doesn't walk into a trap/dead-end/swarm.

Run:  python -m canary.mcp_server      (stdio transport)
Needs the `mcp` SDK (FastMCP). Core scanning has no third-party deps; only the
server transport does.
"""
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
def canary_check(target: str, verbose: bool = False) -> dict:
    """Assess whether to engage a GitHub repo or bounty BEFORE investing effort/tokens.

    Use this before attempting a bounty, cloning, depending on, or contributing to an
    unfamiliar repository. Returns a trust verdict so you can avoid scams, dead-end
    (swarmed) bounties, non-payers, and agent honeypots.

    Args:
        target: GitHub repo/issue URL, or shorthand "owner/repo" or "owner/repo#issue".
        verbose: include the full per-signal breakdown.

    Returns a dict with:
        verdict: ENGAGE | CAUTION | AVOID | UNKNOWN
        engage:  bool — True only when verdict is ENGAGE (your go/no-go gate)
        risk:    0..1 overall risk (higher = avoid), or null
        confidence: 0..1 how much signal was available
        reasons: human-readable explanations
    IMPORTANT: a verdict of UNKNOWN means there was not enough data to judge — treat
    it as "not cleared", never as safe.
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
