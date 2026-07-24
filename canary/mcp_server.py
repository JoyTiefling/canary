"""Canary MCP server — exposes the trust verdict as a tool autonomous agents call
*before* engaging an open-source repo or bounty. The whole point of Canary in one
endpoint: a pre-engagement gate so an agent doesn't walk into a trap/dead-end/swarm.

Run:  python -m canary.mcp_server      (stdio transport)
Needs the `mcp` SDK (FastMCP) ≥ 1.10 (for structured tool output). Core scanning
has no third-party deps; only the server transport does.
"""
from typing import Annotated, Literal, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from .scan import scan
from .score import Verdict

mcp = FastMCP("canary")

VerdictLiteral = Literal["ENGAGE", "CAUTION", "AVOID", "UNKNOWN"]


class SignalOutput(BaseModel):
    """One evidence signal contributing to the verdict.

    Emitted only when the caller requests verbose=True; otherwise the compact
    verdict fields are enough for an agent's go/no-go decision.
    """
    name: str = Field(description="Signal identifier, e.g. 'sig_owner_bounty_flood'.")
    dimension: str = Field(
        description=(
            "Risk dimension the signal contributes to: "
            "authenticity, responsiveness, honeypot, contention, availability, swarm."
        ),
    )
    available: bool = Field(
        description="Whether the underlying data was fetched. Unavailable signals are excluded from scoring — never treated as safe.",
    )
    risk: Optional[float] = Field(
        default=None,
        description="Signal risk 0..1 (higher = more reason to AVOID). Null when available=False.",
    )
    weight: float = Field(description="Weight of this signal in the overall aggregate.")
    detail: str = Field(description="Human-readable explanation of what the signal saw.")
    hard: bool = Field(
        default=True,
        description=(
            "Evidentiary character: true = categorical evidence / direct observation "
            "(can single-handedly downgrade a clean ENGAGE); false = probabilistic tilt "
            "(contributes weighted risk, cannot veto alone)."
        ),
    )


class VerdictOutput(BaseModel):
    """Trust verdict for a GitHub repository or bounty issue.

    Cardinal rule: never `ENGAGE` on missing data. Absence of evidence is not
    evidence of safety — gaps resolve to `UNKNOWN`, not a false green.
    """
    target: str = Field(description="The input target echoed back (URL or owner/repo[#issue]).")
    verdict: VerdictLiteral = Field(
        description=(
            "Overall trust verdict:\n"
            "  ENGAGE  — clean, sufficient signal; safe to proceed.\n"
            "  CAUTION — proceed only with scrutiny; do not automate past it.\n"
            "  AVOID   — hard red flag (honeypot, swarm, reserved, high risk band).\n"
            "  UNKNOWN — not enough data or a required dimension missing. Treat as NOT cleared, never safe."
        ),
    )
    engage: bool = Field(
        description="Direct go/no-go gate. True only when verdict == 'ENGAGE'.",
    )
    risk: Optional[float] = Field(
        default=None,
        description="Overall weighted risk 0..1 across available signals (higher = more reason to avoid). Null if nothing could be scored.",
    )
    confidence: float = Field(
        description="Share of total signal weight that had data behind it, 0..1.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable drivers of the verdict: vetoes, top risks, blind spots.",
    )
    signals: Optional[list[SignalOutput]] = Field(
        default=None,
        description="Full per-signal breakdown. Populated only when the tool was called with verbose=True; otherwise null.",
    )


def _to_verdict_output(target: str, v: Verdict, verbose: bool = False) -> VerdictOutput:
    """Convert an internal Verdict into the tool's typed output shape.

    Kept as a standalone helper (not inlined into the tool) so unit tests can
    exercise the shaping without spinning up the MCP transport.
    """
    return VerdictOutput(
        target=target,
        verdict=v.verdict,
        engage=v.verdict == "ENGAGE",
        risk=round(v.risk, 3) if v.risk is not None else None,
        confidence=round(v.confidence, 3),
        reasons=list(v.reasons),
        signals=[
            SignalOutput(
                name=s.name,
                dimension=s.dimension,
                available=s.available,
                risk=s.risk,
                weight=s.weight,
                detail=s.detail,
                hard=s.hard,
            )
            for s in v.signals
        ] if verbose else None,
    )


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
) -> VerdictOutput:
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

    Do NOT call when:
        - Target is not a GitHub URL/shorthand (e.g. GitLab, Bitbucket, a package name
          without a repo). Verdict will be UNKNOWN with an error — wastes a round-trip.
        - Repo is private. The tool sees only the public API surface, so the answer
          will be UNKNOWN even if the repo is fine.
        - You (or another agent in this session) already checked the same target within
          the last ~30-60 minutes. Repo-level signals (owner age, releases, activity)
          move slowly; cache the previous verdict. Exception: an issue-level check
          where new attempts may have landed since — re-check is warranted.
        - Target is a known upstream you already depend on and trust. Canary is a
          *pre-engagement* gate for unfamiliar repos/bounties, not a re-audit tool for
          codebases already in your dependency graph.

    Returns a typed `VerdictOutput` (see fields on that model). The SDK emits the
    structured object as `structuredContent` on the tool result and advertises the
    schema via `outputSchema`, so callers who want the object can consume it directly
    rather than parsing the text form.

    Tip: set GITHUB_TOKEN in the server environment to raise the GitHub API rate limit.
    Approx cost per call: 1-3 unauth GitHub API calls at the repo level, +2-3 more
    for an issue-level (`owner/repo#N`) target; wall-clock ~1-3 s. Verdict is stable
    across minutes/hours because the underlying signals move slowly (owner age,
    releases, activity band); the fastest-moving component is the attempts count on
    issue-level checks — cache repo-level verdicts freely, refresh issue-level ones
    when new attempts may have landed.
    """
    v, err = scan(target)
    if err:
        return VerdictOutput(
            target=target,
            verdict="UNKNOWN",
            engage=False,
            risk=None,
            confidence=0.0,
            reasons=[f"error: {err}"],
            signals=None,
        )
    return _to_verdict_output(target, v, verbose)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
