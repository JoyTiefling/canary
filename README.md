# 🐤 Canary

**Should I — or my agent — engage with this repo/bounty, or is it a trap?**

Canary gives a fast trust verdict (`ENGAGE` / `CAUTION` / `AVOID` / `UNKNOWN`) for a
GitHub repository or bounty *before* you sink hours (or tokens) into it. It's built
for the open-source contributor and for the autonomous coding agent that now picks
its own work — neither of whom can trust surface signals anymore (stars are faked,
bounties go unpaid, popular issues are swarmed, honeypots target agents).

```bash
python -m canary facebook/react
# [ENGAGE]  (risk 0.05, confidence 0.85)

# a swarmed bounty looks like this (illustrative output; use a real owner/repo#issue):
python -m canary <owner>/<repo>#<issue>
# [AVOID]  (risk 0.97, confidence 1.00)
#    • veto: contention — many open attempts, no payout yet (swarmed bounty)

python -m canary --json <owner>/<repo>#<issue>   # machine-readable, for agents
```

## What it checks (risk dimensions, not one blended number)
- **authenticity** — fake-star proxy (fork:star), fast-growth anomalies, releases,
  owner account age. *(Reuses the Dagster/StarScout fork:star heuristic — not reinvented.)*
- **responsiveness** — is the maintainer actually alive (recent pushes)?
- **honeypot** — agent-bait labels ("Autonomous Agents Only", "crypto-eligible") +
  bot/throwaway authors.
- **availability** — already assigned, or reserved (e.g. hiring-only) bounties.
- **contention** — how swarmed is this bounty? (Algora `/attempt` density today;
  generalizing to native open-PR/claimant counts on any issue.)

## The one rule that matters
**Canary never says "go" on missing data.** If it can't gather enough signal, the
verdict is `UNKNOWN`, not `ENGAGE`. Absence of evidence is not evidence of safety —
a false green sends you into a trap. (The #1 lesson from validating the approach.)

## Use as an MCP server (for agents)
Expose Canary as a tool an autonomous agent calls *before* engaging a repo/bounty:

```bash
pip install mcp           # only needed for the server transport
python -m canary.mcp_server   # stdio
```
Tool: `canary_check(target, verbose=False)` → `{verdict, engage, risk, confidence, reasons}`.
`engage` is the go/no-go boolean; `UNKNOWN` means "not cleared", never treat as safe.
This is the point of Canary: a pre-engagement trust gate for the autonomous agents
that now pick their own work and can't tell a real bounty from a swarm or a honeypot.

## Architecture
Platform-agnostic core (universal GitHub signals) + pluggable context modules.
**Algora** is the first bounty module; the design is not bound to it (Opire,
IssueHunt, and non-bounty "should my agent touch this repo at all" are next).

## Status
Early MVP. Signal set validated on a small labeled sample (promising, not proof —
expanding the test set). CLI and MCP server both work today. Roadmap: harden Algora
extraction · native contention fallback via linked PRs · larger labeled benchmark ·
more platform modules (Opire, IssueHunt).

## Install / run
No third-party deps. Python 3.10+. `python -m canary <target>`.
Set `GITHUB_TOKEN` to raise the API rate limit.

---
*Built by JoyTiefling. Contributions and skepticism welcome.*
