# 🐤 Canary

**Should I — or my agent — engage with this repo or bounty, or is it a trap?**

<!-- mcp-name: io.github.JoyTiefling/canary -->

Canary gives a fast trust verdict — `ENGAGE` / `CAUTION` / `AVOID` / `UNKNOWN` — for a
GitHub repository or bounty *before* you sink hours (or tokens) into it.

## The problem it solves

Surface trust signals are gameable and now routinely AI-faked. Stars are bought,
bounties go unpaid, popular issues are silently swarmed by a dozen contenders, and a new
class of "honeypot" issues is built specifically to lure autonomous coding agents into
dead-end work. There's no shortage of *security* scanners (CVEs, malware, best-practice
scorecards) — but none of them answer the **decision** an individual contributor or an
agent actually faces at the moment of engagement:

> *Is this specific repo/bounty worth my effort, or am I about to walk into a scam,
> a swarm, a non-payer, or a trap?*

Canary is that pre-engagement trust layer. It's built for the open-source contributor
and, especially, for the autonomous coding agent that now picks its own work and can't
tell a real bounty from bait.

## The verdicts

| Verdict     | Meaning                                                                             |
| ----------- | ----------------------------------------------------------------------------------- |
| **ENGAGE**  | Signals clean and sufficient — safe to proceed.                                     |
| **CAUTION** | Proceed only with scrutiny; an elevated risk or a single hot signal. Don't automate past it. |
| **AVOID**   | A hard red flag (honeypot, swarmed bounty, already-taken) or overall high risk. Don't engage. |
| **UNKNOWN** | Not enough data to judge. Treated as *not cleared* — **never** as safe.             |

## The one rule that matters

**Canary never says "go" on missing data.** If it can't gather enough signal, the
verdict is `UNKNOWN`, not `ENGAGE`. Absence of evidence is not evidence of safety — a
false green is what sends you into the trap. This rule is enforced on every code path,
not patched in one place. (It's the hardest-won lesson from building the tool.)

## What it checks (separate risk dimensions, not one blended number)

The worst dimension can veto a verdict — a single real red flag must not be averaged
away by many benign signals.

- **authenticity** — owner account age (with a push-trajectory adjustment so a legit
  young owner can *earn* trust), releases vs. repo age, fast-growth anomalies, and a
  fork:star fake-star proxy (the Dagster/StarScout heuristic — reused, not reinvented).
- **responsiveness** — is the maintainer actually alive (recent pushes)?
- **honeypot** — agent-bait labels ("Autonomous Agents Only", "crypto-eligible",
  "AI agent friendly") combined with bot / throwaway authors.
- **availability** — already assigned, or reserved (e.g. hiring-only) bounties.
- **contention** — how swarmed is this bounty? Algora `/attempt` density, open linked
  PRs on the issue, and owner-level bounty-flood (one owner farming many bounties at once).

## Install & run (CLI)

Requires Python 3.10+.

```bash
# from source, zero install — the scanner core is pure standard library:
python -m canary facebook/react
# [ENGAGE]  (risk 0.05, confidence 0.85)

# or install from PyPI:
pip install canary-trust
canary facebook/react
```

Check a specific bounty/issue, and get machine-readable output for an agent:

```bash
canary owner/repo#123          # bounty/issue-level check (adds contention signals)
canary --json owner/repo#123   # JSON for programmatic use
```

Exit codes: `0` ENGAGE · `1` CAUTION · `2` AVOID · `3` UNKNOWN/error.
Set `GITHUB_TOKEN` to raise the GitHub API rate limit.

## Verdicts in the wild

Illustrative outputs from the reproducible benchmark (`bench/dataset.jsonl`) —
same fixtures, same clock, same verdicts, forever. Reasons are the real ones the
scorer produced, not marketing copy.

```
$ canary tscircuit/tscircuit#328
[AVOID]  (risk 0.85, confidence 0.95)
  - veto: assigned_reserved (availability) — already assigned to seveibar
  - contention: 22 Algora attempts (risk 0.97)
  - contention: 6 open linked PRs — swarmed (risk 0.90)

$ canary ritesh-1918/HELPDESK.AI#1411
[AVOID]  (risk 0.92, confidence 0.90)
  - veto: owner_bounty_flood — 144 open bounties from this owner (farm)
  - contention: 2 open linked PRs

$ canary JoyTiefling/canary
[CAUTION]  (risk ~0.32, confidence moderate)
  - authenticity/owner_age: owner <30d, cold-start band — trajectory
    cannot compensate by design (this is the correct output, not a bug)
```

That last one is Canary's dogfood: **the tool flags its own new owner as
CAUTION.** Conservatism on unknown-new-owners is the feature, not a false
positive — a blind LLM agent visiting an unknown new repo should be told to
look twice, including at us.

On the current 11-entry seed dataset (5 ENGAGE / 2 CAUTION / 4 AVOID) the gate
scores **100% exact match, 0 false-green**. n is small — this is
infrastructure that makes n cheap to grow, not proof that the signal set is
calibrated. See [`bench/README.md`](bench/README.md) for the honest state and
how to add a case.

## Use as an MCP server (for agents)

Expose Canary as a tool an autonomous agent calls *before* engaging a repo or bounty.
Add it to your MCP client config:

```json
{
  "mcpServers": {
    "canary": {
      "command": "uvx",
      "args": ["canary-trust"]
    }
  }
}
```

Or run the stdio server directly:

```bash
uvx canary-trust                 # installed from PyPI
python -m canary.mcp_server      # from source
```

**Tool:** `canary_check(target, verbose=False)` →
`{ verdict, engage, risk, confidence, reasons }`.
`engage` is a plain go/no-go boolean, `True` only on `ENGAGE`. `UNKNOWN` means
"not cleared" — an agent must never treat it as safe.

## Architecture

Platform-agnostic core (universal GitHub signals) + pluggable context modules.
**Algora** is the first bounty module; the design is not bound to it (Opire, IssueHunt,
and non-bounty "should my agent touch this repo at all" are the intended next modules).
The scanner core imports nothing outside the standard library, so it's easy to audit
and vendor; only the MCP server transport pulls in the `mcp` SDK.

## Status & honest limitations

Early MVP — the CLI and MCP server both work today.

- The signal set is validated on a **small labeled sample**: promising, not proof. The
  labeled benchmark is still being grown across all verdict classes.
- Contention outside Algora relies on linked-PR / bounty-flood proxies; other bounty
  platforms' label formats aren't parsed yet (missing data → UNKNOWN, never a false green).
- Some calibration boundaries (e.g. the legit-vs-farm bounty-flood band) are judgement
  calls not yet anchored against a known-legitimate high-volume owner.

If you hit a case Canary gets wrong, that's the most useful thing you can report.

## License

MIT © 2026 JoyTiefling. Contributions and skepticism welcome.
