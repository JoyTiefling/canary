# Pre-registration — archived repos (2026-07-31, solo wake)

Written **before** running `scan()` on the target. Recorded so the result cannot
be reinterpreted after the fact.

## What made me look

Grepped `canary/*.py` for `archived` / `disabled`: **zero hits**. The GitHub repo
payload carries `"archived": true`, and the pipeline never reads it. GitHub
*blocks* new pull requests and issues on an archived repo — contribution is not
risky there, it is **impossible**. That is the cheapest possible ground truth,
and the gate is structurally blind to it.

## Target

`alibaba/fastjson` — chosen adversarially, not randomly: archived, yet
`pushed_at = 2026-07-29` (two days before this probe), 25 611 stars / 6 404
forks (healthy ratio), owner `alibaba` (long-established org), releases present.
Every datum the gate *does* read looks pristine. If the gate ever produces a
false-green from ignoring `archived`, it produces it here.

Selected via GitHub search `archived:true stars:>5000 pushed:>2026-03-01`
(75 hits) — the freshest-pushed large repo in the result set.

## Hypothesis H1

`scan()` ignores `archived`, so a recently-archived healthy repo scores
**ENGAGE** with high confidence.

## Prediction (before running)

- verdict: `ENGAGE`
- no reason string mentions archival or read-only state
- confidence: high (all repo-level dimensions populated)

## Ground truth label for the bench

- expected: `AVOID`
- trap_type: `archived-readonly`
- rationale: a PR cannot be opened at all; sending a contributor there is a
  guaranteed waste, not a probability.

## Falsifier

If `scan()` returns AVOID or CAUTION **for a reason that actually names the
archived/read-only state**, H1 is wrong and no fix is needed. A CAUTION arriving
via `push_recency` or any other unrelated signal does **not** falsify H1 — that
is honesty by coincidence of threshold (the `sig_fake_star({})` pattern from
2026-07-29), and must be recorded as such.

## Second target (negative control)

`localstack/localstack` — archived, but `pushed_at = 2026-03-23` (stale). If the
fix is real it must flag this one *for the archival reason*, not for staleness.
Kept as the discriminating pair: same ground truth, different accidental signals.
