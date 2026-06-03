# Canary benchmark

A reproducible, offline benchmark for the verdict gate. It exists to kill the
honest caveat from the early probes — *"small, self-selected sample + self-chosen
thresholds = confirmation risk"* — by turning ad-hoc spot-checks into a labeled
dataset you can re-run deterministically and measure.

## How it works

The signal pipeline is already pure (signals + scoring do no network; `scan()`
takes an injectable `gh` client). The benchmark exploits that:

1. **Capture** (`capture.py`, online, once) wraps the real GitHub client in a
   `Cassette` that records every API response a target touches into
   `fixtures/<slug>.json`, stamped with the capture time.
2. **Replay** (`run.py`, offline) feeds each cassette back through the *real*
   `scan()` pipeline with `github.set_clock()` frozen to the capture time, so
   age-based signals (owner age, push recency, fast growth) don't drift as the
   recorded repos keep ageing. Same fixture -> same verdict, forever.

Labels in `dataset.jsonl` are **ground truth** — what a contributor *should* do —
not the tool's current output. The benchmark measures the gap between them.

## Run it

```bash
python -m bench.capture          # snapshot fixtures for new dataset entries
python -m bench.capture --force  # refresh existing snapshots
python -m bench.run              # score: false-green, exact match, confusion
python -m bench.run -v           # + per-entry verdict and reasons
python bench/test_bench.py       # harness self-tests (offline, no fixtures needed)
```

## Metrics, in priority order

1. **False-green** — predicted `ENGAGE` on a trap. The one error that actually
   hurts a user (sends them into a swarm / honeypot / dead bounty). `run.py`
   exits non-zero if any occur — use it as a CI gate.
2. **Exact match** — predicted verdict == expected.
3. **Confusion matrix** + per-class precision/recall.

## Honest state (not done — started)

- Current dataset covers **ENGAGE** (legit repos) and **AVOID** (swarmed /
  assigned bounties). **CAUTION and UNKNOWN classes are not yet represented** —
  precision/recall for them is meaningless until the set grows.
- n is still small. This is infrastructure that makes growing n cheap, not proof
  that the gate is calibrated. Each new probe finding should land here as a row.
- Fixtures are raw API snapshots; busy issues (long timelines / comment threads)
  produce large files. Fine at this scale; revisit storage if the set reaches
  hundreds of entries.

## Adding a case

Append a line to `dataset.jsonl` (`target`, `expected`, `trap_type`, `source`,
`notes`), then `python -m bench.capture`. The API is the source of truth for
whether the target exists — a path it can't resolve is reported, never assumed.
