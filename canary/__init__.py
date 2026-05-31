"""Canary — contributor/agent-facing trust verdict for open-source repos & bounties.

Answers ONE question: "Should I (or my agent) engage with this repo/bounty, or is it
a trap / dead-end / swarm / non-payer?" — synthesizing fraud, economics, and
responsiveness signals into ENGAGE / CAUTION / AVOID / UNKNOWN.

Design principles (validated empirically):
  1. Platform-agnostic core + pluggable context modules (Algora is the first module).
  2. Data-absence is a FIRST-CLASS state — never emit a 'go' verdict on missing data.
     Unknown stays UNKNOWN. (The cardinal sin is false-green.)
  3. Separate risk dimensions (authenticity / contention / honeypot / availability),
     not one blended number. The worst dimension can veto.
  4. Reuse prior art for solved sub-signals (fake-star: Dagster/StarScout) — don't
     reinvent. Differentiation lives in the decision layer + bounty economics.
"""
__version__ = "0.0.1"
