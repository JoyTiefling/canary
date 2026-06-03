"""Labeled benchmark dataset loader.

dataset.jsonl holds one JSON object per line:
  target     : 'owner/repo' or 'owner/repo#issue' (or full GitHub URL)
  expected   : ground-truth verdict a contributor SHOULD act on
               (ENGAGE | CAUTION | AVOID | UNKNOWN)
  trap_type  : taxonomy tag (legit / bounty-swarm / honeypot / fake-star / ...)
  source     : provenance — where this label came from (a probe, a blind test)
  notes      : human rationale

Labels are GROUND TRUTH, not the tool's current output. The benchmark measures
the gap between the two; that gap is the point."""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(_HERE, "dataset.jsonl")
FIXTURES_DIR = os.path.join(_HERE, "fixtures")

VERDICTS = ("ENGAGE", "CAUTION", "AVOID", "UNKNOWN")
# A trap is anything a contributor should not walk into; predicting ENGAGE on one
# is the critical "false-green" error the safety metric counts.
TRAP_VERDICTS = ("CAUTION", "AVOID", "UNKNOWN")


def load_dataset(path=DATASET_PATH):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{ln}: bad JSON: {e}") from e
            if "target" not in obj:
                raise ValueError(f"{path}:{ln}: entry missing 'target'")
            out.append(obj)
    return out
