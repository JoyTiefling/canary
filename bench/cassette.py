"""Record/replay shim for the GitHub client, injected into scan(gh=...).

One cassette holds every API response a single target touches, keyed by
method+args. Capture mode wraps a real GitHub and snapshots responses; replay
mode serves them from disk with NO network — so the benchmark is deterministic,
offline, and immune to rate limits. Pair with github.set_clock() to also freeze
time, otherwise age-based signals drift as the recorded repos keep ageing."""
import json
import os
from datetime import datetime, timezone


class Cassette:
    """Duck-types canary.github.GitHub. real=<client> records; real=None replays."""

    def __init__(self, store=None, real=None):
        self.store = store if store is not None else {}
        self.real = real  # set => capture mode; None => replay mode

    def _io(self, key, fetch):
        if self.real is not None:          # capture
            val = fetch()
            self.store[key] = val
            return val
        return self.store.get(key)         # replay (missing => None, i.e. "no data")

    def repo(self, o, n):
        return self._io(f"repo:{o}/{n}", lambda: self.real.repo(o, n))

    def user(self, login):
        return self._io(f"user:{login}", lambda: self.real.user(login))

    def releases(self, o, n):
        v = self._io(f"releases:{o}/{n}", lambda: self.real.releases(o, n))
        return v if isinstance(v, list) else []

    def issue(self, o, n, num):
        return self._io(f"issue:{o}/{n}#{num}", lambda: self.real.issue(o, n, num))

    def issue_comments(self, o, n, num):
        v = self._io(f"comments:{o}/{n}#{num}", lambda: self.real.issue_comments(o, n, num))
        return v if isinstance(v, list) else []

    def issue_timeline(self, o, n, num):
        # Distinguish "recorded as None" (timeline genuinely unavailable) from
        # "missing key": only fall back to None when truly absent in replay.
        key = f"timeline:{o}/{n}#{num}"
        if self.real is not None:
            val = self.real.issue_timeline(o, n, num)
            self.store[key] = val
            return val
        return self.store.get(key)

    def remaining(self):
        return self._io("remaining", lambda: self.real.remaining())


# ---------- disk format ----------
# A cassette file bundles the recorded store with the capture timestamp (for the
# frozen clock) and the target string, so replay is fully self-describing.

def fixture_path(fixtures_dir, slug):
    return os.path.join(fixtures_dir, slug + ".json")


def slug_for(target):
    """Filesystem-safe slug for a target string ('o/r#59' -> 'o__r__59')."""
    return target.replace("/", "__").replace("#", "__").replace(" ", "")


def save_cassette(path, target, store, captured_at=None):
    captured_at = captured_at or datetime.now(timezone.utc).isoformat()
    payload = {"target": target, "captured_at": captured_at, "store": store}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1, sort_keys=True)
    return payload


def load_cassette(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def captured_dt(payload):
    """Parse captured_at into a tz-aware datetime for github.set_clock()."""
    iso = payload.get("captured_at")
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None
