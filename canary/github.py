"""Minimal GitHub REST client + target URL parsing. Unauth by default (60/hr);
set GITHUB_TOKEN for higher limits. No third-party deps."""
import os, json, time, re, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone

_API = "https://api.github.com"
_UA = "canary/0.0.1"


class GitHub:
    def __init__(self, token=None):
        self.token = token or os.environ.get("GITHUB_TOKEN")

    def _get(self, path):
        req = urllib.request.Request(
            _API + path,
            headers={"User-Agent": _UA, "Accept": "application/vnd.github+json"},
        )
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.load(r), r.status
        except urllib.error.HTTPError as e:
            return None, e.code
        except Exception:
            return None, None

    def repo_ex(self, owner, name):
        """(data, http_status) for a repo lookup. `status` in (404, 403, 451) means
        GitHub ANSWERED and the repo is not visible to us — a recorded fact. `status
        is None` means we never got an answer (DNS, timeout, offline) — an absence of
        data about an absence. `repo()` below collapses both to None on purpose: the
        verdict is UNKNOWN either way, so the signal layer must not branch on it. The
        benchmark does need them apart — it may only record a fixture for the first
        kind, or it would freeze a network hiccup into ground truth."""
        return self._get(f"/repos/{owner}/{name}")

    def repo(self, owner, name):
        d, _ = self.repo_ex(owner, name)
        return d

    def remaining(self):
        """Core rate-limit remaining (the /rate_limit endpoint itself is free)."""
        d, _ = self._get("/rate_limit")
        try:
            return d["resources"]["core"]["remaining"]
        except Exception:
            return None

    def user(self, login):
        d, _ = self._get(f"/users/{login}")
        return d

    def events(self, login, per_page=100):
        """Public events for a user (unauthed). GitHub returns up to ~300 events /
        ~90 days. Used by sig_owner_age to detect organic trajectory on a young
        owner (so a legit-new author isn't indistinguishable from a new-scam
        purely on account age). One extra API call; callers should skip it for
        established owners where age IS the trajectory."""
        d, _ = self._get(f"/users/{login}/events/public?per_page={per_page}")
        return d if isinstance(d, list) else []

    def issue(self, owner, name, num):
        d, _ = self._get(f"/repos/{owner}/{name}/issues/{num}")
        return d

    def owner_open_bounties(self, owner):
        """Count an owner's simultaneously-open bounty-labelled issues across all
        their repos (dilution / farm proxy). One Search API call (separate, smaller
        rate bucket). Returns int total_count, or None if unavailable. Counts the
        literal `bounty` label only -- platforms using other label text are missed
        (documented limitation, not silently treated as zero)."""
        q = urllib.parse.quote(f"is:issue is:open label:bounty user:{owner}")
        d, _ = self._get(f"/search/issues?q={q}&per_page=1")
        if not isinstance(d, dict) or "total_count" not in d:
            return None
        return d["total_count"]

    # NOTE on the return contract of the list endpoints below (releases, timeline,
    # comments): `[]` means "fetched successfully, genuinely nothing there"; `None`
    # means "we could not look". They used to collapse both into `[]`, which handed
    # the signal layer a network error dressed as a clean fact -- a failed timeline
    # fetch read as "no linked PRs" (risk 0.05) on the dimension the whole tool
    # exists to measure. The honest-absence branches downstream (sig_linked_prs's
    # `timeline is None`) were unreachable dead code until this distinction existed.

    def releases(self, owner, name):
        d, _ = self._get(f"/repos/{owner}/{name}/releases?per_page=1")
        return d if isinstance(d, list) else None

    def issue_timeline(self, owner, name, num, max_pages=3):
        out = []
        for p in range(1, max_pages + 1):
            d, _ = self._get(f"/repos/{owner}/{name}/issues/{num}/timeline?per_page=100&page={p}")
            if not isinstance(d, list):
                # Page 1 failing means we saw nothing at all -> no data, not "empty".
                # A later page failing leaves a partial-but-real list; keep it.
                return None if p == 1 else out
            if not d:
                break
            out.extend(d)
            if len(d) < 100:
                break
            time.sleep(0.2)
        return out

    def issue_comments(self, owner, name, num, max_pages=6):
        out = []
        for p in range(1, max_pages + 1):
            d, _ = self._get(
                f"/repos/{owner}/{name}/issues/{num}/comments?per_page=100&page={p}"
            )
            if not isinstance(d, list):
                return None if p == 1 else out
            if not d:
                break
            out.extend(d)
            if len(d) < 100:
                break
            time.sleep(0.2)
        return out


_RE_ISSUE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/issues/(\d+)")
_RE_REPO = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/?$")
_RE_SHORT = re.compile(r"^([^/\s]+)/([^/#\s]+)(?:#(\d+))?$")


def parse_target(url):
    """Accept full GitHub issue/repo URLs or shorthand 'owner/repo' / 'owner/repo#n'."""
    url = url.strip()
    m = _RE_ISSUE.search(url)
    if m:
        return {"kind": "issue", "owner": m.group(1), "repo": m.group(2), "num": int(m.group(3))}
    m = _RE_REPO.search(url)
    if m:
        return {"kind": "repo", "owner": m.group(1), "repo": m.group(2)}
    m = _RE_SHORT.match(url)
    if m:
        if m.group(3):
            return {"kind": "issue", "owner": m.group(1), "repo": m.group(2), "num": int(m.group(3))}
        return {"kind": "repo", "owner": m.group(1), "repo": m.group(2)}
    return None


# Reference clock. None => wall-clock now(). The benchmark sets this to a fixture's
# capture time so age-based signals (owner_age, push_recency, fast_growth...) replay
# deterministically instead of drifting as repos age. Production leaves it None.
_CLOCK = None


def set_clock(dt):
    """Freeze 'now' (tz-aware datetime) for age computations; pass None to restore."""
    global _CLOCK
    _CLOCK = dt


def age_days(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        now = _CLOCK or datetime.now(timezone.utc)
        return (now - dt).days
    except Exception:
        return None
