"""Minimal GitHub REST client + target URL parsing. Unauth by default (60/hr);
set GITHUB_TOKEN for higher limits. No third-party deps."""
import os, json, time, re, urllib.request, urllib.error
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

    def repo(self, owner, name):
        d, _ = self._get(f"/repos/{owner}/{name}")
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

    def issue(self, owner, name, num):
        d, _ = self._get(f"/repos/{owner}/{name}/issues/{num}")
        return d

    def releases(self, owner, name):
        d, _ = self._get(f"/repos/{owner}/{name}/releases?per_page=1")
        return d if isinstance(d, list) else []

    def issue_timeline(self, owner, name, num, max_pages=3):
        out = []
        for p in range(1, max_pages + 1):
            d, _ = self._get(f"/repos/{owner}/{name}/issues/{num}/timeline?per_page=100&page={p}")
            if not isinstance(d, list) or not d:
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
            if not isinstance(d, list) or not d:
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


def age_days(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None
