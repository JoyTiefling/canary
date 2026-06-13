"""Signal computations — PURE functions over already-fetched data (no network here,
so they're trivially testable). Each returns a SignalResult tagged with a risk
dimension. risk is 0..1 (higher = more reason to AVOID); available=False means
'no data' and the signal is excluded from scoring (never treated as 0/safe)."""
from dataclasses import dataclass
from .github import age_days

DIMENSIONS = ("authenticity", "responsiveness", "honeypot", "contention", "availability")


@dataclass
class SignalResult:
    name: str
    dimension: str
    available: bool
    risk: float | None   # 0..1, None when unavailable
    weight: float
    detail: str


def _ok(name, dim, risk, weight, detail):
    return SignalResult(name, dim, True, risk, weight, detail)


def _na(name, dim, weight, detail):
    return SignalResult(name, dim, False, None, weight, detail)


# ---------- repo-level (universal, any GitHub repo) ----------

def _trajectory(events):
    """(total_push_commits, distinct_push_days) from a user's public events.
    Empty / None / no PushEvents -> (0, 0). Date bucket = YYYY-MM-DD of
    `created_at`. Pure (caller fetches; we don't network here)."""
    if not events:
        return 0, 0
    days, total = set(), 0
    for ev in events:
        if ev.get("type") != "PushEvent":
            continue
        when = (ev.get("created_at") or "")[:10]
        if not when:
            continue
        days.add(when)
        total += len((ev.get("payload") or {}).get("commits") or [])
    return total, len(days)


def sig_owner_age(owner_user, events=None):
    """Owner account age with optional trajectory adjustment (DESIGN.md §7 / ROADMAP).
    The default suspicion on a new owner is correct for a blind agent — but a legit
    young owner should be able to *earn* trust via observable work (push trajectory).
    `events` is the unauth public events list (see GitHub.events); when present and
    the owner shows a real push trajectory, the risk band eases — without granting
    exceptions to brand-new accounts (the <30d bootstrap floor is non-negotiable)."""
    if not owner_user:
        return _na("owner_age", "authenticity", 0.6, "owner profile unavailable")
    a = age_days(owner_user.get("created_at"))
    if a is None:
        return _na("owner_age", "authenticity", 0.6, "no owner created_at")
    if a < 30:
        # Bootstrap floor: too new for trajectory to compensate. Pay the days tax.
        return _ok("owner_age", "authenticity", 0.8, 0.6,
                   f"owner account very new ({a}d, bootstrap floor)")
    if a < 120:
        commits, days = _trajectory(events)
        if commits >= 20 and days >= 14:
            return _ok("owner_age", "authenticity", 0.45, 0.6,
                       f"owner new ({a}d) but active ({commits}c/{days}d trajectory)")
        return _ok("owner_age", "authenticity", 0.8, 0.6,
                   f"owner account very new ({a}d, weak/no trajectory)")
    if a < 365:
        commits, days = _trajectory(events)
        if commits >= 10 and days >= 7:
            return _ok("owner_age", "authenticity", 0.15, 0.6,
                       f"owner young ({a}d) but active ({commits}c/{days}d trajectory)")
        return _ok("owner_age", "authenticity", 0.4, 0.6,
                   f"owner account young ({a}d, weak/no trajectory)")
    return _ok("owner_age", "authenticity", 0.05, 0.6, f"owner established ({a}d)")


def sig_releases(repo, releases):
    age = age_days(repo.get("created_at"))
    has = bool(releases)
    if has:
        return _ok("releases", "authenticity", 0.05, 0.4, "has releases")
    if age is not None and age > 180:
        return _ok("releases", "authenticity", 0.5, 0.4, f"no releases despite age {age}d")
    return _ok("releases", "authenticity", 0.2, 0.4, "no releases (young repo)")


def sig_fast_growth(repo):
    age = age_days(repo.get("created_at"))
    stars = repo.get("stargazers_count", 0)
    if age is None:
        return _na("fast_growth", "authenticity", 0.5, "no created_at")
    if age < 60 and stars > 300:
        return _ok("fast_growth", "authenticity", 0.75, 0.5, f"{stars}★ in {age}d (suspiciously fast)")
    return _ok("fast_growth", "authenticity", 0.05, 0.5, f"{stars}★ over {age}d")


def sig_fake_star(repo):
    """Fork:star ratio heuristic (Dagster/StarScout: very low ratio at scale = suspect).
    Low weight & guarded — this is a weak proxy, not proof."""
    stars = repo.get("stargazers_count", 0)
    forks = repo.get("forks_count", 0)
    if stars < 100:
        return _na("fake_star", "authenticity", 0.3, "too few stars to judge ratio")
    ratio = forks / stars
    if ratio < 0.015:
        return _ok("fake_star", "authenticity", 0.6, 0.3, f"fork:star={ratio:.3f} very low (fake-star proxy)")
    return _ok("fake_star", "authenticity", 0.05, 0.3, f"fork:star={ratio:.3f} healthy")


def sig_push_recency(repo):
    p = age_days(repo.get("pushed_at"))
    if p is None:
        return _na("push_recency", "responsiveness", 0.4, "no pushed_at")
    if p > 365:
        return _ok("push_recency", "responsiveness", 0.7, 0.4, f"no push in {p}d (abandoned?)")
    if p > 180:
        return _ok("push_recency", "responsiveness", 0.45, 0.4, f"stale: last push {p}d ago")
    return _ok("push_recency", "responsiveness", 0.05, 0.4, f"active: pushed {p}d ago")


# ---------- honeypot (hard signal; GitHub-level) ----------

_HONEY_LABELS = ("agents only", "autonom", "crypto-eligible", "ai agent friendly")


def sig_honeypot(repo, issue=None):
    labels = []
    author_login = ""
    if issue:
        labels = [l.get("name", "").lower() for l in (issue.get("labels") or [])]
        author_login = ((issue.get("user") or {}).get("login") or "").lower()
    hits = [l for l in labels if any(k in l for k in _HONEY_LABELS)]
    bot_author = author_login.endswith("[bot]") or "clanker" in author_login
    if hits and bot_author:
        return _ok("honeypot", "honeypot", 0.95, 0.7, f"agent-bait labels {hits} + bot author")
    if hits:
        return _ok("honeypot", "honeypot", 0.85, 0.7, f"agent-bait labels {hits}")
    if bot_author:
        return _ok("honeypot", "honeypot", 0.55, 0.7, f"bot/clanker author '{author_login}'")
    if issue is None:
        return _na("honeypot", "honeypot", 0.4, "no issue to inspect")
    return _ok("honeypot", "honeypot", 0.05, 0.7, "no honeypot markers")


# ---------- issue-level: availability & contention ----------

def sig_assigned_reserved(issue):
    assignees = issue.get("assignees") or ([] if not issue.get("assignee") else [issue["assignee"]])
    labels = [l.get("name", "").lower() for l in (issue.get("labels") or [])]
    reserved = any("reserved" in l or "interview" in l for l in labels)
    if reserved:
        return _ok("assigned_reserved", "availability", 0.95, 0.6, "reserved/interview-only label")
    if assignees:
        who = ",".join(a.get("login", "?") for a in assignees)
        return _ok("assigned_reserved", "availability", 0.85, 0.6, f"already assigned to {who}")
    return _ok("assigned_reserved", "availability", 0.05, 0.6, "no one assigned")


def parse_algora_attempts(comments):
    """Find the algora bot comment & count attempts. Returns (count, found:bool)."""
    for c in comments:
        login = ((c.get("user") or {}).get("login") or "").lower()
        body = c.get("body") or ""
        is_algora = "algora" in login
        looks_like_table = "🟢" in body or "/attempt" in body
        if (is_algora and looks_like_table) or ("🟢" in body and "bounty" in body.lower()):
            return body.count("🟢") + body.count("🔴"), True
    return 0, False


def sig_linked_prs(timeline):
    """Open pull requests cross-referencing the issue = someone is already attempting it.
    Universal contention signal (works without any bounty platform). Proxy: cross-ref
    events may include forks/mentions, so treat as evidence, not proof."""
    if timeline is None:
        return _na("linked_prs", "contention", 0.6, "timeline unavailable")
    open_prs, all_prs = set(), set()
    for ev in timeline:
        if ev.get("event") == "cross-referenced":
            src = (ev.get("source") or {}).get("issue") or {}
            if src.get("pull_request"):
                n = src.get("number")
                all_prs.add(n)
                if src.get("state") == "open":
                    open_prs.add(n)
    no, nt = len(open_prs), len(all_prs)
    if no >= 3:
        return _ok("linked_prs", "contention", 0.9, 0.6, f"{no} open linked PRs (swarmed)")
    if no == 2:
        return _ok("linked_prs", "contention", 0.78, 0.6, "2 open linked PRs")
    if no == 1:
        return _ok("linked_prs", "contention", 0.7, 0.6, "1 open linked PR (someone's already on it)")
    if nt >= 1:
        return _ok("linked_prs", "contention", 0.3, 0.6, f"{nt} linked PR(s), all closed")
    return _ok("linked_prs", "contention", 0.05, 0.6, "no linked PRs")


def sig_owner_bounty_flood(open_bounty_count):
    """Owner-level dilution: one owner with many simultaneously-open bounties can't
    realistically review/pay them all -- each issue is diluted and the pool reads as
    a farm. This is contention the per-issue signals miss entirely (a fresh farm
    issue has 0 attempts and 0 linked PRs, yet is still a trap). Calibrated safe-side
    but not trigger-happy: heavy-but-plausible counts only downgrade a clean go to
    CAUTION; industrial counts cross the contention veto. None => no data, excluded.

    Threshold caveat: the legit/farm boundary in the 11-50 band is a judgement call
    not yet calibrated against a known *legitimate* high-volume owner -- only the
    extreme end (ritesh-1918, 144) is empirically anchored. See bench dataset."""
    n = open_bounty_count
    if n is None:
        return _na("owner_bounty_flood", "contention", 0.4, "owner open-bounty count unavailable")
    if n <= 3:
        return _ok("owner_bounty_flood", "contention", 0.05, 0.5, f"owner has {n} open bounties (normal)")
    if n <= 10:
        return _ok("owner_bounty_flood", "contention", 0.3, 0.5, f"{n} open bounties from this owner (busy)")
    if n <= 25:
        return _ok("owner_bounty_flood", "contention", 0.55, 0.5, f"{n} open bounties from this owner (heavy dilution)")
    if n <= 50:
        return _ok("owner_bounty_flood", "contention", 0.75, 0.5, f"{n} open bounties from this owner (farm-scale dilution)")
    return _ok("owner_bounty_flood", "contention", 0.92, 0.5, f"{n} open bounties from this owner (industrial bounty farm)")


def sig_contention(issue, comments):
    attempts, found = parse_algora_attempts(comments)
    if found:
        if attempts == 0:
            risk = 0.1
        elif attempts <= 2:
            risk = 0.35
        elif attempts <= 5:
            risk = 0.65
        elif attempts <= 12:
            risk = 0.85
        else:
            risk = 0.97
        return _ok("contention", "contention", risk, 0.7, f"{attempts} Algora attempts")
    # No Algora table → fall back to weak comment-volume proxy, but DON'T claim freshness.
    n = issue.get("comments", 0)
    if n >= 25:
        return _ok("contention", "contention", 0.6, 0.35, f"{n} comments (contested, no Algora data)")
    # genuinely insufficient contention data — stay unavailable (never false-green)
    return _na("contention", "contention", 0.7, "no Algora attempt table found; contention unknown")
