"""Signal computations — PURE functions over already-fetched data (no network here,
so they're trivially testable). Each returns a SignalResult tagged with a risk
dimension. risk is 0..1 (higher = more reason to AVOID); available=False means
'no data' and the signal is excluded from scoring (never treated as 0/safe)."""
from dataclasses import dataclass
from .github import age_days

DIMENSIONS = ("authenticity", "responsiveness", "honeypot", "contention", "availability",
              "engageability", "swarm")


@dataclass
class SignalResult:
    name: str
    dimension: str
    available: bool
    risk: float | None   # 0..1, None when unavailable
    weight: float
    detail: str
    hard: bool = True    # categorical evidence / direct observation; False = probabilistic tilt.
                         # DESIGN §8: only HARD signals can single-block a clean ENGAGE.
                         # Default True for safety — a signal must opt OUT of veto power.


def _ok(name, dim, risk, weight, detail, hard=True):
    return SignalResult(name, dim, True, risk, weight, detail, hard)


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
    exceptions to brand-new accounts (the <30d bootstrap floor is non-negotiable).

    HARD, all bands (§8, calibrated 2026-07-23): young-owner-without-observable-work
    is the classic throwaway-farm profile; trajectory is the designed discriminator
    (§7), and the error costs are asymmetric (false positive = recoverable CAUTION,
    false negative = contributor walks into a trap). Bootstrap floor stays absolute —
    no conditional escape (self-audit 2026-06-22 filed as data, status quo won)."""
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
    if releases is None:
        # `None` = the releases endpoint did not answer; `[]` = it answered "none".
        # Reading a failed fetch as "this project ships nothing" invents evidence.
        return _na("releases", "authenticity", 0.4, "releases endpoint unavailable")
    age = age_days(repo.get("created_at"))
    has = bool(releases)
    if has:
        return _ok("releases", "authenticity", 0.05, 0.4, "has releases")
    if age is not None and age > 180:
        return _ok("releases", "authenticity", 0.5, 0.4, f"no releases despite age {age}d")
    if age is None:
        # No created_at means we're looking at degraded/partial repo data, not at a
        # young repo. Inferring "young, no releases yet" from absence would assert a
        # fact we don't have — the false-certainty sibling of the false-green sin.
        return _na("releases", "authenticity", 0.4, "no repo metadata (created_at missing)")
    return _ok("releases", "authenticity", 0.2, 0.4, "no releases (young repo)")


def sig_fast_growth(repo):
    age = age_days(repo.get("created_at"))
    stars = repo.get("stargazers_count")
    if age is None:
        return _na("fast_growth", "authenticity", 0.5, "no created_at")
    if stars is None:
        # A missing star count is not a zero star count: defaulting to 0 would
        # report "healthy, slow growth" about a repo whose popularity we never saw.
        return _na("fast_growth", "authenticity", 0.5, "no star count in repo data")
    if age < 60 and stars > 300:
        # SOFT (§8): fast growth can be legit virality — risk tilt, not proof.
        return _ok("fast_growth", "authenticity", 0.75, 0.5, f"{stars}★ in {age}d (suspiciously fast)", hard=False)
    return _ok("fast_growth", "authenticity", 0.05, 0.5, f"{stars}★ over {age}d", hard=False)


def sig_fake_star(repo):
    """Fork:star ratio heuristic (Dagster/StarScout: very low ratio at scale = suspect).
    Low weight & guarded — this is a weak proxy, not proof.
    SOFT (§8, calibrated 2026-07-23): StarScout proves fake stars via account-level
    forensics (cluster analysis); WE only compute a ratio proxy. Until account-level
    detection is implemented, the evidentiary character of this signal is
    probabilistic — flip to hard=True if/when real forensics land."""
    stars = repo.get("stargazers_count")
    forks = repo.get("forks_count")
    if stars is None:
        return _na("fake_star", "authenticity", 0.3, "no star count in repo data")
    if stars < 100:
        return _na("fake_star", "authenticity", 0.3, "too few stars to judge ratio")
    if forks is None:
        # Absent fork count used to default to 0 -> ratio 0.000 -> "very low
        # (fake-star proxy)" at risk 0.6. That is an ACCUSATION manufactured out of
        # a missing field: the false-certainty sin pointed at the risky side.
        return _na("fake_star", "authenticity", 0.3, "no fork count in repo data")
    ratio = forks / stars
    if ratio < 0.015:
        return _ok("fake_star", "authenticity", 0.6, 0.3, f"fork:star={ratio:.3f} very low (fake-star proxy)", hard=False)
    return _ok("fake_star", "authenticity", 0.05, 0.3, f"fork:star={ratio:.3f} healthy", hard=False)


def sig_fork_swarm(repo):
    """Repo-level swarm lens on fork:star — same datum as sig_fake_star, different question.
    fake_star asks 'is the social proof manufactured?' (low ratio at scale).
    fork_swarm asks 'is this small bounty repo being swarmed by hunters?' (high ratio
    at small scale). Soft swarm signal — caps at 0.55 (single-block downgrade,
    no hard veto): a swarmed fork:star is a probability tilt, not proof of contention
    (forks may include legit contributors).

    NOTE on dimension: this reads the *repo-level* swarm, not the *issue-level* fight.
    It is deliberately NOT tagged 'contention' — otherwise an issue-target with no
    issue data would satisfy the `required=('contention',)` gate on this repo signal
    alone and false-green (regression fixed 2026-07-02; see bench/test_bench.py
    test_missing_key_replays_as_no_data_not_crash). Pairs with sig_linked_prs /
    sig_contention / sig_owner_bounty_flood which read the actual issue-level fight.

    Anchor: HELPDESK.AI 149f/90★ — caught blind 2026-06-01 (Engram #2470 dogfood). Old
    fake_star punted ('too few stars to judge'); the swarm read sees the population."""
    stars = repo.get("stargazers_count")
    forks = repo.get("forks_count")
    if stars is None or forks is None:
        # Both counts are load-bearing for the ratio; missing either one used to be
        # silently read as 0 and could report "healthy for scale" about a swarm we
        # never measured.
        return _na("fork_swarm", "swarm", 0.4, "repo star/fork counts unavailable")
    if stars + forks < 20:
        return _na("fork_swarm", "swarm", 0.4, "repo too small to read swarm signal")
    if stars == 0:
        # All-forks-no-stars is odd but ambiguous (vendored mirrors, template repos);
        # let issue-level contention signals decide, don't single-handedly punish.
        return _na("fork_swarm", "swarm", 0.4, "no stars baseline for swarm ratio")
    ratio = forks / stars
    # SOFT all bands (§8, calibrated 2026-07-23): docstring already said "soft
    # contention signal" — the flag now matches intent. Amplifier, not veto:
    # pairs with linked_prs/contention/flood into a real CAUTION, passes alone
    # on a tutorial repo (6/8 false-positives on the tutorial set, ROADMAP).
    if stars < 200 and ratio >= 1.5:
        return _ok("fork_swarm", "swarm", 0.55, 0.4,
                   f"{forks} forks / {stars}★ on a small repo — hunter swarm", hard=False)
    if stars < 500 and ratio >= 1.0:
        return _ok("fork_swarm", "swarm", 0.3, 0.4,
                   f"{forks} forks / {stars}★ — heavy swarm for repo size", hard=False)
    return _ok("fork_swarm", "swarm", 0.05, 0.4,
               f"fork:star={ratio:.2f}, healthy for scale ({stars}★)", hard=False)


def sig_repo_open(repo):
    """Can a contribution physically land here at all?

    An archived repo is READ-ONLY: GitHub refuses new pull requests and issues on
    it. That is not elevated risk, it is a closed door — every other signal on such
    a repo is answering a question that no longer applies. `disabled` (repo taken
    offline by GitHub) is the same closed door by a different mechanism.

    Absence of the flag is NOT permission (2026-07-29 absence-vs-empty rule): a
    payload that never told us whether the door is open leaves the signal
    unavailable, so its weight lowers confidence instead of silently reading as
    'open'. This matters because `.get("archived")` returning None is falsy, and
    the naive `if not archived` spelling would treat 'we were not told' exactly
    like 'we were told no'.
    """
    archived = repo.get("archived")
    disabled = repo.get("disabled")
    if archived is None and disabled is None:
        return _na("repo_open", "engageability", 0.7,
                   "repo payload carries no archived/disabled flag -- cannot assert the repo accepts work")
    if archived:
        return _ok("repo_open", "engageability", 1.0, 0.7,
                   "repo is ARCHIVED (read-only): GitHub refuses new pull requests and issues")
    if disabled:
        return _ok("repo_open", "engageability", 1.0, 0.7,
                   "repo is DISABLED by GitHub: contribution is not possible")
    return _ok("repo_open", "engageability", 0.02, 0.7, "repo is open to contributions")


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
        # Completeness first, verdict second. Both components (bait labels, bot
        # author) feed the same score, so a payload missing either one can only
        # produce an under-read — and this signal's 0.95/0.85 band is what crosses
        # the honeypot veto. A partial read that lands at 0.55 slips under it: the
        # trap gets waved through because of a fetch gap, not because of facts.
        missing = [k for k in ("labels", "user") if k not in issue]
        if missing:
            return _na("honeypot", "honeypot", 0.4,
                       f"issue payload incomplete ({', '.join(missing)}) — cannot rule honeypot in or out")
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
    # `assignees` is the authoritative multi-assignee field; `assignee` is the legacy
    # single one. If the authoritative field is absent we have not been told who holds
    # this issue — and the legacy field being None says nothing about multi-assignment.
    missing = [k for k in ("labels", "assignees") if k not in issue]
    if missing:
        return _na("assigned_reserved", "availability", 0.6,
                   f"issue payload incomplete ({', '.join(missing)})")
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
        # SOFT at n=1 (§8, calibrated 2026-07-23): a single cross-ref may be a
        # fork/mention proxy artifact (see docstring). n>=2 is unambiguous fact.
        return _ok("linked_prs", "contention", 0.7, 0.6, "1 open linked PR (someone's already on it)", hard=False)
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
        # SOFT (§8, calibrated 2026-07-23): dilution probability in the boundary
        # band — the commaai/opendbc false-positive fix. 26+ stays HARD (farm-scale
        # is a categorical pattern).
        return _ok("owner_bounty_flood", "contention", 0.55, 0.5, f"{n} open bounties from this owner (heavy dilution)", hard=False)
    if n <= 50:
        return _ok("owner_bounty_flood", "contention", 0.75, 0.5, f"{n} open bounties from this owner (farm-scale dilution)")
    return _ok("owner_bounty_flood", "contention", 0.92, 0.5, f"{n} open bounties from this owner (industrial bounty farm)")


def sig_contention(issue, comments):
    if comments is None:
        # Comments endpoint did not answer. Falling through would run the Algora
        # parser over nothing and then reach for the comment-count proxy — reporting
        # "contention unknown" for the right reason matters here, because this
        # dimension is `required` for issue targets (score.aggregate).
        return _na("contention", "contention", 0.7, "comments unavailable; contention unknown")
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
