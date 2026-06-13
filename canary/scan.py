"""Orchestration: fetch data for a target and build the signal set, then aggregate.
Network lives here; signal math stays pure in signals.py."""
from . import signals as S
from .github import GitHub, parse_target, age_days
from .score import aggregate, Verdict


def scan(url, gh=None):
    gh = gh or GitHub()
    t = parse_target(url)
    if not t:
        return None, "could not parse target (use a github repo/issue URL or owner/repo[#n])"

    owner, repo = t["owner"], t["repo"]
    rd = gh.repo(owner, repo)
    if rd is None:
        # Distinguish rate-limit from a genuinely missing repo — don't let an
        # exhausted limit masquerade as "repo not reachable".
        if gh.remaining() == 0:
            return None, "GitHub API rate limit exhausted -- set GITHUB_TOKEN or wait for reset"
        # Repo not found: deleted/private/renamed. A vanished repo is itself a risk
        # flag (honeypots get taken down), but we don't *know* — flag, don't assert.
        v = aggregate([
            S.SignalResult("repo_exists", "authenticity", True, 0.6, 1.0,
                           "repo not reachable via API (deleted/private/renamed?)")
        ])
        return v, None

    sigs = []
    owner_user = gh.user((rd.get("owner") or {}).get("login")) if rd.get("owner") else None
    # Fetch trajectory only when it can actually change the verdict band:
    # <30d bootstrap floor and ≥365d established are inert to events.
    owner_events = None
    if owner_user:
        owner_age = age_days(owner_user.get("created_at"))
        if owner_age is not None and 30 <= owner_age < 365:
            owner_events = gh.events(owner_user.get("login"))
    releases = gh.releases(owner, repo)
    sigs += [
        S.sig_owner_age(owner_user, owner_events),
        S.sig_releases(rd, releases),
        S.sig_fast_growth(rd),
        S.sig_fake_star(rd),
        S.sig_push_recency(rd),
    ]

    issue = None
    required = ()
    if t["kind"] == "issue":
        # For a bounty/issue, contention is the core question. If we can't measure it,
        # the verdict must be UNKNOWN — never a repo-only false-green (a partial fetch
        # that drops the issue-level signals must not collapse into an ENGAGE).
        required = ("contention",)
        issue = gh.issue(owner, repo, t["num"])
        if issue:
            comments = gh.issue_comments(owner, repo, t["num"])
            timeline = gh.issue_timeline(owner, repo, t["num"])
            sigs += [
                S.sig_assigned_reserved(issue),
                S.sig_contention(issue, comments),
                S.sig_linked_prs(timeline),
                S.sig_owner_bounty_flood(gh.owner_open_bounties(owner)),
            ]

    sigs.append(S.sig_honeypot(rd, issue))
    return aggregate(sigs, required_dims=required), None
