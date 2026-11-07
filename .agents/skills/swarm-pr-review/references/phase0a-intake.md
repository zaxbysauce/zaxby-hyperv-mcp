# Phase 0A signal-intake steps (fetch, classify, merge) and anti-patterns

### Step 1 — Fetch all PR feedback surfaces

The commands below are GitHub examples. On GitLab, Bitbucket, Gerrit, or
another code host, use the host's API/connector/CLI to enumerate the same full
surface, including pagination and unresolved-thread state. Host choice never
reduces the intake ledger.

```bash
# Issue comments (general PR thread)
gh api --paginate repos/{owner}/{repo}/issues/{PR_NUMBER}/comments

# Review comments (inline code comments)
gh api --paginate repos/{owner}/{repo}/pulls/{PR_NUMBER}/comments

# Review summaries (approve/request-changes/comment events)
gh api --paginate repos/{owner}/{repo}/pulls/{PR_NUMBER}/reviews
```

`--paginate` requests every REST page. These three calls are gate-allowed as
written. A literal jq filter passed as one closed double-quoted `gh api --jq`
argument is also allowed when it needs no backslash-escaped nested double
quotes; use `gh_evidence` when a portable filter cannot meet that shape. A real
shell pipeline to `jq` or another command remains blocked. To
separate bot/automated reviews (Copilot, Codex, CodeRabbit, etc.) from human
ones, apply the same predicate in context to the JSON already returned above
— `user.type == "Bot"` or a `user.login` match against
`bot|copilot|coderabbit|codex` (case-insensitive) — instead of re-fetching
with a shell-side `--jq` filter. `gh_evidence` with `target: "pr"` and
`fields: "comments"` is the sanctioned read-only tool path for the same PR
comment data when a tool call is preferred over a raw shell command. `gh pr
view --json comments,reviews` is convenience-only because those fields have
item caps; never use it as the authoritative "all signals" intake.

### Step 2 — Classify each comment

| Category | Action |
|----------|--------|
| **Human review with file:line evidence** | Add as candidate finding with `source: existing-review` — still needs reviewer validation |
| **Bot/automated finding with specific code reference** | Add as candidate finding with `source: bot-review` — high false-positive rate, treat as unverified |
| **General feedback / style preference** | Add as advisory obligation |
| **Resolved/outdated comment** | Skip — note in report under "Ingested Resolved Comments" |
| **Requested changes not yet addressed** | Add as HIGH-priority obligation |

### Step 3 — Merge into review pipeline

All ingested comments become candidate findings or obligations. They follow the
same Phase 3-8 pipeline as freshly discovered findings. Ingested findings are
NOT pre-confirmed — they still require independent reviewer validation per the
Anti-Self-Review Rule.

**Comment-ledger output:**
```
[INGESTED] | source | category | file:line (if applicable) | original_author | status: PENDING_VALIDATION / SKIPPED_OUTDATED / ADVISORY
```

### Anti-patterns
- ✗ Ignoring bot reviews because "bots produce false positives" — they also catch real issues
- ✗ Pre-confirming human review comments without independent validation — even senior reviewers make mistakes
- ✗ Skipping inline review comments and only reading the summary — inline comments contain the evidence
