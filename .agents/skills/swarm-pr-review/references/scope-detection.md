# Scope Detection, pre-flight git ref availability, and shell rules under the PR_REVIEW gate

### Shell rules under the PR_REVIEW gate

The gate accepts one command per tool call — never compose commands with
`&&`, `;`, shell pipelines, redirects (`>`, `>>`, `<`), or `$(...)`/`` ` ``
substitution. The only literal-pipe exception is inside one closed
double-quoted `gh api --jq` argument with no backslash-escaped nested double
quotes; that escape is ambiguous under `cmd.exe`. The exception does not
permit an outer pipeline or any other control syntax.
A single leading `cd <dir> &&` prefix and a trailing `2>&1` suffix are
tolerated, but only on read-only commands. State-transition verbs — `git
fetch`, `git checkout`, `git switch`, `git branch`, and `gh pr checkout` —
must always run bare: no `cd` prefix, no `2>&1` suffix.

Allowed read-only `git` subcommands: `status`, `log`, `show`, `diff`,
`rev-parse`, `merge-base`, `ls-files`, `grep`, `blame`, `cat-file`,
`for-each-ref`, `branch --list` (listing only — mutation flags are blocked),
`remote -v`, and `config --get`.

Prefer tools over raw shell for state that a single read-only command cannot
cover cleanly:

- `pr_workflow_status` — observe local HEAD, branch, dirty-file state,
  remotes, and gate state in one read-only call.
- `gh_evidence` — bounded PR/issue/run metadata without a shell round-trip.
- If `gh` is not installed, the web fetch tool against the equivalent
  `api.github.com` REST URL is the degraded read-only path.


Determine review scope using this priority:

1. explicit user-provided PR URL, PR number, commit, branch, or file scope,
2. current feature branch diff vs the remote-tracking base ref (`origin/main`,
   `origin/master`; a local `main`/`master` only as a last resort — it is only as
   fresh as the last fetch and yields a different merge base),
3. staged changes,
4. latest commit,
5. user-specified files or directories.

Record:

- base ref,
- head ref,
- commit range,
- changed files,
- deleted files,
- generated files,
- lockfiles,
- test files,
- docs/config/schema files,
- whether the working tree is dirty.

If scope cannot be determined, review the narrowest safe scope available and state the limitation.

### Pre-flight git ref availability

Before launching explorers (Phase 3), perform this exact standalone sequence:

1. Resolve and retain the authoritative full `pr_head_sha` from PR metadata.
2. Verify the working tree is clean with `git status --porcelain`. If it is
   dirty at all — tracked changes, untracked files, or both — call
   `prepare_pr_workflow_checkout` (Profile A). The tool supports
   self-discovery: call it with no `paths` argument to auto-discover and
   preserve every dirty path in one step, including untracked files; an
   already-clean tree returns a no-op (nothing is stashed, no receipt is
   written). Pass explicit `paths` only when you already have the exact,
   bounded list of dirty tracked files and want the older exact-match
   contract. Without the controller (Profiles B/C), do not blind-stash over
   dirty state: surface tracked changes to the user, or abort. Do not issue
   `git stash` through shell.
   Treat the controller's Git-state result as final for this attempt: `clean`
   proceeds, `stashable` permits exactly one checkout-preparation call, and
   `recovery-required` or `indeterminate` means report the typed
   `required_action`, abort/clear any already-active gate, and stop. Retry only
   when the controller explicitly returns `retryable: true`; never fight an
   unmerged index or in-progress Git operation with repeated stash attempts.
3. Fetch the PR head as one standalone command, for example
   `git fetch origin refs/pull/<N>/head`. Do not compose fetch and checkout.
3a. Fetch the base branch as its own standalone command, for example
   `git fetch origin main`. Skipping this is the single most common cause of a
   rejected dispatch: the merge base is recomputed against `base_ref`, and a
   local `main`/`refs/heads/main` that was never refreshed resolves to a
   different commit than `origin/main` for the same `base_sha`.
4. Prove the full commit exists locally with two portable standalone commands:
   `git rev-parse --verify <full_pr_head_sha>^0`, then
   `git cat-file -t <full_pr_head_sha>`. The second command must print
   `commit`. This avoids shell/wrapper parsing differences around the
   `^{commit}` suffix on Windows.
5. Check out the exact PR filesystem with
   `git switch --detach <full_pr_head_sha>`. Do not use `--track FETCH_HEAD`:
   `FETCH_HEAD` is not a remote-tracking branch.
6. Confirm `git rev-parse HEAD` equals the full `pr_head_sha`, bind that exact
   head (Profile A: through the first PR-review controller call; Profiles B/C:
   record it at the top of the findings ledger and repeat it in every lane
   prompt), and finish this before dispatching explorer lanes.

Explorer agents read files from the working tree, not from git history. Passing
the commit range in a prompt cannot substitute for this checkout because
`Read` / `Glob` / `Grep` operate on the filesystem.
- Explicitly pass the verified merge-base range (`base_sha...pr_head_sha`) in every explorer delegation so explorers inspect exactly the bound PR diff. Include `base_ref` only as the live ref used to recompute `base_sha`; do not substitute a two-dot branch-tip range.

If refs cannot be fetched or checked out, state the limitation in the context pack.
