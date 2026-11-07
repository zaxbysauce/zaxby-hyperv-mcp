# Pre-flight PR branch checkout

## Pre-flight: Check Out the PR Branch Locally

Before verifying any claim or making any fix, ensure the PR branch is the working
tree:

- If `head_ref` is a remote branch that is not checked out locally, fetch it
  (`git fetch origin <head_ref>`).
- **Check for parallel work first.** Before checkout, use the repository or
  runtime's parallel-work check. When the bundled
  `parallel-work-check` skill exists, it is one conditional implementation to
  detect concurrent pushes from other agents (for example the repo's
  auto-review bot following up, a maintainer pushing fixes, or parallel swarm
  work). If remote has new commits: read `git log local..remote`, evaluate whether the parallel work
  supersedes your planned fixes, and prefer the parallel work if it's more
  comprehensive (more tests, better edge coverage, clearer error handling).
  Abort your rebase, take the remote state, then add minor improvements on top.
- Verify the working tree is clean first (`git status --porcelain`). If any
  tracked or untracked changes exist, call `prepare_pr_workflow_checkout`
  before binding (Profile A). Omit `paths` to auto-discover and atomically
  preserve every dirty path, including untracked files; pass explicit `paths`
  only for an exact bounded tracked-file set. It creates an auditable stash
  receipt containing the original branch/HEAD and a structured
  `operation: "restore"` recovery instruction. Do not issue `git stash`
  through shell.
  Without the controller, surface dirty state to the user or abort the checkout
  — do not blind-stash.
- Treat `recovery-required` and `indeterminate` controller results as terminal
  for the current attempt: report the typed `required_action`, abort/clear any
  already-active gate, and stop. Only `stashable` permits one preparation call;
  retry only when the controller explicitly returns `retryable: true`.
- **Check out the head branch locally before dispatching feedback lanes.** Feedback verification reads the working-tree
  filesystem (`Read`/`Glob`/`Grep`), and fixes must land on the PR branch — without a
  checkout you would verify and patch the base branch's code instead. Record the
  exact `merge_base...head_ref` range for diff-scoped inspection.
 - Pass the exact `merge_base...head_ref` commit range in every read-only verification or
   explorer/advisory-lane delegation so lane agents can inspect specific revisions
   with `git show` when needed.
- If no PR reference was provided (a pasted-feedback session on the current branch),
   confirm the current branch is the intended PR branch before editing.
- A detached checkout at the authoritative full PR head is a valid pre-bind
  intake state. On the first Profile-A bind, the controller attaches it only
  when Git reports exactly one safe candidate: an existing local branch at
  that SHA whose upstream is an exact remote ref at the same SHA, or one exact
  remote-tracking ref. It never guesses a remote/name boundary. Zero
  candidates, multiple candidates, a linked-worktree-owned local branch, or an
  existing mismatched upstream fails closed without publishing the bind. Retry
  is idempotent if switching succeeded but state persistence failed.
- The existing constrained tracked-branch and safe `gh pr checkout` pre-bind
  forms remain supported on every profile after proving the exact SHA and a
  unique intended remote ref. Never use force, submodule-recursive, or detached
  `gh pr checkout` variants.
- Immediately after the first bind and before feedback verification dispatch,
  prove that `git rev-parse HEAD` equals the authoritative full `pr_head_sha`,
  `git status --porcelain` is empty, and the current branch tracks the intended
  PR head remote/branch. A detached exact-head checkout is intake-only; the
  bind must attach it before feedback dispatch or publication.

When a verification lane result includes `output_ref`, treat `output` as a
preview and call `retrieve_lane_output` before using it to classify, resolve,
disprove, or group feedback items. If the result is `output_degraded`,
`transcript_incomplete`, or truncated without a usable ref, keep the affected
ledger items as `NEEDS_MORE_EVIDENCE` or re-dispatch a narrower read-only lane.
(Profile A. On Profiles B/C, read each verification subagent's or pass's full
report directly — a truncated or summary-only report is a preview, not
verification evidence, and keeps its items open the same way.)
