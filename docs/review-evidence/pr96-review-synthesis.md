# PR #96 swarm-pr-review — synthesis

Run id `pr96-20261021`. Head `fbb78b712b798e414945f61e980c0f683b4dbf2f`, base `origin/main` (`e8ec728`).

## Signals ingested (Phase 1)

| Signal | State at review time |
|---|---|
| PR comments | none |
| PR reviews | none |
| Inline review comments | none |
| Bot findings | Cubic AI reviewer check `skipping` |
| CI | `test (3.10)`, `test (3.11)`, `test (3.12)`, `floor` all pass |
| Mergeable | MERGEABLE, mergeState CLEAN, base in sync |
| Closes | #22 |
| Commits | 8 |

Every item above is a CLAIM until validation. The CI result was re-verified by the validation shards.

## Lane coverage

Base lanes: 6 dispatched, 6 returned (wiring-dataflow 13, runtime-behavior 17,
security-trust 10, test-coverage 22, obligation-drift 13, docs-config 13).

Micro-lanes: 8 families MATCHED and dispatched; 3 NOT_TRIGGERED with absence
evidence (see the trigger-eval ledger in `candidates.md`). One micro lane
(test-infrastructure + unclassified-risk) returned empty on first dispatch and was
**retried once** per the coverage gate; the retry produced 9 candidates. No
family is unsettled.

## Verified findings

88 raw candidate rows → 16 deduplicated clusters → independent validation
(3 reviewer shards) → critic challenge (2 passes).

| ID | Severity (final) | Summary | Validated by |
|---|---|---|---|
| PRR-002 | **HIGH** | A persisted `active` job row is never demoted, so 128 never-stopped jobs permanently block `job_start` host-wide. The relay side self-heals; the job side does not. | shard A VERIFIED 0.93; critic pass1 SURVIVES 0.90; pass2 SURVIVES HIGH 0.90 |
| PRR-001 | MEDIUM | The AC10 integration test cannot pass: the parent's stop resolves the default store, and the children get a deny-all config. | shard A VERIFIED 0.95; pass1 DOWNGRADE→MEDIUM 0.90; pass2 CONFIRMED 0.90 |
| PRR-003 | MEDIUM | The write-through is not atomic; `_register` can strand a launched guest process whose `job_id` the caller never receives. | shard A VERIFIED 0.95; pass1 DOWNGRADE→MEDIUM; pass2 CONFIRMED 0.90 |
| PRR-004 | MEDIUM | The relay registration-failure path leaks the listener and masks the original exception. | shard A VERIFIED 0.95; pass1 DOWNGRADE→MEDIUM; pass2 CONFIRMED 0.90 |
| PRR-005 | MEDIUM | `_recover` rewrites live peers' rows, and cap eviction then deletes a live peer's relay row. | shard A VERIFIED 0.88 |
| PRR-007 | MEDIUM | `peek_vm_name`'s store fallback has no owner filter and is eagerly evaluated outside the error envelope, opening the store (a write transaction) on five tool hot paths. | shard B VERIFIED 0.95 |
| PRR-008 | MEDIUM | `owner is None` skips the ownership check; the store made the registry cross-process. | shard B VERIFIED 0.92 |
| PRR-009 | MEDIUM | The store path is neither validated nor hardened; the integration suite rewrites the developer's real store; `soak_bench.py` materialises the store in the repo tree. | shard B VERIFIED 0.92 |
| PRR-011 | MEDIUM | `open()` failure handling: split transactions, an independent retry budget that can block a call ~43 s with no cancellation, and a refusal path that checkpoints a WAL database (contradicting its own docstring and AC7). | shard B VERIFIED 0.93 |
| PRR-013 | MEDIUM | One restored relay row reads `interrupted` by id and `active` in the listing; the duplicate scan is local-only while the cap is a union. | shard C VERIFIED 0.95 (3 of 4 sub-claims) |
| PRR-014 | MEDIUM | `job_stop` nulls the credential before the durable write, and two concurrent stops race the provenance and persist `inline`. | shard C VERIFIED 0.95 |
| PRR-015 | MEDIUM | Six-plus invariants survive the shipped suite under mutation, including `job_stop`'s "never taskkill PID 0" refusal, which has no test at all. | shard C VERIFIED 0.95; pass1 SURVIVES HIGH; pass2 DOWNGRADE→MEDIUM 0.80 |
| PRR-016 | MEDIUM | The PR body's evidence lives outside the PR (`.agents/issue-traces/` is git-excluded), so the cited harness and probe log are not reviewable from the PR; one flaky test is disclosed nowhere. | shard C PARTIALLY VERIFIED 0.90 |
| PRR-006 | LOW | A restored credential's identity is not pinned; the issue explicitly sanctions the re-resolution. | shard A VERIFIED 0.92; pass1 DOWNGRADE→LOW 0.85; pass2 CONFIRMED 0.85 |
| PRR-010 | LOW | The forward-migration direction is absent; the issue assigns migrations to PR 2/3. | shard B VERIFIED 0.95; pass1 DOWNGRADE→LOW 0.90; pass2 CONFIRMED 0.90 |
| PRR-012 | LOW | `StateStoreError` messages interpolate the full absolute path into the client envelope, against the repo's own stated posture at `pswindows.py:465-470`. | shard B VERIFIED 0.90 |

## Rejected / overturned claims (transparency over silent drops)

| Claim | Lane | Why it was dropped |
|---|---|---|
| PRR-001(c) no `PYTHONPATH` pin | subprocess-platform | OVERTURNED by shard A: the editable install plus `sys.executable` make the child import succeed. |
| PRR-013 sub-claim 4 `relay_stop` docstring mismatch | runtime-behavior | OVERTURNED by shard C: the docstring makes no such claim and a repeat stop does return the note. |
| PRR-016 "tool inventory 54 vs 57 unreconciled" | obligation-drift | OVERTURNED by shard C: `test_c03_tool_surface.py:29-30` documented the stale 54 at BASE. |
| PRR-016 "4 failures, not 2" | obligation-drift | NOT REPRODUCIBLE by shard C's baseline run (2 failures, as claimed). The undisclosed-flake half was still reproduced. |
| PRR-015 "C3's `orphaned` assertion survives mutating the orphan branch" | test-coverage | FALSIFIED by shard C's own probe: disabling the orphan branch makes the test FAIL, because the crashed child's row keeps `cred_ref="inline"` and short-circuits earlier. Dropped from the cluster. |
| PRR-002 "README documents no cap interaction" | runtime-behavior | OVERSTATED by shard A: the README documents the cap; it omits the permanent cross-restart consequence. |

## Micro-lane attestation

All 11 families are accounted for. 8 MATCHED families each produced candidate
rows; 3 NOT_TRIGGERED families carry concrete absence evidence in the trigger-eval
ledger. One attestation of note: the `concurrency-state` micro lane returned
`[CLEAN]` for the lock-ORDER sub-check after verifying all 13 dual-lock sites in
both modules — the store-lock > registry-lock invariant holds.

## Obligation check

The PR closes #22 as claimed, with two honest corrections already recorded in its
body: the issue's "tool inventory stays at 54" is stale (57 is correct and was
already reconciled in-tree at base), and AC10 is NON-EXECUTABLE. All 13
acceptance criteria are otherwise covered by frozen checks, and the repository's
own deferred-work scanner reports no marker of any kind on an added line.

## Verdict

**REQUEST_CHANGES.** One HIGH (PRR-002) is a live, durable, cross-process
denial with no in-band recovery: inline-credential rows can never be removed
through the API, rows owned by another principal cannot be removed by a different
principal, and the cap counts all rows regardless of owner. Eleven further
verified findings at MEDIUM/LOW are all in code, docs or tests this PR introduced.

## Handoff

The validated findings are carried into `swarm-pr-feedback`. The disposition
plan (one per item, planned BEFORE the closeout gate) is at
`.zcode/pr-review/pr96-20261021/feedback-handoff.md`.