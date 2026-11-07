# Intake Surfaces detail (async advisory lanes, CI matrix cascade, PR body claim verification)

### Async advisory verification lanes

After the complete feedback ledger exists and before editing, run independent
read-only verification lanes. Under Profile A, use
`dispatch_lanes_async` with `mode: "swarm-pr-feedback:verification"`, the
complete immutable `feedback_inventory` ID list, the exact current
`pr_head_sha`, and each lane's exact
`feedback_item_ids` ownership list for independent read-only verification lanes:
comment classification, CI/log root-cause inspection, test impact mapping,
release/docs claim checks, and stale-branch/conflict analysis. Partition the
ledger so each `FB-###` item is owned by exactly one verification lane and the
union of lanes covers the entire ledger — no feedback item may be left
unassigned to a lane; state each lane's owned IDs both structurally and in its
prompt. The runtime rejects missing, duplicate, overlapping, or unknown item
ownership and blocks mutation until the verification batch settles. Scale
the lane count to the ledger size: a 1–3 item round may use a single combined
lane, while a large multi-round intake may warrant one lane per category above.
Cap each `dispatch_lanes_async` batch at 8 lanes (`MAX_LANES`); if the ledger
needs more than 8 verification lanes, dispatch in sequential batches and settle
each batch's COVERAGE GATE before the next — do not over-spawn lanes for a
trivial round. Record each returned `batch_id`, then continue only ledger-safe
architect work: normalize feedback IDs, gather deterministic PR metadata, prepare
reproduction commands, and plan likely fix groups. Do not edit, close items, or
mark feedback resolved from running lanes.

Every verification lane must end with one parseable row for each owned item:

```text
[FEEDBACK-VERIFIED] | FB-### | CONFIRMED/PARTIAL/DISPROVED/PRE_EXISTING/NEEDS_MORE_EVIDENCE/NEEDS_USER_DECISION | evidence
```

Non-empty prose without this marker contract is not a settled verification
artifact and cannot unlock mutation.

Before the Verification step can mark any item `CONFIRMED`, `PARTIAL`,
`DISPROVED`, `PRE_EXISTING`, `NEEDS_MORE_EVIDENCE`, or `NEEDS_USER_DECISION`,
every open verification batch must be fully settled. Poll with
`collect_lane_results` (wait omitted or `false`) to process settled lanes
incrementally — clustering confirmed items and pre-reading files for settled
findings while ledger-safe work remains — then issue a final
`collect_lane_results` with `wait: true` per batch once independent work is
exhausted, to confirm every lane is settled.
Missing, stale, cancelled, or failed lanes are coverage gaps that must be closed
before marking any item CONFIRMED/PARTIAL/DISPROVED/PRE_EXISTING. Apply the
COVERAGE GATE:
retry failed lanes (max 2) as another
`swarm-pr-feedback:verification` async batch with the same immutable inventory,
exact `pr_head_sha`, agent type, prompt, scope, and isolation, or stop and
surface the lane failure to the user as BLOCKED. Under Profile A, blocking and
direct-Task fallbacks are rejected because they cannot satisfy the durable
ownership and head-provenance gate.
Do not proceed with "blocking verification and record that async advisory lanes
were unavailable" — record-and-continue is not coverage closure.

Under Profile B, partition the same immutable inventory across fresh read-only
verification subagents — every `FB-###` item owned by exactly one lane and the
union of lanes covering the entire ledger — with each prompt stating its owned
IDs and the exact `pr_head_sha`, and each lane returning one
`[FEEDBACK-VERIFIED]` row per owned item. Under Profile C, verify the ledger
in sequential category passes with the same one-row-per-item contract. On
every profile, no item may be classified until its verification lane or pass
has settled, and unclosable verification gaps are surfaced as BLOCKED.

### CI matrix cascade check (do this before fixing)

When the PR's `unit` job is a matrix across multiple OSes and downstream jobs
(`integration`, `smoke`) have `needs: unit`, an OS leg failure blocks the
entire pipeline. Before triaging, check:

1. Are `integration` or `smoke` jobs in `skipped` or `cancelled` state rather
   than `failed`? That signals a unit matrix cascade — the unit job failed
   on one OS leg, blocking the downstream jobs from running on the current
   HEAD.
2. If a unit OS leg is the blocker, classify the failure:
   - **Code issue** — the test itself fails. Reproduce locally; if the
     test passes locally, the runner is the problem.
   - **Runner performance** — the test step exceeds the configured timeout.
     Run all files in the step locally with per-file timing; if cumulative
     local runtime is <10 min and the runner can't complete in 60+ min, the
     issue is runner performance. Bump the CI timeout as a stopgap and file
     a follow-up issue for parallelization. Do not loop bumping the timeout
     past 90 min without filing the follow-up.
3. Surface cascade failures to the user explicitly. The downstream jobs'
   results don't exist; the code's coverage of the current HEAD cannot be
   confirmed by CI alone.

### PR body claim verification

The `.swarm/evidence/` paths below apply only when the reviewed repository uses
this plugin's council evidence contract. For any other repository, locate the
authoritative CI attestation, code-host review record, or repository-declared
evidence store; the universal rule is that an approval claim needs a real,
retrievable provenance artifact.

PR body text like "PHASE 2 council APPROVED (5/5, round 2)" or "Final council
APPROVED" must be backed by an evidence file under `.swarm/evidence/` — phase
councils write `.swarm/evidence/{phaseNumber}/phase-council.json`; the final
council writes the flat `.swarm/evidence/final-council.json`. Bot-generated PR
bodies commonly auto-fill these claims without real review. Before accepting
such a claim as part of triage:

1. Check whether the corresponding evidence file exists with `verdict:APPROVED`.
2. If the claim is unsupported, mark the closure ledger item as
   `NEEDS_MORE_EVIDENCE` rather than `CONFIRMED`. Do not silently drop the
   claim — it indicates the PR body was generated without a real review.
