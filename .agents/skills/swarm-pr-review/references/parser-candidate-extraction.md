# Candidate extraction via parser

### Candidate extraction via parser

Under Profile A, after `collect_lane_results` returns for base lanes, process
each lane result that carries an `output_ref`. The orchestrator MUST use the
candidate parser rather than preview-text extraction:

1. For each singleton base `output_ref`, call `parse_lane_candidates` with
   `output_ref`, `producer: "swarm-pr-review"`,
   `expected_family: "base_explorer"`, and `expected_lane` set to the exact
   `workflow_lane` declared at dispatch. For a consolidated tier-S/M lane, call
   the parser once for each owned dimension with that dimension as
   `expected_lane` and pass `expected_lanes` as the lane's complete
   `owned_workflow_lanes` array on every call. The parser reads the full artifact
   from disk (no preview truncation issue), rejects unowned rows, and returns
   structured `ParseResultWithSidecar` records.
2. Filter the returned `candidates[]` by `producer: "swarm-pr-review"` plus the
   exact `source_batch_id` and `source_lane_id` from the base dispatch. Treat a
   family mismatch or parse error as a lane-output failure; family metadata is
   not the acceptance boundary.
3. Group the filtered candidates into reviewer-sized chunks:
   - by file area (group by the directory or module of the `file_line` field),
   - by category (group by the `category` field),
   - by count (target max 50 candidates per chunk; smaller chunks are fine).
4. Stage reviewer-sized chunks, but do not dispatch reviewers yet. Phase 4 must
   complete trigger accounting and settle every launched micro-lane first.

If a lane has `output_degraded: true`, no usable `output_ref`, or `transcript_incomplete: true` without typed positive-candidate recovery, apply the COVERAGE GATE (Phase 3). An incomplete base or micro discovery lane may proceed only when it is explicitly named by a `salvaged_workflow_lane_recoveries` entry whose `kind` is `transcript-incomplete-terminal-candidate`; that recovery validates the retained positive `[CANDIDATE]` row only. Council, reviewer, and critic lanes never qualify for this incomplete-transcript recovery and must retry. Recovery never validates `[CLEAN]`, candidate absence, an unowned sibling lane, or an incomplete lane with no matching entry. Do not use blocking or direct-Task fallbacks while the controller is active, mark affected candidates UNVERIFIED to proceed, or infer candidate absence from a preview. Under Profiles B/C, which have no typed recovery validation, a truncated, incomplete, empty, or attestation-free subagent report is the same lane-output failure and takes the same COVERAGE GATE.

After candidate parsing and before reviewer dispatch, persist the post-explorer
candidate ledger. The base-only write is admissible immediately after base
settlement — it is the durable recovery point for context compaction from base
settlement onward; once trigger evaluation completes, a full-inventory
(base+micro) `post_explorer` write may refresh it ahead of Phase 6.

**Profiles B/C row convention:** without the parser, the `[CANDIDATE]` row
format is the extraction contract itself. Explorers emit the rows directly in
their reports (see the Explorer Prompt Template reference); the orchestrator
collects them verbatim, validates each row's field count and lane id, and
treats malformed rows — or output with neither `[CANDIDATE]` rows nor a fully
populated `[CLEAN]` attestation — as a lane-output failure under the COVERAGE
GATE. If the parser is unavailable under Profile A, the same row convention
applies as a fallback, but the orchestrator SHOULD use the parser as the
primary extraction mechanism.

**lane id uniqueness for parallel dispatches:** When re-dispatching failed or
re-running explorer lanes, every `dispatch_lanes_async` or `dispatch_lanes`
lane `id` MUST be unique within that dispatch batch and should include lane and
attempt suffixes (e.g., `pr_review_explore_lane1_attempt2`). Never reuse an id
in the same batch unless intentionally replacing that exact lane before dispatch.

Explorers optimize for recall. Over-reporting is expected. Explorers produce candidates only.

The six dimensions are a fixed **check-type** partition, not an area
partition: every PR needs all six review dimensions, and the lanes
deliberately overlap by file, each receiving the same diff (via
`common_prompt` under Profile A) and viewing it through a different lens. Six
dimensions are this workflow's high-assurance coverage floor, not a claim that
research proves a universal optimal agent count — the published evidence
favors complementary, distinct-lens reviewers over duplicated generalists, and
finding rates rise with diff size, which is why dispatch (not coverage)
follows the depth tier. Repository policy may add scrutiny but may never
reduce the six dimensions. Coverage is guaranteed by all six dimensions
reading the whole diff, so the disjoint-partition rule that governs area-split
fan-outs does not apply.

| `workflow_lane` | Focus | Required checks |
|---|---|---|
| `intent-architecture` | Intent, scope, architecture, and integration | obligation mapping, design fit, callers/consumers, sibling patterns, docs and claimed-vs-actual behavior |
| `correctness-state` | Functional correctness, data/state flow, edge cases, and failure paths | input domains, nullability, ordering, transactions, error behavior, rollback, backwards behavior |
| `tests-falsifiability` | Tests, test validity, regressions, and claimed validation | assertion strength, negative paths, isolation, fixtures, deterministic timing, missing proof |
| `security-trust` | Security, privacy, trust boundaries, unsafe inputs/sinks, and supply chain | authorization, injection, secrets, provenance, dependency risk, data exposure, abuse paths |
| `reliability-performance` | Reliability, concurrency, retries, resource bounds, and performance | races, retry semantics, timeouts, lifecycle, caching, algorithmic cost, operational failure modes |
| `compatibility-delivery` | API/schema/config compatibility, maintainability, build/deploy, docs, and release behavior | public contracts, migrations, runtime/platform support, packaging, CI, rollout and recovery guidance |
