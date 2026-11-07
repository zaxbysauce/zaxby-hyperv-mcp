# Council Mode Workflow detail


Council mode is opt-in only and adversarial.

When triggered:

1. Build the same context pack as default mode.
2. After the default base-dimension and risk-family coverage is complete, launch all supplementary council agents. Under Profile A, use one `dispatch_lanes_async` call with `mode: "swarm-pr-review:council"`, the same exact `pr_head_sha`, and one unique `workflow_lane` per council member; continue independent context preparation while they run, polling with `collect_lane_results` (without `wait`) to process settled agents incrementally, and use `wait: true` only when no independent work remains. All agents must be settled and their candidates added to the ledger before reviewer classification; under Profile A the runtime enforces this join barrier, and blocking, sequential, or direct-Task fallback is not equivalent to the structured council dispatch — bypassing the active controller is `BLOCKED`. Under Profile B, dispatch council members as parallel subagents with the same marker contract and settle them all before reviewer classification; under Profile C, run each council lens as a separate sequential pass.
3. Each council agent assumes all work is wrong until code evidence proves otherwise.
4. Each agent hunts within its lane only.
5. Council uses the micro-lane row family: `[CANDIDATE] | candidate_id | micro_lane | severity | category | file:line | claim | invariant_violated | evidence_summary | confidence | risk_impact | risk_tags`. Emit one row per `EVIDENCE_FOUND` or `SUSPICIOUS` claim, or a fully populated `[CLEAN] | micro_lane | coverage_scope | evidence` row when no candidate survives. Put the exact council `workflow_lane` value in the `micro_lane` data field. Council prose without one of those markers does not settle the lane.
6. Agents must not return `CONFIRMED`, `DISPROVED`, or final severity; candidate severity remains provisional until reviewer classification.
7. The independent reviewer then classifies every council candidate as `CONFIRMED`, `DISPROVED`, `UNVERIFIED`, or `PRE_EXISTING`.
8. Apply critic challenge to reviewer-confirmed HIGH/CRITICAL or borderline findings.
9. Final synthesis distinguishes real blockers, real low-severity issues, accepted caveats, disproved council claims, and follow-up quality work.

Default council lanes:

- correctness and edge cases,
- security and trust boundaries,
- dependency and deployment safety,
- docs and intent-vs-actual,
- tests and falsifiability,
- performance and architecture when risk justifies it.

Council prompt requirements:

- branch and commit range,
- context pack summary,
- files owned by that lane,
- relevant impact cone,
- explicit checklist,
- strict output cap,
- `EVIDENCE_FOUND / SUSPICIOUS / CLEAN` only,
- file:line evidence required for `EVIDENCE_FOUND`.

Council findings are supplementary, not authoritative overrides. Do not adopt council severities or claims without independent validation.
