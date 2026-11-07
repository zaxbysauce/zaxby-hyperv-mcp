# Phase 10 Metrics and Knowledge Writeback / Phase 11 Post-Fix Re-verification

## Phase 10: Metrics and Knowledge Writeback

At the end of the review, include review quality metrics in the final report's
validation provenance. Persist them only through an invoked evidence tool and
record the exact `.swarm/evidence/` path returned by that tool; if no invoked
tool supports metrics (including all of Profiles B/C), state `NOT PERSISTED —
no metrics evidence writer` and keep the metrics block in the final report and
session ledger rather than naming a nonexistent command or path.

Record:

- raw candidates by base lane,
- raw candidates by micro-lane,
- deterministic tool candidates,
- reviewer-confirmed findings,
- reviewer-disproved findings,
- reviewer-unverified findings,
- critic-upheld findings,
- critic-downgraded findings,
- critic-disproved findings,
- final reported findings,
- suppressed non-actionable candidates,
- recurring false-positive patterns,
- commands or probes used,
- token/time cost if available,
- accepted/fixed findings when known.

Knowledge writeback rules:

- Write back only validated true positives or validated false-positive patterns.
- Include file patterns, invariant, evidence, and why it was confirmed/disproved.
- Mark repo-specific lessons as project-tier unless there is strong evidence they generalize.
- Never promote quarantined or unvalidated knowledge to hive-tier.
- Never store secrets, private tokens, or raw sensitive logs.

---

## Phase 11: Post-Fix Re-verification

When the PR author pushes fixes after a review, perform a targeted re-verification before updating the verdict.

### Re-verification scope

Only re-verify findings the author claims to have fixed. Do not re-run the full review pipeline.

### Re-verification steps

1. For each finding the author claims fixed:
   a. Read the changed file(s) from the updated branch at the specific lines referenced in the original finding.
   b. Verify the fix addresses the root cause, not just the symptom.
   c. Check that the fix does not introduce a new issue in the same area.
2. Run CI checks on the updated branch to confirm no regressions.
3. For findings the author did not address, carry forward the original finding with unchanged status.

### Re-verification output

```
[REVERIFIED] | finding_id | FIXED / PARTIALLY_FIXED / NOT_FIXED / NEW_ISSUE | evidence | updated_severity
```

- `FIXED`: the root cause is resolved and no new issue introduced.
- `PARTIALLY_FIXED`: the root cause is partially addressed or a residual concern remains.
- `NOT_FIXED`: the root cause persists unchanged.
- `NEW_ISSUE`: the fix introduced a new problem at the same location.

Update the verdict only after re-verifying all previously blocking findings.
