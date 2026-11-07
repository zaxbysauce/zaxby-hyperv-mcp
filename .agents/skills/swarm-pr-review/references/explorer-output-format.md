# Explorer output format

### Explorer output format

Explorers emit structured candidate records. The parser reads the full lane
artifact and extracts these records. The canonical record shape is:

The fence below is documentation formatting only. Emit the header and all
machine-readable rows as unfenced plain text; do not emit the backticks.

```text
[CANDIDATE] | candidate_id | lane | severity | category | file:line | claim | evidence_summary | impact_context | confidence | risk_impact | risk_tags
```

Profile A now treats `submit_pr_review_result` as the authoritative settlement path for base and micro discovery lanes. The caller-bound structured receipt dominates later prose, truncation, or transcript incompleteness. Transcript candidate/clean rows remain deprecated compatibility only when `pr_review_legacy_transcript_compatibility` was explicitly enabled for that lane and no structured receipt exists; a present-but-invalid structured result fails closed and never falls back.

When compatibility mode is active, Profile A stores the full assistant transcript. The parser locates the first pipe-delimited line whose first field is exactly `[CANDIDATE]`, ignores unmarked preamble, and requires the exact canonical base/micro header; malformed markers or marker-prefixed rows without a header fail closed. The controller refuses a missing marker. Markerless positional fallback remains only for legacy callers outside that trust boundary; explorers should put the canonical header first.

The confidence data value must be exactly LOW, MEDIUM, or HIGH.

Under Profile A the parser-backed transcript path is compatibility-only; a successful `submit_pr_review_result` receipt is authoritative. On Profiles B/C — and on a Profile A lane whose snapped contract explicitly enables deprecated legacy transcript compatibility and lacks a structured receipt — the explorer emits `[CANDIDATE]` rows directly as the extraction contract.

Explorers must not use `CONFIRMED`, `DISPROVED`, or `PRE_EXISTING`.

A base lane that finds no surviving candidates must submit exactly one structured CLEAN result and then stop. Only a lane in the deprecated transcript-compatibility path may instead emit exactly one fully populated clean row:

The fence below is documentation formatting only. Emit the clean attestation
as unfenced plain text; do not emit the backticks.

```text
[CLEAN] | lane | coverage_scope | evidence
```

Header-only `[CLEAN]` markers, prose-only "clean" claims, or empty output do
not settle the lane.

---

---

# Explorer context contract

### Explorer context contract

Every explorer must inspect or explicitly mark unavailable:

1. the changed hunk,
2. at least one caller, consumer, or downstream impact-cone node,
3. at least one callee, dependency, or upstream assumption,
4. at least one sibling implementation or prior pattern,
5. the nearest relevant test or missing-test location,
6. deterministic signal entries mapped to its files/symbols,
7. relevant Swarm knowledge/evidence entries, if present.
8. the exact bound review range to analyze (`base_sha...pr_head_sha`),
