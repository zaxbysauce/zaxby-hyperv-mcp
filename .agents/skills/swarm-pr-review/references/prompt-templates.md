# Reviewer Prompt Template

Every child review prompt must use `repo_map` `diff_context` and `impact_cone`; for trust-boundary or data-flow candidates it must also use `route_trace` and `data_trace`. Graph evidence is advisory only. Require source anchors. If freshness is stale or inconclusive, confidence is low, source is missing, the language is unsupported/dynamic, the graph is absent, or an action fails, validate against the direct source, Git diff, and searches before returning a finding.

Use this template when dispatching reviewer subagents (Profile A — content only; the controller injects the authoritative row contract and its card):

```text
You are the independent reviewer. Validate only the candidates assigned below.
Do not search for new issues except where needed to validate reachability or mitigation.
Do not trust explorer severity.

Context pack summary:
- scope: ...
- obligations: ...
- impact cone: ...
- deterministic signals: ...
- relevant Swarm artifacts / knowledge: ...
- base_ref: <commit SHA of base branch>
- head_ref: <commit SHA of PR head branch>

Candidates:
- ...

For each assigned candidate, return one structured reviewer verdict row in the
exact format the controller-appended contract card specifies (the card carries
the full field grammar, enums, and escaping rules). Verdict rows are accepted
anywhere in the response, exactly one live row per assigned ID; no other line
in your response may begin with the row marker.

Do not copy the contract card's explicitly DISCARDED examples as live rows.

You must check caller context, reachability, schema/middleware/framework mitigations, state-machine constraints, test coverage, PR-introducedness, and severity.

IMPORTANT: If a finding claims behavior is "new" or "introduced by the PR", you MUST read the equivalent code on the base branch (git show <base_ref>:<file>) to verify it was not present before. A reviewer claim of "this is new" is invalid without base-branch evidence. Do not compare the new code to an idealized baseline — compare it to what actually existed on the base branch at the time of the PR.
```

---

# Critic Prompt Template

Use this template when dispatching critic subagents (Profile A — content only; the controller injects the authoritative row contract and its card):

```text
You are the adversarial critic. Challenge only reviewer-confirmed findings assigned below.
Your goal is to reduce false positives, severity inflation, and non-actionable reports.

For each finding, challenge:
- whether evidence proves the claim,
- whether the path is reachable,
- whether mitigations apply,
- whether severity is inflated,
- whether it is PR-introduced,
- whether suggested fixes are safe/actionable,
- whether related files were missed,
- whether multiple findings should be grouped.

For each assigned finding, return one structured critic verdict row in the
exact format the controller-appended contract card specifies. The card states
the UPHELD and DOWNGRADED severity rules; UPHELD keeps the reviewer's own
severity for the item and the controller renders each assigned item's reviewer
severity in its contract block. Verdict rows are accepted anywhere in the
response, exactly one live row per assigned ID; no other line in your response
may begin with the row marker. The same free-text escaping rules the card
states apply to critic reason and required-change fields. A waited collection
deadline is an observer deadline only: it bounds the collect call and never
cancels or terminalizes lane work (issue #2381) — poll again, explicitly
cancel, or rely on the presumed-stale sweep.
```

---

# Base Explorer Prompt Template

Use this template when dispatching a base explorer (Profile A — content only; the controller injects the authoritative output contract):

```text
You are a base explorer. Optimize for recall, not final judgment.
Return candidates only. Do not use CONFIRMED, DISPROVED, or PRE_EXISTING.
On Profile A structured PR-review discovery lanes, call `submit_pr_review_result`
exactly once with the canonical base-lane result and then stop. Do not append
duplicate candidate or clean transcript rows or recap prose after that
tool call.
Transcript machine rows are deprecated legacy compatibility only. Emit them
only when the dispatched lane explicitly enables
`pr_review_legacy_transcript_compatibility`.
Do not narrate progress or repeat the prompt. Keep the complete final response at or below 12,000 characters; spend that budget on evidence-bearing rows and the minimum prose needed to make them auditable. When the controller-appended contract declares a per-lane final_response_char_budget, that number is authoritative over this template default.

Lane:
Scope:
base_ref:
head_ref:
Obligations:
Changed files/hunks:
Impact cone:
Relevant deterministic signals:
Relevant Swarm artifacts / knowledge:
Checklist:

You must inspect or mark unavailable:
1. changed hunk,
2. caller/consumer,
3. callee/dependency,
4. sibling implementation or prior pattern,
5. nearest test or missing-test location,
6. deterministic signals,
7. Swarm artifacts/knowledge,
8. the exact `base_sha...pr_head_sha` merge-base range and both endpoint revisions.

Candidate and clean rows go in the structured result (or, only where legacy
transcript compatibility is explicitly enabled, in the plain marker-row format
the controller contract specifies — never inside a Markdown fence).
```

---

# Micro-Lane / Council Explorer Prompt Template

Use this template when dispatching a micro-lane or council explorer (Profile A — content only; the controller injects the authoritative output contract):

```text
You are a micro-lane or council explorer. Optimize for recall, not final judgment.
Return candidates only. Do not use CONFIRMED, DISPROVED, or PRE_EXISTING.
On Profile A structured PR-review discovery lanes, call `submit_pr_review_result`
exactly once with the canonical micro-lane result and then stop. Do not append
duplicate candidate or clean transcript rows or recap prose after that
tool call.
Transcript machine rows are deprecated legacy compatibility only. Emit them
only when the dispatched lane explicitly enables
`pr_review_legacy_transcript_compatibility`.
Do not narrate progress or repeat the prompt. Keep the complete final response at or below 12,000 characters; spend that budget on evidence-bearing rows and the minimum prose needed to make them auditable. When the controller-appended contract declares a per-lane final_response_char_budget, that number is authoritative over this template default.

Micro/council lane:
Scope:
base_ref:
head_ref:
Obligations:
Changed files/hunks:
Impact cone:
Relevant deterministic signals:
Relevant Swarm artifacts / knowledge:
Checklist:

You must inspect or mark unavailable:
1. changed hunk,
2. caller/consumer,
3. callee/dependency,
4. sibling implementation or prior pattern,
5. nearest test or missing-test location,
6. deterministic signals,
7. Swarm artifacts/knowledge,
8. the exact `base_sha...pr_head_sha` merge-base range and both endpoint revisions.

Candidate and clean rows go in the structured result (or, only where legacy
transcript compatibility is explicitly enabled, in the plain marker-row format
the controller contract specifies — never inside a Markdown fence). Council
explorers: your controller contract carries a response-format override — the
reply is plain marker rows, not a fenced JSON block.
```

Under Profile A the authoritative discovery-settlement path is exactly one
`submit_pr_review_result` call per base/micro lane. Transcript
candidate/clean rows remain a deprecated fallback only when the
lane's snapped `pr_review_legacy_transcript_compatibility` contract enables
them and no structured receipt exists. On Profiles B/C the candidate row
formats below remain the extraction contract. Explorers emit structured
records regardless of which harness runs them.

Do not let speed degrade validation quality.

---

## Profile B/C row formats

On Profiles B/C there is no controller-injected contract, so the marker rows below ARE the extraction contract. Each line is the full row grammar; the `EXAMPLE — NOT A LIVE ROW: ` prefix keeps a verbatim echo from parsing as a live marker row (field 0 must be the bare marker).

EXAMPLE — NOT A LIVE ROW: [REVIEWED] | item_id | classification | evidence_type | severity | introduced_by_pr | file:line | rationale | probe | reviewer_notes | risk_impact | risk_tags

EXAMPLE — NOT A LIVE ROW: [CRITIC] | item_id | status | severity | rationale | required_change

EXAMPLE — NOT A LIVE ROW: [CANDIDATE] | candidate_id | lane | severity | category | file:line | claim | evidence_summary | impact_context | confidence | risk_impact | risk_tags

EXAMPLE — NOT A LIVE ROW: [CANDIDATE] | candidate_id | micro_lane | severity | category | file:line | claim | invariant_violated | evidence_summary | confidence | risk_impact | risk_tags

EXAMPLE — NOT A LIVE ROW: [CLEAN] | lane | coverage_scope | evidence

EXAMPLE — NOT A LIVE ROW: [CLEAN] | micro_lane | coverage_scope | evidence

On Profiles B/C, verdict and candidate rows are accepted anywhere in the response, exactly one live row per assigned ID, and no other line may begin with the marker.

## Contract addendum (2026-10-12)

- **Candidate rows are defect claims only.** Never emit verification notes,
  confirmations, or coverage observations as CANDIDATE rows, and no
  INFO-severity candidates — confirmations belong in the lane's
  attestation/clean row. A misattributed or confirmatory candidate inflates
  reviewer adjudication for zero signal.
