# Re-baseline runbook (frozen-checkpoint drift repair)

The issue-tracer checkpoint manifests live under `.agents/issue-traces/` (git-ignored), so a
later PR that edits a frozen file with no `AMEND` row drifts the manifest silently: nothing in
CI re-verifies it, and the drift surfaces only when a later trace needs the same frozen files.
This runbook is the sanctioned repair procedure.

## When to run it

Run the drift inventory (one command, below) whenever a PR touches a file that appears in a
checkpoint manifest — i.e. before merging any PR whose diff intersects
`src/`, `tests/unit/test_*.py`, or `README.md` paths pinned by a closed trace. The `--check` gate compares the docs copy against a live regeneration and exits
1 on drift between the two; it does not by itself assert that every trace is
clean — read the inventory's CHANGED tallies (or run the verifier per trace)
for that. Verifier exit codes are `0` (clean) and `1` (drift found); no legacy
manifest format remains in the tree (a repo-wide sweep finds only exit 0/1).

## One-command local verification

```
python scripts/gen_trace_drift_inventory.py --check
```

`--check` regenerates the inventory in-memory and compares it against
`docs/issue-trace-drift-inventory.md`; exit 1 + a diff means the docs copy is stale (either the
tree moved under a frozen pair — new drift — or the docs copy was hand-edited). Regenerate and
commit:

```
python scripts/gen_trace_drift_inventory.py
```

## Repair procedure (per drifted pair)

1. **Extract verbatim.** Read the drifted pair's EFFECTIVE manifest row (the last row for its
   `(path, check-id)` pair) and copy its `argv` and `expect` cells verbatim — never retyped
   (regex-escaping differences break verify-semantics against the trace's acceptance table).
2. **Append the AMEND row.**
   `bash .agents/skills/issue-tracer/scripts/repro-check.sh checkpoint --slug <trace> --reason CHECK_WRONG --id <check-id> --argv "<verbatim argv>" --expect "<verbatim expect>" --base <original replay base, preserved> -- <path>`
   One row per drifted `(path, check-id)` pair.
3. **Replay.** `bash .agents/skills/issue-tracer/scripts/repro-check.sh run --slug <trace> --id <check-id> --base <base> --class <class from the trace's acceptance table> --expect "<verbatim expect>" [--copy <base-absent files>] -- <argv>` — base leg RED (or PRESERVING GREEN/GREEN) and head leg GREEN per class.
4. **Sync the trace's acceptance table** if (and only if) the amendment changed an `argv`/`expect` cell: the table cell must equal the new effective row (verify-semantics enforces it).
5. **Re-anchor.**

   ```
   bash .agents/skills/issue-tracer/scripts/repro-check.sh anchor --slug <trace>
   ```
6. **Verify before posting.** `grep -q '^issue-tracer-checkpoint-v1 slug=' <captured receipt line>` then
   `verify-anchor --slug <trace> --receipt '<the exact literal>'` on the literal you are about to
   publish; post it as a NEW comment explicitly superseding the previous receipt (name which
   comment ids it replaces).
7. **Re-verify the whole trace:** `verify-checkpoint --slug <trace>` must report every pair OK
   before you close the repair.

## Stable-predicate rule

An effective `expect` cell must never encode a raw count that suite growth breaks (`5 failed,
1094 passed`). Pin signatures, not counts: for full-suite checks pin the pytest summary verb
(`passed`) or a named test node; for node-level checks pin the failure-signature family
(the `AssertionError: ACn:` prefix). Suite-size churn then edits nothing.

## Amendment reasons

- `CHECK_WRONG` — the check's mechanism was wrong, drifted, or its predicate unstable; the
  amendment repairs provenance and stays within the original intent.
- `AC_CHANGED_BY_USER` — the acceptance criterion itself moved by sanctioned decision (e.g. a
  version re-pin); record the authority in the PR body or the issue comment.
