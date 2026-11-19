# Re-baseline runbook (frozen-checkpoint drift repair)

The issue-tracer checkpoint manifests live under `.agents/issue-traces/` (git-ignored), so a
later PR that edits a frozen file with no `AMEND` row drifts the manifest silently: nothing in
CI re-verifies it, and the drift surfaces only when a later trace needs the same frozen files.
This runbook is the sanctioned repair procedure.

## When to run it

Run the drift inventory (one command, below) whenever a PR touches a file that appears in a
checkpoint manifest — e.g. before merging any PR whose diff intersects `src/`,
`tests/unit/test_*.py`, `tests/integration/*.py`, frozen `repro/check-*.sh` scripts,
`README.md`, or the docs/scripts this wave pinned. The authoritative membership test is
the manifest itself: grep `.agents/issue-traces/*/repro/checkpoint.manifest` for the path. The `--check` gate compares the docs copy against a live regeneration AND
fails on real drift: any sibling (non-self-referential) frozen pair whose
verify-checkpoint reports CHANGED exits 1 even when the docs copy matches
the regeneration, and a verify-checkpoint that exits nonzero with no
CHANGED lines (a broken local setup) fails the gate too. Regeneration
clears only the docs-copy staleness; a genuine CHANGED pair is repaired by
the per-pair AMEND procedure below, never by regenerating. Verifier exit codes are `0` (clean) and `1` (drift found); exit `2` means a
missing or malformed trace/manifest (invalid local checkpoint setup — not a
clean-or-drift result), and the generator's `--check` treats it as a gate failure. No
legacy manifest format remains in the tree (a repo-wide sweep finds only exit 0/1).

## One-command local verification

Prerequisite: the git-ignored local trace store must exist (`.agents/issue-traces/` with
checkpoint manifests). From a clean checkout the gate fails closed with exit 2 — restore
or re-sync the local traces first; it cannot run there.

```
python scripts/gen_trace_drift_inventory.py --check
```

`--check` regenerates the inventory in-memory, compares it against
`docs/issue-trace-drift-inventory.md`, and fails on any sibling CHANGED
pair or broken leg even when the docs copy matches. exit 1 with a
`CHANGED <trace>: ...` line means REAL drift — repair it with the per-pair
AMEND procedure below (regeneration cannot clear it); exit 1 with a diff
but no CHANGED lines means only the docs copy is stale — regenerate and
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

## The amend-guard and the trace ledger (#148)

Every AMEND row is guarded by a two-tier contract, enforced by
`scripts/verify_amend_verbatim.py` and wired into the inventory gate: once the
baseline watermark below activates it, the generator invokes the guard on every
manifest it walks (during regeneration and `--check`), so the pre-push chain
enforces it end to end.

- **argv mismatch = gate failure.** An AMEND row whose `argv` differs from its predecessor
  effective row for the same `(path, check-id)` pair is retype corruption: the guard exits 1,
  the inventory run fails (`GUARD FAIL <trace>` naming the row), and `--check` returns 1.
- **expect-only or base-only change = WARN, disclosed.** An AMEND that changes only `expect`
  (a `CHECK_WRONG` stable-predicate repair) or only `base` (a versioning-policy amendment)
  exits 2: the generator discloses `GUARD WARN <trace>` on stderr and continues. These tiers
  are sanctioned only with acceptance-table sync and fresh replay evidence.
- **verbatim = silent OK.** An AMEND preserving `argv`/`expect`/`base` byte-for-byte is the
  normal re-freeze shape and prints nothing.

The watermark lives in the committed `docs/amend-guard-baseline.json`
(`{trace-slug: {"watermark_seq": <max row seq dispositioned>, "dispositioned_commit":
<40-hex>, "legacy_argv_exceptions": <count>}}`). AMEND rows with
`seq <= watermark_seq` are BASELINE-dispositioned (counted, never FAIL) — the reviewed
legacy repair rows predate the guard and are immutable, append-only history. The recorded
`dispositioned_commit` is always a proper ancestor of the commit carrying the baseline file,
never the activation commit itself (the two-commit repair-then-activate sequencing) — that
ancestor invariant is documented here and in the guard's docstring but not yet enforced in
code (enforcing it needs a full-history git checkout; the guard verifies watermarks and
argv-exception counts only). A manifest with NO baseline entry is watermark 0: new traces
are born strict from row 1. While
the baseline file is absent the generator skips the guard entirely — its presence IS the
activation switch.

Pre-AMEND floor — run the tool before every planned AMEND:

```
python scripts/verify_amend_verbatim.py .agents/issue-traces/<trace>/repro/checkpoint.manifest --repo-root .
```

1. Expect exit 0 before touching the manifest; exit 2 lines name already-sanctioned semantic
   amendments; exit 1 means STOP — repair the corruption first with the per-pair procedure
   above, never AMEND on top of it.
2. Append the AMEND row, then re-run the tool: the new row must read verbatim (exit 0) or be
   a disclosed WARN tier with its evidence recorded.
3. `--json` emits machine-readable findings (the generator's per-manifest invocation shape).

The trace ledger (`docs/issue-trace-ledger.md`) closes the deletion-laundering hole:
comparing the store against the rendered document cannot see a deleted trace — after
deletion both lack the slug — so the register of every slug ever rendered lives outside the
store, as committed state.

- Regeneration appends newly rendered slugs automatically
  (`- <slug> | active | <first-rendered commit> | -`).
- An `active` ledger slug that is no longer rendered is reported as `MISSING <slug>` on
  stderr and fails `--check` (regeneration exits nonzero with the same disclosure): restore
  the trace store, or retire the slug.
- Retirement is the only manual edit: flip the row to
  `- <slug> | retired | <commit> | <date> <reason>`. Only then does the gate go clean for an
  intentionally removed trace.
- Quine safety: the ledger carries no inventory-derived value (no blobs, counts, or
  verdicts), and guard/MISSING results are never rendered into the document — consecutive
  regenerations are byte-stable.

Hook contract: a pre-push gate exit `2` means the local checkpoint setup itself is broken
(missing manifests/store) — BLOCK the push and restore the store first; exit `2` is never a
skip-with-warning (the old skip arm is removed; the maintainer-host hook is fixed host-side
and disclosed in the PR). Exit `1` stays a real drift failure; exit `0` passes.
