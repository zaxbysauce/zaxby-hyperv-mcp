# Critic PASS 2 — impact and severity challenge, PR #96

Head fbb78b7, base e8ec728. Every line number below was re-verified against the
checked-out tree, and every severity was re-derived from the mechanics rather
than inherited from pass 1. Where pass 1 and I diverge, the divergence is the
point.

## Verdict tally

| Finding | Pass-2 verdict | Severity I assign |
| --- | --- | --- |
| H2 (PRR-002) active job rows never demoted, cap wedges | SURVIVES | HIGH (low end) |
| H7 (PRR-015) guardrail claim + six unpinned invariants | DOWNGRADE | MEDIUM |
| H1 (PRR-001) AC10 integration test unrunnable | confirm downgrade | MEDIUM |
| H3 (PRR-003) write-through not atomic | confirm downgrade | MEDIUM |
| H4 (PRR-004) relay _release divergence + masked error | confirm downgrade | MEDIUM |
| H5 (PRR-006) restored credential identity not pinned | confirm downgrade | LOW |
| H6 (PRR-010) forward migration unimplemented | confirm downgrade | LOW |

## Overall verdict: NEEDS_REVISION

H2 is a live availability defect in the flagship capability this PR ships; H7
is a genuine coverage gap whose "false verification claim" leg is weaker than
pass 1 presented. Both must be fixed before merge, along with the H3/H4 code
defects. H1/H5/H6 are process/documentation items.

---

## H2 — verdict: SURVIVES — HIGH (low end). I confirm pass 1.

The mandate asked me to probe four specific weakenings. All four fail; two
strengtheners surfaced instead.

**Probe 1: is there any in-band path that removes an `active` row?**
No. The only writers of job state are `_reserve_slot` (writes `starting`,
guestjobs.py:262-265), `_register` (writes `active`, :309), `_release_slot`
(deletes the `starting` placeholder, :299), cap eviction (deletes only
stopped/orphaned rows, :241-248), and `job_stop` (writes `stopped`, :843-845).
`job_status` — the one function that OBSERVES process exit — performs no store
write anywhere in its body (guestjobs.py:657-687). I confirmed against BASE
(git show e8ec728:src/hyperv_mcp/guestjobs.py): the stopped flag was set
only in `job_stop` at base too (base :602), so "exited jobs stay unstopped" is
pre-existing. What the PR changes is the remedy: at base a server restart
wiped `_jobs` and reset the cap; at head the store survives the restart BY
DESIGN, recovery only demotes `starting` (statestore.py:443-445), and the cap
counts the union with the store (guestjobs.py:239) — so the wedge is now
durable, and shared host-wide because the default path is
`%LOCALAPPDATA%\hyperv-mcp\state.db` for every server process
(statestore.py:575). The mandate's specific question — does a job that exits
on its own stay `active` forever? — is CONFIRMED: nothing demotes on observed
exit, before or after this PR.

**Probe 2: DB-file deletion as self-heal — does that make it MEDIUM?**
No. Two independent reasons. First, the workaround is heavier than it looks:
on Windows the server's open SQLite connection holds the file, so deletion
requires stopping the service; it destroys ALL durable state (the very feature
this PR exists to provide); and — the decisive point — the rows re-accumulate
after every subsequent client restart, so this is recurring operational toil,
not a fix. The realistic steady state: every agent workflow that starts jobs
which finish naturally and are never explicitly stopped leaves permanent rows;
the module docstring itself says "a stdio client restart is enough" to make
handles unaddressable, i.e. restarts are expected and frequent. N=128 is
reachable in weeks of normal use, and a single crash of a server running a
full registry wedges `job_start` on the next boot. Second, and worse than
pass 1 recorded: inline-credential rows can NEVER be removed through the API
at all. `_restored_credential` (guestjobs.py:99-113) raises CredentialError
for `cred_ref="inline"`, so a restored inline-cred `active` row fails
`job_stop` at `_entry_credential` (:779) before any leg runs — unremovable
even with the id in hand. And owned rows are removable only by their original
owner: `_restore_entry` returns None for a foreign owner (:134-135), so a
different agent principal gets `unknown job_id` (:348-351) even WITH the id.
The cap, however, counts every row regardless of owner (:239) — agent B's
`job_start` wedges on agent A's stranded rows and agent B cannot remediate
them. For stdio (owner=None) remediation-by-known-id works for env/file rows;
for multi-agent HTTP it does not.

**Probe 3: does the missing listing tool make it worse?**
Yes, and it is the difference between an incident and a mystery. Relays have a
no-id `relay_status` listing (relay.py:863-881) plus a self-healing
`interrupted` normalization (:183-185, :698-700) — a peer's `open()` flips
stranded `active` relay rows to an evictable state. Jobs have neither: server.py
registers only `hyperv_guest_job_start/_status/_output/_stop` (server.py:1873-1900),
and `Store.job_rows` has exactly one caller — the cap itself
(guestjobs.py:218). So the stranded ids are undiscoverable through the MCP
surface; an MCP-only operator sees a permanent "registry is full" with no
listed cause. An operator WITH sqlite3 access can run
`UPDATE jobs SET state='orphaned'` against the live file (multi-process SQLite
access is the store's own premise), which is the only reason this is the low
end of HIGH rather than higher.

**Probe 4: relay-side asymmetry.** Confirmed as pass 1 read it — the relay
half was given a self-healing answer, the job half was not. That asymmetry is
the strongest internal evidence this is unfinished design, not an accepted
trade-off. Required fix: demote on observed exit in `job_status` (the
reviewer's suggested hook is correct), or make recovery demote `active` rows
with a liveness/PID check, or add a job listing; at minimum, orphan
inline-credential rows at recovery so they become evictable. Confidence 90/100.

## H7 — verdict: DOWNGRADE to MEDIUM. I disagree with pass 1's HIGH.

This is the cross-model disagreement this pass exists to surface. The
substance of H7 survives — the coverage gaps are real and I verified all of
them independently — but the severity-rationale pass 1 gave is wrong in one
load-bearing place, and the corrected rationale lands at MEDIUM.

**Where pass 1 overshoots: the "falsified claim" leg.** Pass 1 wrote that the
claim "each proven by an executed mutation probe" is falsified. It is not —
not in the round-2/3 block at least. I read
`.agents/issue-traces/22-durable-state-store/08a-recurrence-sweep.md` and
`repro/probe-log.md`: twelve mutation probes (M1-M12) were genuinely executed
against byte-copied files with restore-verified hygiene, and ALL TWELVE were
KILLED. M6-M12 map one-to-one onto the six round-2/3 pins the comment block
at guardrail.py:199-203 describes, so the sentence "Every one is proven by an
executed mutation probe" is literally TRUE for the pins it scopes. What is
actually wrong with the header is much smaller: the module docstring says
"Eight pins" (guardrail.py:7) but there are NINE test functions — the UNC
refusal pin (test_store_refuses_a_network_path) was added later
(commit fbb78b7) with no recorded probe and no header update. So the honest
defect is a stale count plus one unprobed ninth pin — a documentation nit —
NOT a fabricated verification claim. This matters because pass 1 priced H7 at
HIGH partly on "the module's false claim is the PR's own evidence of
verification," and that premise is mostly false.

**What survives, re-priced.** The six unpinned invariants are real; I
re-verified each:

1. PID-0 refusal (guestjobs.py:762-778): zero tests. The only `job_stop` in
   the new suite is guardrail.py:467 on a RUNNING job; the orphaned tests
   (test_e01_durable_state.py:279-283, guardrail.py:347-373) exercise
   `job_status`'s early return (:664-672), never the stop refusal. This guard
   exists to prevent `_stop_script(0, "")` taskkilling the Win32 children of
   PID 0 as guest admin — the most destructive single operation in this
   codebase. This is the one sub-item that keeps H7 at the top of MEDIUM: it
   guards a destructive op, AND the natural H2 fix (demote on observed exit)
   will refactor exactly this region, so the regression vehicle is realistic.
2. `_recover` relay UPDATE (statestore.py:446-449): never runs against a
   populated relays table — the reload-based tests never re-run
   `statestore.open()` (the `_stores` cache survives module reloads), the
   store tests open fresh files, and C3's crash-child store has an empty
   relays table. The jobs half of the SAME function IS pinned by C3, which
   makes the relay half read as oversight. Mutates durable state, unpinned.
3. busy_timeout PRAGMA deletion (statestore.py:261): mutation-invisible, as
   pass 1 said — Python's connect default timeout=5.0 yields 5000 ms, so
   `store.busy_timeout_ms >= 5000` (test_e01_state_store.py:93) passes with
   the PRAGMA deleted. The blind timeout=0.0 control (:85-91) proves the READ
   is sensitive, not that open() SET it. Partial pin (a lowered value IS
   caught); deletion is not. Minor.
4. resolve_state_db_path config-key branch (statestore.py:572-574): zero test
   references to resolve_state_db_path anywhere in tests/; C5 (:317-325)
   checks Config parsing only, C9 checks the default branch. Minor.
5. Cap unions (guestjobs.py:239, relay.py:683) and store-only-key eviction:
   no test puts rows in the store AND entries in the local dict and exercises
   union counting or store-only eviction — the one cap test (guardrail.py:207-245)
   pins the local-live-not-evicted direction for relays only, at _MAX_RELAYS=1
   with a single key in both views. M6 probed only the same direction. Minor-to-moderate.
6. `_release` store-side relay_delete (relay.py:744): no test injects a store
   failure into relay_start; the pre-existing test_relay.py has no _release/
   relay_delete reference either. Overlaps H4.

**The seventh sub-item is its own defect class, confirmed.** The relay_stop
pin (guardrail.py:322-338) asserts `reads == [True]` by observing only
`__getitem__`. Two independent failures, verified from the test source: (a)
UNDER-strong — a mutant that reads `stopped` under the lock but writes it
outside passes, and that mutant re-opens the exact double-shutdown race the
pin exists to close (the recorded M7 probe only moved the READ outside; the
write-outside direction was never probed); (b) OVER-strict — a correct
implementation that reads the flag twice under one lock acquisition fails
(`reads == [True, True]`), a false failure of correct future code. A pin that
is simultaneously too loose and too tight is worse than no pin: it costs
maintainer trust when it fires. This needs fixing as part of H7 (observe the
write via `__setitem__`, or assert `reads` non-empty and all-True rather than
exactly `[True]`).

**Why MEDIUM and not HIGH.** H7 is a test-only finding against code that is
correct today; its worst case is a silent regression on a destructive path.
H2 is a live production wedge; H3/H4 are live-but-rare code defects. A
verification gap on correct code ranks below all three. HIGH was defensible
only under the "false claim = counterfeit evidence" framing, and that framing
does not survive contact with the probe log. The PID-0 pin absence and the
fragile assertion together justify the top of MEDIUM, not more. Fix: correct
the header count, add the two dangerous pins (PID-0 refusal envelope; recover
against a populated relays table), relax the over-fitted assertion to observe
the write, and the residual drops to LOW. Confidence 80/100 — this is a
judgment call on weighting, and pass 1's HIGH is not irrational, but MEDIUM
is the honest rating.

## Downgrade confirmations

**H1 (PRR-001) — MEDIUM, confirm.** Re-read the test
(tests/integration/test_hyperv_real.py:252-345): the parent resolves the
DEFAULT `%LOCALAPPDATA%` store (running_vm.cfg has state_db_path=None and the
parent env never sets HYPERV_MCP_STATE_DB), while the child writes the tmp DB
— so the final `guestjobs.job_stop(running_vm.cfg, job_id)` raises unknown
job_id; and the starter child does `Config.load()` with no policy inputs, so
it dies even earlier on PolicyDenied. It fails LOUD at the first subprocess
assert, it is env-gated out of CI, and the unit suite (C1-C6, C8, C9) covers
the substance with faked PS. The only real loss is the genuine PS-Direct round
trip. A permanently-red acceptance test for the flagship feature is a real
process defect; ~4 lines fix it. MEDIUM, not HIGH (no production impact) and
not LOW (the first integrator to run the suite eats a wall). Confidence 90/100.

**H3 (PRR-003) — MEDIUM, confirm.** Ordering gap real (_register publishes to
_jobs before the store upsert with no compensation; job_start calls it after
the guest leg has launched a live process — guestjobs.py:302-309, :642).
Consequence confirmed: store failure post-launch raises with no job_id and
leaks the live guest process. The realistic trigger is a single narrow store
failure (BUSY past the timeout or disk/corruption — the latter breaks the
store anyway); failure is loud; the `starting` row from the reservation makes
the job addressable as orphaned afterward; and the memory/store eviction
divergence inside store.transaction() self-heals on the next reservation.
MEDIUM. Confidence 90/100.

**H4 (PRR-004) — MEDIUM, confirm.** Mechanically confirmed (relay.py:736-744,
:778-812): the local delete is guarded on `in_flight` while the store delete
is unconditional, so the post-registration upsert-failure window leaves the
live relay in `_relays` with its row deleted, and the same failure makes
`_release`'s relay_delete raise, skipping server_close and masking the
original exception. Reachable only through a store failure at one specific
statement; every pre-registration failure hits the in-flight placeholder where
_release is correct. Bounded, mostly self-consistent (no-id listing recovers
the id; duplicate scan still catches re-starts; the leaked daemon listener
dies with the process). Masked exception is diagnostics loss, not behavioral.
MEDIUM. Confidence 90/100.

**H5 (PRR-006) — LOW, confirm.** The issue's own text sanctions re-resolution
("re-resolves through credentials.resolve_guest()"), the README documents it,
and under credential rotation re-resolution is arguably the DESIRED behavior —
pinning the old identity would strand every restored job instead. The
genuinely dangerous substitution (inline silently becoming the environment
identity) is pinned in code (guestjobs.py:107-113 refuses) and by a dedicated
guardrail test (guardrail.py:376-436, probed M10/M12). Residual is a README
clarification. LOW. Confidence 85/100.

**H6 (PRR-010) — LOW, confirm.** SCHEMA_VERSION=1: open() (:491-497) refuses
found>1, uses found==1 as-is, builds found==0 (:518-531). No forward-migration
gap exists at v1, and the issue explicitly assigns 1->2 and 2->3 to PR 2/PR 3.
The user_version=0-writer attack is benign at v1 (CREATE IF NOT EXISTS no-ops;
version rewritten to 1; no column churn — and jobs/relays are schema-stable
even against a hypothetical future v2 file). A note for PR 2's author, not a
defect of this diff. LOW. Confidence 90/100.

## Files inspected (all absolute)

- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\statestore.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\guestjobs.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\relay.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\server.py (job tool registration only)
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_state_store_guardrail.py
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_state_store.py
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_durable_state.py
- E:\ZCode\zaxby-hyperv-mcp\tests\integration\test_hyperv_real.py
- E:\ZCode\zaxby-hyperv-mcp\.agents\issue-traces\22-durable-state-store\08a-recurrence-sweep.md
- E:\ZCode\zaxby-hyperv-mcp\.agents\issue-traces\22-durable-state-store\repro\probe-log.md
- base guestjobs.py via `git show e8ec728:src/hyperv_mcp/guestjobs.py`
