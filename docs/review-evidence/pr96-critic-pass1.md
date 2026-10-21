# Critic PASS 1 — false-positive and root-cause challenge, PR #96 HIGH findings

Head fbb78b7, base e8ec728. Every line number below was re-verified against the
checked-out tree, not the reviewer's notes. Cross-model angle: I re-derived each
mechanic independently before accepting it.

## Verdict tally

| Finding | Verdict | Severity after challenge |
| --- | --- | --- |
| H1 (PRR-001) AC10 integration test unrunnable | DOWNGRADE | MEDIUM |
| H2 (PRR-002) active job rows never demoted, cap wedges | SURVIVES | HIGH (low end) |
| H3 (PRR-003) write-through not atomic | DOWNGRADE | MEDIUM |
| H4 (PRR-004) relay _release divergence + masked error | DOWNGRADE | MEDIUM |
| H5 (PRR-006) restored credential identity not pinned | DOWNGRADE | LOW |
| H6 (PRR-010) forward migration direction unimplemented | DOWNGRADE | LOW |
| H7 (PRR-015) guardrail "proven by mutation probe" claim false | SURVIVES | HIGH (arguable) |

---

## H1 (PRR-001) — verdict: DOWNGRADE to MEDIUM

Root cause: test-harness env wiring bug, not a product defect. The integration
harness provides policy to subprocess children through no mechanism at all —
the children call Config.load() and the only policy inputs are
HYPERV_MCP_CONFIG (unset) and HYPERV_MCP_UNRESTRICTED (ambient only), so the
reviewer's "does the harness provide policy some other way" attack fails: it
does not.

What I verified independently:

- tests/integration/test_hyperv_real.py:271 builds
  env = dict(os.environ, HYPERV_MCP_STATE_DB=str(db)). The parent pytest process
  never sets HYPERV_MCP_STATE_DB in os.environ (integration conftest.py sets
  nothing), and running_vm.cfg is the directly-constructed
  Config(unrestricted=True, audit_log_path=..., verify_sha256=True) whose
  state_db_path is None. So the parent's guestjobs.job_stop(running_vm.cfg,
  job_id) at test:332 resolves via statestore.resolve_state_db_path to
  %LOCALAPPDATA%\hyperv-mcp\state.db, not the tmp DB; _lookup raises
  unknown job_id. Mechanic confirmed.
- Child policy: starter child does Config.load() (test:279) with no config file
  and no HYPERV_MCP_UNRESTRICTED added by the test. vmident.resolve ->
  policy.vm_allowed raises PolicyDenied("vm", "no allowed_vm_patterns
  configured") because Config.unrestricted defaults to False
  (src/hyperv_mcp/config.py:141, :214-215). Mechanic confirmed. The unit-suite
  children, by contrast, explicitly pass "HYPERV_MCP_UNRESTRICTED": "1" in the
  child env and set the state DB var in the parent env
  (tests/unit/test_e01_durable_state.py:258-264; test_e01_state_store.py:123-129)
  — the AC10 author had the correct pattern in-repo and did not copy it.
- Docstring "hard kill ... skip every cleanup path" vs a clean
  subprocess.run that exits 0 after job_start: confirmed inaccurate, but
  functionally irrelevant to what the test proves (the store row persists
  regardless of how the child dies).
- No try/finally around the guest ping: true but weak — guarded_vm
  restores the checkpoint on teardown, which kills the guest process. Bounded.

Why DOWNGRADE and not SURVIVES: the defect is confined to an opt-in suite
(gated on HYPERV_MCP_INTEGRATION=1), it fails loudly (returncode assert /
unknown job_id), so it creates no false confidence, and AC10's substance —
restart survival, credential re-resolution, no-secret-in-store, persisted
stop — is covered by C1-C6, C8, C9 in tests/unit/test_e01_durable_state.py
and test_e01_state_store.py. The only thing actually lost is the real
PowerShell Direct round trip, which the faked-PS unit tests cannot give. A
broken acceptance test for the flagship feature is a real process defect but
not a production-integrity HIGH. Fix is ~4 lines: export the state DB var into
os.environ (or construct the parent cfg with state_db_path=str(db)), add
HYPERV_MCP_UNRESTRICTED=1 to the child env, correct the docstring.

## H2 (PRR-002) — verdict: SURVIVES

Root cause correctly identified. I attacked this from three directions and all
three hold:

- No demotion path exists for an active job row. _recover
  (src/hyperv_mcp/statestore.py:443-449) only flips starting -> orphaned;
  job_status (src/hyperv_mcp/guestjobs.py:657-687) observes the guest
  process but never writes the store; the eviction predicate
  (guestjobs.py:234-236) accepts only stopped/orphaned. The only exit is
  an explicit job_stop, which requires knowing the job_id.
- There is no job-listing tool: Store.job_rows is called only inside
  _reserve_slot (guestjobs.py:218); server.py registers
  hyperv_guest_job_status/_output/_stop only, none list. So a crashed
  server's stranded active rows are undiscoverable through the API; an
  operator must open the SQLite file by hand to find the ids to stop.
- Realism: "128 never-stopped jobs" is not a far-fetched trigger. The cap is
  128; a single crash of a server running a full registry wedges job_start
  host-wide on the next boot, permanently until manual remediation, across
  every process sharing the store. The relay side was given a self-healing
  answer (_restore_relay normalizes active -> interrupted, and the cap
  eviction treats interrupted as evictable — relay.py:683-690) while the job
  side was left without one; the asymmetry is visible evidence the job half
  is unfinished. The reviewer's suggested natural hook (demote in job_status
  when the guest process is observed exited) is exactly where a future fix
  belongs. "Permanently" is slightly overstated (manual job_stop works if
  you can find the ids and the env credential still resolves), which is why
  this sits at the low end of HIGH rather than the top, but the finding
  survives as stated.

## H3 (PRR-003) — verdict: DOWNGRADE to MEDIUM

Root cause: the ordering gap is real — _register (guestjobs.py:302-309)
publishes to _jobs then upserts the store with no compensation, and
job_start (guestjobs.py:642) calls it after the guest leg has launched a
live process, so a store failure raises after launch and the caller gets an
exception with no job_id. I confirm the consequence is exactly as stated.
The sub-claims also check out: _reserve_slot/_release_slot mutate memory
inside store.transaction() without rollback, and on the "registry is full"
raise (guestjobs.py:250-252) the store evictions roll back while the memory
evictions do not.

Why DOWNGRADE: the trigger is a local SQLite write failure at one
narrow point. The realistic flavor is SQLITE_BUSY past the 5 s busy timeout —
which the C8 two-process test shows is absorbed under genuine concurrency —
or disk-full/corruption, which breaks the whole store anyway and is not
specific to this window. The failure is loud, not silent; the starting row
from _reserve_slot survives, so after recovery the job is addressable (as
orphaned, evictable, honest); and the in-transaction memory/store divergence
on eviction self-heals on the next reservation because _stopped re-reads the
store rows for store-only keys. Compare H2, whose wedge needs no failure at
all. Real defect — the honest fix is to kill the launched guest process on a
failed _register (or register before launch) — but the probability x impact
product is MEDIUM.

## H4 (PRR-004) — verdict: DOWNGRADE to MEDIUM

Root cause: mechanically confirmed. _release (src/hyperv_mcp/relay.py:736-744)
guards the in-memory delete on current.get("in_flight"); the registered
entry (relay.py:778-791) has no in_flight key, so a failed
post-registration store.relay_upsert (relay.py:795) leaves the live relay in
_relays while store.relay_delete (relay.py:744) deletes its row
unconditionally; and if the store is the failing thing, _release's own
relay_delete raises, server.server_close() (relay.py:809) is skipped, and
the original exception is masked. The exception path does reach _release
with a registered non-in-flight entry — that is precisely the
post-registration window.

Why DOWNGRADE: this state is reachable only through a store failure at one
specific statement. Every pre-registration failure (bind failure, thread
construction) happens while the entry is still the in-flight placeholder,
where _release is correct. The consequences are bounded and mostly
self-consistent: the relay stays live and is discoverable/stoppable in-process
via the no-id relay_status listing (the caller that lost the id can recover
it there), the duplicate scan still catches re-starts of the same
vm:guest_port from _relays, and the missed server_close leaks a daemon
listener that dies with the process and is likewise stoppable in-process. The
masked exception is a diagnostics loss, not a behavioral one. Worth fixing
(make _release unconditional on the local delete, or move the upsert ahead
of the _relays publish), but not HIGH.

## H5 (PRR-006) — verdict: DOWNGRADE to LOW

Root cause: this is the implementation faithfully following the spec, and the
spec is not obviously wrong. The issue's own words — an env/file reference
"re-resolves through credentials.resolve_guest()" — are exactly what
_restored_credential (guestjobs.py:99-113) does. The drift scenarios the
reviewer names both require the operator to change the credential environment
between start and restore: setting HYPERV_GUEST_PASSWORD_FILE where the job
started env-only, or changing HYPERV_GUEST_USERNAME. Across a server
restart with a static service environment (the deployment this store exists
for), README:325 ("re-resolves its credential from the source it was started
with") is accurate — the cred_ref does re-resolve from the same source
kind. Under credential rotation, live re-resolution is arguably the desired
behavior: pinning the old, now-invalid identity would strand every restored
job instead of letting it reattach. The genuinely dangerous substitution —
inline credentials silently becoming the environment identity — is pinned
both in code (cred_ref="inline" refuses) and by a dedicated guardrail test
(test_e01_state_store_guardrail.py:376-436). What remains is a loosely worded
README sentence and an optional enhancement (record the username in the row
and refuse on mismatch). That is a documentation/clarification item, not a
code defect.

## H6 (PRR-010) — verdict: DOWNGRADE to LOW

Root cause: with SCHEMA_VERSION = 1 there is no forward-migration gap to be
a defect of this PR. open() (statestore.py:491-497) refuses found > 1,
uses found == 1 as-is, and builds found == 0 (statestore.py:518-531) — the
only "older" version possible today. The issue explicitly assigns the 1->2 and
2->3 migrations to PR 2 and PR 3 ("This PR sets version 1; PR 2 and PR 3 add
their tables through migrations"), so a 0->1-only implementation is the
sanctioned scope, and the module docstring says the same. The user_version = 0
writer attack is theoretical and, at v1, benign: CREATE TABLE IF NOT EXISTS
no-ops against the existing schema, the version is rewritten to 1, and no
column is added or dropped; even against a hypothetical future v2 file
reset to 0, v1 code only touches jobs/relays, which are schema-stable, so no
corruption results. A valid forward-migration note for PR 2's author
(implement the 0 < found < SCHEMA_VERSION branch when it becomes reachable),
not a defect of this diff.

## H7 (PRR-015) — verdict: SURVIVES

Root cause: the claim being challenged — "Each pins an invariant ... proven by
an executed mutation probe" (test_e01_state_store_guardrail.py:7 and :199-203)
— is falsified, and I verified every one of the reviewer's six sub-claims
independently rather than trusting the review:

1. job_stop's orphaned/PID-0 refusal (guestjobs.py:762-775): the only
   job_stop in the new suite is guardrail.py:467, which stops a running
   job. Nothing exercises the refusal path — the path whose whole purpose is
   to prevent _stop_script(0, "") enumerating and taskkilling the Win32
   children of PID 0 as guest admin.
2. _recover's relay UPDATE (statestore.py:446-449): the reload-based
   guardrail test re-imports guestjobs/relay but never re-runs
   statestore.open() (the _stores cache survives the reload), and the
   store tests open fresh files. The statement never runs against a populated
   relays table. The jobs half of the same function is pinned by C3 — which
   makes the unexercised relay half look like an oversight, not a judgment.
3. busy_timeout (statestore.py:261): the test's blind timeout=0.0 control
   proves the read is sensitive, but the store's own connection inherits
   Python's default timeout=5.0 = 5000 ms, so deleting the explicit
   PRAGMA busy_timeout=5000 leaves store.busy_timeout_ms >= 5000 passing.
   The mutation is invisible to the suite, exactly as the reviewer says.
4. resolve_state_db_path's config-key branch (statestore.py:572-574): grep
   shows zero test references to resolve_state_db_path anywhere in tests/;
   C5 checks Config.from_dict parsing only.
5. The cap unions (guestjobs.py:239, relay.py:683): no test ever puts rows in
   the store and entries in _jobs/_relays simultaneously and exercises
   union counting or store-only-key eviction; the one cap test
   (guardrail.py:207-245) pins the local-live-not-evicted invariant for
   relays only, at _MAX_RELAYS=1 with a single key present in both views.
6. _release's store-side relay_delete (relay.py:744): no test injects a
   store failure into relay_start, so the unconditional delete is
   unasserted — and per H4 it is the statement that diverges the two views.
7. The relay_stop pin (guardrail.py:322-338): _TrackingEntry overrides
   __getitem__ only, so a mutant that reads stopped under the lock but
   writes it outside passes, while a correct implementation that reads twice
   under the lock fails (reads == [True] is over-specific). Confirmed by
   reading the test, not the review.

Severity note: I keep this at HIGH only because two of the unpinned behaviors
(the PID-0 refusal, the recovery write) exist precisely to prevent a
destructive guest operation, and the module's false claim is the PR's own
evidence of verification. If the maintainers treat the docstring as
aspirational rather than a claim, the residual value is a set of targeted
test additions — but the finding as stated is accurate and survives. The
correct disposition is to fix the docstring and add the missing pins, not to
argue them away.

---

## Overall verdict

NEEDS_REVISION. H2 and H7 survive unchanged in substance; H3 and H4 are real
code defects whose severity is capped by a rare trigger; H1, H5, H6 are not
production defects (test wiring, sanctioned spec behavior, sanctioned scope
respectively). Nothing here is a false positive, but four of seven HIGH labels
were doing more work than the underlying mechanics support.

Key files:
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\statestore.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\guestjobs.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\relay.py
- E:\ZCode\zaxby-hyperv-mcp\src\hyperv_mcp\credentials.py
- E:\ZCode\zaxby-hyperv-mcp\tests\integration\test_hyperv_real.py
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_durable_state.py
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_state_store.py
- E:\ZCode\zaxby-hyperv-mcp\tests\unit\test_e01_state_store_guardrail.py
