# Fix-round mutation probe log — PR #96

The review round's probes and their results. The harness ships beside this
file (`pr96-fix-round-probes.py`); it applies ONE mutation that reverts a fix,
runs the pinning test EXPECTING it to go red, then restores from a byte copy and
asserts byte-identity. It never uses `git checkout --`.

**29/29 behaved as required** — 28 mutants killed, plus one deliberate
behaviour-preserving control that was correctly ACCEPTED (a correct double read
of the `stopped` flag must not fail the atomicity pin).

| # | Probe | Result |
|---|---|---|
| 1 | `job_status` exit demotion | KILLED |
| 2 | recovery inline demotion | KILLED |
| 3 | recovery relay UPDATE | KILLED |
| 4 | `_register` compensation | KILLED |
| 5 | `_reserve_slot` memory rollback | KILLED |
| 6 | `_release_slot` compensation | KILLED |
| 7 | relay `_release` in_flight guard | KILLED |
| 8 | relay `_release` store delete removed | KILLED |
| 9 | relay `_release` raises | KILLED |
| 10 | relay eviction own-written guard | KILLED |
| 11 | restored relay normalization | KILLED |
| 12 | job peek owner filter | KILLED |
| 13 | job peek guard | KILLED |
| 14 | relay peek owner filter | KILLED |
| 15 | job restore strict owner | KILLED |
| 16 | relay restore strict owner | KILLED |
| 17 | config absolute-path rule | KILLED |
| 18 | config CWD fallback restored | KILLED |
| 19 | early version refusal removed | KILLED |
| 20 | path back in the refusal message | KILLED |
| 21 | null before the durable write | KILLED |
| 22 | job cap union | KILLED |
| 23 | relay cap union | KILLED |
| 24 | PID-0 refusal branch removed | KILLED |
| 25 | `resolve_state_db_path` config-key branch removed | KILLED |
| 26 | `relay_stop` write outside the lock | KILLED |
| 27 | soak store redirect removed | KILLED |
| 28 | server lazy peek resolution disabled | KILLED |
| 29 | control: a correct double read | ACCEPTED (correct) |

## Two harness shapes that were wrong before this log

Both were caught by the control probe, and both would have made every probe read
"KILLED" regardless of the code:

1. **Scoring by exit code.** The suite has a pre-existing environment failure
   (`psutil` is absent from this venv), so the suite never exits 0 and every
   probe reads KILLED — including the behaviour-preserving control.
2. **Deselecting a fixed list of known flakes.** The suite's load-dependent
   failures ROTATE between runs: `test_b03_stdio_proxy`,
   `test_c02_busy_wiring::test_slot_wait...`, `test_c02_ps_cap` and
   `test_c03_check_strength` each appear in some runs and not others.

The only sound scoring is a set difference against the baseline run taken
immediately before each probe, with a control that must NOT kill. The five
independent spot-checks that were run afterwards use exactly that shape.

## The independent spot-checks

Five probes written after the fix round, against dimensions the fixer's harness
did not cover. All five KILLED, with the control SURVIVING:

| Probe | Result |
|---|---|
| a `None` caller cannot reach an owned row | KILLED |
| `peek_vm_name`'s owner filter removed | KILLED |
| `job_status` exit demotion removed | KILLED |
| relay restore owner filter relaxed | KILLED |
| `statestore` makedirs no longer guarded | KILLED |
| control: a behaviour-preserving edit | SURVIVED (correct) |
