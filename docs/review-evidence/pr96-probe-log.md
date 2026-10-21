# Probe log — E01 durable-state-store

Twelve probes, each reverting ONE load-bearing line, running the SHIPPED suite
(`test_e01_durable_state.py`, `test_e01_state_store.py`,
`test_e01_state_store_guardrail.py`, `test_guestjobs.py`, `test_relay.py`,
`test_b02_guardrail.py`, `test_b02_ownership_relay.py`, `test_config.py`,
`test_credentials.py`), and requiring it to go RED.

Harness: `scripts/_probe_all.py` (deleted before commit; reconstructed here in
full so the log is reproducible). Restores from byte copies and asserts
byte-identity afterwards. `git checkout --` is deliberately NOT used: these files
are uncommitted for most of the trace, and restoring from the index destroyed the
`guestjobs.py` and `relay.py` patches once.

| Probe | Mutation | Result |
|---|---|---|
| M1 | delete the `_lookup` store fallback | KILLED (exit 1) |
| M2 | delete the `relay_status` store fallback | KILLED (exit 1) |
| M3 | add a `password TEXT` column to `jobs` | KILLED (exit 1) |
| M4 | add a `command TEXT` column to `jobs` | KILLED (exit 1) |
| M5 | stop persisting the relay stop | KILLED (exit 1) |
| M6 | evict a live local relay on an `interrupted` store row | KILLED (exit 1) |
| M7 | read `relay_stop`'s `already` flag outside the lock | KILLED (exit 1) |
| M8 | derive the listing's `local_ids` from the filtered selection | KILLED (exit 1) |
| M9 | cache a restored `starting` row | KILLED (exit 1) |
| M10 | map inline tool arguments to `cred_ref="env"` | KILLED (exit 1) |
| M11 | stop persisting the job's `cred_ref` provenance | KILLED (exit 1) |
| M12 | key the inline-credential reference on the password source only, so a username-only override records `env` | KILLED (exit 1) |

Round-2 note. When the round-2 review ran these, M6-M9 all SURVIVED: the
reviewer's probes killed them but the shipped suite did not. Four guardrail pins
were added, and M6-M9 now die in the shipped suite.

Round-4 note. M10's first form (keying on `p_source == "inline argument"`) left the
username-only inline override mislabelled as `env`: `server._cred_args` takes the
inline branch when EITHER argument is set, and `resolve_guest` honours an inline
username, so a username-only call starts the job as that account and a restored
leg then re-resolves the ENVIRONMENT username — silently running a different
account. Keying on `(username or password)` closes it, and M12 pins the
username-only dimension directly.

Round-3 note. M7 and M11 also survived at first. M7's original pin parked a
thread *inside* `entry["stopped"]`, so the read completed only after the other
thread had written — the mutant passed for the same reason the fixed code did.
The pin now observes lock discipline directly (a lock wrapper records whether
`_relays_lock` is held, the entry records whether each `stopped` read happened
while it was), single-threaded and deterministic. M11 had no pin at all until
`test_stop_persists_the_credential_reference` was added.
