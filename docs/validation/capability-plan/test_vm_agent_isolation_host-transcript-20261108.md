# Live seam leg — #31 supplement AC16 (trace 31-79-live-host-confirmation)

Record type: live-pass evidence. This transcript records the FINAL gate
invocation and its observed results only.

tree-id: 96b4917761a76882ee37ce32383a5088f92bcf6f
provenance note: the tree-id is the trace convention's STAGED WORKING-TREE
snapshot at run time, NOT a commit tree (the base head's tree is
89204550c286772a6ebf49b2d8dbccccad7a6ab9; this snapshot tree is a local
object and is not resolvable from a fresh clone). The verifiable
executed-code binding is by BLOB: the tests/host executor files in that
working tree are byte-identical to the shipped head
(tests/host/conftest.py blob 6d39bbf220d02388f315ed39d44fc8757559dcfa,
tests/host/test_vm_agent_isolation_host.py blob
7ec1470bee82bfa96c14a5bd54a483052f2dfee3 at head
ebad12c20dd011c6cc4b9a10d240079d2adf6e04 — the LIVE RUN executed these
pre-fix bytes; the post-review fix wave hardened the helper contracts
without changing the recorded run's claims).
- head at run time: 250003bd8073719fd58f2d6d8260a8b97d0c26dd (main)
- host build: Windows host 10.0.26300 x64 (Hyper-V), 2026-11-08
- lab: golden.vhdx minted with New-VHD -Dynamic (1 GiB) + read-only mark;
  two self-minted disposable clones (host-iso-a-ad3fa48c,
  host-iso-b-5366f5aa), 512 MB / 1 vCPU / no NIC; least-privilege lab
  config (allowed_vm_patterns=["host-iso-*"], host_read_roots/host_write_roots
  = the per-run scratch, destructive stop/vm_provision/vm_remove, confirm
  on every call, NO unrestricted); teardown verified (both clones removed,
  golden + child VHDs deleted, infra state file removed by the harness;
  post-teardown VM inventory: only pre-existing VMs).

## The final gate invocation

```
# Git Bash on Windows. <scratch-dir> is the per-run directory the trace
# harness prints when it mints the lab (infra_leg.py up -> "scratch": ...);
# the run recorded here used trace-31-79-66648cdc. Quote Windows paths.
$ HYPERV_MCP_INTEGRATION=1 \
  HYPERV_MCP_TEST_GOLDEN_VHD="C:/Users/Public/Documents/Hyper-V/trace-31-79-66648cdc/golden.vhdx" \
  HYPERV_MCP_HOST_RESULT_RECORD="C:/Users/Public/Documents/Hyper-V/trace-31-79-66648cdc/ac16-result-record.txt" \
  python -m pytest tests/host/test_vm_agent_isolation_host.py \
  -p no:cacheprovider -o addopts=
...
tests\host\test_vm_agent_isolation_host.py ..                            [100%]

======================== 2 passed in 63.31s (0:01:03) =========================
```

## Observed assertion-result record (emitted live by the legs)

```
assert: test: tests/host/test_vm_agent_isolation_host.py::test_owner_clone_lifecycle_with_seam
assert: running observed (host-iso-a-ad3fa48c)
assert: off observed (host-iso-a-ad3fa48c)
assert: refused before any deletion work
assert: running observed (host-iso-b-5366f5aa)
assert: off observed (host-iso-b-5366f5aa)
assert: parent digest unchanged
assert: no residual clone disk
assert: test: tests/host/test_vm_agent_isolation_host.py::test_nonowner_teardown_rejected_before_host_ops
assert: non-owner teardown rejected with zero host calls
```

## What each marker proves

- "running observed (host-iso-a-ad3fa48c)" / "(host-iso-b-5366f5aa)": both
  clones reached Running via lifecycle.start_vm + bounded
  wait_for_vm_state (AC16's run leg).
- "off observed (...)": both clones reached Off via turnoff + bounded
  wait (AC16's stop leg) — removals happened only after observed Off.
- "refused before any deletion work": the trace provider reported PENDING;
  vm_remove refused with the production MediaError naming "vm_remove
  refused", the pending status and the clone GUID; the child disk and VM
  were verified intact BEFORE the CLEAN removal — the seam consults
  before any deletion work, LIVE.
- "parent digest unchanged": the golden's SHA-256 AND mtime byte-identical
  before vs after both full clone lifecycles.
- "no residual clone disk": no clone child disk or .avhdx survives under
  the scratch while the golden lived; both clones verified absent
  (fail-closed Get-VM probes) after removal.
- "non-owner teardown rejected with zero host calls": the AC15
  FixtureOwnership harness live: non-owner teardown raises NotOwnerError
  with a pswindows.run_ps spy proving zero PowerShell calls.

## Cleanup readback (post-teardown verification)

```
{"ok": true, "errors": ["delete gen1.vhdx: writable ... failed rc=1:
Set-ItemProperty : Cannot find path ... does not exist."]}
state file gone: True
post-teardown VM inventory: 10 VMs, all pre-existing (names redacted;
machine-local per the repo's trace-evidence convention)
```

The one recorded error is benign by design: the Set-ItemProperty writable
mark ran on the gen1.vhdx that vm_remove's delete_disks pass had already
consumed; the teardown's absence verification passed (VM GONE, disks gone,
state removed).

Correction (review PRR-004, 2026-11-09): this harness's `down` removes the
two VHDs and the state file only — it does NOT remove the scratch directory
itself, and at recording time the directory remained on the host holding
audit.jsonl. The operator removed it manually after this transcript was
recorded (verified: no trace-31-79-* directory remains under the Hyper-V
default folder).
