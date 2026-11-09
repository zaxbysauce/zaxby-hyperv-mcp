"""Live-host VM-agent-isolation legs — issue #31 supplement AC16 (trace
31-79-live-host-confirmation).

AC16: "WHEN the independent-VM plan is executed on a real Hyper-V host from
a read-only golden VHDX, THE SYSTEM SHALL provision, run, stop and remove
every owned clone with no parent-disk mutation or residual child disk,
invoking the configured cleanup-provider seam before delete."

Legs:
  * test_owner_clone_lifecycle_with_seam — TWO owned clones complete the
    full lifecycle: clone -> start -> Running observed -> turnoff -> Off
    observed -> the applicable provider-removal sequence. Clone-a proves
    the seam LIVE: the trace provider reports PENDING once, vm_remove
    refuses (the production MediaError naming "vm_remove refused", the
    pending status and the clone GUID) BEFORE any deletion work (VM and
    child disk intact), then CLEAN removal succeeds. Clone-b takes the
    straight clean path. The golden parent's SHA-256 (chunked read) AND
    mtime must be unchanged; no residual clone disk or .avhdx survives.
  * test_nonowner_teardown_rejected_before_host_ops — the synthetic
    owner-keyed harness (AC15) runs live in the host-test process: a
    non-owner teardown raises NotOwnerError with ZERO host calls (a
    pswindows.run_ps spy proves the count stayed at zero).

Identity contract (plan-critic r5): the creation-returned "id" is the
cleanup identity, recorded BEFORE any further fallible operation; later
resolution only verifies it (a mismatch fails the test while the original
ID stays tracked for cleanup — never replaced).

Absence contract (r6 + review PRR-001): VM absence is NEVER inferred from
a resolver exception OR from a silenced/suppressed Get-VM failure
(-ErrorAction SilentlyContinue collapses "query failed" into "absent" —
reviewer-executed live). Absence is proven only by an explicit
GUID-scoped Get-VM probe with -ErrorAction Stop whose probe succeeds
(rc==0) and reports GONE; PRESENT, unknown, and PROBE-ERROR all RETAIN
the tracked entry.

Cleanup contract (plan v4/r6 + review): the finally forces the provider
CLEAN, drives best-effort turnoff/remove per tracked clone, emits the full
cleanup report (failures AND benign kept inventory) to the result record
and stderr INSIDE the finally with report-specific line kinds (never filed
as observed assertions) and a guarded write that never masks an in-flight
primary exception — and only when no primary exception is in flight does
the test fail on an incomplete report. Benign kept rows
(not_owned_ancestor, already_gone) are inventory, never failures; failure
reasons (delete_failed, merge_pending, cleanup_leg_failed,
outside_host_write_roots, in_use_by_other_vm) and residual child disks
always are. An already-removed VM (resolver transport error + gone probe)
is benign inventory on the VM axis too, symmetric with the disk axis.
"""

import hashlib
import os
import sys
import uuid

import pytest

from hyperv_mcp import agent_isolation, lifecycle, media, pswindows

pytestmark = pytest.mark.hyperv_real

NODE_A = "tests/host/test_vm_agent_isolation_host.py::test_owner_clone_lifecycle_with_seam"
NODE_B = "tests/host/test_vm_agent_isolation_host.py::test_nonowner_teardown_rejected_before_host_ops"

BENIGN_KEPT = ("not_owned_ancestor", "already_gone")

# Chunk size for the golden digest: a 1 MiB read window keeps the sha-256
# pass bounded for any operator-supplied golden size (review PRR-013).
_DIGEST_CHUNK = 1024 * 1024


def _digest(path: str) -> tuple[str, float]:
    st = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_DIGEST_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest(), st.st_mtime


def _wait_state(cfg, name: str, states: list[str], timeout_s: int = 300) -> str:
    return lifecycle.wait_for_vm_state(cfg, name, states, timeout_s)


def _vm_absent(cfg, guid: str) -> str:
    """Fail-closed absence probe (r6 + review PRR-001 + fix-round review).

    'gone' ONLY when the Get-VM ENUMERATION succeeds (rc==0) and the GUID
    is not among the returned VMs. Two failure shapes must never collapse
    into absence:
      - a suppressed cmdlet failure (the original PRR-001 fail-open:
        -ErrorAction SilentlyContinue printed GONE with rc=0 for a FAILED
        query), and
      - Hyper-V's own "unable to find" — with -ErrorAction Stop,
        Get-VM -Id <absent-guid> is a TERMINATING error, so a per-GUID
        lookup cannot distinguish not-found from query-failed (the
        fix-round reviewer live-proved rc=3/PROBE-ERROR for a valid
        absent GUID).

    The probe therefore enumerates ALL VMs once with -ErrorAction Stop and
    filters by Id in PowerShell: enumeration success + empty filter =
    genuine absence; any enumeration failure prints PROBE-ERROR and exits
    rc=3, which maps to 'unknown' here. 'present' only when the successful
    enumeration contains the GUID."""
    script = (
        "try {\n"
        "    $all = @(Get-VM -ErrorAction Stop)\n"
        "} catch {\n"
        "    'PROBE-ERROR'\n"
        "    exit 3\n"
        "}\n"
        "if (@($all | Where-Object { $_.Id -eq '" + guid + "' }).Count) { 'PRESENT' } else { 'GONE' }\n"
    )
    try:
        result = pswindows.run_ps(script, timeout_s=120)
    except Exception:
        return "unknown"  # a raised transport error is unknown, never absence
    if result.returncode != 0:
        return "unknown"  # includes the probe's own PROBE-ERROR rc=3 (PRR-001)
    if "GONE" in result.stdout:
        return "gone"
    if "PRESENT" in result.stdout:
        return "present"
    return "unknown"


class _TraceProvider:
    """Trace-scoped cleanup provider: logs every consult and returns PENDING
    on the first call (proving the seam gates deletion live), CLEAN after.
    force_clean() is the unconditional cleanup lever (plan v4)."""

    def __init__(self, log_path: str) -> None:
        self.log_path = log_path
        self._pending = True

    def reconcile(self, vm_guid: str) -> str:
        status = "pending" if self._pending else "clean"
        self._pending = False
        with open(self.log_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(f"consult {vm_guid} -> {status}\n")
        return status

    def force_clean(self) -> None:
        self._pending = False


def _cleanup_tracked(cfg, provider, tracked, report, benign) -> None:
    """Non-masking, VISIBLE, fail-closed failure-path cleanup (r5/r6 +
    review PRR-009): provider CLEAN first; for every tracked
    [guid, name, child] entry: best-effort turnoff + Off-wait, best-effort
    removal by vm_id; every error, residual child, and non-benign kept
    reason is APPENDED to report; benign kept rows and ALREADY-GONE VMs go
    to benign inventory (symmetric with the disk axis); an entry leaves
    tracking only when the absence probe says 'gone' AND the child disk is
    confirmed deleted — 'present', 'unknown', or 'PROBE-ERROR' all retain
    the entry."""
    provider.force_clean()
    for entry in list(tracked):
        guid, name, child = entry
        try:
            lifecycle.stop_vm(cfg, vm_id=guid, method="turnoff", confirm=True)
            _wait_state(cfg, name, ["Off"], timeout_s=180)
        except Exception as exc:
            if _vm_absent(cfg, guid) == "gone":
                # PRR-009 symmetry: an already-removed VM is benign on the
                # stop leg too.
                benign.append(f"already gone (VM, stop leg) {guid}: {exc}")
            else:
                report.append(f"stop {guid}: {exc}")
        try:
            removed = media.vm_remove(cfg, vm_id=guid, delete_disks=True, confirm=True)
            if not removed.get("ok"):
                report.append(f"remove {guid}: {removed}")
            else:
                for kept in removed.get("kept", []) or []:
                    text = str(kept)
                    if any(reason in text for reason in BENIGN_KEPT):
                        benign.append(f"kept (benign) {guid}: {text}")
                    else:
                        report.append(f"kept (failure) {guid}: {text}")
        except Exception as exc:
            if _vm_absent(cfg, guid) == "gone":
                # PRR-009: an already-removed VM is benign inventory on the
                # VM axis, symmetric with the disk axis's already_gone.
                benign.append(f"already gone (VM) {guid}: {exc}")
            else:
                report.append(f"remove {guid}: {exc}")
        if os.path.exists(child):
            report.append(f"residual child disk: {child}")
            continue
        absence = _vm_absent(cfg, guid)
        if absence == "gone":
            tracked.remove(entry)
        else:
            report.append(f"absence {absence} for {guid} (entry retained)")


def _emit_cleanup_reports(host, report, benign) -> None:
    """Emit cleanup outcome INSIDE the finally (plan-critic r6): visible on
    the result record and stderr even when a primary exception is already
    propagating; report lines use the record's "report: " kind so a
    cleanup failure is never filed as an observed assertion (PRR-007)."""
    if benign:
        line = "cleanup benign inventory: " + "; ".join(benign)
        sys.stderr.write(line + "\n")
        host.note(line, kind="report")
    if report:
        line = "cleanup incomplete: " + "; ".join(report)
        sys.stderr.write(line + "\n")
        host.note(line, kind="report")


def test_owner_clone_lifecycle_with_seam(host, tmp_path):
    import pathlib

    cfg = host.cfg
    golden = host.golden
    before = _digest(golden)
    provider_log = str(tmp_path / "provider_journal.jsonl")
    provider = _TraceProvider(provider_log)
    provider_name = f"ac16-live-{uuid.uuid4().hex[:8]}"
    agent_isolation.register_cleanup_provider(provider_name, provider)
    cfg.agent_isolation.cleanup_provider = provider_name

    host.note(f"test: {NODE_A}")
    tracked: list[list] = []  # [guid, name, child] — retained until verified gone
    report: list[str] = []
    benign: list[str] = []
    try:
        # --- clone-a: full lifecycle + live seam refusal, then clean removal
        name_a = f"host-iso-a-{uuid.uuid4().hex[:8]}"
        child_a = os.path.join(host.clone_disks, f"{name_a}.vhdx")
        out_a = media.vm_clone(cfg, name_a, golden, child_a, memory_mb=512,
                               cpu_count=1, switch_name="", confirm=True)
        assert out_a["ok"], out_a
        guid_a = str(out_a.get("id") or "")
        assert guid_a, f"vm_clone returned no id: {out_a}"
        tracked.append([guid_a, name_a, child_a])  # recorded BEFORE any fallible op

        lifecycle.start_vm(cfg, vm_name=name_a)  # success proven by the bounded wait
        assert _wait_state(cfg, name_a, ["Running"], timeout_s=180) == "Running"
        host.note(f"running observed ({name_a})")

        lifecycle.stop_vm(cfg, vm_name=name_a, method="turnoff", confirm=True)
        assert _wait_state(cfg, name_a, ["Off"], timeout_s=180) == "Off"
        host.note(f"off observed ({name_a})")

        # the seam consults BEFORE any deletion work: PENDING refuses with
        # the production error, and the VM + child disk are untouched
        with pytest.raises(media.MediaError) as refused:
            media.vm_remove(cfg, vm_id=guid_a, delete_disks=True, confirm=True)
        message = str(refused.value)
        assert "vm_remove refused" in message, message
        assert "pending" in message, message
        assert guid_a in message, message
        assert os.path.isfile(child_a), "refusal must leave the child disk intact"
        host.note("refused before any deletion work")

        provider.force_clean()
        removed_a = media.vm_remove(cfg, vm_id=guid_a, delete_disks=True, confirm=True)
        assert removed_a.get("ok"), removed_a
        assert not os.path.isfile(child_a), "clean removal deletes the child disk"
        assert _vm_absent(cfg, guid_a) == "gone", "post-removal absence probe"
        tracked.remove([guid_a, name_a, child_a])  # verified gone on both axes

        # --- clone-b: straight clean path through the same seam
        name_b = f"host-iso-b-{uuid.uuid4().hex[:8]}"
        child_b = os.path.join(host.clone_disks, f"{name_b}.vhdx")
        out_b = media.vm_clone(cfg, name_b, golden, child_b, memory_mb=512,
                               cpu_count=1, switch_name="", confirm=True)
        assert out_b["ok"], out_b
        guid_b = str(out_b.get("id") or "")
        assert guid_b, f"vm_clone returned no id: {out_b}"
        tracked.append([guid_b, name_b, child_b])
        lifecycle.start_vm(cfg, vm_name=name_b)
        assert _wait_state(cfg, name_b, ["Running"], timeout_s=180) == "Running"
        host.note(f"running observed ({name_b})")
        lifecycle.stop_vm(cfg, vm_name=name_b, method="turnoff", confirm=True)
        assert _wait_state(cfg, name_b, ["Off"], timeout_s=180) == "Off"
        host.note(f"off observed ({name_b})")
        removed_b = media.vm_remove(cfg, vm_id=guid_b, delete_disks=True, confirm=True)
        assert removed_b.get("ok"), removed_b
        assert not os.path.isfile(child_b)
        assert _vm_absent(cfg, guid_b) == "gone", "post-removal absence probe"
        tracked.remove([guid_b, name_b, child_b])

        # --- no parent mutation, no residual clone disk
        after = _digest(golden)
        assert after == before, "parent digest unchanged"
        host.note("parent digest unchanged")
        leftovers = [p for p in (child_a, child_b) if os.path.exists(p)]
        avhdx = [p.name for p in pathlib.Path(host.clone_disks).glob("*.avhdx")
                 if name_a in p.name or name_b in p.name]
        assert not leftovers and not avhdx, f"residual clone disk: {leftovers + avhdx}"
        host.note("no residual clone disk")

        # --- FixtureOwnership live (AC15 harness in the live session)
        ownership = agent_isolation.FixtureOwnership()
        ownership.register("owner-a", guid_a, "fixture-x")
        assert ownership.vm_guid_for("owner-a", "fixture-x") == guid_a
        ownership.teardown("owner-a", "fixture-x")  # owner teardown succeeds
        with pytest.raises(agent_isolation.NotOwnerError):
            ownership.teardown("owner-b", "fixture-x")
        assert ownership.vm_guid_for("owner-a", "fixture-x") is None

        # the refusal consult ordering is visible in the provider journal
        journal = open(provider_log, encoding="utf-8").read()
        assert f"consult {guid_a} -> pending" in journal, journal
        assert f"consult {guid_a} -> clean" in journal, journal
    finally:
        _cleanup_tracked(cfg, provider, tracked, report, benign)
        _emit_cleanup_reports(host, report, benign)
    # reached only when body AND finally both completed cleanly
    if report:
        pytest.fail(f"cleanup incomplete (leaks are never silent): {report}")


def test_nonowner_teardown_rejected_before_host_ops(host, monkeypatch):
    host.note(f"test: {NODE_B}")
    ownership = agent_isolation.FixtureOwnership()
    ownership.register("owner-live", "synthetic-guid-not-a-vm", "fixture-y")

    counter = {"n": 0}
    real_run_ps = pswindows.run_ps

    def spy_run_ps(*args, **kwargs):
        counter["n"] += 1
        return real_run_ps(*args, **kwargs)

    monkeypatch.setattr(pswindows, "run_ps", spy_run_ps)
    with pytest.raises(agent_isolation.NotOwnerError) as rejected:
        ownership.teardown("someone-else", "fixture-y")
    assert "not owned by" in str(rejected.value)
    assert counter["n"] == 0, (
        "non-owner teardown must be rejected before ANY host operation; "
        f"observed {counter['n']} PowerShell calls")
    host.note("non-owner teardown rejected with zero host calls")
