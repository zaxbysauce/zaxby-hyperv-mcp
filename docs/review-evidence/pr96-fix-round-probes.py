"""Mutation-probe driver for the PR #96 review fixes.

For every probe: byte-copy the file, apply ONE targeted mutation that
reverts a fix, run the pinning test EXPECTING it to go red, restore from
the byte copy, and assert byte-identity. Never `git checkout --`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PY = str(REPO / ".venv" / "Scripts" / "python")

# (label, file, old, new, test)
PROBES = [
    (
        "PRR-002a job_status demotion",
        "src/hyperv_mcp/guestjobs.py",
        '    if status == "exited" and cfg is not None:',
        '    if False and status == "exited" and cfg is not None:',
        "tests/unit/test_guestjobs.py::test_status_observing_exit_retires_the_durable_row",
    ),
    (
        "PRR-002b recovery inline demotion",
        "src/hyperv_mcp/statestore.py",
        '        if row.state != JOB_ACTIVE or row.cred_ref != "inline":\n            continue',
        "        if True:\n            continue",
        "tests/unit/test_e01_state_store_guardrail.py::test_recovery_orphans_inline_rows_whose_pid_is_gone",
    ),
    (
        "PRR-002b recovery relay UPDATE",
        "src/hyperv_mcp/statestore.py",
        '        "UPDATE relays SET state = ? WHERE state = ?",',
        '        "UPDATE relays SET state = ? WHERE 0",',
        "tests/unit/test_e01_state_store_guardrail.py::test_recovery_interrupts_a_populated_relays_table",
    ),
    (
        "PRR-003 _register compensation",
        "src/hyperv_mcp/guestjobs.py",
        "        except Exception:\n            # Compensation in the failure direction: fall back to the",
        "        except Exception:\n            raise\n            # Compensation in the failure direction: fall back to the",
        "tests/unit/test_guestjobs.py::test_register_store_failure_still_hands_back_the_job_id",
    ),
    (
        "PRR-003 _reserve_slot memory rollback",
        "src/hyperv_mcp/guestjobs.py",
        "                for key, entry, cred in evicted:",
        "                for key, entry, cred in []:",
        "tests/unit/test_guestjobs.py::test_full_registry_rolls_the_memory_eviction_back",
    ),
    (
        "PRR-003 _release_slot compensation",
        "src/hyperv_mcp/guestjobs.py",
        "            # losing the pairing silently is strictly worse.\n            with _jobs_lock:\n                _jobs.setdefault(job_id, entry)",
        "            # losing the pairing silently is strictly worse.\n            with _jobs_lock:\n                pass",
        "tests/unit/test_guestjobs.py::test_release_slot_failure_restores_the_placeholder",
    ),
    (
        "PRR-004 _release in_flight guard restored",
        "src/hyperv_mcp/relay.py",
        "            _relays.pop(relay_id, None)",
        "            current = _relays.get(relay_id)\n"
        "            if current is not None and current.get(\"in_flight\"):\n"
        "                del _relays[relay_id]",
        "tests/unit/test_relay.py::test_failed_registration_leaves_no_row_and_no_listener",
    ),
    (
        "PRR-004/015 _release store delete removed",
        "src/hyperv_mcp/relay.py",
        "            # the duplicate scan.\n            store.relay_delete(relay_id)",
        "            # the duplicate scan.\n            pass",
        "tests/unit/test_relay.py::test_failed_registration_leaves_no_row_and_no_listener",
    ),
    (
        "PRR-004 _release raises",
        "src/hyperv_mcp/relay.py",
        "            store.relay_delete(relay_id)\n        except Exception:",
        "            store.relay_delete(relay_id)\n        except Exception:\n            raise",
        "tests/unit/test_relay.py::test_release_never_raises_and_the_original_error_wins",
    ),
    (
        "PRR-005 own-written eviction guard",
        "src/hyperv_mcp/relay.py",
        "                    if _we_wrote(key):",
        "                    if True:",
        "tests/unit/test_relay.py::test_cap_eviction_keeps_a_foreign_store_row",
    ),
    (
        "PRR-013 restored normalization",
        "src/hyperv_mcp/relay.py",
        '    if entry["row_state"] == statestore.RELAY_ACTIVE:\n        # A row not in the local registry',
        '    if False:\n        # A row not in the local registry',
        "tests/unit/test_relay.py::test_restored_relay_reads_agree_by_id_and_in_the_listing",
    ),
    (
        "PRR-007 job peek owner filter",
        "src/hyperv_mcp/guestjobs.py",
        "        if row is not None and (row.owner or None) == owner:\n            return str(row.vm_name or \"\")",
        "        if row is not None:\n            return str(row.vm_name or \"\")",
        "tests/unit/test_guestjobs.py::test_peek_vm_name_is_owner_filtered_and_never_raises",
    ),
    (
        "PRR-007 job peek guard",
        "src/hyperv_mcp/guestjobs.py",
        "        try:\n            row = _store(cfg).job_get(key)\n        except Exception:\n            return \"\"",
        "        row = _store(cfg).job_get(key)",
        "tests/unit/test_guestjobs.py::test_peek_vm_name_is_owner_filtered_and_never_raises",
    ),
    (
        "PRR-007 relay peek owner filter",
        "src/hyperv_mcp/relay.py",
        "        if row is not None and (row.owner or None) == owner:\n            return str(row.vm_name or \"\")",
        "        if row is not None:\n            return str(row.vm_name or \"\")",
        "tests/unit/test_relay.py::test_peek_relay_vm_name_is_owner_filtered_and_never_raises",
    ),
    (
        "PRR-008 job restore strict owner",
        "src/hyperv_mcp/guestjobs.py",
        "    if (row.owner or None) != owner:\n        return None",
        "    if owner is not None and (row.owner or None) != owner:\n        return None",
        "tests/unit/test_e01_state_store_guardrail.py::test_unattributed_caller_cannot_address_an_owned_row",
    ),
    (
        "PRR-008 relay restore strict owner",
        "src/hyperv_mcp/relay.py",
        "    if (row.owner or None) != owner:\n        return None",
        "    if owner is not None and (row.owner or None) != owner:\n        return None",
        "tests/unit/test_e01_state_store_guardrail.py::test_unattributed_caller_cannot_address_an_owned_row",
    ),
    (
        "PRR-009 config absolute rule",
        "src/hyperv_mcp/config.py",
        "            if not Path(self.state_db_path).is_absolute():",
        "            if False and not Path(self.state_db_path).is_absolute():",
        "tests/unit/test_config.py::test_state_db_path_must_be_absolute_or_null",
    ),
    (
        "PRR-009 config cwd fallback restored",
        "src/hyperv_mcp/config.py",
        "        or tempfile.gettempdir()\n    )",
        "        or os.getcwd()\n    )",
        "tests/unit/test_config.py::test_state_db_default_falls_back_to_the_temp_dir",
    ),
    (
        "PRR-011 early version refusal removed",
        "src/hyperv_mcp/statestore.py",
        "    early = _probed_user_version(path)",
        "    early = None",
        "tests/unit/test_e01_state_store.py::test_store_schema_contract",
    ),
    (
        "PRR-012 path back in the refusal message",
        "src/hyperv_mcp/statestore.py",
        '        where = f" in ({_where(path)})" if _where(path) else ""\n        raise StateStoreError(\n            f"state store{where} has schema version {early}, "',
        '        where = f" ({path})" if _where(path) else ""\n        raise StateStoreError(\n            f"state store{where} has schema version {early}, "',
        "tests/unit/test_e01_state_store_guardrail.py::test_store_errors_name_the_directory_not_the_path",
    ),
    (
        "PRR-014 null before the durable write",
        "src/hyperv_mcp/guestjobs.py",
        "                recorded_ref = str(current[\"cred_ref\"])",
        "                recorded_ref = str(current[\"cred_ref\"])\n                current[\"cred\"] = None",
        "tests/unit/test_guestjobs.py::test_stop_writes_the_durable_row_before_nulling_the_credential",
    ),
    (
        "PRR-015 job cap union",
        "src/hyperv_mcp/guestjobs.py",
        "                known = set(_jobs) | set(rows)",
        "                known = set(_jobs)",
        "tests/unit/test_e01_state_store_guardrail.py::test_job_cap_counts_store_only_rows",
    ),
    (
        "PRR-015 relay cap union",
        "src/hyperv_mcp/relay.py",
        "            known = set(_relays) | set(rows)",
        "            known = set(_relays)",
        "tests/unit/test_relay.py::test_relay_cap_counts_store_only_rows",
    ),
    (
        "PRR-015 PID-0 refusal branch removed",
        "src/hyperv_mcp/guestjobs.py",
        '    if entry.get("row_state") == statestore.JOB_ORPHANED:\n        # A crash inside the guest start leg leaves',
        '    if False:\n        # A crash inside the guest start leg leaves',
        "tests/unit/test_e01_state_store_guardrail.py::test_stop_refuses_an_orphaned_row_without_a_guest_leg",
    ),
    (
        "PRR-015 resolve config-key branch removed",
        "src/hyperv_mcp/statestore.py",
        '    configured = (cfg.state_db_path or "").strip()\n    if configured:\n        return configured',
        '    configured = (cfg.state_db_path or "").strip()\n    if False:\n        return configured',
        "tests/unit/test_e01_state_store_guardrail.py::test_resolve_state_db_path_honours_the_config_key",
    ),
    (
        "PRR-015 relay_stop write outside the lock",
        "src/hyperv_mcp/relay.py",
        "        with _relays_lock:\n            already = bool(entry[\"stopped\"])\n            entry[\"stopped\"] = True",
        "        with _relays_lock:\n            already = bool(entry[\"stopped\"])\n        entry[\"stopped\"] = True",
        "tests/unit/test_e01_state_store_guardrail.py::test_relay_stop_reads_stopped_under_the_registry_lock",
    ),
    (
        "PRR-009 soak store redirect removed",
        "scripts/soak_bench.py",
        '    bootstrap_env = {"HYPERV_MCP_CONFIG": str(cfg)}\n    operator_db = os.environ.get("HYPERV_MCP_STATE_DB", "").strip()\n    if operator_db:\n        bootstrap_env["HYPERV_MCP_STATE_DB"] = operator_db\n    else:\n        bootstrap_env["HYPERV_MCP_STATE_DB"] = str(audit_log.parent / "soak-state.db")',
        '    bootstrap_env = {"HYPERV_MCP_CONFIG": str(cfg)}',
        "tests/unit/test_d05_soak_session_reuse.py::test_fake_mode_redirects_the_state_store_and_honours_an_operator_override",
    ),
    (
        "PRR-007 server lazy peek resolution disabled",
        "src/hyperv_mcp/server.py",
        "        if callable(audit_vm_name):\n            try:\n                audit_vm_name = str(audit_vm_name() or \"\")\n            except Exception:\n                audit_vm_name = \"\"",
        "        if callable(audit_vm_name):\n            audit_vm_name = \"\"",
        "tests/unit/test_b01_audit_correlation_guardrail.py::test_raising_job_output_kwargs_are_sole_source",
    ),
]

# The "correct double read" control: relay_stop reads twice under the lock and
# the relaxed pin must still pass (the old `reads == [True]` would not).
CONTROLS = [
    (
        "control: relay_stop double read accepted",
        "src/hyperv_mcp/relay.py",
        "        with _relays_lock:\n            already = bool(entry[\"stopped\"])\n            entry[\"stopped\"] = True",
        "        with _relays_lock:\n            already = bool(entry[\"stopped\"])\n"
        "            already = bool(entry[\"stopped\"])\n"
        "            entry[\"stopped\"] = True",
        "tests/unit/test_e01_state_store_guardrail.py::test_relay_stop_reads_stopped_under_the_registry_lock",
    ),
]


def run_probe(label: str, rel: str, old: str, new: str, test: str, expect_fail: bool) -> str:
    path = REPO / rel
    backup = path.with_suffix(path.suffix + ".probe-backup")
    original = path.read_bytes()
    shutil.copyfile(path, backup)
    try:
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            return f"SKIP  {label}: anchor count {text.count(old)} (expected 1)"
        path.write_text(text.replace(old, new), encoding="utf-8")
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
        proc = subprocess.run(
            [PY, "-m", "pytest", test, "-p", "no:cacheprovider", "-q", "--no-header"],
            cwd=str(REPO),
            env=env,
            capture_output=True, text=True, timeout=600,
        )
        # Restore FIRST, then judge: the restore must happen whatever pytest did.
    finally:
        restored = backup.read_bytes()
        path.write_bytes(restored)
        backup.unlink()
        if path.read_bytes() != original:
            return f"HYGIENE-FAIL {label}: restore is not byte-identical"
    failed = proc.returncode != 0
    if failed == expect_fail:
        return f"{'KILLED' if expect_fail else 'ACCEPTED'} {label}"
    return f"SURVIVED {label}: returncode={proc.returncode} tail={proc.stdout[-200:]}"


def main() -> int:
    results = []
    for label, rel, old, new, test in PROBES:
        results.append(run_probe(label, rel, old, new, test, expect_fail=True))
    for label, rel, old, new, test in CONTROLS:
        results.append(run_probe(label, rel, old, new, test, expect_fail=False))
    for line in results:
        print(line)
    bad = [line for line in results if not line.startswith(("KILLED", "ACCEPTED"))]
    print(f"\n{len(results) - len(bad)}/{len(results)} probes behaved as required")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
