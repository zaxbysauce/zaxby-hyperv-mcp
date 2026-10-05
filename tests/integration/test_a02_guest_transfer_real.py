r"""Real-guest junction escape checks for issue #6 AC8 (opt-in; see conftest).

The whole module skips with a named reason unless ALL conftest gates hold
(`HYPERV_MCP_INTEGRATION=1`, `HYPERV_MCP_TEST_VM`, guest credentials) — see
`tests/integration/conftest.py`.

Scenario (AC8): configured guest roots `C:\mcp-w` / `C:\mcp-r` with
guest-held junctions `C:\mcp-w\esc -> C:\Windows\Temp` and
`C:\mcp-r\esc -> C:\Windows\System32\drivers\etc`. `guest_put` through the
write junction and `guest_get` through the read junction must BOTH return
`ok: false, error_class: "policy"`, leave no `a03.txt` (or staging file)
under `C:\Windows\Temp`, and write no local file. This is the real-guest
proof that in-guest assertion placement (before any in-guest side effect),
`-ErrorAction Stop` termination, and policy classification compose end to
end — mocked unit tests cannot exercise the `-Session` remoting leg.
"""

import itertools
import json
import time

import pytest

pytestmark = [pytest.mark.hyperv_real]

# Unique per CREATION (same collision rationale as test_hyperv_real.py).
_CHECKPOINT_SEQ = itertools.count(1)
CHECKPOINT = "mcp-it-ac8-{}".format(time.strftime("%Y%m%d-%H%M%S"))


def _rooted_cfg(vm_name, it_tmp):
    from hyperv_mcp.config import Config

    src = it_tmp / "host-src"
    src.mkdir(exist_ok=True)
    dst = it_tmp / "host-dst"
    dst.mkdir(exist_ok=True)
    cfg = Config(
        allowed_vm_patterns=[vm_name],
        host_read_roots=[str(src)],
        host_write_roots=[str(dst)],
        guest_read_roots=["C:\\mcp-r"],
        guest_write_roots=["C:\\mcp-w"],
        verify_sha256=True,
    )
    cfg.destructive.guest_write = True
    # The finally block restores a checkpoint; without the category switch
    # that restore is denied and swallowed into the cleanup report, so the
    # VM would keep test-created roots/junctions between runs.
    cfg.destructive.checkpoint_restore = True
    cfg.destructive.require_confirm = False
    return cfg


def test_guest_junction_inside_root_is_denied(it, it_tmp):
    from hyperv_mcp import filetransfer, guestexec, lifecycle

    vm = it.vm
    cfg = _rooted_cfg(vm, it_tmp)
    checkpoint = f"{CHECKPOINT}-{next(_CHECKPOINT_SEQ)}"
    lifecycle.checkpoint_create(cfg, vm, checkpoint)
    try:
        lifecycle.start_vm(cfg, vm)
        setup = guestexec.guest_run_ps(
            cfg,
            vm,
            # Check each mklink's exit code: without it a first-junction
            # failure would be masked by the second command's success.
            # (No check after New-Item: $LASTEXITCODE there is stale/null
            # and would exit the script prematurely.)
            "New-Item -ItemType Directory -Path 'C:\\mcp-w', 'C:\\mcp-r' -Force | Out-Null; "
            "cmd /c mklink /J C:\\mcp-w\\esc C:\\Windows\\Temp; "
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
            "cmd /c mklink /J C:\\mcp-r\\esc C:\\Windows\\System32\\drivers\\etc; "
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
            cred=it.creds,
        )
        assert setup["ok"] and setup["exit_code"] == 0, setup

        # --- put through the escaping junction: denied in-guest, no side effects
        src = it_tmp / "host-src" / "a03.txt"
        src.write_text("junction escape attempt")
        put = filetransfer.guest_put(
            cfg, vm, str(src), r"C:\mcp-w\esc\a03.txt",
            confirm=True, verify=True, cred=it.creds,
        )
        assert put["ok"] is False and put["error_class"] == "policy", put
        assert "policy: guest write denied" in put["error"], put

        probe = guestexec.guest_run_ps(
            cfg,
            vm,
            "$file = Test-Path -LiteralPath 'C:\\Windows\\Temp\\a03.txt'; "
            # Staging names are uuid siblings (no destination-name prefix),
            # so the orphan probe matches any *.mcptmp, not a03.txt*.
            "$staging = @(Get-ChildItem -LiteralPath 'C:\\Windows\\Temp' -File "
            "-ErrorAction SilentlyContinue | Where-Object { "
            "$_.Name -like '*.mcptmp' }).Count; "
            "'{0}|{1}' -f $file, $staging",
            cred=it.creds,
        )
        assert probe["ok"] and probe["exit_code"] == 0, probe
        assert probe["stdout"].strip() == "False|0", probe

        # --- get through the escaping junction: denied, no local file written
        local_dest = it_tmp / "host-dst" / "hosts"
        got = filetransfer.guest_get(
            cfg, vm, r"C:\mcp-r\esc\hosts", str(local_dest),
            verify=True, cred=it.creds,
        )
        assert got["ok"] is False and got["error_class"] == "policy", got
        assert "policy: guest read denied" in got["error"], got
        assert not local_dest.exists()
    finally:
        # Best-effort junction teardown inside the test, then checkpoint
        # restore reverts roots/junctions regardless (record, don't hide).
        try:
            guestexec.guest_run_ps(
                cfg,
                vm,
                "cmd /c rmdir C:\\mcp-w\\esc; cmd /c rmdir C:\\mcp-r\\esc",
                cred=it.creds,
            )
        except Exception:  # noqa: BLE001 - restore below is the real cleanup
            pass
        try:
            lifecycle.checkpoint_restore(cfg, vm, checkpoint, confirm=True)
        except Exception as exc:  # noqa: BLE001 - report, don't hide
            with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
                json.dump(
                    {"unrestored_vm": vm, "checkpoint": checkpoint, "error": str(exc)},
                    fh,
                )


def test_put_to_existing_directory_is_invalid(it, it_tmp):
    """A directory destination must come back as error_class "invalid" —
    classified by the in-guest container check BEFORE the copy, so no
    staging file is ever created inside the container."""
    from hyperv_mcp import filetransfer, guestexec, lifecycle

    vm = it.vm
    cfg = _rooted_cfg(vm, it_tmp)
    checkpoint = f"{CHECKPOINT}-{next(_CHECKPOINT_SEQ)}"
    lifecycle.checkpoint_create(cfg, vm, checkpoint)
    try:
        lifecycle.start_vm(cfg, vm)
        setup = guestexec.guest_run_ps(
            cfg,
            vm,
            "New-Item -ItemType Directory -Path 'C:\\mcp-w\\dir' -Force | Out-Null",
            cred=it.creds,
        )
        assert setup["ok"] and setup["exit_code"] == 0, setup

        src = it_tmp / "host-src" / "a04.txt"
        src.write_text("into a directory destination")
        put = filetransfer.guest_put(
            cfg, vm, str(src), r"C:\mcp-w\dir",
            confirm=True, verify=True, cred=it.creds,
        )
        assert put["ok"] is False and put["error_class"] == "invalid", put
        assert "invalid destination" in put["error"], put

        probe = guestexec.guest_run_ps(
            cfg,
            vm,
            "$staging = @(Get-ChildItem -LiteralPath 'C:\\mcp-w\\dir' -File "
            "-Recurse -ErrorAction SilentlyContinue | Where-Object { "
            "$_.Name -like '*.mcptmp' }).Count; "
            "'{0}' -f $staging",
            cred=it.creds,
        )
        assert probe["ok"] and probe["exit_code"] == 0, probe
        assert probe["stdout"].strip() == "0", probe
    finally:
        try:
            lifecycle.checkpoint_restore(cfg, vm, checkpoint, confirm=True)
        except Exception as exc:  # noqa: BLE001 - report, don't hide
            with open("hyperv-it-cleanup-report.json", "w", encoding="utf-8") as fh:
                json.dump(
                    {"unrestored_vm": vm, "checkpoint": checkpoint, "error": str(exc)},
                    fh,
                )
