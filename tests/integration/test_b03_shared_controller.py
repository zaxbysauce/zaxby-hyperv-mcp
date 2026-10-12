"""B03 shared-controller integration checks (ENH-09 acceptance freeze).

Real-Hyper-V counterparts of the B03 unit freeze
(tests/unit/test_b03_stdio_proxy.py): two stdio proxies converging on ONE
controller route VM mutations through the controller's per-VM lock — both
agents' operations land in the ONE controller's audit sink, and no proxy
spawns interleaved PowerShell. (The cross-agent VMBusy envelope itself is
masked until the controller stops serializing sync tool calls — FND-01,
Workstream C PR 3 / issue #16; agent-b's call queues behind agent-a's.) The
logon-task launcher's registered task brings up a controller that serves
a flagless proxy child. These run only on a real Hyper-V host under the
tests/integration environment guards; the VM is checkpointed before invasive
work and restored afterwards (the test_hyperv_real protocol).
"""

import asyncio
import itertools
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import hyperv_mcp.http_entry as http_entry
from hyperv_mcp import pswindows

pytestmark = [pytest.mark.hyperv_real]

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = str(REPO_ROOT / "src")
TASK_NAME = "hyperv-mcp-http"
TASK_PORT = 8787
TOKEN_A_ENV = "B03_IT_TOKEN_A"
TOKEN_B_ENV = "B03_IT_TOKEN_B"

_CHECKPOINT_SEQ = itertools.count(1)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _main_rc(module, argv: list[str]) -> int:
    """Call a console-script main(argv) and normalize argparse's SystemExit
    spelling into the process exit code it produces."""
    try:
        rc = module.main(argv)
    except SystemExit as exc:
        rc = int(exc.code or 0)
    return rc


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0):
            return True
    except OSError:
        return False


def _wait_listening(port: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.5)
    return False


def _child_env(updates: dict[str, str | None]) -> dict[str, str]:
    """Full parent environment (guest credentials flow to the controller),
    repo src importable, None-valued updates removed so each proxy child
    presents exactly its own agent token."""
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR
    for key, value in updates.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _spawn_controller(port: int, env: dict[str, str]) -> subprocess.Popen:
    """A real detached hyperv-mcp-http controller child on the given port.
    Termination on the assertion path too (PRR-012/T-2): the caller's
    try/finally only exists if this function returns."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "hyperv_mcp.http_entry", "--port", str(port)],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_listening(port, timeout_s=60.0):
        try:
            proc.terminate()
            proc.wait(timeout=10.0)
        except Exception:  # noqa: BLE001 - best-effort reap before re-raising
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        raise AssertionError(
            f"the hyperv-mcp-http controller never listened on 127.0.0.1:{port}"
        )
    return proc


def _proxy_call(
    args: list[str],
    env_updates: dict[str, str | None],
    tool: str,
    arguments: dict | None = None,
    timeout_s: float = 120.0,
) -> object | None:
    """One real ClientSession over stdio against a spawned proxy child;
    returns the tool call's first JSON text payload, or None when the child
    could not complete the initialize/tool round trip."""
    env = _child_env(env_updates)

    async def _drive() -> object | None:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "hyperv_mcp", *args],
            cwd=str(REPO_ROOT),
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments or {})
        texts = [
            block.text
            for block in (result.content or [])
            if getattr(block, "type", "") == "text" and getattr(block, "text", None)
        ]
        if not texts:
            return None
        try:
            return json.loads(texts[0])
        except ValueError:
            return None

    try:
        return asyncio.run(asyncio.wait_for(_drive(), timeout=timeout_s))
    except Exception:
        return None


def _scan_processes(predicate) -> list:
    """Live psutil processes whose joined cmdline satisfies predicate()."""
    import psutil

    matches = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
        except psutil.NoSuchProcess:
            continue
        except psutil.Error:
            continue
        if cmdline and predicate(cmdline):
            matches.append(proc)
    return matches


def _terminate_processes(procs: list) -> None:
    """Terminate then force-kill a list of psutil processes."""
    import psutil

    for proc in procs:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
    _gone, alive = psutil.wait_procs(procs, timeout=5.0)
    for proc in alive:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass


def _mentions_port(cmdline: str, port: int) -> bool:
    """Whole-number port match (PRR-020): '1234' must not match 51234."""
    return re.search(r"(?<!\d)" + str(port) + r"(?!\d)", cmdline) is not None


def _terminate_controllers_on_port(port: int) -> int:
    """Reap controller children matched by the EXACT port in their cmdline,
    so unrelated hyperv-mcp-http processes (including operators' and any
    controller whose port merely contains these digits) stay untouched."""
    procs = _scan_processes(
        lambda cmdline: _mentions_port(cmdline, port)
        and ("hyperv_mcp.http_entry" in cmdline or TASK_NAME in cmdline)
    )
    _terminate_processes(procs)
    return len(procs)


def _proxy_powershell_offenders(proxy_url: str) -> tuple[int, list[str]]:
    """Live proxy children for proxy_url and any PowerShell executables in
    their descendant trees (a proxy forwards JSON-RPC; it never spawns
    powershell itself)."""
    import psutil

    offenders = []
    proxies = _scan_processes(
        lambda cmdline: "hyperv_mcp" in cmdline and "--proxy" in cmdline and proxy_url in cmdline
    )
    for proxy in proxies:
        try:
            for child in proxy.children(recursive=True):
                name = (child.name() or "").lower()
                if name in ("powershell.exe", "pwsh.exe"):
                    offenders.append(name)
        except psutil.NoSuchProcess:
            continue
    return len(proxies), offenders


@pytest.fixture()
def guarded_vm(it):
    """Checkpoint before invasive work; restore afterwards (the
    test_hyperv_real.py protocol, kept local so this module stands alone)."""
    from hyperv_mcp import lifecycle

    checkpoint = f"b03-it-pre-{time.strftime('%Y%m%d-%H%M%S')}-{next(_CHECKPOINT_SEQ)}"
    lifecycle.checkpoint_create(it.cfg, it.vm, checkpoint)
    it.checkpoint = checkpoint
    yield it
    try:
        lifecycle.checkpoint_restore(it.cfg, it.vm, checkpoint, confirm=True)
    except Exception as exc:  # noqa: BLE001 - report, don't hide
        with open("b03-it-cleanup-report.json", "w", encoding="utf-8") as fh:
            json.dump({"unrestored_vm": it.vm, "checkpoint": checkpoint, "error": str(exc)}, fh)


# ---------------------------------------------------------------------------
# shared VM lock across two proxies
# ---------------------------------------------------------------------------


def test_two_proxies_share_vm_lock(it, guarded_vm, tmp_path):
    """Two proxy children on two agent identities must serialize VM mutations
    through ONE controller: both agents' operations land in the shared
    controller's audit sink (cross-agent attribution), exactly one
    hyperv-mcp-http process serves, and no proxy spawns PowerShell.

    Known boundary (recorded 2026-10-12): the cross-agent VMBusy envelope is
    masked until the controller's sync-tool serialization is removed
    (FND-01, Workstream C PR 3 / issue #16) — agent-b's call queues behind
    agent-a's, so its body runs after the lock releases. The in-process
    non-blocking busy path is pinned by the vmlocks unit suite; this test
    pins the consolidation half of the contract.

    The proxies only forward MCP JSON-RPC: exactly one hyperv-mcp-http
    controller process serves, and no proxy child ever has a powershell.exe
    descendant (sampled for the whole in-flight window). The guarded_vm
    fixture restores the VM afterwards."""
    from hyperv_mcp import lifecycle

    # Widen the lock window deterministically: start_vm holds the per-VM
    # lock across Start-VM AND the wait for Running (seconds on a real
    # guest), so the exercise stops the VM first and makes agent-a's
    # start_vm the long lock holder. (A graceful shutdown's lock hold is
    # only the Stop-VM cmdlet initiation - the wait for Off runs after the
    # lock releases - which makes the busy race a coin flip.)
    lifecycle.stop_vm(it.cfg, it.vm, method="turnoff", confirm=True)

    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    audit = tmp_path / "b03-it-audit.jsonl"
    config = tmp_path / "b03-it-cfg.json"
    config.write_text(
        json.dumps(
            {
                "unrestricted": True,
                "audit_log_path": str(audit),
                "http": {
                    "port": port,
                    "agents": {"agent-a": TOKEN_A_ENV, "agent-b": TOKEN_B_ENV},
                },
            }
        ),
        encoding="utf-8",
    )
    token_a = secrets.token_urlsafe(24)
    token_b = secrets.token_urlsafe(24)
    controller_proc = _spawn_controller(
        port,
        _child_env(
            {
                "HYPERV_MCP_CONFIG": str(config),
                TOKEN_A_ENV: token_a,
                TOKEN_B_ENV: token_b,
            }
        ),
    )
    try:
        # Sample the proxy children's descendant trees for the whole
        # exercise, so "no powershell under a proxy" is checked while the
        # proxies are demonstrably alive.
        offenders: set[str] = set()
        peak_alive_proxies = 0
        stop_monitor = threading.Event()

        def _monitor() -> None:
            nonlocal peak_alive_proxies
            while not stop_monitor.is_set():
                alive, found = _proxy_powershell_offenders(url)
                offenders.update(found)
                peak_alive_proxies = max(peak_alive_proxies, alive)
                stop_monitor.wait(1.0)

        monitor = threading.Thread(target=_monitor, daemon=True)
        monitor.start()

        outcome: dict[str, object] = {}
        a_done = threading.Event()
        b_session_box: dict = {}

        def _agent_b_session() -> None:
            """Pre-warm agent-b's proxy session so its start_vm fires the
            moment agent-a's stop holds the lock (spawning a fresh proxy
            child per poll loses the race to a graceful shutdown)."""
            env = _child_env(
                {
                    "HYPERV_MCP_CONFIG": str(config),
                    TOKEN_A_ENV: None,
                    TOKEN_B_ENV: token_b,
                }
            )

            async def _hold():
                params = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "hyperv_mcp", "--proxy", url],
                    cwd=str(REPO_ROOT),
                    env=env,
                )
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        b_session_box["session"] = session
                        b_session_box["loop"] = asyncio.get_running_loop()
                        b_session_box["ready"].set()
                        await asyncio.get_event_loop().create_future()

            b_session_box["ready"] = threading.Event()
            try:
                asyncio.run(_hold())
            except Exception:  # noqa: BLE001 - teardown after cancel
                pass

        def _agent_b_fire_once() -> dict | None:
            """One start_vm through agent-b's live pre-warmed session. The
            session lives on agent-b's event loop, so the call is scheduled
            onto that loop from the main thread."""
            loop = b_session_box.get("loop")
            session = b_session_box.get("session")
            if loop is None or session is None:
                return None

            async def _call():
                return await session.call_tool("hyperv_start_vm", {"vm_name": it.vm})

            try:
                future = asyncio.run_coroutine_threadsafe(_call(), loop)
                result = future.result(timeout=60.0)
            except Exception:  # noqa: BLE001 - transport/timeout → retried
                return None
            texts = [
                block.text
                for block in (result.content or [])
                if getattr(block, "type", "") == "text" and getattr(block, "text", None)
            ]
            if not texts:
                return None
            try:
                return json.loads(texts[0])
            except ValueError:
                return None

        b_thread = threading.Thread(target=_agent_b_session, daemon=True)
        b_thread.start()
        assert b_session_box["ready"].wait(timeout=60.0), (
            "agent-b's pre-warmed proxy session never became ready"
        )

        def _agent_a() -> None:
            try:
                # Retry on busy only: agent-b's short holds must not fail
                # the stop; every other outcome is final.
                deadline = time.monotonic() + 600.0
                while time.monotonic() < deadline:
                    envelope = _proxy_call(
                        ["--proxy", url],
                        {
                            "HYPERV_MCP_CONFIG": str(config),
                            TOKEN_A_ENV: token_a,
                            TOKEN_B_ENV: None,
                        },
                        "hyperv_start_vm",
                        {"vm_name": it.vm},
                        timeout_s=300.0,
                    )
                    if isinstance(envelope, dict) and envelope.get("error_class") == "busy":
                        time.sleep(1.0)
                        continue
                    outcome["a"] = envelope
                    return
                outcome["a"] = None
            finally:
                a_done.set()

        agent_a_thread = threading.Thread(target=_agent_a, daemon=True)
        agent_a_thread.start()

        # Fire agent-b's start_vm through its live session while agent-a's
        # start_vm is in flight. NOTE (recorded 2026-10-12): the controller
        # currently serializes sync tool calls (FND-01, Workstream C PR 3 /
        # issue #16 owns the fix), so agent-b's call queues behind agent-a's
        # and the VMBusy envelope is NOT observable yet — the audit rows
        # (both agent_ids, sequential) are the recorded evidence of the
        # consolidation. The in-process busy path itself is pinned by the
        # vmlocks unit suite; cross-agent busy lands with #16.
        b_envelopes: list[str] = []
        while not a_done.is_set():
            envelope = _agent_b_fire_once()
            b_envelopes.append(str(envelope)[:120])
            if envelope is None:
                # dead/failed session: avoid a CPU-pegging spin (PRR-026)
                time.sleep(0.5)

        agent_a_thread.join(timeout=300.0)
        stop_monitor.set()
        monitor.join(timeout=5.0)
        print(f"B-POLL ENVELOPES: {b_envelopes}", flush=True)

        envelope_a = outcome.get("a")
        # hyperv_start_vm's success shape is the bare status dict
        # {status: started|already_running, vm_name, state} (no ok: field).
        completed = isinstance(envelope_a, dict) and (
            envelope_a.get("ok") is True
            or envelope_a.get("status") in ("started", "already_running")
        )
        assert completed, (
            f"agent-a's start through the shared controller did not complete: "
            f"{envelope_a!r}"
        )
        audit_rows = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        vm_rows = {
            row.get("agent_id")
            for row in audit_rows
            if row.get("tool") in ("hyperv_start_vm", "hyperv_stop_vm")
        }
        assert {"agent-a", "agent-b"} <= vm_rows, (
            f"both agents' VM operations must land in the ONE controller's "
            f"audit sink; saw agent ids {sorted(vm_rows)}"
        )
        serving = len(
            _scan_processes(
                lambda cmdline: "hyperv_mcp.http_entry" in cmdline
                and _mentions_port(cmdline, port)
            )
        )
        assert serving == 1, (
            f"exactly one hyperv-mcp-http controller process must serve the "
            f"two proxies; psutil sees {serving}"
        )
        assert peak_alive_proxies >= 1, (
            "no live proxy child was observed during the in-flight window"
        )
        assert not offenders, (
            "a proxy child spawned PowerShell itself instead of forwarding "
            f"JSON-RPC to the controller: {sorted(offenders)}"
        )
    finally:
        _terminate_controllers_on_port(port)
        if controller_proc.poll() is None:
            controller_proc.terminate()
        try:
            controller_proc.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            controller_proc.kill()
            controller_proc.wait(timeout=10.0)


# ---------------------------------------------------------------------------
# logon-task controller serves a flagless proxy
# ---------------------------------------------------------------------------


def test_logon_task_controller_serves_proxy(it, monkeypatch, tmp_path):
    """--install-logon-task (real pswindows.run_ps) registers the per-user
    logon task; the exported task XML carries neither the token value nor
    the literal HYPERV_GUEST_PASSWORD; Start-ScheduledTask brings up a
    controller on 127.0.0.1:8787 that serves hyperv_list_vms through a
    flagless `python -m hyperv_mcp` proxy child presenting the same token.

    Task Scheduler builds the task-spawned process environment from the
    USER's registry environment, not the caller's process env — so the
    token is persisted user-scope first (the documented `setx` path) and
    restored in the finally block. The strict logoff/logon TRIGGER cycle is
    a manual acceptance step (outside pytest's blast radius): after this
    test passes, log off and back on and verify the task ran
    (Get-ScheduledTask -TaskName hyperv-mcp-http | Select-Object State,
    LastRunTime shows Ready with a fresh LastRunTime, and 127.0.0.1:8787
    accepts). Cleanup unregisters the task, restores the user environment,
    and terminates ONLY the task-spawned controller PID."""
    if _port_open(TASK_PORT):
        pytest.skip(
            f"port {TASK_PORT} already has a listener (a controller is "
            "already running); AC10 needs the logon task to own it"
        )
    token = secrets.token_urlsafe(32)
    monkeypatch.delenv("HYPERV_MCP_CONFIG", raising=False)
    env_name = "HYPERV_MCP_HTTP_TOKEN"
    # The task-spawned controller reads its config the same way the token is
    # persisted: user-scope registry environment. Point it at an
    # unrestricted config so list_vms is policy-allowed for the task run.
    task_cfg = tmp_path / "b03-logon-task-cfg.json"
    task_cfg.write_text(
        json.dumps({"unrestricted": True}),
        encoding="utf-8",
    )

    def _psq(value: str) -> str:
        return value.replace("'", "''")

    def _user_env(operation: str, name: str, value: str = "") -> bool:
        script = (
            "[Environment]::"
            f"{operation}EnvironmentVariable('{_psq(name)}', '{_psq(value)}', 'User')"
        )
        result = pswindows.run_ps(script)
        return result.ok()

    prior = pswindows.run_ps(
        f"[Environment]::GetEnvironmentVariable('{env_name}', 'User')"
    )
    prior_token = prior.stdout.strip() if prior.ok() and prior.stdout.strip() else None
    prior_cfg = pswindows.run_ps(
        "[Environment]::GetEnvironmentVariable('HYPERV_MCP_CONFIG', 'User')"
    )
    prior_cfg_value = (
        prior_cfg.stdout.strip() if prior_cfg.ok() and prior_cfg.stdout.strip() else None
    )
    controller_pids: set[int] = set()
    try:
        assert _user_env("Set", env_name, token), (
            "persisting the token user-scope failed"
        )
        assert _user_env("Set", "HYPERV_MCP_CONFIG", str(task_cfg)), (
            "persisting the config path user-scope failed"
        )
        rc = _main_rc(http_entry, ["--install-logon-task"])
        assert rc == 0, f"--install-logon-task must register the task; rc={rc}"
        exported = pswindows.run_ps(f"(Export-ScheduledTask -TaskName '{TASK_NAME}').Xml")
        assert exported.ok(), "Export-ScheduledTask failed: " + (exported.stderr or "")[:200]
        xml = exported.stdout
        assert token not in xml, "the task XML leaked the token value"
        assert "HYPERV_GUEST_PASSWORD" not in xml, (
            "the task XML leaked the guest password variable name"
        )

        before = {
            proc.info["pid"]
            for proc in _scan_processes(
                lambda cmdline: "hyperv_mcp.http_entry" in cmdline
                or TASK_NAME in cmdline
            )
        }
        started = pswindows.run_ps(f"Start-ScheduledTask -TaskName '{TASK_NAME}'")
        assert started.ok(), "Start-ScheduledTask failed: " + (started.stderr or "")[:200]
        assert _wait_listening(TASK_PORT, timeout_s=90.0), (
            f"the task-started controller never listened on 127.0.0.1:{TASK_PORT}"
        )
        after = _scan_processes(
            lambda cmdline: "hyperv_mcp.http_entry" in cmdline or TASK_NAME in cmdline
        )
        controller_pids = {
            proc.info["pid"] for proc in after if proc.info["pid"] not in before
        }
        assert controller_pids, (
            "no task-spawned controller process was found; something else "
            "took the port"
        )
        owner = pswindows.run_ps(
            "(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort "
            f"{TASK_PORT} -State Listen | Select-Object -First 1).OwningProcess"
        )
        assert owner.ok() and owner.stdout.strip().isdigit(), (
            f"nothing owns a listener on 127.0.0.1:{TASK_PORT}"
        )
        assert int(owner.stdout.strip()) in controller_pids, (
            f"the 127.0.0.1:{TASK_PORT} listener is not the task-spawned "
            f"controller (owner {owner.stdout.strip()!r} not in "
            f"{sorted(controller_pids)})"
        )
        payload = _proxy_call([], {env_name: token}, "hyperv_list_vms", {})
        # hyperv_list_vms payloads arrive as a VM list or (single-text-block
        # shape) one VM dict; either proves the task controller served it.
        assert isinstance(payload, (list, dict)) and payload, (
            f"a flagless proxy could not list VMs through the task-started "
            f"controller: {payload!r}"
        )
        names = (
            [v.get("name") for v in payload if isinstance(v, dict)]
            if isinstance(payload, list)
            else [payload.get("name")]
        )
        if it.vm not in names:
            # A different VM's row still proves list_vms served; assert the
            # test VM is visible through the host itself for completeness.
            from hyperv_mcp import lifecycle as _lifecycle

            host_names = [
                v.get("name") for v in _lifecycle.list_vms(it.cfg) if isinstance(v, dict)
            ]
            assert it.vm in host_names, (
                f"the task controller served VMs but {it.vm} was not among "
                f"them: names={names} host={host_names}"
            )
    finally:
        pswindows.run_ps(
            f"Stop-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue"
        )
        pswindows.run_ps(f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false")
        import psutil

        victims = []
        for pid in controller_pids:
            try:
                victims.append(psutil.Process(pid))
            except psutil.NoSuchProcess:
                continue
        _terminate_processes(victims)
        restored = True
        if prior_token is None:
            restored &= pswindows.run_ps(
                f"[Environment]::SetEnvironmentVariable('{env_name}', $null, 'User')"
            ).ok()
        else:
            restored &= _user_env("Set", env_name, prior_token)
        if prior_cfg_value is None:
            restored &= pswindows.run_ps(
                "[Environment]::SetEnvironmentVariable("
                "'HYPERV_MCP_CONFIG', $null, 'User')"
            ).ok()
        else:
            restored &= _user_env("Set", "HYPERV_MCP_CONFIG", prior_cfg_value)
        if not restored:
            print(
                "WARNING: user-scope env restore failed; the developer's "
                "registry may still hold the test token/config (PRR-026)",
                file=sys.stderr,
            )
