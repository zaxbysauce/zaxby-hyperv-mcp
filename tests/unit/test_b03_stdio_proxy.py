"""B03 stdio-proxy / shared-controller checks (ENH-09 acceptance freeze).

Freezes the standing contract of the stdio proxy front door: `hyperv-mcp
--proxy URL` forwards MCP JSON-RPC unchanged to an explicit streamable-HTTP
controller, the flagless default mode proxies to the controller configured at
http.host/http.port (auto-starting a detached hyperv-mcp-http when nothing
listens there), `--standalone` keeps today's in-process stdio server, and
`hyperv-mcp-http --install-logon-task` registers the per-user logon
scheduled task via pswindows.run_ps. Failure paths never leak token values,
cleartext non-loopback controller URLs are refused before any network I/O,
and audit rows keep naming the calling agent. hyperv_relay_status is the
probe tool: it reads the in-memory relay registry only, so a unit test can
drive a real controller with no PowerShell and no Hyper-V.
"""

import asyncio
import importlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx2
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import hyperv_mcp.http_entry as http_entry
import hyperv_mcp.pswindows as pswindows
import hyperv_mcp.server as server_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = str(REPO_ROOT / "src")

# Distinct sentinel token values per acceptance criterion; asserted to be
# absent from child output, never echoed in assertion messages.
AC2_TOKEN = "sentinel-ac2-token-7f3b"
AC3_TOKEN = "sentinel-ac3-token-91af"
AC5_TOKEN = "sentinel-ac5-token-2c9d"
AC6_TOKEN = "sentinel-ac6-token-44ce"
AC7_TOKEN = "sentinel-ac7-token-b16d"
AC8_TOKEN = "sentinel-ac8-token-d08b"
TOKEN_A = "sentinel-ac4-agent-a-3f91"
TOKEN_B = "sentinel-ac4-agent-b-7c22"

# The proxy contract answers outstanding client request ids within 10 s;
# whole-session drivers get a wider bound so the 10 s contract stays the
# discriminating assertion and the 120 s pytest timeout stays far away.
REQUEST_DEADLINE_S = 10.0
SESSION_DEADLINE_S = 30.0


# ---------------------------------------------------------------------------
# child process / environment helpers
# ---------------------------------------------------------------------------


def _probe_env(**token_envs: str) -> dict[str, str]:
    """Environment for raw-spawned proxy children: repo src importable, no
    inherited HYPERV_MCP_CONFIG, plus the given token variables."""
    env = dict(os.environ)
    env.pop("HYPERV_MCP_CONFIG", None)
    env["PYTHONPATH"] = SRC_DIR
    env.update(token_envs)
    return env


def _session_env(updates: dict[str, str | None]) -> dict[str, str]:
    """Environment for ClientSession-driven proxy children: full parent
    environment (so a shared HYPERV_MCP_CONFIG flows), repo src importable,
    with None-valued updates REMOVED so each child presents exactly its own
    agent token."""
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR
    for key, value in updates.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _free_port() -> int:
    """An ephemeral loopback port number with (at pick time) no listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0):
            return True
    except OSError:
        return False


def _wait_listening(port: int, timeout_s: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.2)
    return False


def _main_rc(module, argv: list[str]) -> int:
    """Call a console-script main(argv) and normalize argparse's SystemExit
    spelling into the process exit code it produces."""
    try:
        rc = module.main(argv)
    except SystemExit as exc:
        rc = int(exc.code or 0)
    return rc


def _audit_rows(path: Path) -> list[dict]:
    """Parsed JSONL audit rows; a not-yet-written sink reads as empty."""
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# raw line JSON-RPC probe (AC1 / AC2)
# ---------------------------------------------------------------------------


class _ProxyProbe:
    """A spawned proxy child probed with raw newline-delimited JSON-RPC.

    A daemon reader thread collects every stdout line and captures the first
    response that answers request id 1, so a hung or instantly-exited child
    surfaces as "no reply within the deadline" rather than a blocked read.
    """

    def __init__(self, args: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "hyperv_mcp", *args],
            cwd=str(REPO_ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.lines: list[str] = []
        self._box: dict[str, dict] = {}
        self._reply = threading.Event()
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.append(line)
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if (
                isinstance(msg, dict)
                and msg.get("id") == 1
                and ("error" in msg or "result" in msg)
            ):
                self._box["reply"] = msg
                self._reply.set()
                return

    def request_initialize(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "0"},
            },
        }
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(json.dumps(request) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError):
            # The child already exited; the missing reply is the assertion.
            pass

    def await_reply(self, timeout_s: float) -> dict | None:
        self._reply.wait(timeout_s)
        return self._box.get("reply")

    def wait_exit(self, timeout_s: float = 10.0) -> None:
        try:
            self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.terminate()

    def stderr_text(self) -> str:
        self._reader.join(timeout=5.0)
        try:
            assert self.proc.stderr is not None
            return self.proc.stderr.read() or ""
        except (OSError, ValueError):
            return ""

    def terminate(self) -> None:
        for op in (self.proc.terminate, self.proc.kill):
            try:
                op()
                self.proc.wait(timeout=5.0)
                return
            except (OSError, subprocess.TimeoutExpired):
                continue

    def close(self) -> None:
        if self.proc.poll() is None:
            self.terminate()


class _UnauthorizedHandler(BaseHTTPRequestHandler):
    """Answers every method with HTTP 401 and a bearer challenge, no body."""

    def _reject(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="hyperv-mcp"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        self._reject()

    do_GET = do_PUT = do_DELETE = do_PATCH = _reject

    def do_HEAD(self) -> None:
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args) -> None:  # noqa: A002 - stdlib signature
        return


class _UnauthorizedStub:
    """A controller stand-in on an ephemeral loopback port that rejects
    every request with 401, exercising the proxy's rejection path."""

    def __init__(self) -> None:
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _UnauthorizedHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def start(self) -> "_UnauthorizedStub":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# real MCP client session over a spawned proxy child (AC4 / AC6 / AC7 / AC8)
# ---------------------------------------------------------------------------


def _proxy_tool_payload(
    args: list[str],
    env_updates: dict[str, str | None],
    tool: str = "hyperv_relay_status",
    arguments: dict | None = None,
    timeout_s: float = SESSION_DEADLINE_S,
) -> object | None:
    """Drive one real ClientSession over stdio against a spawned proxy child
    and return the tool call's first JSON text payload.

    None means the child could not complete the initialize/tool round trip
    (argparse refusal, missing transport, protocol failure) — the caller's
    success assertion is the acceptance discriminator.
    """
    env = _session_env(env_updates)

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


# ---------------------------------------------------------------------------
# real in-process streamable-HTTP controller (the http_entry.main wiring)
# ---------------------------------------------------------------------------


class _Controller:
    """A real controller served by a uvicorn background thread."""

    def __init__(self, port: int, config_path: Path, audit_path: Path) -> None:
        self.port = port
        self.config_path = config_path
        self.audit_path = audit_path
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def stop(self) -> None:
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=15.0)


@pytest.fixture()
def controller(tmp_path, monkeypatch):
    """Factory for real in-process controllers, wired exactly the way
    hyperv_mcp.http_entry.main serves one: configure_http_auth(verifier)
    BEFORE bootstrap(), bootstrap(), get_mcp(), then uvicorn serves
    mcp.streamable_http_app() on 127.0.0.1:<ephemeral port> in a background
    thread.

    Teardown stops uvicorn and reloads hyperv_mcp.server so later tests see
    an un-bootstrapped module (the test_b01_agent_identity fresh_server
    idiom; bootstrap() is idempotent per process and must not leak this
    controller's config into any other test).
    """

    def start(
        cfg_doc: dict,
        verifier_factory,
        env_updates: dict[str, str | None],
    ) -> _Controller:
        index = len(started)
        port = _free_port()
        audit_path = tmp_path / f"controller-{index}-audit.jsonl"
        doc = json.loads(json.dumps(cfg_doc))
        http_doc = dict(doc.get("http") or {})
        http_doc["port"] = port
        doc["http"] = http_doc
        doc["audit_log_path"] = str(audit_path)
        config_path = tmp_path / f"controller-{index}-cfg.json"
        config_path.write_text(json.dumps(doc), encoding="utf-8")
        for key, value in env_updates.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        monkeypatch.setenv("HYPERV_MCP_CONFIG", str(config_path))

        importlib.reload(server_module)
        server_module.configure_http_auth(verifier_factory())
        server_module.bootstrap()
        mcp = server_module.get_mcp()

        handle = _Controller(port, config_path, audit_path)
        handle.server = uvicorn.Server(
            uvicorn.Config(
                mcp.streamable_http_app(),
                host="127.0.0.1",
                port=port,
                log_level="warning",
            )
        )
        handle.thread = threading.Thread(
            target=handle.server.run, daemon=True, name=f"b03-controller-{index}"
        )
        handle.thread.start()
        assert _wait_listening(port), (
            f"the in-process controller never listened on 127.0.0.1:{port}"
        )
        started.append(handle)
        return handle

    started: list[_Controller] = []
    yield start
    for handle in reversed(started):
        handle.stop()
    importlib.reload(server_module)


# ---------------------------------------------------------------------------
# psutil reaping (AC8): the auto-started controller must outlive the proxy,
# so the test reaps it by matching its cmdline against the configured port.
# ---------------------------------------------------------------------------


def _terminate_where(predicate) -> int:
    """Terminate processes whose joined cmdline satisfies predicate().

    psutil is a host-side acceptance dependency: when absent the sweep is
    reported (stderr) instead of masking the test's own assertion.
    """
    try:
        import psutil
    except ImportError:
        print(
            "WARNING: psutil unavailable; auto-started controller children "
            "were not reaped by the acceptance sweep",
            file=sys.stderr,
        )
        return 0
    victims = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
            if cmdline and predicate(cmdline):
                proc.terminate()
                victims.append(proc)
        except psutil.NoSuchProcess:
            continue
        except psutil.Error:
            continue
    if victims:
        _gone, alive = psutil.wait_procs(victims, timeout=5.0)
        for proc in alive:
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
    return len(victims)


def _terminate_controllers_on_port(port: int) -> int:
    """Reap controller children started for THIS test: the port number in the
    cmdline is the discriminator, so unrelated hyperv-mcp-http processes on
    other ports stay untouched."""
    port_str = str(port)
    return _terminate_where(
        lambda cmdline: port_str in cmdline
        and ("hyperv_mcp.http_entry" in cmdline or "hyperv-mcp-http" in cmdline)
    )


# ---------------------------------------------------------------------------
# PowerShell task-script matching (AC5)
# ---------------------------------------------------------------------------


def _ps_assignment(script: str, key: str, value: str) -> bool:
    """A PowerShell setting in either spelling: -Key Value / -Key 'Value'
    (parameter form) or Key = 'Value' (property/hashtable form)."""
    lowered = script.lower()
    return bool(
        re.search(rf"-{re.escape(key)}\s+['\"]?{re.escape(value)}", lowered)
        or re.search(rf"{re.escape(key)}\s*=\s*['\"]?{re.escape(value)}", lowered)
    )


def _ps_execution_time_limit_zero(script: str) -> bool:
    """ExecutionTimeLimit set to zero: the literal 0 form or either
    New-TimeSpan spelling (with or without -Seconds)."""
    return bool(
        re.search(
            r"executiontimelimit\s+(?:0|\(?new-timespan(?:\s+0|\s+-seconds\s+0)\)?)",
            script.lower(),
        )
    )


# ---------------------------------------------------------------------------
# AC1: unreachable controller
# ---------------------------------------------------------------------------


def test_proxy_unreachable_controller_answers_initialize_with_error():
    """--proxy to a dead controller port must answer the outstanding
    initialize request id with a JSON-RPC error (code -32000) within 10 s —
    not hang, not exit without a reply."""
    probe = _ProxyProbe(
        ["--proxy", f"http://127.0.0.1:{_free_port()}/mcp"], _probe_env()
    )
    try:
        probe.request_initialize()
        reply = probe.await_reply(REQUEST_DEADLINE_S)
        assert reply is not None, (
            "no JSON-RPC reply for initialize within 10 s against an "
            "unreachable controller"
        )
        assert reply.get("id") == 1, (
            f"the reply must answer request id 1; got id {reply.get('id')!r}"
        )
        assert "error" in reply, (
            "an unreachable controller must surface as a JSON-RPC error, not a result"
        )
        error = reply.get("error") or {}
        assert error.get("code") == -32000, (
            f"the proxy error contract is code -32000; got {error.get('code')!r}"
        )
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# AC2: rejected token
# ---------------------------------------------------------------------------


def test_proxy_rejected_token_answers_initialize_with_error():
    """A controller 401 must yield an error reply for initialize within 10 s;
    stderr names the token environment variable and the token value appears
    nowhere in the child's stdout or stderr."""
    stub = _UnauthorizedStub().start()
    probe = _ProxyProbe(
        ["--proxy", f"{stub.url}/mcp"], _probe_env(HYPERV_MCP_HTTP_TOKEN=AC2_TOKEN)
    )
    try:
        probe.request_initialize()
        reply = probe.await_reply(REQUEST_DEADLINE_S)
        assert reply is not None, (
            "no error reply for initialize within 10 s after a 401 rejection"
        )
        assert "error" in reply, (
            "the 401 rejection must surface as a JSON-RPC error, not a result"
        )
        probe.wait_exit()
        stderr = probe.stderr_text()
        stdout_text = "".join(probe.lines)
        assert "HYPERV_MCP_HTTP_TOKEN" in stderr, (
            "the 401 refusal must name the token environment variable on stderr"
        )
        assert AC2_TOKEN not in stdout_text + stderr, (
            "the token value leaked into the proxy child's output"
        )
    finally:
        probe.close()
        stub.stop()


# ---------------------------------------------------------------------------
# AC3: cleartext non-loopback refusal before any network I/O
# ---------------------------------------------------------------------------


def test_proxy_refuses_cleartext_non_loopback_url(monkeypatch, capsys):
    """--proxy http://<non-loopback host> must be refused with rc 2 and a
    stderr message mentioning loopback BEFORE any network I/O (no HTTP
    client may even be constructed), never leaking the token value."""
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", AC3_TOKEN)
    monkeypatch.delenv("HYPERV_MCP_CONFIG", raising=False)

    def _no_async_client(*args, **kwargs):
        raise AssertionError(
            "cleartext non-loopback refusal must happen before any HTTP "
            "client construction"
        )

    # mcp 2.x speaks httpx2 (the SDK's own HTTP stack); the tripwire guards
    # the client class the proxy actually constructs.
    monkeypatch.setattr(httpx2.AsyncClient, "__init__", _no_async_client)
    try:
        rc = server_module.main(["--proxy", "http://203.0.113.5:8787/mcp"])
    except SystemExit as exc:  # argparse refusal spelling
        rc = int(exc.code or 0)
    captured = capsys.readouterr()
    assert rc == 2, (
        f"--proxy with a cleartext non-loopback URL must exit 2; got rc={rc}"
    )
    assert "loopback" in captured.err.lower(), (
        "the refusal must explain the loopback requirement on stderr"
    )
    assert AC3_TOKEN not in captured.out + captured.err, (
        "the cleartext refusal leaked the token value"
    )


# ---------------------------------------------------------------------------
# AC4: two agents, one controller, audit attribution
# ---------------------------------------------------------------------------


def test_two_proxies_share_one_controller_with_distinct_agents(controller):
    """Two proxy children presenting different per-agent tokens must both be
    served by ONE controller, and the controller's audit rows for the two
    hyperv_relay_status calls must name exactly {'agent-a', 'agent-b'}."""
    agents = {"agent-a": "PROBE_TOKEN_A", "agent-b": "PROBE_TOKEN_B"}

    def _verifier():
        rc, pairs = http_entry._resolve_agent_tokens(agents, "")
        assert rc == 0, "agent token resolution must succeed with both variables set"
        return http_entry._MultiTokenVerifier(pairs)

    handle = controller(
        {"http": {"agents": agents}},
        _verifier,
        {
            "PROBE_TOKEN_A": TOKEN_A,
            "PROBE_TOKEN_B": TOKEN_B,
            "HYPERV_MCP_HTTP_TOKEN": None,
        },
    )
    # Each child presents exactly one agent token (the other variable is
    # removed), so a conforming proxy can only identify as its own agent.
    envelope_a = _proxy_tool_payload(
        ["--proxy", handle.url],
        {"PROBE_TOKEN_A": TOKEN_A, "PROBE_TOKEN_B": None},
    )
    envelope_b = _proxy_tool_payload(
        ["--proxy", handle.url],
        {"PROBE_TOKEN_A": None, "PROBE_TOKEN_B": TOKEN_B},
    )
    assert isinstance(envelope_a, dict) and envelope_a.get("ok") is True, (
        "agent-a's proxy child could not complete hyperv_relay_status "
        "through the shared controller"
    )
    assert isinstance(envelope_b, dict) and envelope_b.get("ok") is True, (
        "agent-b's proxy child could not complete hyperv_relay_status "
        "through the shared controller"
    )
    rows = [
        r for r in _audit_rows(handle.audit_path) if r.get("tool") == "hyperv_relay_status"
    ]
    agent_ids = {r.get("agent_id") for r in rows}
    assert len(rows) == 2 and agent_ids == {"agent-a", "agent-b"}, (
        f"the shared controller must audit exactly one row per agent; got "
        f"{len(rows)} rows with agent ids {sorted(str(a) for a in agent_ids)}"
    )


# ---------------------------------------------------------------------------
# AC5: logon-task launcher flags
# ---------------------------------------------------------------------------


def test_install_logon_task_registers_via_powershell(monkeypatch, capsys):
    """--install-logon-task must register the hardened per-user
    hyperv-mcp-http logon task through pswindows.run_ps — logon trigger,
    RunLevel Limited, no execution time limit, IgnoreNew on duplicate
    instances, restart on failure, interactive principal, idempotent
    -Force registration — with no token material in the script;
    --uninstall-logon-task unregisters the task."""
    sink: list[str] = []

    def _recorder(script, **kwargs):
        sink.append(script)
        return pswindows.PSResult(stdout="SUCCESS", returncode=0)

    # The launcher reaches PowerShell through pswindows.run_ps; patch the
    # name in every module that can hold it so either import spelling
    # (from .pswindows import run_ps / pswindows.run_ps) is intercepted.
    monkeypatch.setattr(pswindows, "run_ps", _recorder)
    monkeypatch.setattr(http_entry, "run_ps", _recorder, raising=False)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", AC5_TOKEN)
    monkeypatch.delenv("HYPERV_MCP_CONFIG", raising=False)

    rc = _main_rc(http_entry, ["--install-logon-task"])
    capsys.readouterr()
    assert rc == 0, (
        f"--install-logon-task must succeed through the PowerShell recorder; rc={rc}"
    )
    assert sink, "no PowerShell script was recorded for --install-logon-task"
    install_text = "\n".join(sink)
    lowered = install_text.lower()
    assert "new-scheduledtaskaction" in lowered, (
        "the task action must be defined with New-ScheduledTaskAction"
    )
    assert "hyperv-mcp-http" in lowered, (
        "the scheduled task must be named hyperv-mcp-http"
    )
    assert "new-scheduledtasktrigger" in lowered and "atlogon" in lowered, (
        "the trigger must be New-ScheduledTaskTrigger -AtLogOn"
    )
    assert _ps_assignment(install_text, "runlevel", "limited"), (
        "the task principal must run at RunLevel Limited"
    )
    assert _ps_execution_time_limit_zero(install_text), (
        "the task must set ExecutionTimeLimit to zero (no time limit)"
    )
    assert _ps_assignment(install_text, "multipleinstances", "ignorenew"), (
        "concurrent task starts must be IgnoreNew"
    )
    assert "restartcount" in lowered or "restartinterval" in lowered, (
        "the task must restart on failure (RestartCount/RestartInterval)"
    )
    assert _ps_assignment(install_text, "logontype", "interactive"), (
        "the task principal must use LogonType Interactive"
    )
    assert "register-scheduledtask" in lowered and "-force" in lowered, (
        "registration must use Register-ScheduledTask -Force (idempotent replace)"
    )
    assert AC5_TOKEN not in install_text, (
        "the registration script leaked the token value"
    )

    sink.clear()
    rc = _main_rc(http_entry, ["--uninstall-logon-task"])
    capsys.readouterr()
    assert rc == 0, f"--uninstall-logon-task must succeed; rc={rc}"
    assert sink, "no PowerShell script was recorded for --uninstall-logon-task"
    assert "unregister-scheduledtask" in "\n".join(sink).lower(), (
        "uninstall must Unregister-ScheduledTask"
    )


# ---------------------------------------------------------------------------
# AC6: default mode proxies to the configured controller
# ---------------------------------------------------------------------------


def test_default_mode_proxies_to_configured_controller(controller):
    """A flagless hyperv-mcp child must serve hyperv_relay_status through the
    controller configured at http.host/http.port — audited EXACTLY once by
    the controller under the authenticated shared-token principal, never
    served in-process."""
    handle = controller(
        {"http": {}},
        lambda: http_entry._StaticTokenVerifier(AC6_TOKEN),
        {"HYPERV_MCP_HTTP_TOKEN": AC6_TOKEN},
    )
    envelope = _proxy_tool_payload(
        [],
        {
            "HYPERV_MCP_CONFIG": str(handle.config_path),
            "HYPERV_MCP_HTTP_TOKEN": AC6_TOKEN,
        },
    )
    assert isinstance(envelope, dict) and envelope.get("ok") is True, (
        "flagless default mode could not serve hyperv_relay_status through "
        "the configured controller"
    )
    rows = [
        r for r in _audit_rows(handle.audit_path) if r.get("tool") == "hyperv_relay_status"
    ]
    assert len(rows) == 1, (
        f"exactly one controller audit row must record the call; got {len(rows)}"
    )
    assert rows[0].get("agent_id") == "local-cli", (
        "the row must be the controller's authenticated shared-token "
        f"principal; got agent_id={rows[0].get('agent_id')!r}"
    )


# ---------------------------------------------------------------------------
# AC7: --standalone keeps the in-process stdio server
# ---------------------------------------------------------------------------


def test_standalone_flag_serves_in_process(controller, tmp_path):
    """A --standalone child must serve hyperv_relay_status in-process: the
    call succeeds while the shared controller's audit log gains ZERO rows
    for it (the child audits to its own isolated sink)."""
    handle = controller(
        {"http": {}},
        lambda: http_entry._StaticTokenVerifier(AC7_TOKEN),
        {"HYPERV_MCP_HTTP_TOKEN": AC7_TOKEN},
    )
    child_cfg = tmp_path / "standalone-cfg.json"
    child_cfg.write_text(
        json.dumps(
            {
                "http": {"port": handle.port},
                "audit_log_path": str(tmp_path / "standalone-audit.jsonl"),
            }
        ),
        encoding="utf-8",
    )
    before = len(
        [r for r in _audit_rows(handle.audit_path) if r.get("tool") == "hyperv_relay_status"]
    )
    envelope = _proxy_tool_payload(
        ["--standalone"],
        {
            "HYPERV_MCP_CONFIG": str(child_cfg),
            "HYPERV_MCP_HTTP_TOKEN": AC7_TOKEN,
        },
    )
    assert isinstance(envelope, dict) and envelope.get("ok") is True, (
        "--standalone could not serve hyperv_relay_status in-process"
    )
    after = len(
        [r for r in _audit_rows(handle.audit_path) if r.get("tool") == "hyperv_relay_status"]
    )
    assert after == before, (
        f"--standalone must not route calls through the shared controller; "
        f"controller audit rows went from {before} to {after}"
    )


# ---------------------------------------------------------------------------
# AC8: default mode auto-starts a detached controller
# ---------------------------------------------------------------------------


def test_default_mode_autostarts_controller_when_absent(tmp_path):
    """With nothing listening on the configured http.port, a flagless
    hyperv-mcp child must auto-start a DETACHED hyperv-mcp-http controller
    (inheriting the child's config and token environment), complete the
    hyperv_relay_status call, and leave the configured port listening."""
    port = _free_port()
    config_path = tmp_path / "autostart-cfg.json"
    config_path.write_text(
        json.dumps(
            {
                "http": {"port": port},
                "audit_log_path": str(tmp_path / "autostart-audit.jsonl"),
            }
        ),
        encoding="utf-8",
    )
    envelope = _proxy_tool_payload(
        [],
        {
            "HYPERV_MCP_CONFIG": str(config_path),
            "HYPERV_MCP_HTTP_TOKEN": AC8_TOKEN,
        },
    )
    assert isinstance(envelope, dict) and envelope.get("ok") is True, (
        "flagless default mode could not auto-start the controller and "
        "serve hyperv_relay_status"
    )
    try:
        assert _port_open(port), (
            f"the configured port {port} must still be listening after the "
            "auto-started controller serves the call (the controller must "
            "outlive the proxy)"
        )
    finally:
        # Reap the detached controller: the port in its cmdline is the
        # discriminator that spares unrelated controllers.
        _terminate_controllers_on_port(port)
