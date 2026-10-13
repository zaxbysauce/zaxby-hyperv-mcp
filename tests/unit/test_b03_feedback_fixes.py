"""Feedback-round tests for the stdio proxy's auto-start preconditions and
the logon-task launcher's script generation (PR 51 swarm-pr-review findings
PRR-001/PRR-006/PRR-027; NOT part of the checkpoint-anchored C1-C8 file).

- agents-mode auto-start must fail fast naming the missing agent token
  variables (never burn the 15 s port timeout on a controller that cannot
  start), while a single-agent environment passes the guard;
- --install-logon-task's generated Register-ScheduledTask script must
  PARSE in real PowerShell with --host/--port embedded inside the
  -Argument literal, and a single-flag usage must be refused rc 2;
- the -Execute path is single-quote-escaped (a path containing an
  apostrophe must not break the task definition).
"""

import base64
import subprocess

import pytest

import hyperv_mcp.http_entry as http_entry
from hyperv_mcp import stdio_proxy
from hyperv_mcp.config import Config


def _agents_cfg(agents: dict[str, str]) -> Config:
    cfg = Config()
    object.__setattr__(cfg.http, "agents", agents)
    return cfg


class _NoSpawn:
    """ensure_controller must refuse BEFORE spawning anything."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, argv, **kwargs):  # pragma: no cover - must never run
        self.calls.append(str(argv))
        raise AssertionError(f"ensure_controller spawned despite refusal: {argv}")


def test_agents_autostart_fails_fast_naming_missing_vars(monkeypatch):
    """A partial agent-token environment (1 of 2 vars) must be refused with
    the MISSING variable NAMES before any spawn or port wait."""
    monkeypatch.setenv("FEEDBACK_AGENT_A_TOKEN", "present-value")
    monkeypatch.delenv("FEEDBACK_AGENT_B_TOKEN", raising=False)
    cfg = _agents_cfg(
        {"agent-a": "FEEDBACK_AGENT_A_TOKEN", "agent-b": "FEEDBACK_AGENT_B_TOKEN"}
    )
    sentinel = _NoSpawn()
    monkeypatch.setattr(stdio_proxy.subprocess, "Popen", sentinel)
    monkeypatch.setattr(stdio_proxy.subprocess, "run", sentinel)
    with pytest.raises(stdio_proxy.ProxyRefused) as excinfo:
        stdio_proxy.ensure_controller(cfg)
    message = str(excinfo.value)
    assert "FEEDBACK_AGENT_B_TOKEN" in message, message
    assert "FEEDBACK_AGENT_A_TOKEN" not in message or "missing" in message.lower()
    assert "present-value" not in message, "token value leaked into the refusal"
    assert sentinel.calls == [], "refusal must precede any spawn"


def test_agents_autostart_zero_vars_names_all(monkeypatch):
    """Zero agent vars set (legacy fallback shape) also refuses fast, naming
    every missing variable."""
    for name in ("FEEDBACK_ZERO_A", "FEEDBACK_ZERO_B"):
        monkeypatch.delenv(name, raising=False)
    cfg = _agents_cfg({"agent-a": "FEEDBACK_ZERO_A", "agent-b": "FEEDBACK_ZERO_B"})
    sentinel = _NoSpawn()
    monkeypatch.setattr(stdio_proxy.subprocess, "Popen", sentinel)
    monkeypatch.setattr(stdio_proxy.subprocess, "run", sentinel)
    with pytest.raises(stdio_proxy.ProxyRefused) as excinfo:
        stdio_proxy.ensure_controller(cfg)
    message = str(excinfo.value)
    assert "FEEDBACK_ZERO_A" in message and "FEEDBACK_ZERO_B" in message, message
    assert sentinel.calls == []


def test_single_agent_autostart_passes_the_guard(monkeypatch):
    """With the ONE configured agent's var set, the agents-mode guard must
    not refuse (the spawned controller validates all configured agents and
    exactly one is configured here). Assert via a stub spawn that the guard
    lets the spawn happen — the port never listens, so the refusal that
    follows must be the TIMEOUT message, not a missing-var message."""
    monkeypatch.setenv("FEEDBACK_SOLO_TOKEN", "solo-value")
    cfg = _agents_cfg({"solo": "FEEDBACK_SOLO_TOKEN"})
    monkeypatch.setattr(stdio_proxy, "AUTOSTART_WAIT_S", 0.3)
    monkeypatch.setattr(stdio_proxy, "port_listening", lambda *a, **k: False)
    started: list[object] = []

    class _Stub:
        """Minimal spawn stub: stdout carries the success marker the
        post-spawn gate inspects; stderr empty."""

        stdout = "breakaway\n"
        stderr = ""
        returncode = 0

    def fake_spawn(argv, **kwargs):  # noqa: ARG001 - stub signature
        started.append(argv)
        return _Stub()

    monkeypatch.setattr(stdio_proxy.subprocess, "Popen", fake_spawn)
    monkeypatch.setattr(stdio_proxy.subprocess, "run", fake_spawn)
    with pytest.raises(stdio_proxy.ProxyRefused) as excinfo:
        stdio_proxy.ensure_controller(cfg)
    message = str(excinfo.value)
    assert "did not accept connections" in message, message
    assert "FEEDBACK_SOLO_TOKEN" not in message
    assert started, "the single-agent shape must reach the spawn path"


def test_shared_token_autostart_fails_fast_without_spawning(monkeypatch):
    """No http.agents and a missing shared token_env variable: the spawned
    controller inherits this environment and dies instantly without the
    token (observed as an 87-spawn failure storm in one day), so
    ensure_controller must refuse naming the variable BEFORE any spawn or
    port wait."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    cfg = Config()
    sentinel = _NoSpawn()
    monkeypatch.setattr(stdio_proxy.subprocess, "Popen", sentinel)
    monkeypatch.setattr(stdio_proxy.subprocess, "run", sentinel)
    with pytest.raises(stdio_proxy.ProxyRefused) as excinfo:
        stdio_proxy.ensure_controller(cfg)
    message = str(excinfo.value)
    assert "HYPERV_MCP_HTTP_TOKEN" in message, message
    assert "die immediately" in message, message
    assert sentinel.calls == [], "the refusal must precede any spawn"


def test_shared_token_autostart_passes_the_guard_when_set(monkeypatch):
    """With the shared token set, the missing-token guard must not refuse:
    the spawn path is reached (stubbed) and the eventual refusal is the
    port timeout, not a token message."""
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "shared-value")
    cfg = Config()
    monkeypatch.setattr(stdio_proxy, "AUTOSTART_WAIT_S", 0.3)
    monkeypatch.setattr(stdio_proxy, "port_listening", lambda *a, **k: False)
    started: list[object] = []

    class _Stub:
        """Minimal spawn stub: stdout carries the success marker the
        post-spawn gate inspects; stderr empty."""

        stdout = "breakaway\n"
        stderr = ""
        returncode = 0

    def fake_spawn(argv, **kwargs):  # noqa: ARG001 - stub signature
        started.append(argv)
        return _Stub()

    monkeypatch.setattr(stdio_proxy.subprocess, "Popen", fake_spawn)
    monkeypatch.setattr(stdio_proxy.subprocess, "run", fake_spawn)
    with pytest.raises(stdio_proxy.ProxyRefused) as excinfo:
        stdio_proxy.ensure_controller(cfg)
    message = str(excinfo.value)
    assert "did not accept connections" in message, message
    assert "HYPERV_MCP_HTTP_TOKEN" not in message, message
    assert started, "the shared-token shape must reach the spawn path"


# ---------------------------------------------------------------------------
# launcher script generation (PRR-006/PRR-027)
# ---------------------------------------------------------------------------


def _parses_in_powershell(script: str) -> tuple[bool, str]:
    """Real-parser oracle (reviewer round-2 finding: the refs must be
    PRE-INITIALIZED — [ref]$null on an unassigned variable silently leaves
    $errs unbound and the oracle can never fail). A deliberate self-test
    with a parse-broken fixture asserts this oracle itself can fail."""
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    ps = (
        "$errs = $null; $tokens = $null; "
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "[System.Text.Encoding]::Unicode.GetString("
        f"[System.Convert]::FromBase64String('{enc}')), [ref]$tokens, [ref]$errs)"
        " | Out-Null; if ($errs.Count) { 'ERR:' + $errs[0].Message } else { 'PARSE-OK' }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True
    )
    return ("ERR:" not in (result.stdout or "")), (result.stdout or "").strip()[:200]


def test_parse_oracle_can_fail():
    """Self-test of the oracle: a deliberately unparsable fixture must make
    it report ok=False (the round-2 reviewer caught a can-not-fail variant)."""
    ok, detail = _parses_in_powershell("Write-Output 'unterminated")
    assert not ok, f"the parse oracle can never fail: {detail}"


def test_install_script_embeds_host_port_inside_argument(monkeypatch):
    """--host/--port must ride INSIDE the -Argument literal so the generated
    New-ScheduledTaskAction line parses (reviewer finding F1). Parametrized
    over both _controller_command shapes — the console script on PATH (empty
    base arguments) and the -m module fallback — because which one resolves
    depends on how the environment installed the package (CI installs the
    console script; a bare interpreter does not), and the assertions must
    not depend on that."""
    for base_args in ("", "-m hyperv_mcp.http_entry"):
        monkeypatch.setattr(
            http_entry,
            "_controller_command",
            lambda b=base_args: ("C:\\py\\hyperv-mcp-http.exe", b),
        )
        script = http_entry._install_script(host="10.0.0.5", port="9999")
        action = next(
            line for line in script.splitlines() if "New-ScheduledTaskAction" in line
        )
        assert "-Argument '" in action, action
        # the flags are INSIDE the quoted argument value: they appear in the
        # text after -Argument and --port 9999 is followed by the closing
        # quote of the literal, never by the bare line
        after = action.split("-Argument", 1)[1]
        assert "--host 10.0.0.5 --port 9999" in after, action
        assert "--port 9999'" in after, action
        assert "' --host" not in action, action
        ok, detail = _parses_in_powershell(script)
        assert ok, detail


def test_install_script_default_parses():
    ok, detail = _parses_in_powershell(http_entry._install_script())
    assert ok, detail


def test_install_script_escapes_apostrophe_paths(monkeypatch):
    """A resolved controller path containing an apostrophe must be escaped,
    keeping the script parseable (reviewer finding F2)."""
    monkeypatch.setattr(
        http_entry, "_controller_command", lambda: ("C:\\O'Brien\\hyperv-mcp-http.exe", "")
    )
    script = http_entry._install_script()
    action = next(line for line in script.splitlines() if "New-ScheduledTaskAction" in line)
    assert "O''Brien" in action, action
    ok, detail = _parses_in_powershell(script)
    assert ok, detail


def test_install_script_rejects_single_host_or_port_flag():
    """Passing only one of --host/--port is refused instead of silently
    dropping the value (reviewer finding F1)."""
    with pytest.raises(ValueError, match="BOTH --host and --port"):
        http_entry._install_script(host="10.0.0.5")
    with pytest.raises(ValueError, match="BOTH --host and --port"):
        http_entry._install_script(port="9999")
