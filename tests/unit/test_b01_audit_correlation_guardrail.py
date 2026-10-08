"""B01 defect-class guardrail (issue #10): every audit row carries the
correlation keys (agent_id, request_id, and job_id/relay_id where one
applies), attribution values are pinned under authenticated calls, the
pre-tool rejection writer survives malformed arguments, per-agent token
variables never reach a spawned child environment, and combined
agents+legacy token mode verifies each principal to its own client_id.

This file is NOT part of the frozen Phase-2.5 checkpoint; it is the
Phase-4.2 guardrail plus the plan's Part 7 edge-case tests."""

import asyncio
import importlib
import json

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.http_entry as http_entry
import hyperv_mcp.pswindows as pswindows
import hyperv_mcp.server as server_module
from hyperv_mcp.config import Config, ConfigError

AUDIT_KEYS = {
    "ts", "tool", "vm_name", "category", "ok", "duration_ms", "exit_code",
    "error_class", "agent_id", "request_id", "job_id", "relay_id",
}


class _FakeSettings:
    def __init__(self):
        self.host = None
        self.port = None


class _FakeMcp:
    def __init__(self):
        self.settings = _FakeSettings()
        self.run_calls = []

    def run(self, transport="stdio"):
        self.run_calls.append(transport)
        return 0


@pytest.fixture()
def verifier_capture(monkeypatch):
    fake = _FakeMcp()
    box = {"verifier": None}
    monkeypatch.setattr(http_entry, "bootstrap", lambda: http_entry.Config.load())
    monkeypatch.setattr(http_entry, "get_mcp", lambda: fake)

    def _capture(verifier):
        box["verifier"] = verifier

    monkeypatch.setattr(http_entry, "configure_http_auth", _capture)
    return box


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


@pytest.fixture()
def audited_server(tmp_path, fresh_server):
    log = tmp_path / "audit.jsonl"
    doc = {
        "allowed_vm_patterns": ["test-*"],
        "audit_log_path": str(log),
        "destructive": {"relay": True},
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    return mod, log


def _rows(log) -> list:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _as_agent(client_id: str):
    return AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[]))


def _agents_config(tmp_path, extra: dict | None = None) -> str:
    doc = {
        "http": {
            "agents": {"agent-a": "B01_TOKEN_A", "agent-b": "B01_TOKEN_B"},
            **(extra or {}),
        }
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_combined_agents_and_legacy_tokens_both_verify(tmp_path, monkeypatch, verifier_capture):
    """With http.agents configured AND the legacy token_env set, both
    principals verify: agents to their ids, the legacy token to local-cli."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-aaa")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb")
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "tok-legacy")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    assert http_entry.main([]) == 0
    verifier = verifier_capture["verifier"]
    assert verifier is not None
    results = [
        asyncio.run(verifier.verify_token(tok))
        for tok in ("tok-aaa", "tok-bbb", "tok-legacy", "tok-nope")
    ]
    assert [r.client_id if r else None for r in results] == [
        "agent-a", "agent-b", "local-cli", None,
    ]


def test_legacy_agent_token_collision_refuses_naming_both(tmp_path, monkeypatch, verifier_capture, capsys):
    """An agent token equal to the legacy shared token is a startup error
    naming the agent id (and the legacy principal), never the value."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-same")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb")
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "tok-same")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    rc = http_entry.main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert "agent-a" in err and "local-cli" in err
    assert "tok-same" not in err
    assert verifier_capture["verifier"] is None


def test_blank_agent_token_value_treated_as_missing(monkeypatch, capsys):
    """Whitespace-only agent token values follow the legacy truthiness
    semantics: blank counts as unset and refuses startup."""
    rc, pairs = http_entry._resolve_agent_tokens(
        {"agent-a": "B01_TOKEN_BLANK"}, legacy_token="",
    )
    assert rc == 2 and pairs == []
    assert "agent-a" in capsys.readouterr().err


def test_authenticated_rejections_carry_agent_id_and_distinct_request_ids(audited_server):
    """Two malformed-argument calls under one authenticated agent write two
    rejection rows, each attributing agent-a, with DISTINCT non-empty
    request_ids (bites a once-per-process request_id default)."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    token = auth_context_var.set(_as_agent("agent-a"))
    try:
        asyncio.run(mcp.call_tool("hyperv_server_info", {"bogus_arg": 1}))
        asyncio.run(mcp.call_tool("hyperv_server_info", {"other_bad": 2}))
    finally:
        auth_context_var.reset(token)
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_server_info" and r["ok"] is False]
    assert len(rows) == 2, f"expected two rejection rows, got {len(rows)}"
    assert all(r["agent_id"] == "agent-a" for r in rows)
    ids = {r["request_id"] for r in rows}
    assert len(ids - {None, ""}) == 2, f"request_ids not distinct: {ids}"


def test_wrong_typed_job_id_rejection_still_writes_one_row(audited_server):
    """A wrong-typed job_id argument is str()-coerced: exactly one rejection
    row, carrying job_id '123'; an absent relay_id serializes as null. A
    falsy numeric id (0) shares the absent representation — the empty handle
    is not a resource reference, matching the vm_name idiom at the same
    site."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    asyncio.run(mcp.call_tool("hyperv_guest_job_status", {"job_id": 123}))
    asyncio.run(mcp.call_tool("hyperv_guest_job_status", {"job_id": 0}))
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_guest_job_status"]
    assert len(rows) == 2, f"expected exactly two rejection rows, got {len(rows)}"
    assert all(r["ok"] is False for r in rows)
    by_id = {r["job_id"]: r for r in rows}
    assert "123" in by_id and by_id["123"]["relay_id"] is None
    assert None in by_id  # 0 coerces to the absent representation


def test_failed_job_followup_audit_row_carries_supplied_job_id(audited_server):
    """A job follow-up whose tool leg RAISES (unknown job_id) still audits
    the row with the job_id the call supplied — the failure path is the only
    source when no result dict exists to adopt from (impl review P2)."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    asyncio.run(mcp.call_tool("hyperv_guest_job_status", {"job_id": "no-such-job-id-123"}))
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_guest_job_status" and r["ok"] is False]
    assert len(rows) == 1, f"expected one failure row, got {len(rows)}"
    assert rows[0]["error_class"] == "invalid"
    assert rows[0]["job_id"] == "no-such-job-id-123"
    assert rows[0]["vm_name"] == ""  # peek of an unknown id: honest empty


def test_failed_relay_stop_audit_row_carries_supplied_relay_id(audited_server):
    """The relay failure analogue: relay_stop on an unknown relay_id audits
    relay_id with the supplied value and an honest empty vm_name."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    asyncio.run(mcp.call_tool("hyperv_relay_stop", {"relay_id": "relay-404-nope"}))
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_relay_stop" and r["ok"] is False]
    assert len(rows) == 1, f"expected one failure row, got {len(rows)}"
    assert rows[0]["error_class"] == "invalid"
    assert rows[0]["relay_id"] == "relay-404-nope"
    assert rows[0]["vm_name"] == ""


def test_guest_tool_credential_failure_envelope_and_audit(audited_server, monkeypatch):
    """_run_guest_tool's cred_factory path maps a CredentialError to the
    credential envelope AND audits error_class 'credential'."""
    mod, log = audited_server
    monkeypatch.delenv("HYPERV_GUEST_USERNAME", raising=False)
    monkeypatch.delenv("HYPERV_GUEST_PASSWORD", raising=False)
    mcp = mod.get_mcp()
    result = asyncio.run(mcp.call_tool("hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe",
    }))
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    payload = json.loads(content[0].text)
    assert payload.get("ok") is False and payload.get("error_class") == "credential"
    rows = [r for r in _rows(log) if r["tool"] == "hyperv_guest_job_start"]
    assert rows and rows[-1]["error_class"] == "credential"
    assert rows[-1]["ok"] is False


def test_agent_token_env_stripped_from_child_environment(tmp_path, monkeypatch):
    """Every http.agents env var name is stripped from spawned child
    environments, like the other server secrets (issue #10)."""
    from hyperv_mcp.config import HttpPolicy

    monkeypatch.setenv("B01_TOKEN_A", "tok-secret-value")
    monkeypatch.setenv("PATH", "C:\\Windows")
    cfg = Config(http=HttpPolicy(agents={"agent-a": "B01_TOKEN_A"}))
    pswindows.init(cfg, lambda text: text)
    try:
        env = pswindows.child_env()
        assert "B01_TOKEN_A" not in env
        assert env.get("PATH") == "C:\\Windows"
    finally:
        pswindows.init(Config(), lambda text: text)


def test_guardrail_every_audit_row_carries_full_correlation_key_set(audited_server):
    """The class guardrail: across representative audited paths (read tool,
    authenticated calls as two DIFFERENT agents, malformed rejection,
    anonymous call), every written row carries the full key set, agent_id
    matches the caller (null when anonymous), and request_ids are unique."""
    mod, log = audited_server
    mcp = mod.get_mcp()

    asyncio.run(mcp.call_tool("hyperv_server_info", {}))  # anonymous read

    token = auth_context_var.set(_as_agent("agent-a"))
    try:
        asyncio.run(mcp.call_tool("hyperv_relay_status", {"relay_id": ""}))
    finally:
        auth_context_var.reset(token)
    token = auth_context_var.set(_as_agent("agent-b"))
    try:
        asyncio.run(mcp.call_tool("hyperv_relay_status", {"relay_id": ""}))
    finally:
        auth_context_var.reset(token)

    asyncio.run(mcp.call_tool("hyperv_server_info", {"nope": 1}))  # rejection

    rows = _rows(log)
    assert len(rows) == 4, f"expected four audited paths, got {len(rows)}"
    for row in rows:
        assert set(row) == AUDIT_KEYS, f"audit key set drifted: {sorted(set(row) ^ AUDIT_KEYS)}"
        assert isinstance(row["request_id"], str) and row["request_id"]
    by_tool_ok = [r for r in rows if r["tool"] == "hyperv_relay_status" and r["ok"]]
    assert [r["agent_id"] for r in by_tool_ok[-2:]] == ["agent-a", "agent-b"]
    anonymous = [r for r in rows if r["tool"] == "hyperv_server_info" and r["ok"]]
    assert anonymous and all(r["agent_id"] is None for r in anonymous)
    rejection = [r for r in rows if r["ok"] is False]
    assert rejection and rejection[-1]["agent_id"] is None  # written outside any auth context
    request_ids = {r["request_id"] for r in rows}
    assert len(request_ids) == len(rows), "request_id collision across rows"
    # No resource ids on these paths: absent handles stay JSON null, not "".
    assert all(r["job_id"] is None and r["relay_id"] is None for r in rows)


def test_reserved_and_invalid_agent_ids_refused():
    with pytest.raises(ConfigError, match="reserved"):
        Config.from_dict({"http": {"agents": {"local-cli": "SOME_VAR"}}})
    with pytest.raises(ConfigError, match="agent id"):
        Config.from_dict({"http": {"agents": {"bad id!": "SOME_VAR"}}})
    with pytest.raises(ConfigError, match="must not shadow"):
        Config.from_dict({"http": {"agents": {"agent-a": "PATH"}}})
