"""B01 agent-identity checks: per-agent http tokens (http.agents) map each
agent's token to its own client_id, and audit records name the calling agent
(agent_id), the request (request_id) and the handle a follow-up tool acted
on (job_id for guest jobs, relay_id plus vm_name for relays)."""

import asyncio
import importlib
import json
import re
import uuid

import pytest

import hyperv_mcp.http_entry as http_entry
import hyperv_mcp.server as server_module
from hyperv_mcp import guestjobs, pswindows, relay
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

# Identity resolution (issue #8): vmident.resolve runs a by-name leg before
# job_start / relay_start. Distinct VM names must resolve to DISTINCT GUIDs
# (test_guestjobs / test_relay FakePS pattern, per-name guid).
_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    """Stable per-name GUID: distinct names are distinct VMs."""
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _start_ok():
    return _ok({"pid": 4242, "job_dir": "C:\\Users\\x\\AppData\\Local\\Temp\\hyperv-mcp-job-abc"})


def _texts(result):
    """Text blocks from any in-process mcp.call_tool return shape."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    return [c.text for c in content if getattr(c, "type", "") == "text"]


def _envelope(mcp, tool: str, args: dict) -> dict:
    """Call a registered tool in-process and parse its JSON text envelope."""
    result = asyncio.run(mcp.call_tool(tool, args))
    texts = _texts(result)
    assert texts, f"expected a text envelope for {tool}"
    return json.loads(texts[0])


def _rows(log) -> list:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _newest(rows, tool: str) -> dict:
    matching = [r for r in rows if r.get("tool") == tool]
    assert matching, f"no audit row was written for {tool}"
    return matching[-1]


@pytest.fixture(autouse=True)
def _clean_registries():
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()
    guestjobs.clear_registry_for_tests()


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
    """http_entry harness that RECORDS the verifier handed to
    configure_http_auth instead of swallowing it."""
    fake = _FakeMcp()
    box = {}
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
    """Bootstrapped server whose audit sink is a per-test JSONL file; relay
    category enabled, 'test-*' VMs allowed."""
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


def _guest_env(monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "unit-test-pass")


def _agents_config(tmp_path) -> str:
    doc = {"http": {"agents": {"agent-a": "B01_TOKEN_A", "agent-b": "B01_TOKEN_B"}}}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_per_agent_tokens_map_to_distinct_client_ids(
    tmp_path, monkeypatch, verifier_capture, capsys
):
    """http.agents names a per-agent token variable; each token must verify
    to its OWN client_id and an unknown token to None."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-aaa-111")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb-222")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    rc = http_entry.main([])
    captured = capsys.readouterr()
    assert rc == 0, (
        f"http.agents per-agent tokens refused at startup: rc={rc}, "
        f"stderr={captured.err.strip()!r}"
    )
    verifier = verifier_capture.get("verifier")
    assert verifier is not None, "no token verifier was installed for the agents map"
    results = [
        asyncio.run(verifier.verify_token(tok))
        for tok in ("tok-aaa-111", "tok-bbb-222", "tok-unknown-999")
    ]
    client_ids = [r.client_id if r else None for r in results]
    assert client_ids == ["agent-a", "agent-b", None], (
        f"per-agent tokens must map to their own client_id, got {client_ids}"
    )


def test_duplicate_agent_token_refused_naming_agents_not_token(
    tmp_path, monkeypatch, verifier_capture, capsys
):
    """Two agents sharing one token value must refuse startup, name BOTH
    agents, never print the token, and install no verifier."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-same-secret")
    monkeypatch.setenv("B01_TOKEN_B", "tok-same-secret")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    rc = http_entry.main([])
    captured = capsys.readouterr()
    assert rc == 2, f"a duplicate agent token must refuse startup, got rc={rc}"
    assert "agent-a" in captured.err, (
        f"the refusal must name the colliding agent 'agent-a'; "
        f"stderr={captured.err.strip()!r}"
    )
    assert "agent-b" in captured.err, (
        f"the refusal must name the colliding agent 'agent-b'; "
        f"stderr={captured.err.strip()!r}"
    )
    assert "tok-same-secret" not in captured.out + captured.err, (
        "the refusal leaked the shared token value"
    )
    assert "verifier" not in verifier_capture, (
        "a token verifier must not be installed when two agents share one token"
    )


def test_audit_record_names_calling_agent(audited_server):
    """An authenticated call's audit row must carry the caller's client_id
    as agent_id (auth_context_var set exactly as AuthContextMiddleware does)."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    user = AuthenticatedUser(AccessToken(token="t", client_id="agent-a", scopes=[]))
    ctx_token = auth_context_var.set(user)
    try:
        asyncio.run(mcp.call_tool("hyperv_relay_status", {"relay_id": ""}))
    finally:
        auth_context_var.reset(ctx_token)
    row = _newest(_rows(log), "hyperv_relay_status")
    assert row.get("agent_id") == "agent-a", (
        f"the audit row must name the authenticated calling agent via "
        f"agent_id; got {row.get('agent_id')!r}"
    )


def test_audit_request_ids_unique_across_calls(audited_server):
    """Every audited tool call must carry its own unique request_id."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    asyncio.run(mcp.call_tool("hyperv_relay_status", {"relay_id": ""}))
    asyncio.run(mcp.call_tool("hyperv_relay_status", {"relay_id": ""}))
    rows = [r for r in _rows(log) if r.get("tool") == "hyperv_relay_status"]
    assert len(rows) >= 2, f"expected two audited calls, got {len(rows)}"
    ids = {r.get("request_id") for r in rows[-2:]}
    assert len(ids - {None, ""}) == 2, (
        f"each audited call must carry a unique request_id; "
        f"last two rows carry {sorted(repr(i) for i in ids)}"
    )


def test_job_status_audit_names_vm_and_job(audited_server, monkeypatch):
    """hyperv_guest_job_status audits under the job's vm_name AND job_id."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    fake = FakePS([
        _start_ok(),
        _ok({"status": "running", "process_name": "sqlprobe"}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe", "args": ["/c", "echo hi"],
    })
    assert started.get("ok") is True, f"job_start failed: {started}"
    job_id = started["job_id"]
    status = _envelope(mcp, "hyperv_guest_job_status", {"job_id": job_id})
    assert status.get("ok") is True, f"job_status failed: {status}"
    row = _newest(_rows(log), "hyperv_guest_job_status")
    assert row.get("vm_name") == "test-vm", (
        f"the audit row must name the job's VM; got {row.get('vm_name')!r}"
    )
    assert row.get("job_id") == job_id, (
        f"the audit row must carry the job_id the tool acted on; "
        f"got {row.get('job_id')!r}, expected {job_id!r}"
    )


def test_relay_stop_audit_names_vm_and_relay(audited_server, monkeypatch):
    """hyperv_relay_stop audits under the relay's vm_name AND relay_id."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    mcp = mod.get_mcp()
    relay_id = None
    try:
        started = _envelope(mcp, "hyperv_relay_start", {
            "vm_name": "test-vm", "guest_port": 9222, "host_port": 0,
        })
        assert started.get("ok") is True, f"relay_start failed: {started}"
        relay_id = started["relay_id"]
        stopped = _envelope(mcp, "hyperv_relay_stop", {"relay_id": relay_id})
        assert stopped.get("ok") is True, f"relay_stop failed: {stopped}"
        row = _newest(_rows(log), "hyperv_relay_stop")
        assert row.get("vm_name") == "test-vm", (
            f"the audit row must name the relay's VM; got {row.get('vm_name')!r}"
        )
        assert row.get("relay_id") == relay_id, (
            f"the audit row must carry the relay_id the tool stopped; "
            f"got {row.get('relay_id')!r}, expected {relay_id!r}"
        )
    finally:
        entry = relay._relays.get(relay_id) if relay_id else None
        if entry is not None and not entry.get("stopped"):
            relay.relay_stop(mod.CFG, relay_id)


def test_job_start_audit_records_returned_job_id(audited_server, monkeypatch):
    """hyperv_guest_job_start's audit row must record the job_id it returned."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([_start_ok()]))
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe", "args": ["/c", "echo hi"],
    })
    assert started.get("ok") is True, f"job_start failed: {started}"
    job_id = started["job_id"]
    row = _newest(_rows(log), "hyperv_guest_job_start")
    assert row.get("job_id") == job_id, (
        f"the audit row must record the returned job_id; "
        f"got {row.get('job_id')!r}, expected {job_id!r}"
    )


def test_relay_start_audit_records_returned_relay_id(audited_server, monkeypatch):
    """hyperv_relay_start's audit row must record the relay_id it returned."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    mcp = mod.get_mcp()
    relay_id = None
    try:
        started = _envelope(mcp, "hyperv_relay_start", {
            "vm_name": "test-vm", "guest_port": 9222, "host_port": 0,
        })
        assert started.get("ok") is True, f"relay_start failed: {started}"
        relay_id = started["relay_id"]
        row = _newest(_rows(log), "hyperv_relay_start")
        assert row.get("relay_id") == relay_id, (
            f"the audit row must record the returned relay_id; "
            f"got {row.get('relay_id')!r}, expected {relay_id!r}"
        )
    finally:
        entry = relay._relays.get(relay_id) if relay_id else None
        if entry is not None and not entry.get("stopped"):
            relay.relay_stop(mod.CFG, relay_id)
