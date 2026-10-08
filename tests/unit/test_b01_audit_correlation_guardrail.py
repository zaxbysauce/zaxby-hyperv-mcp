"""B01 defect-class guardrail (issue #10): every audit row carries the
correlation keys (agent_id, request_id, and job_id/relay_id where one
applies), attribution values are pinned under authenticated calls, the
pre-tool rejection writer survives malformed arguments, per-agent token
variables never reach a spawned child environment, and combined
agents+legacy token mode verifies each principal to its own client_id.

This file is NOT part of the frozen Phase-2.5 checkpoint; it is the
Phase-4.2 guardrail plus the plan's Part 7 edge-case tests."""

import asyncio
import base64
import importlib
import json

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.http_entry as http_entry
import hyperv_mcp.pswindows as pswindows
import hyperv_mcp.server as server_module
from hyperv_mcp import auditlog, credentials, guestjobs, relay
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


@pytest.fixture(autouse=True)
def _module_state():
    """Registry + module-global hygiene: bootstrap() installs auditlog,
    credentials and pswindows globals that outlive a test; snapshot and
    restore them so later test files never inherit this file's tmp sinks
    (impl review PRR-008c)."""
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    saved = (auditlog._config, pswindows._config, pswindows._redact)
    yield
    auditlog._config, pswindows._config, pswindows._redact = saved
    relay.clear_registry_for_tests()
    guestjobs.clear_registry_for_tests()


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


def _newest(rows, tool: str) -> dict:
    matching = [r for r in rows if r.get("tool") == tool]
    assert matching, f"no audit row was written for {tool}"
    return matching[-1]


def _guest_env(monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "unit-test-pass")


class FakePS:
    """run_ps stand-in with per-name GUID resolution (test_guestjobs
    pattern): resolution legs answer deterministically, everything else pops
    the scripted queue."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            import re as _re
            import uuid as _uuid

            m = _re.search(r"ElementName -eq '([^']*)'", script)
            guid = str(_uuid.uuid5(_uuid.NAMESPACE_OID, m.group(1) if m else ""))
            return pswindows.PSResult(stdout=guid, returncode=0)
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


def test_combined_agents_and_legacy_tokens_both_verify(tmp_path, monkeypatch, verifier_capture, capsys):
    """With http.agents configured AND the legacy token_env set, both
    principals verify: agents to their ids, the legacy token to local-cli —
    and the banner discloses the extra shared principal (impl review
    PRR-005)."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-aaa")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb")
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "tok-legacy")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    assert http_entry.main([]) == 0
    assert "legacy shared token" in capsys.readouterr().err
    verifier = verifier_capture["verifier"]
    assert verifier is not None
    results = [
        asyncio.run(verifier.verify_token(tok))
        for tok in ("tok-aaa", "tok-bbb", "tok-legacy", "tok-nope")
    ]
    assert [r.client_id if r else None for r in results] == [
        "agent-a", "agent-b", "local-cli", None,
    ]


def test_combined_agents_banner_counts_principals(tmp_path, monkeypatch, verifier_capture, capsys):
    """Agents-only mode does NOT advertise a legacy principal."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-aaa")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    assert http_entry.main([]) == 0
    assert "legacy shared token" not in capsys.readouterr().err


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
    semantics: blank counts as unset and refuses startup. The variable is
    pinned to whitespace so the test exercises the strip branch, not the
    unset branch (impl review PRR-007)."""
    monkeypatch.setenv("B01_TOKEN_BLANK", "   ")
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
    with pytest.raises(ConfigError, match="agent id"):
        # $ matched before a trailing newline; fullmatch must not (PRR-002)
        Config.from_dict({"http": {"agents": {"agent-a\n": "SOME_VAR"}}})
    with pytest.raises(ConfigError, match="must be an object"):
        Config.from_dict({"http": {"agents": ["agent-a"]}})
    with pytest.raises(ConfigError, match="must not shadow"):
        Config.from_dict({"http": {"agents": {"agent-a": "PATH"}}})
    with pytest.raises(ConfigError, match="environment"):
        Config.from_dict({"http": {"agents": {"agent-a": ""}}})
    with pytest.raises(ConfigError, match="environment"):
        # a value that cannot be an env var NAME would be echoed verbatim by
        # the missing-variable startup error — reject the paste (PRR-013)
        Config.from_dict({"http": {"agents": {"agent-a": "tok-pasted-secret"}}})
    with pytest.raises(ConfigError, match="environment"):
        Config.from_dict({"http": {"agents": {"agent-a": "B01-TOKEN-HYPHEN"}}})


def test_non_ascii_agent_token_refused_and_never_raises(tmp_path, monkeypatch, verifier_capture, capsys):
    """A non-ASCII token could never survive an Authorization header
    round-trip: startup refuses it rc 2 naming the agent (impl review
    PRR-001), and the byte-encoded comparator degrades any presented value
    to a non-match instead of raising inside the auth middleware."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("B01_TOKEN_A", "tok-é-nonascii")
    monkeypatch.setenv("B01_TOKEN_B", "tok-bbb")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    rc = http_entry.main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert "agent-a" in err
    assert "é" not in err  # the value itself is never printed
    assert verifier_capture["verifier"] is None
    verifier = http_entry._MultiTokenVerifier([("agent-a", "tok-ascii")])
    assert asyncio.run(verifier.verify_token("tok-é")) is None  # no TypeError
    assert asyncio.run(verifier.verify_token("tok-ascii")) is not None


def test_padded_and_whitespace_tokens_normalized_or_refused(monkeypatch):
    """Padded agent tokens are stripped so they still authenticate; a
    whitespace-only legacy token is refused like a blank agent one; and
    stripped values participate in the collision refusal (impl review
    PRR-006)."""
    monkeypatch.setenv("B01_PAD", "  tok-pad  ")
    rc, pairs = http_entry._resolve_agent_tokens({"agent-a": "B01_PAD"}, legacy_token="")
    assert rc == 0 and pairs == [("agent-a", "tok-pad")]
    monkeypatch.setenv("B01_PAD2", "tok-pad")
    rc, _ = http_entry._resolve_agent_tokens({"agent-a": "B01_PAD2"}, legacy_token="  tok-pad  ")
    assert rc == 2  # stripped values collide: identity collapse refused
    rc, pairs = http_entry._resolve_agent_tokens({"agent-a": "B01_PAD2"}, legacy_token="   ")
    assert rc == 0 and pairs == [("agent-a", "tok-pad")]  # whitespace legacy = unset


def test_anonymous_preempts_agents(tmp_path, monkeypatch, verifier_capture, capsys):
    """--allow-anonymous preempts a configured agents map: rc 0, no
    verifier, banner says ANONYMOUS (branch order pinned — impl review
    PRR-009a)."""
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.delenv("B01_TOKEN_A", raising=False)
    monkeypatch.delenv("B01_TOKEN_B", raising=False)
    monkeypatch.setenv("HYPERV_MCP_CONFIG", _agents_config(tmp_path))
    rc = http_entry.main(["--allow-anonymous"])
    captured = capsys.readouterr()
    assert rc == 0
    assert verifier_capture["verifier"] is None
    assert "ANONYMOUS" in captured.err


def test_multi_verifier_scans_every_pair_and_handles_empty(monkeypatch):
    """The verifier's scan-all-pairs contract: with duplicate values the
    LAST pair wins (startup refusal makes that unreachable via main, but it
    is the class contract an early-return rewrite would break), and an
    empty presented token is a non-match (impl review PRR-009b)."""
    verifier = http_entry._MultiTokenVerifier([
        ("agent-a", "tok-dup"), ("agent-b", "tok-dup"), ("agent-c", "tok-c"),
    ])
    assert asyncio.run(verifier.verify_token("tok-dup")).client_id == "agent-b"
    assert asyncio.run(verifier.verify_token("tok-c")).client_id == "agent-c"
    assert asyncio.run(verifier.verify_token("")) is None


def test_job_output_and_job_stop_audit_names_vm_and_job(audited_server, monkeypatch):
    """Success-path attribution for job_output and job_stop: the result
    dicts carry job_id/vm_name and the adoption clause lands them in the
    audit rows (the call-site audit kwargs are pinned separately on the
    raise path — see test_raising_job_output_audit_kwargs_sole_source)."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    payload = {
        "head_hex": "",
        "tail_b64": base64.b64encode(b"hi").decode(),
        "truncated": False,
        "size": 2,
    }
    fake = FakePS([
        _start_ok(),
        _ok(payload), _ok(payload),  # job_output: stdout leg, stderr leg
        _ok({"stopped": True, "alive_pids": [], "job_dir_removed": True,
             "pid_reused": False}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe", "args": ["/c", "echo hi"],
    })
    assert started.get("ok") is True, f"job_start failed: {started}"
    job_id = started["job_id"]
    out = _envelope(mcp, "hyperv_guest_job_output", {"job_id": job_id})
    assert out.get("ok") is True, f"job_output failed: {out}"
    stopped = _envelope(mcp, "hyperv_guest_job_stop", {"job_id": job_id})
    assert stopped.get("ok") is True, f"job_stop failed: {stopped}"
    rows = _rows(log)
    for tool in ("hyperv_guest_job_output", "hyperv_guest_job_stop"):
        row = _newest(rows, tool)
        assert row.get("vm_name") == "test-vm", f"{tool} lost the VM"
        assert row.get("job_id") == job_id, f"{tool} lost the job_id"


def test_relay_status_with_live_relay_attributes_vm_and_relay(audited_server, monkeypatch):
    """relay_status's given-id arm resolves the VM from the registry (impl
    review PRR-009d — the list-all arm stays honestly empty)."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_relay_start", {
        "vm_name": "test-vm", "guest_port": 9223, "host_port": 0,
    })
    assert started.get("ok") is True, f"relay_start failed: {started}"
    relay_id = started["relay_id"]
    try:
        row = _envelope(mcp, "hyperv_relay_status", {"relay_id": relay_id})
        assert row.get("ok") is True, f"relay_status failed: {row}"
        audit_row = _newest(_rows(log), "hyperv_relay_status")
        assert audit_row.get("vm_name") == "test-vm"
        assert audit_row.get("relay_id") == relay_id
    finally:
        entry = relay._relays.get(relay_id)
        if entry is not None and not entry.get("stopped"):
            relay.relay_stop(mod.CFG, relay_id)


def test_rejection_on_registered_job_resolves_vm(audited_server, monkeypatch):
    """A wrong-typed argument against a REGISTERED job writes a rejection
    row that still names the job's VM, joining it to the start row like the
    success path does (impl review PRR-003)."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe",
    })
    assert started.get("ok") is True, f"job_start failed: {started}"
    job_id = started["job_id"]
    asyncio.run(mcp.call_tool(
        "hyperv_guest_job_output", {"job_id": job_id, "tail_bytes": "not-an-int"},
    ))
    row = _newest(_rows(log), "hyperv_guest_job_output")
    assert row.get("ok") is False and row.get("error_class") == "invalid"
    assert row.get("job_id") == job_id
    assert row.get("vm_name") == "test-vm"


def test_raising_job_output_and_job_stop_kwargs_are_sole_source(audited_server, monkeypatch):
    """On the raise path no result dict exists, so the call-site
    audit_job_id/audit_vm_name kwargs are the SOLE source of the row's
    correlation keys — deleting either tool's kwarg pair must fail here
    (review round 1, PRR-009c)."""
    mod, log = audited_server
    _guest_env(monkeypatch)
    fake = FakePS([_start_ok(), RuntimeError("guest leg boom"), RuntimeError("guest leg boom 2")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    started = _envelope(mcp, "hyperv_guest_job_start", {
        "vm_name": "test-vm", "command": "cmd.exe",
    })
    assert started.get("ok") is True, f"job_start failed: {started}"
    job_id = started["job_id"]
    out = _envelope(mcp, "hyperv_guest_job_output", {"job_id": job_id})
    assert out.get("ok") is False  # the guest leg raised
    stop = _envelope(mcp, "hyperv_guest_job_stop", {"job_id": job_id})
    assert stop.get("ok") is False
    rows = _rows(log)
    out_row = _newest(rows, "hyperv_guest_job_output")
    assert out_row.get("vm_name") == "test-vm", "output raise path lost the VM"
    assert out_row.get("job_id") == job_id, "output raise path lost the job_id"
    stop_row = _newest(rows, "hyperv_guest_job_stop")
    assert stop_row.get("vm_name") == "test-vm", "stop raise path lost the VM"
    assert stop_row.get("job_id") == job_id, "stop raise path lost the job_id"


def test_rejection_ids_are_str_coerced_at_the_server_seam(audited_server, monkeypatch):
    """_opt_id's str() coercion is pinned at the server seam: the captured
    log_operation kwargs carry str ids for a raw int argument (impl review
    PRR-012 — a row-level assertion alone cannot see this line)."""
    mod, log = audited_server
    mcp = mod.get_mcp()
    captured = {}
    real = auditlog.log_operation

    def _capture(**kwargs):
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(auditlog, "log_operation", _capture)
    asyncio.run(mcp.call_tool("hyperv_guest_job_status", {"job_id": 123}))
    assert isinstance(captured.get("job_id"), str) and captured["job_id"] == "123"
    assert captured.get("relay_id") is None


def test_new_audit_fields_pass_redaction(tmp_path):
    """The four new string fields pass credentials.redact like every other
    audit field (impl review PRR-009f)."""
    secret = "super-secret-token-value"
    credentials.registry().register(secret)
    log = tmp_path / "audit.jsonl"
    auditlog.init(Config(audit_log_path=str(log)))
    auditlog.log_operation(
        tool="t", vm_name="v", category="c", ok=True,
        agent_id=f"agent-{secret}", request_id=f"req-{secret}",
        job_id=f"job-{secret}", relay_id=None,
    )
    raw = log.read_text(encoding="utf-8")
    row = json.loads(raw.splitlines()[-1])
    assert secret not in raw
    assert row["agent_id"] == "agent-***REDACTED***"
    assert row["request_id"].startswith("req-***REDACTED***")
    assert row["job_id"] == "job-***REDACTED***"
    assert row["relay_id"] is None
