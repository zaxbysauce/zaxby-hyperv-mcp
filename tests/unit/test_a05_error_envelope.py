"""Issue #9 acceptance checks: the desired error-envelope contract.

Authored BEFORE the fix exists. These tests pin the contract every tool
FAILURE must satisfy once issue #9 lands:

  - envelope {ok: false, error: str, error_class: str, retryable: bool,
    retry_after_ms: int | None} delivered as a CallToolResult with
    isError=True and structuredContent == envelope;
  - taxonomy: PolicyDenied -> "policy", CredentialError -> "credential",
    VMBusy -> "busy", ValueError -> "invalid", TimeoutError -> "timeout",
    RuntimeError (incl. ConsoleError, MediaError) -> "transport";
  - retry guidance: "busy" -> retryable=True with int retry_after_ms > 0;
    every other class -> retryable=False, retry_after_ms None;
  - the audit log's error_class agrees with the envelope's;
  - unknown tool arguments are rejected as "invalid" (and the published
    schemas set additionalProperties: false);
  - under deny-all nothing reaches PowerShell: failures classify only as
    policy / credential / invalid.

Success shapes are unchanged and not re-pinned here. Every external touch
(PowerShell, git probe) is patched; no sleeps, no real Hyper-V.

Expected on the PRE-FIX tree: test 3 passes (it pins existing behavior);
the rest fail on the contract assertions above — never on collection.
"""

import asyncio
import importlib
import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import hyperv_mcp.server as server_module
from hyperv_mcp.console import ConsoleError
from hyperv_mcp.vmlocks import VMBusy

WMI_BOOM = "VM not found in WMI namespace (is it running?)"
BUSY_MSG = "another operation is already running on VM 'test-vm'"
# Under deny-all a failure may only classify as one of these; a "transport"
# here means the census reached the patched PowerShell path.
DENY_ALL_CLASSES = {"policy", "credential", "invalid"}


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


def _boot(fresh_server, tmp_path, doc: dict):
    """Reload + bootstrap the server against a config file holding `doc`."""
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return fresh_server({"HYPERV_MCP_CONFIG": str(p)})


def _unrestricted_doc(audit_log=None) -> dict:
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    if audit_log is not None:
        doc["audit_log_path"] = str(audit_log)
    return doc


def _env_guest_creds(monkeypatch) -> None:
    """Env-only guest credentials so credential resolution succeeds (the
    password-file variants are cleared so the env values win)."""
    for var in (
        "HYPERV_GUEST_PASSWORD_FILE",
        "HYPERV_GUEST_VICTIM_PASSWORD_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "probe-admin")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "probe-guest-password")


def _no_guest_creds(monkeypatch) -> None:
    """Force credential resolution to fail deterministically."""
    for var in (
        "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_PASSWORD_FILE",
        "HYPERV_GUEST_VICTIM_USERNAME", "HYPERV_GUEST_VICTIM_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)


def _content_blocks(result):
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content  # in-process call_tool returns a CallToolResult
    return content if isinstance(content, list) else [content]


def _envelope_from_result(result, label: str) -> dict:
    text_blocks = [c for c in _content_blocks(result) if getattr(c, "type", "") == "text"]
    assert text_blocks, f"expected a text envelope block for {label}"
    env = json.loads(text_blocks[0].text)
    assert isinstance(env, dict), f"expected a JSON object envelope for {label}, got {env!r}"
    return env


def _envelope(mcp, tool: str, args: dict) -> dict:
    result = asyncio.run(mcp.call_tool(tool, args))
    return _envelope_from_result(result, tool)


def _maybe_envelope(result):
    """Best-effort parse: the parsed JSON when the first text block is JSON,
    else None (success shapes that are not failure envelopes are skipped)."""
    text_blocks = [c for c in _content_blocks(result) if getattr(c, "type", "") == "text"]
    if not text_blocks:
        return None
    try:
        return json.loads(text_blocks[0].text)
    except ValueError:
        return None


def _last_audit_record(path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines, f"audit log {path} is empty"
    return json.loads(lines[-1])


# ---------------------------------------------------------------------------
# 1. busy is retryable
# ---------------------------------------------------------------------------


def test_lifecycle_busy_is_retryable_envelope(fresh_server, tmp_path, monkeypatch):
    _env_guest_creds(monkeypatch)
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc())
    mcp = mod.get_mcp()

    def busy(*args, **kwargs):  # the tool passes vm_id as a kwarg
        raise VMBusy(BUSY_MSG)

    monkeypatch.setattr("hyperv_mcp.lifecycle.start_vm", busy)

    env = _envelope(mcp, "hyperv_start_vm", {"vm_name": "test-vm"})
    assert (env["ok"], env["error_class"], env["retryable"]) == (False, "busy", True)
    assert isinstance(env.get("retry_after_ms"), int) and env["retry_after_ms"] > 0


# ---------------------------------------------------------------------------
# 2. guest-tool busy carries the retry fields too
# ---------------------------------------------------------------------------


def test_guest_busy_envelope_carries_retry_fields(fresh_server, tmp_path, monkeypatch):
    _env_guest_creds(monkeypatch)
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc())
    mcp = mod.get_mcp()

    def busy(*args, **kwargs):
        raise VMBusy(BUSY_MSG)

    monkeypatch.setattr("hyperv_mcp.guestexec.guest_run", busy)

    env = _envelope(mcp, "hyperv_guest_run", {"vm_name": "test-vm", "command": "cmd.exe"})
    assert env["ok"] is False
    assert env["error_class"] == "busy"
    assert env.get("retryable") is True
    assert isinstance(env.get("retry_after_ms"), int) and env["retry_after_ms"] > 0


# ---------------------------------------------------------------------------
# 3. ConsoleError stays a transport envelope (pins existing behavior)
# ---------------------------------------------------------------------------


def test_screenshot_console_error_is_envelope(fresh_server, tmp_path, monkeypatch):
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc())
    mcp = mod.get_mcp()

    def wmi_boom(*args, **kwargs):
        raise ConsoleError(WMI_BOOM)

    monkeypatch.setattr("hyperv_mcp.console.screenshot", wmi_boom)

    env = _envelope(mcp, "hyperv_console_screenshot", {"vm_name": "test-vm"})
    assert (env["ok"], env["error_class"]) == (False, "transport")
    assert WMI_BOOM in env["error"]


# ---------------------------------------------------------------------------
# 4. invalid input is an envelope (non-retryable) and is audited
# ---------------------------------------------------------------------------


def test_wait_vm_state_invalid_state_is_envelope_and_audited(fresh_server, tmp_path):
    audit = tmp_path / "audit.jsonl"
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc(audit_log=audit))
    mcp = mod.get_mcp()

    env = _envelope(mcp, "hyperv_wait_vm_state", {"vm_name": "test-vm", "states": ["Exploded"]})
    assert (env["ok"], env["error_class"], env["retryable"]) == (False, "invalid", False)

    rec = _last_audit_record(audit)
    assert rec["tool"] == "hyperv_wait_vm_state"
    assert rec["ok"] is False
    assert rec["error_class"] == "invalid"


# ---------------------------------------------------------------------------
# 5. census: every tool fails as an envelope under deny-all, nothing
#    reaches PowerShell
# ---------------------------------------------------------------------------


def _probe_value(prop: dict):
    if "enum" in prop and prop["enum"]:
        return prop["enum"][0]
    ptype = prop.get("type")
    if ptype == "array":
        items = prop.get("items") or {}
        return [1] if items.get("type") in ("integer", "number") else ["probe-value"]
    if ptype in ("integer", "number"):
        return 1
    if ptype == "boolean":
        return False
    if ptype == "object":
        return {}
    return "probe-value"


def _minimal_args(schema: dict) -> dict:
    props = schema.get("properties", {})
    args: dict = {}
    for name in schema.get("required", []):
        if name == "context":
            continue
        if "default" in props.get(name, {}):
            continue
        if name == "vm_name":
            # Empty vm_name is fine: policy denies before the name is used.
            args[name] = ""
            continue
        args[name] = _probe_value(props.get(name, {}))
    return args


def test_every_tool_returns_envelope_under_deny_all(fresh_server, tmp_path, monkeypatch):
    _no_guest_creds(monkeypatch)
    audit = tmp_path / "audit.jsonl"
    mod = _boot(fresh_server, tmp_path, {"audit_log_path": str(audit)})  # {} policy: deny all
    mcp = mod.get_mcp()

    def census_boom(*args, **kwargs):
        raise AssertionError("census reached PowerShell")

    monkeypatch.setattr("hyperv_mcp.pswindows.run_ps", census_boom)
    # Keep the census hermetic: no git probe spawn inside server_info.
    monkeypatch.setattr(mod, "_git_revision", lambda: "probe-revision")

    raised = []
    failures = []
    for tool in asyncio.run(mcp.list_tools()):
        args = _minimal_args(tool.inputSchema)
        try:
            result = asyncio.run(mcp.call_tool(tool.name, args))
        except Exception as exc:  # the census must never raise, whatever the class
            raised.append((tool.name, repr(exc)))
            continue
        env = _maybe_envelope(result)
        if isinstance(env, dict) and env.get("ok") is False:
            failures.append((tool.name, env))

    assert raised == [], f"tools raised instead of returning an envelope: {raised}"
    assert failures, "expected at least one failure envelope under deny-all"
    for name, env in failures:
        assert isinstance(env.get("error_class"), str), f"{name}: error_class must be a str"
        assert isinstance(env.get("retryable"), bool), (
            f"{name}: retryable must be a bool, got {env.get('retryable')!r}"
        )
        assert "retry_after_ms" in env, f"{name}: retry_after_ms key missing"
        assert env["error_class"] in DENY_ALL_CLASSES, (
            f"{name}: under deny-all failures must classify policy/credential/invalid "
            f"(a 'transport' means the patched PowerShell path was reached); "
            f"got {env['error_class']!r}"
        )


# ---------------------------------------------------------------------------
# 6. audit error_class agrees with the envelope
# ---------------------------------------------------------------------------


def test_audit_error_class_matches_envelope(fresh_server, tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc(audit_log=audit))
    mcp = mod.get_mcp()

    def wmi_boom(*args, **kwargs):
        raise ConsoleError(WMI_BOOM)

    monkeypatch.setattr("hyperv_mcp.console.get_display_info", wmi_boom)

    env = _envelope(mcp, "hyperv_console_get_display_info", {"vm_name": "test-vm"})
    assert env["error_class"] == "transport"
    rec = _last_audit_record(audit)
    assert rec["error_class"] == env["error_class"], (
        f"audit error_class {rec['error_class']!r} disagrees with the envelope's "
        f"{env['error_class']!r}"
    )


# ---------------------------------------------------------------------------
# 7. failures set isError and carry structuredContent
# ---------------------------------------------------------------------------


def test_failure_sets_is_error(fresh_server, tmp_path, monkeypatch):
    _env_guest_creds(monkeypatch)
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc())
    mcp = mod.get_mcp()

    async def _call():
        async with create_connected_server_and_client_session(mcp) as client:
            return await client.call_tool(
                "hyperv_guest_job_status", {"job_id": "no-such-job"}
            )

    result = asyncio.run(_call())
    assert result.isError is True
    text_blocks = [c for c in result.content if getattr(c, "type", "") == "text"]
    assert text_blocks, "expected a text envelope block"
    env = json.loads(text_blocks[0].text)
    assert env["ok"] is False
    assert result.structuredContent == env


# ---------------------------------------------------------------------------
# 8. unknown arguments are rejected (invalid) and never reach the tool body
# ---------------------------------------------------------------------------


def test_unknown_argument_rejected(fresh_server, tmp_path, monkeypatch):
    mod = _boot(fresh_server, tmp_path, _unrestricted_doc())
    mcp = mod.get_mcp()

    calls = []

    def fake_list_vms(cfg):
        calls.append(cfg)
        return []

    monkeypatch.setattr("hyperv_mcp.lifecycle.list_vms", fake_list_vms)

    result = asyncio.run(mcp.call_tool("hyperv_list_vms", {"confirm_everything": True}))
    env = _envelope_from_result(result, "hyperv_list_vms")
    assert env.get("ok") is False and env.get("error_class") == "invalid", (
        f"an unknown argument must be rejected as an invalid-input error, got {env!r}"
    )
    assert "confirm_everything" in env["error"]
    assert len(calls) == 0, "the tool body ran despite an unknown argument"

    for tool in asyncio.run(mcp.list_tools()):
        assert tool.inputSchema.get("additionalProperties") is False, (
            f"{tool.name}: inputSchema must set additionalProperties: false"
        )
