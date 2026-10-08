"""B02 acceptance-check probes for issue #11: jobs and relays belong to the
agent that started them; relays authenticate requests with a per-relay
secret, are capped and evicted, start atomically, and issue 128-bit ids.

These nine probes pin the issue's acceptance criteria AC1-AC9 as
caller-observable behavior at the CURRENT (buggy) HEAD; every one of them is
RED at the pre-fix base by design and must turn GREEN only when the fix for
https://github.com/zaxbysauce/zaxby-hyperv-mcp/issues/11 lands. AC1-AC5
drive the MCP tool layer with the SDK auth context set (per-agent identity,
issue #10's plumbing); AC6-AC9 probe the module level directly where the
tool wrapper would swallow the signal in an envelope.
"""

import asyncio
import base64
import importlib
import json
import re
import threading
import urllib.error
import urllib.request
import uuid

import pytest
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

import hyperv_mcp.server as server_module
from hyperv_mcp import guestjobs, pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

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


def _relay_cfg() -> Config:
    return Config(
        allowed_vm_patterns=["test-*"],
        destructive=DestructivePolicy(relay=True),
    )


def _guest_env(monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "unit-test-pass")


def _as_agent(client_id: str):
    """Set the SDK auth context exactly as AuthContextMiddleware does."""
    return auth_context_var.set(AuthenticatedUser(AccessToken(token="t", client_id=client_id, scopes=[])))


def _guest_legs(fake: FakePS) -> int:
    """run_ps calls that are NOT the by-name identity-resolution leg."""
    return len([s for s in fake.scripts if not _is_resolution_leg(s)])


def _stop_relay(cfg: Config, relay_id) -> None:
    entry = relay._relays.get(relay_id) if relay_id else None
    if entry is not None and not entry.get("stopped"):
        relay.relay_stop(cfg, relay_id)


def _trailing_hex_run(text: str) -> str:
    end = len(text)
    while end > 0 and text[end - 1] in "0123456789abcdef":
        end -= 1
    return text[end:]


@pytest.fixture(autouse=True)
def _clean_registries():
    guestjobs.clear_registry_for_tests()
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()
    guestjobs.clear_registry_for_tests()


@pytest.fixture()
def audited_server(tmp_path):
    """Bootstrapped server (B01 pattern): per-test JSONL audit sink, relay
    category enabled, 'test-*' VMs allowed, credentials from environment."""
    log = tmp_path / "audit.jsonl"
    doc = {
        "allowed_vm_patterns": ["test-*"],
        "audit_log_path": str(log),
        "destructive": {"relay": True},
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    yield mod
    importlib.reload(server_module)


# -- AC1 / AC2: foreign agent cannot read or stop another agent's job --------


def test_foreign_agent_cannot_read_job_status(audited_server, monkeypatch):
    mod = audited_server
    _guest_env(monkeypatch)
    fake = FakePS(
        [
            _start_ok(),
            _ok({"status": "running", "process_name": "sqlprobe"}),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    ctx = _as_agent("agent-a")
    try:
        started = _envelope(
            mcp,
            "hyperv_guest_job_start",
            {
                "vm_name": "test-vm",
                "command": "cmd.exe",
                "args": ["/c", "echo hi"],
            },
        )
    finally:
        auth_context_var.reset(ctx)
    assert started.get("ok") is True, f"agent-a job_start failed: {started}"
    job_id = started["job_id"]
    ctx = _as_agent("agent-b")
    try:
        env = _envelope(mcp, "hyperv_guest_job_status", {"job_id": job_id})
    finally:
        auth_context_var.reset(ctx)
    assert (env["ok"], _guest_legs(fake)) == (False, 1)


def test_foreign_agent_cannot_stop_job(audited_server, monkeypatch):
    mod = audited_server
    _guest_env(monkeypatch)
    fake = FakePS([_start_ok(), _ok({"stopped": True})])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    ctx = _as_agent("agent-a")
    try:
        started = _envelope(
            mcp,
            "hyperv_guest_job_start",
            {
                "vm_name": "test-vm",
                "command": "cmd.exe",
                "args": ["/c", "echo hi"],
            },
        )
    finally:
        auth_context_var.reset(ctx)
    assert started.get("ok") is True, f"agent-a job_start failed: {started}"
    job_id = started["job_id"]
    ctx = _as_agent("agent-b")
    try:
        env = _envelope(mcp, "hyperv_guest_job_stop", {"job_id": job_id})
    finally:
        auth_context_var.reset(ctx)
    entry = guestjobs._jobs[job_id]
    assert (env["ok"], entry["stopped"]) == (False, False)


# -- AC3 / AC4: foreign agent cannot stop or enumerate another agent's relay --


def test_foreign_agent_cannot_stop_relay(audited_server, monkeypatch):
    mod = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    mcp = mod.get_mcp()
    relay_id = None
    try:
        ctx = _as_agent("agent-a")
        try:
            started = _envelope(
                mcp,
                "hyperv_relay_start",
                {
                    "vm_name": "test-vm",
                    "guest_port": 9222,
                    "host_port": 0,
                },
            )
        finally:
            auth_context_var.reset(ctx)
        relay_id = started["relay_id"]
        ctx = _as_agent("agent-b")
        try:
            env = _envelope(mcp, "hyperv_relay_stop", {"relay_id": relay_id})
        finally:
            auth_context_var.reset(ctx)
        assert (env["ok"], relay._relays[relay_id]["stopped"]) == (False, False)
    finally:
        _stop_relay(mod.CFG, relay_id)


def test_relay_status_lists_only_callers_relays(audited_server, monkeypatch):
    mod = audited_server
    _guest_env(monkeypatch)
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    mcp = mod.get_mcp()
    relay_id = None
    try:
        ctx = _as_agent("agent-a")
        try:
            started = _envelope(
                mcp,
                "hyperv_relay_start",
                {
                    "vm_name": "test-vm",
                    "guest_port": 9222,
                    "host_port": 0,
                },
            )
        finally:
            auth_context_var.reset(ctx)
        relay_id = started["relay_id"]
        ctx = _as_agent("agent-b")
        try:
            env = _envelope(mcp, "hyperv_relay_status", {"relay_id": ""})
        finally:
            auth_context_var.reset(ctx)
        rows = env["relays"]
        assert len(rows) == 0
    finally:
        _stop_relay(mod.CFG, relay_id)


# -- AC5: the loopback listener must not serve unauthenticated requests ------


def test_relay_listener_rejects_request_without_relay_secret(audited_server, monkeypatch):
    mod = audited_server
    _guest_env(monkeypatch)
    body = json.dumps({"Browser": "probe"}).encode()
    fake = FakePS(
        [
            _ok(
                {
                    "status": 200,
                    "content_type": "application/json",
                    "body_b64": base64.b64encode(body).decode(),
                }
            ),
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    mcp = mod.get_mcp()
    relay_id = None
    try:
        ctx = _as_agent("agent-a")
        try:
            started = _envelope(
                mcp,
                "hyperv_relay_start",
                {
                    "vm_name": "test-vm",
                    "guest_port": 9222,
                    "host_port": 0,
                },
            )
        finally:
            auth_context_var.reset(ctx)
        relay_id = started["relay_id"]
        url = f"http://127.0.0.1:{started['host_port']}/json/version"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert (status, _guest_legs(fake)) == (401, 0)
    finally:
        _stop_relay(mod.CFG, relay_id)


# -- AC6 / AC7: the relay registry is capped and evicts stopped entries ------


def test_relay_count_is_capped(monkeypatch):
    monkeypatch.setattr(relay, "_MAX_RELAYS", 2, raising=False)
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    started = []
    third = None
    try:
        started.append(relay.relay_start(cfg, "test-vm", 9222, cred=CRED))
        started.append(relay.relay_start(cfg, "test-vm", 8080, cred=CRED))
        with pytest.raises(RuntimeError):
            third = relay.relay_start(cfg, "test-vm", 7000, cred=CRED)
        assert len(relay._relays) <= 2
    finally:
        for out in started + ([third] if third is not None else []):
            _stop_relay(cfg, out["relay_id"])


def test_stopped_relays_are_evicted_not_retained(monkeypatch):
    monkeypatch.setattr(relay, "_MAX_RELAYS", 2, raising=False)
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    for cycle in range(4):
        out = relay.relay_start(cfg, "test-vm", 9000 + cycle, cred=CRED)
        relay.relay_stop(cfg, out["relay_id"])
    assert len(relay._relays) <= 2


# -- AC8: two concurrent starts for the same target admit exactly one --------


def test_concurrent_duplicate_relay_start_admits_exactly_one(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    # Both threads must pass the duplicate-target check before either binds:
    # rendezvous inside _RelayServer.__init__ (the bind step), so the two
    # checks necessarily observe a registry without the other's entry.
    barrier = threading.Barrier(2, timeout=2)
    original_init = relay._RelayServer.__init__

    def synced_init(server_self, *args, **kwargs):
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        original_init(server_self, *args, **kwargs)

    monkeypatch.setattr(relay._RelayServer, "__init__", synced_init)
    outcomes = []
    lock = threading.Lock()

    def starter():
        try:
            out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
            outcome = ("ok", out["relay_id"])
        except Exception as exc:
            outcome = ("error", exc)
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=starter) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    ok_count = sum(1 for kind, _ in outcomes if kind == "ok")
    try:
        assert ok_count == 1
    finally:
        for kind, relay_id in outcomes:
            if kind == "ok":
                _stop_relay(cfg, relay_id)


# -- AC9: job_id and relay_id carry 128 bits of randomness -------------------


def test_job_and_relay_ids_carry_128_bits(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([_start_ok()])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    job = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=CRED)
    out = relay.relay_start(cfg, "test-vm", 9333, cred=CRED)
    try:
        job_bits = len(job["job_id"]) * 4
        relay_bits = len(_trailing_hex_run(out["relay_id"])) * 4
        assert [job_bits, relay_bits] == [128, 128]
    finally:
        _stop_relay(cfg, out["relay_id"])
