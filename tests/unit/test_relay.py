"""Relay tests: category gate, loopback-only bind, real ephemeral listener,
forwarded request via mocked PS Direct, counters, stop semantics."""

import base64
import json
import re
import time
import urllib.request
import uuid

import pytest

from hyperv_mcp import pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


def _cap_path(url: str) -> str:
    """The capability path of a relay_start url: /<secret>/ (issue #11)."""
    assert url.startswith("http://")
    return "/" + url.split("//", 1)[1].split("/", 1)[1]

_ENC_RE = re.compile(r"\$enc = '([A-Za-z0-9+/=]+)'")

# Identity resolution (issue #8): vmident.resolve runs a by-name leg before
# relay_start. Distinct VM names must resolve to DISTINCT GUIDs — the
# duplicate-relay check compares resolved GUIDs, so a shared fake GUID would
# falsely mark different VMs as one target (test_a04 FakePS pattern).
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


def _relay_cfg(enabled: bool = True) -> Config:
    return Config(
        allowed_vm_patterns=["test-*"],
        destructive=DestructivePolicy(relay=enabled),
    )


@pytest.fixture(autouse=True)
def _clean_relays():
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()


def test_category_denied_by_default(monkeypatch):
    cfg = Config(allowed_vm_patterns=["test-*"])  # relay defaults False
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied, match="relay"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert called.scripts == []
    assert relay._relays == {}


def test_non_loopback_bind_rejected():
    cfg = _relay_cfg()
    with pytest.raises(ValueError, match="loopback-only"):
        relay.relay_start(cfg, "test-vm", 9222, bind="0.0.0.0", cred=CRED)
    assert relay._relays == {}


def test_start_binds_real_ephemeral_port(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    assert out["ok"] is True
    assert out["bind"] == "127.0.0.1"
    assert out["host_port"] > 0
    # Capability URL (issue #11): the returned url carries the relay's
    # secret as its first path segment — the only place it is returned.
    assert out["url"].startswith(f"http://127.0.0.1:{out['host_port']}/")
    assert len(out["url"].split("/", 3)[3].rstrip("/")) >= 22
    # Listener is live: a TCP connect succeeds (and forwards via the queue-less
    # fake raising inside the handler thread -> 502 envelope, proving the path).
    fake.responses.append(pswindows.PSResult(stdout="", returncode=1, stderr="boom"))
    try:
        urllib.request.urlopen(out["url"] + "/json/version", timeout=10)
        raised = False
    except urllib.error.HTTPError as exc:
        raised = exc.code == 502
    assert raised


def test_forwarded_request_returns_guest_response(monkeypatch):
    cfg = _relay_cfg()
    body = json.dumps({"Browser": "Chrome/126"}).encode()
    fake = FakePS([
        _ok({"status": 200, "content_type": "application/json",
             "body_b64": base64.b64encode(body).decode()}),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    with urllib.request.urlopen(out["url"] + "/json/version", timeout=10) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/json"
        assert json.loads(resp.read().decode())["Browser"] == "Chrome/126"
        assert resp.headers.get("X-Hyperv-Relay") == out["relay_id"]
    # The forwarded leg targets the guest loopback with the request path.
    # The inner forward script rides the PS-Direct wrapper's b64 payload.
    # scripts[0] is relay_start's identity-resolution leg; [1] the forward.
    m = _ENC_RE.search(fake.scripts[1])
    assert m
    inner = base64.b64decode(m.group(1)).decode("utf-8")
    assert "'http://127.0.0.1:9222/json/version'" in inner
    assert "Invoke-WebRequest" in inner
    assert "UseBasicParsing" in inner
    # Counters updated.
    status = relay.relay_status(cfg, out["relay_id"])
    counters = status["relays"][0]["counters"]
    assert counters["requests"] == 1
    assert counters["ok"] == 1
    assert counters["bytes_out"] == len(body)


def test_duplicate_target_rejected(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    first = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    with pytest.raises(ValueError, match="already exists"):
        relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    # Different guest port on the same VM is fine.
    second = relay.relay_start(cfg, "test-vm", 8080, cred=CRED)
    assert second["host_port"] != first["host_port"]


def test_relay_ids_unique_same_port_different_vms(monkeypatch):
    """Review r1 finding 11: thread-id ids collided and silently dropped a
    live listener from the registry."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    a = relay.relay_start(cfg, "test-vm-a", 9222, cred=CRED)
    b = relay.relay_start(cfg, "test-vm-b", 9222, cred=CRED)
    assert a["relay_id"] != b["relay_id"]
    assert set(relay._relays) == {a["relay_id"], b["relay_id"]}
    status = relay.relay_status(cfg)
    assert len(status["relays"]) == 2


def test_authority_form_target_rejected_400(monkeypatch):
    """Review r1 finding 10 (critical SSRF): an authority-form target
    ("@evil.example/") must never reach the guest URL builder."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    # Python's HTTP server accepts authority-form; the handler must reject.
    # The capability path authenticates; the original raw target follows it
    # verbatim, so the strip hands the guards exactly what they saw before.
    import socket

    target = _cap_path(out["url"]).encode() + b"@evil.example:8080/json"
    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(b"GET " + target + b" HTTP/1.1\r\nHost: x\r\n\r\n")
        data = sock.recv(4096)
    assert b" 400 " in data.split(b"\r\n")[0]
    # No guest forward leg ran, and the surviving script IS the by-name
    # resolution leg (relay_start's identity resolution; a guest forward or
    # any other leg would not emit $vmTarget as its last line).
    assert len(fake.scripts) == 1
    assert fake.scripts[0].rstrip().endswith("$vmTarget")


def test_rejected_request_body_cannot_smuggle_followup(monkeypatch):
    """Review r2 N1: a rejected request carrying a body must close the
    connection — its buffered body was previously parsed as the NEXT
    request and executed as a guest forward."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    import socket

    smuggled = b"GET /smuggled-by-reject HTTP/1.1\r\nHost: x\r\n\r\n"
    cap = _cap_path(out["url"]).encode()
    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(
            b"POST " + cap + b"@evil.example:8080/x HTTP/1.1\r\nHost: x\r\n"
            + b"Content-Length: " + str(len(smuggled)).encode() + b"\r\n\r\n"
            + smuggled
        )
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    # Exactly ONE response (the 400), the connection closes, and the
    # buffered body never executes as a guest forward.
    assert data.count(b"HTTP/1.1") == 1
    assert b" 400 " in data.split(b"\r\n")[0]
    assert b"Connection: close" in data
    assert b" 200 " not in data
    assert len(fake.scripts) == 1  # only the resolution leg; no guest forward
    assert fake.scripts[0].rstrip().endswith("$vmTarget")


def test_chunked_transfer_encoding_rejected_411(monkeypatch):
    """Review r1 finding 14: chunked bodies were silently dropped; review
    r2 N1: the rejection must close the connection (chunked framing bytes
    were previously parsed as a follow-up request line)."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    import socket

    cap = _cap_path(out["url"]).encode()
    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(
            b"POST " + cap + b"/upload HTTP/1.1\r\nHost: x\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        data = sock.recv(4096)
    assert b" 411 " in data.split(b"\r\n")[0]
    assert b"Connection: close" in data
    assert len(fake.scripts) == 1  # only the resolution leg; no guest forward
    assert fake.scripts[0].rstrip().endswith("$vmTarget")


def test_forward_script_host_is_always_loopback():
    # The handler rejects authority/absolute-form targets before
    # _forward_script ever runs (see the 400 test); this pins the builder's
    # URL shape for a sane path so the guest-side host is always loopback.
    script = relay._forward_script(9222, "GET", "/json/version", {}, b"")
    assert "'http://127.0.0.1:9222/json/version'" in script


def test_stop_marks_stopped_and_nulls_cred(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    port = out["host_port"]
    stopped = relay.relay_stop(cfg, out["relay_id"])
    assert stopped["ok"] is True
    assert stopped["stopped"] is True
    # PRIMARY: registry entry stopped + cred nulled.
    entry = relay._relays[out["relay_id"]]
    assert entry["stopped"] is True
    assert entry["context"]["cred"] is None
    # Best-effort: port refuses connections shortly after stop.
    refused = False
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/x", timeout=2)
        except urllib.error.HTTPError:
            time.sleep(0.1)  # still served -> retry window
            continue
        except Exception:
            refused = True
            break
    assert refused
    # Idempotent second stop.
    again = relay.relay_stop(cfg, out["relay_id"])
    assert again["stopped"] is True and "note" in again


def test_unknown_relay_id():
    cfg = _relay_cfg()
    with pytest.raises(ValueError, match="unknown relay_id"):
        relay.relay_stop(cfg, "relay-nope")


def test_status_lists_all(monkeypatch):
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    relay.relay_start(cfg, "test-vm", 8080, cred=CRED)
    status = relay.relay_status(cfg)
    assert len(status["relays"]) == 2
    assert {r["guest_port"] for r in status["relays"]} == {9222, 8080}


def test_negative_content_length_rejected_400(monkeypatch):
    """PRR-021: Content-Length < 0 must 400 (rfile.read(-1) would block the
    handler until EOF)."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    import socket

    cap = _cap_path(out["url"]).encode()
    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(
            b"POST " + cap + b"/x HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
        )
        data = sock.recv(4096)
    assert b" 400 " in data.split(b"\r\n")[0]
    assert b"Connection: close" in data
    assert len(fake.scripts) == 1  # only the resolution leg; no guest forward
    assert fake.scripts[0].rstrip().endswith("$vmTarget")


def test_start_requires_credentials():
    """PRR-016a: cred=None must ValueError before any registry insert."""
    cfg = _relay_cfg()
    with pytest.raises(ValueError, match="guest credentials are required"):
        relay.relay_start(cfg, "test-vm", 9222, cred=None)
    assert relay._relays == {}


def test_request_with_nulled_cred_gets_clean_503(monkeypatch):
    """PRR-003: a request racing relay_stop (cred already nulled, listener
    still draining) gets a clean stopped signal, not an internal
    AttributeError 502."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    relay._relays[out["relay_id"]]["context"]["cred"] = None
    try:
        urllib.request.urlopen(out["url"] + "/x", timeout=10)
        raised = False
    except urllib.error.HTTPError as exc:
        raised = exc.code == 503
    assert raised
    assert len(fake.scripts) == 1  # only the resolution leg; no guest forward
    assert fake.scripts[0].rstrip().endswith("$vmTarget")


def test_concurrent_stop_single_shutdown(monkeypatch):
    """PRR-027b: two racing stops on one relay — both succeed, exactly one
    observes already-stopped, cred ends nulled."""
    import threading

    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    results = []
    lock = threading.Lock()

    def stopper():
        r = relay.relay_stop(cfg, out["relay_id"])
        with lock:
            results.append(r)

    threads = [threading.Thread(target=stopper) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert len(results) == 2
    assert all(r["stopped"] is True for r in results)
    assert sum(1 for r in results if "note" in r) == 1
    assert relay._relays[out["relay_id"]]["context"]["cred"] is None


# ---------------------------------------------------------------------------
# Durable-store review pins (PRR-004 / PRR-005 / PRR-007/008 / PRR-013 /
# PRR-015). Each is red with the pre-fix shape; the mutation probes ran
# against byte copies of the fixed sources and were restored with
# byte-identity asserted.
# ---------------------------------------------------------------------------


def test_release_never_raises_and_the_original_error_wins(monkeypatch):
    """PRR-004: on a bind failure the withdrawal must never raise — a raising
    _release used to replace the bind error the caller needs to see."""
    import sqlite3

    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    # Occupy a port so the listener constructor fails with OSError.
    import socket

    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]

        def boom(self, relay_id):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(statestore.Store, "relay_delete", boom)
        with pytest.raises(RuntimeError, match="could not bind"):
            relay.relay_start(cfg, "test-vm", 9406, host_port=port, cred=CRED)
        # The reservation placeholder is gone from the registry even though
        # the store delete itself failed.
        assert relay._relays == {}


def test_failed_registration_leaves_no_row_and_no_listener(monkeypatch):
    """PRR-004/PRR-015: a failure AFTER registration (the durable write) must
    withdraw everything — the in-memory entry AND the store row — and still
    reach server_close, or a live listener keeps serving with no registry
    row backing it."""
    import sqlite3

    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    first = relay.relay_start(cfg, "test-vm", 9407, cred=CRED)
    live_port = first["host_port"]
    calls = {"n": 0}
    real_upsert = statestore.Store.relay_upsert

    def flaky_upsert(self, row):
        calls["n"] += 1
        if calls["n"] == 2:  # the failing start's REGISTRATION write
            raise sqlite3.OperationalError("disk I/O error")
        return real_upsert(self, row)

    monkeypatch.setattr(statestore.Store, "relay_upsert", flaky_upsert)
    with pytest.raises(sqlite3.OperationalError):
        relay.relay_start(cfg, "test-vm", 9408, cred=CRED)
    # No registry entry, no store row for the failed start.
    assert set(relay._relays) == {first["relay_id"]}
    store = statestore.store_for(cfg)
    assert {row.relay_id for row in store.relay_rows()} == {first["relay_id"]}
    # server_close was reached: the listener of the failed start never bound
    # is unobservable, but the FIRST relay's listener is still healthy and
    # the port it owns still accepts connections (nothing was dropped on the
    # failure path).
    import socket

    with socket.create_connection(("127.0.0.1", live_port), timeout=10):
        pass
    relay.relay_stop(cfg, first["relay_id"])


def test_restored_relay_reads_agree_by_id_and_in_the_listing(monkeypatch):
    """PRR-013: one raw `active` row must read the SAME state everywhere —
    the listing used to publish `active` while the by-id read said
    `interrupted`."""
    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    store = statestore.store_for(cfg)
    relay_id = "relay-9409-deadbeef" + "0" * 23
    store.relay_upsert(statestore.RelayRow(
        relay_id=relay_id, vm_name="test-vm",
        vm_id="11111111-2222-3333-4444-555555555555", guest_port=9409,
        started_at="2026-01-01T00:00:00Z", state=statestore.RELAY_ACTIVE,
        cred_ref="inline",
    ))
    by_id = relay.relay_status(cfg, relay_id)["relays"][0]
    assert by_id["state"] == "interrupted", by_id
    listed = next(
        r for r in relay.relay_status(cfg)["relays"]
        if r["relay_id"] == relay_id
    )
    assert listed["state"] == "interrupted", listed
    assert listed["thread_alive"] is False, listed


def test_relay_cap_counts_store_only_rows(monkeypatch):
    """PRR-015: the relay cap counts the UNION with the store — a store-only
    key must count, or separate server processes collectively exceed
    _MAX_RELAYS."""
    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    store = statestore.store_for(cfg)
    for i in range(2):
        store.relay_upsert(statestore.RelayRow(
            relay_id=f"relay-94{i:02d}-peer" + "0" * 24,
            vm_name="test-vm", vm_id=f"{i}" * 36, guest_port=9500 + i,
            state=statestore.RELAY_ACTIVE, cred_ref="env",
        ))
    relay._MAX_RELAYS = 2
    try:
        with pytest.raises(RuntimeError, match="registry is full"):
            relay.relay_start(cfg, "test-vm", 9410, cred=CRED)
    finally:
        relay._MAX_RELAYS = 16


def test_cap_eviction_keeps_a_foreign_store_row(monkeypatch):
    """PRR-005: cap eviction must not delete a store row this process did not
    write — the row could be a live peer's, and deleting it makes the peer's
    relay unaddressable after its next restart. The slot is still freed."""
    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    store = statestore.store_for(cfg)
    foreign = "relay-9411-foreign" + "0" * 22
    store.relay_upsert(statestore.RelayRow(
        relay_id=foreign, vm_name="peer-vm",
        vm_id="99999999-2222-3333-4444-555555555555", guest_port=9411,
        state=statestore.RELAY_INTERRUPTED, cred_ref="env",
    ))
    relay._MAX_RELAYS = 1
    try:
        started = relay.relay_start(cfg, "test-vm", 9412, cred=CRED)
        # The start was admitted (the slot was freed) but the peer's row is
        # still in the store, untouched.
        row = store.relay_get(foreign)
        assert row is not None and row.state == statestore.RELAY_INTERRUPTED, row
        relay.relay_stop(cfg, started["relay_id"])
    finally:
        relay._MAX_RELAYS = 16


def test_peek_relay_vm_name_is_owner_filtered_and_never_raises(monkeypatch):
    """PRR-007/PRR-008: the relay peek reads a store row only for its owner —
    a foreign OR unattributed caller gets "" — and a failing store read
    degrades to "" instead of escaping the error envelope."""
    from hyperv_mcp import statestore

    cfg = _relay_cfg()
    store = statestore.store_for(cfg)
    relay_id = "relay-9413-owned" + "0" * 21
    store.relay_upsert(statestore.RelayRow(
        relay_id=relay_id, vm_name="owned-vm",
        vm_id="11111111-2222-3333-4444-555555555555", guest_port=9413,
        state=statestore.RELAY_ACTIVE, cred_ref="env", owner="agent-a",
    ))
    assert relay.peek_vm_name(relay_id, cfg, owner="agent-a") == "owned-vm"
    assert relay.peek_vm_name(relay_id, cfg, owner=None) == ""
    assert relay.peek_vm_name(relay_id, cfg, owner="agent-b") == ""

    def boom(self, key):
        raise statestore.StateStoreError("store unavailable")

    monkeypatch.setattr(statestore.Store, "relay_get", boom)
    assert relay.peek_vm_name(relay_id, cfg, owner="agent-a") == ""
