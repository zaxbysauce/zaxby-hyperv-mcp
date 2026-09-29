"""Relay tests: category gate, loopback-only bind, real ephemeral listener,
forwarded request via mocked PS Direct, counters, stop semantics."""

import base64
import json
import re
import time
import urllib.request

import pytest

from hyperv_mcp import pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")

_ENC_RE = re.compile(r"\$enc = '([A-Za-z0-9+/=]+)'")


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
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
    assert out["url"] == f"http://127.0.0.1:{out['host_port']}"
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
    m = _ENC_RE.search(fake.scripts[0])
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
    import socket

    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(b"GET @evil.example:8080/json HTTP/1.1\r\nHost: x\r\n\r\n")
        data = sock.recv(4096)
    assert b" 400 " in data.split(b"\r\n")[0]
    # No guest leg ran.
    assert fake.scripts == []


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
    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(
            b"POST @evil.example:8080/x HTTP/1.1\r\nHost: x\r\n"
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
    assert fake.scripts == []


def test_chunked_transfer_encoding_rejected_411(monkeypatch):
    """Review r1 finding 14: chunked bodies were silently dropped; review
    r2 N1: the rejection must close the connection (chunked framing bytes
    were previously parsed as a follow-up request line)."""
    cfg = _relay_cfg()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    import socket

    with socket.create_connection(("127.0.0.1", out["host_port"]), timeout=10) as sock:
        sock.sendall(
            b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        data = sock.recv(4096)
    assert b" 411 " in data.split(b"\r\n")[0]
    assert b"Connection: close" in data
    assert fake.scripts == []


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
