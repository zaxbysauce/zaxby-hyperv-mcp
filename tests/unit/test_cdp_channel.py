"""Issue #127 acceptance checks (trace 135-127-138-gui-electron-drivability):
the CDP channel — WebSocket frames over a tcp relay (#135) and the four
first-class CDP tools (hyperv_cdp_targets / _eval / _input / _snapshot).

ACs carried (per the issue's 2026-11-09 re-assessment supplement):
  AC1  test_relay_proxies_websocket_upgrade          NEW-SURFACE
  AC3  test_cdp_eval_returns_value_with_size_cap     NEW-SURFACE
  AC4  test_cdp_input_dispatches_trusted_mouse_events NEW-SURFACE
  AC5  test_cdp_tools_refuse_without_relay_policy    NEW-SURFACE
  AC6  test_http_relay_unchanged                     PRESERVING (passes
       against the current code; the spec is new, so its recorded base leg
       is the file-absence signature, but the behaviour it pins — the plain
       HTTP relay — is green today and must stay green)
  AC8  test_snapshot_lists_nodes_with_refs           NEW-SURFACE
  AC9  test_click_by_ref_resolves_the_box_itself     NEW-SURFACE
  AC10 test_stale_ref_dispatches_nothing             NEW-SURFACE
  AC11 test_tools_never_close_or_create_targets      NEW-SURFACE

The issue's original AC2 (upgrade without the relay's secret -> 401) is
SUPERSEDED by the supplement ("a tcp relay carries no secret ... No check
is frozen for AC2"), so no check is authored for it here; the access
boundary is the loopback-only bind, bound by #135 AC6.

Tool calling contract these checks freeze (the implementation must provide
it; the issue names the tools and their semantics, not the argument names):
  - hyperv_cdp_targets(relay_id) -> {ok, targets[]}
  - hyperv_cdp_eval(relay_id, target_id, expression) -> {ok, value, truncated}
  - hyperv_cdp_input(relay_id, target_id, x?, y?) or (..., ref=...) -> {ok}
  - hyperv_cdp_snapshot(relay_id, target_id) -> {ok, nodes[{ref, role,
    name}], lines[]} — one text line per node carrying its role, name and
    state; a ref from a snapshot that is no longer the target's latest is
    refused with error_class "stale_ref" (the hyperv_ui_act discipline).

What is faked: the guest DevTools endpoint is a local threaded HTTP +
WebSocket server (real RFC 6455 framing, minimal CDP semantics) standing
behind the relay's injected guest stream (hvsock.connect monkeypatched);
every host PowerShell leg is stubbed (a resolution-leg-serving recorder
that refuses any other leg — no PowerShell may sit in the CDP data path).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import os
import re
import socket
import threading
import time
import urllib.request
import uuid
from types import SimpleNamespace

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _resolved_guid(script: str) -> str:
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class StrictPS:
    """Serves by-name resolution legs; ANY other PowerShell leg fails the
    check — the CDP path is bytes over the relay, never a host PS process."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        raise AssertionError(
            f"unexpected PowerShell leg in the CDP path: {script[:120]!r}")


# ---------------------------------------------------------------------------
# socket plumbing
# ---------------------------------------------------------------------------


class SockReader:
    """Buffered reader over a blocking socket with per-read deadlines."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def _fill(self, timeout: float) -> str:
        self.conn.settimeout(max(0.01, timeout))
        try:
            chunk = self.conn.recv(65536)
        except TimeoutError:
            return "timeout"
        except OSError:
            return "closed"
        if not chunk:
            return "closed"
        self.buf += chunk
        return "data"

    def read_exact(self, n: int, timeout: float = 15.0):
        if n == 0:
            return b""
        deadline = time.monotonic() + timeout
        while len(self.buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if self._fill(min(0.5, remaining)) == "closed":
                return None
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_until(self, marker: bytes, timeout: float = 15.0):
        deadline = time.monotonic() + timeout
        while marker not in self.buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if self._fill(min(0.5, remaining)) == "closed":
                return None
        idx = self.buf.find(marker)
        out, self.buf = self.buf[:idx], self.buf[idx + len(marker):]
        return out


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def read_ws_frame(reader: SockReader, timeout: float = 15.0):
    """(opcode, payload) of one frame, or None on close/timeout."""
    hdr = reader.read_exact(2, timeout=timeout)
    if hdr is None:
        return None
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    length = hdr[1] & 0x7F
    if length == 126:
        ext = reader.read_exact(2, timeout=timeout)
        if ext is None:
            return None
        length = int.from_bytes(ext, "big")
    elif length == 127:
        ext = reader.read_exact(8, timeout=timeout)
        if ext is None:
            return None
        length = int.from_bytes(ext, "big")
    if length > 64 * 1024 * 1024:
        return None
    mask = reader.read_exact(4, timeout=timeout) if masked else b""
    payload = reader.read_exact(length, timeout=timeout)
    if payload is None:
        return None
    if masked and mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def write_ws_frame(sock, opcode: int, payload: bytes) -> None:
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + n.to_bytes(2, "big")
    else:
        header += bytes([127]) + n.to_bytes(8, "big")
    sock.sendall(header + payload)


def client_send_frame(sock, payload: bytes) -> None:
    """A client-to-server frame: masked, text opcode."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    header = bytes([0x81])
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:
        header += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    sock.sendall(header + mask + masked)


# ---------------------------------------------------------------------------
# the fake DevTools endpoint
# ---------------------------------------------------------------------------


def ax_node(node_id, parent_id, child_ids, role, name, props):
    return {
        "nodeId": node_id, "parentId": parent_id, "childIds": child_ids,
        "backendDOMNodeId": abs(hash(node_id)) % 100000,
        "role": {"type": "role", "value": role},
        "name": {"type": "string", "value": name},
        "properties": [
            {"name": key, "value": {"type": "boolean", "value": value}}
            for key, value in props
        ],
    }


def ax_tree(with_ok: bool) -> list[dict]:
    children = ["txt-search"] + (["btn-ok", "chk-enable"] if with_ok else [])
    nodes = [ax_node("root-1", "root", children, "pane", "Main",
                     [("focusable", True)])]
    nodes.append(ax_node("txt-search", "root-1", [], "textbox", "Search",
                         [("focusable", True)]))
    if with_ok:
        nodes.append(ax_node("btn-ok", "root-1", [], "button", "OK",
                             [("focusable", True)]))
        nodes.append(ax_node("chk-enable", "root-1", [], "checkbox", "Enable",
                             [("focusable", False)]))
    return nodes


class FakeDevTools:
    """Threaded local server standing in for the guest's DevTools port as
    seen through the relay's guest stream: consumes the relay header line,
    answers ok, then serves HTTP /json listings and WebSocket CDP sessions.
    Records every CDP command as (method, params) in self.commands.
    """

    def __init__(self):
        self.commands: list[tuple[str, dict]] = []
        self.headers: list[bytes] = []
        self.eval_value = "cdp-eval-value"
        # quad for DOM.getContentQuads: a 10,20 -> 110,70 box (centre 60,45)
        self.quad = [10, 20, 110, 20, 110, 70, 10, 70]
        self.ax_tree = ax_tree(with_ok=True)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self.targets = [
            {"id": "page-1", "type": "page", "title": "Main Window",
             "url": "app://main",
             "webSocketDebuggerUrl":
                 f"ws://127.0.0.1:{self.port}/devtools/page/page-1"},
        ]
        self._stop = threading.Event()
        self._conns: list[socket.socket] = []
        self._conns_lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass
        with self._conns_lock:
            conns = list(self._conns)
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._conns_lock:
                self._conns.append(conn)
            threading.Thread(target=self._serve_one, args=(conn,),
                             daemon=True).start()

    def _serve_one(self, conn) -> None:
        try:
            reader = SockReader(conn)
            header = reader.read_until(b"\n", timeout=10)
            if header is None:
                return
            self.headers.append(header)
            conn.sendall(b'{"ok":true}\n')
            head = reader.read_until(b"\r\n\r\n", timeout=10)
            if head is None:
                return
            lines = head.decode("latin-1").split("\r\n")
            request_line = lines[0] if lines else ""
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            if "websocket" in headers.get("upgrade", "").lower():
                key = headers.get("sec-websocket-key", "")
                conn.sendall((
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n"
                ).encode())
                self._cdp_session(conn, reader)
                return
            path = request_line.split(" ")[1] if " " in request_line else "/"
            if path in ("/json", "/json/list"):
                body = json.dumps(self.targets).encode()
            elif path == "/json/version":
                body = json.dumps({
                    "Browser": "HeadlessChrome/126",
                    "webSocketDebuggerUrl":
                        f"ws://127.0.0.1:{self.port}/devtools/browser/UUID1",
                }).encode()
            else:
                body = json.dumps({"error": "not found"}).encode()
                conn.sendall(_http_response(404, "Not Found", body))
                return
            conn.sendall(_http_response(200, "OK", body))
        except Exception:
            pass

    def _cdp_session(self, conn, reader) -> None:
        while not self._stop.is_set():
            frame = read_ws_frame(reader, timeout=15)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 0x8:  # close
                try:
                    write_ws_frame(conn, 0x8, b"")
                except Exception:
                    pass
                return
            if opcode == 0x9:  # ping
                write_ws_frame(conn, 0xA, payload)
                continue
            if opcode not in (0x1, 0x2):
                continue
            try:
                msg = json.loads(payload.decode("utf-8"))
            except Exception:
                continue
            if not isinstance(msg, dict) or "method" not in msg:
                continue
            method = str(msg.get("method") or "")
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            self.commands.append((method, params))
            try:
                reply = json.dumps({
                    "id": msg.get("id"),
                    "result": self._result_for(method, params),
                }).encode()
                write_ws_frame(conn, 0x1, reply)
            except Exception:
                return

    def _result_for(self, method: str, params: dict) -> dict:
        if method == "Runtime.evaluate":
            value = self.eval_value
            if isinstance(value, bool):
                rtype = "boolean"
            elif isinstance(value, (int, float)):
                rtype = "number"
            elif isinstance(value, str):
                rtype = "string"
            else:
                rtype = "object"
            return {"result": {"type": rtype, "value": value}}
        if method == "DOM.getContentQuads":
            return {"quads": [list(self.quad)]}
        if method == "Accessibility.getFullAXTree":
            return {"nodes": [dict(n) for n in self.ax_tree]}
        return {}


def _http_response(status: int, reason: str, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


# ---------------------------------------------------------------------------
# server + relay stack
# ---------------------------------------------------------------------------


CDP_CONFIG = {
    "allowed_vm_patterns": ["test-*"],
    "destructive": {"relay": True},
}


@pytest.fixture()
def fresh_server():
    def make(environ: dict):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod

    yield make
    importlib.reload(server_module)


@pytest.fixture(autouse=True)
def _clean_relays():
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()


@pytest.fixture()
def cdp_stack(fresh_server, monkeypatch, tmp_path):
    """Boot the server, start one tcp relay whose guest stream is the local
    FakeDevTools, and hand back the handles. RED at base: hvsock / the tcp
    kind are absent (they belong to #135, which this issue depends on)."""
    from hyperv_mcp import hvsock, relay, uia

    cfg_path = tmp_path / "cdp-config.json"
    cfg_path.write_text(json.dumps(CDP_CONFIG), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_path)})

    monkeypatch.setattr(
        uia, "helper_capabilities",
        lambda *a, **k: {"uia", "msaa", "stream"}, raising=False)
    fake = FakeDevTools()
    monkeypatch.setattr(
        hvsock, "connect",
        lambda *a, **k: socket.create_connection(
            ("127.0.0.1", fake.port), timeout=15))
    ps = StrictPS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    cfg = Config.from_dict(CDP_CONFIG)
    out = relay.relay_start(cfg, "test-vm", 9222, kind="tcp", cred=CRED)
    try:
        yield SimpleNamespace(mod=mod, out=out, fake=fake, ps=ps, cfg=cfg)
    finally:
        fake.close()
        try:
            relay.relay_stop(cfg, out["relay_id"])
        except Exception:
            pass


def content_blocks(result):
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    return content if isinstance(content, list) else [content]


def _envelope_from(result, label: str) -> dict:
    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)


def _call_tool(mod, name: str, args: dict) -> dict:
    """Happy-path call: the tool exists and answers an envelope."""
    try:
        result = asyncio.run(mod.get_mcp().call_tool(name, args))
    except Exception as exc:
        pytest.fail(f"{name}: the call itself failed: {exc!r}")
    return _envelope_from(result, name)


def _refuse_tool(mod, name: str, args: dict) -> dict:
    """Expected-refusal call: must answer a failure envelope, not raise."""
    try:
        result = asyncio.run(mod.get_mcp().call_tool(name, args))
    except Exception as exc:
        pytest.fail(
            f"{name}: refusals must return an error envelope, the call "
            f"raised instead: {exc!r}")
    return _envelope_from(result, name)


def _snapshot_ref(stack, name: str = "OK") -> str:
    """Take a snapshot and return the ref of its node named `name`."""
    env = _call_tool(stack.mod, "hyperv_cdp_snapshot",
                     {"relay_id": stack.out["relay_id"],
                      "target_id": "page-1"})
    assert env.get("ok") is True, f"snapshot failed: {json.dumps(env)[:300]}"
    for node in env.get("nodes") or []:
        if node.get("name") == name:
            ref = node.get("ref")
            assert isinstance(ref, str) and ref, "snapshot refs must be strings"
            return ref
    pytest.fail(f"no node named {name!r} in the snapshot: {env.get('nodes')!r}")


# ---------------------------------------------------------------------------
# AC1 — a WebSocket upgrade completes and frames carry both directions
# ---------------------------------------------------------------------------


def test_relay_proxies_websocket_upgrade(cdp_stack):
    """AC1: a WebSocket upgrade sent through the tcp relay to the
    guest-loopback DevTools port completes (101 with the correct
    Sec-WebSocket-Accept) and frames carry in both directions."""
    port = cdp_stack.out["host_port"]
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        "GET /devtools/page/page-1 HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
        reader = SockReader(sock)
        sock.sendall(request.encode())
        head = reader.read_until(b"\r\n\r\n", timeout=15)
        assert head is not None, "AC1: no upgrade response arrived"
        status_line = head.decode("latin-1").split("\r\n")[0]
        assert " 101 " in status_line, (  # the upgrade completed
            f"AC1: the upgrade did not complete; first line {status_line!r}")
        headers = {}
        for line in head.decode("latin-1").split("\r\n")[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        assert headers.get("sec-websocket-accept", "").lower() == ws_accept(key).lower(), (
            "AC1: the handshake bytes were not carried intact "
            f"(accept {headers.get('sec-websocket-accept')!r})")
        payload = json.dumps({
            "id": 1, "method": "Runtime.evaluate",
            "params": {"expression": "1+1"},
        }).encode()
        client_send_frame(sock, payload)
        frame = read_ws_frame(reader, timeout=15)
        assert frame is not None, "AC1: no frame came back through the relay"
        opcode, data = frame
        msg = json.loads(data.decode("utf-8"))
        assert msg.get("id") == 1, f"AC1: wrong frame came back: {msg!r}"
        assert "result" in msg, f"AC1: the frame lost its result: {msg!r}"
    assert cdp_stack.fake.headers, (
        "AC1: the guest stream was never dialled — the upgrade did not ride "
        "the relay")


# ---------------------------------------------------------------------------
# AC3 — hyperv_cdp_eval returns the value and truncates at the cap
# ---------------------------------------------------------------------------


def test_cdp_eval_returns_value_with_size_cap(cdp_stack):
    """AC3: hyperv_cdp_eval returns the expression's value; a value over the
    documented size cap comes back truncated with truncated=true."""
    relay_id = cdp_stack.out["relay_id"]
    cdp_stack.fake.eval_value = "small-value"
    env = _call_tool(cdp_stack.mod, "hyperv_cdp_eval",
                     {"relay_id": relay_id, "target_id": "page-1",
                      "expression": "'small-value'"})
    assert env.get("ok") is True, f"AC3: {json.dumps(env)[:300]}"
    assert env.get("value") == "small-value", (
        f"AC3: the expression's value must come back; got {env.get('value')!r}")
    assert env.get("truncated") is False, "AC3: a small value is not truncated"

    big = "z" * (4 * 1024 * 1024)
    cdp_stack.fake.eval_value = big
    env2 = _call_tool(cdp_stack.mod, "hyperv_cdp_eval",
                      {"relay_id": relay_id, "target_id": "page-1",
                       "expression": "big"})
    assert env2.get("ok") is True, f"AC3: {json.dumps(env2)[:300]}"
    assert env2.get("truncated") is True, (
        "AC3: a 4 MiB value exceeds the documented cap and must be "
        "reported truncated")
    returned = env2.get("value")
    assert isinstance(returned, str) and 0 < len(returned) < len(big), (
        f"AC3: the over-cap value must come back shortened; got "
        f"{len(returned) if isinstance(returned, str) else returned!r} bytes")
    evaluates = [c for c in cdp_stack.fake.commands
                 if c[0] == "Runtime.evaluate"]
    assert len(evaluates) == 2, (  # count before detail
        f"AC3: expected 2 Runtime.evaluate commands; saw "
        f"{[c[0] for c in cdp_stack.fake.commands]}")


# ---------------------------------------------------------------------------
# AC4 — hyperv_cdp_input dispatches trusted pressed/released mouse events
# ---------------------------------------------------------------------------


def test_cdp_input_dispatches_trusted_mouse_events(cdp_stack):
    """AC4: a coordinate click sends Input.dispatchMouseEvent mousePressed
    then mouseReleased at the given CSS-pixel coordinates."""
    cdp_stack.fake.commands.clear()
    env = _call_tool(cdp_stack.mod, "hyperv_cdp_input",
                     {"relay_id": cdp_stack.out["relay_id"],
                      "target_id": "page-1", "x": 314, "y": 159})
    assert env.get("ok") is True, f"AC4: {json.dumps(env)[:300]}"
    dispatches = [c for c in cdp_stack.fake.commands
                  if c[0] == "Input.dispatchMouseEvent"]
    assert len(dispatches) == 2, (  # count before detail
        f"AC4: a click is exactly one pressed and one released event; saw "
        f"{[c[0] for c in cdp_stack.fake.commands]}")
    assert [d[1].get("type") for d in dispatches] == [
        "mousePressed", "mouseReleased"], (
        f"AC4: wrong event sequence: {[d[1] for d in dispatches]}")
    for _method, params in dispatches:
        assert params.get("x") == 314 and params.get("y") == 159, (
            f"AC4: events must land on the given CSS pixels; got {params!r}")
        assert params.get("button") == "left", (
            f"AC4: a click is the left button; got {params.get('button')!r}")


# ---------------------------------------------------------------------------
# AC5 — the relay policy category gates the CDP tools
# ---------------------------------------------------------------------------


def test_cdp_tools_refuse_without_relay_policy(fresh_server, tmp_path):
    """AC5: with the relay category disabled every CDP tool refuses before
    opening any connection, with a denial naming the relay policy."""
    cfg_path = tmp_path / "no-relay.json"
    cfg_path.write_text(json.dumps({"allowed_vm_patterns": ["test-*"]}),
                        encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(cfg_path)})
    calls = [
        ("hyperv_cdp_targets", {"relay_id": "relay-9999-tcp"}),
        ("hyperv_cdp_eval", {"relay_id": "relay-9999-tcp",
                             "target_id": "page-1", "expression": "1"}),
        ("hyperv_cdp_input", {"relay_id": "relay-9999-tcp",
                              "target_id": "page-1", "x": 1, "y": 2}),
        ("hyperv_cdp_snapshot", {"relay_id": "relay-9999-tcp",
                                 "target_id": "page-1"}),
    ]
    assert len(calls) == 4  # every tool below must refuse
    for name, args in calls:
        env = _refuse_tool(mod, name, args)
        text = json.dumps(env).lower()
        assert env.get("ok") is False, (
            f"AC5: {name} must refuse under a disabled relay category")
        assert "relay" in text and "denied" in text, (
            f"AC5: {name}'s refusal must name the relay policy denial; got "
            f"{text[:200]}")


# ---------------------------------------------------------------------------
# AC6 — PRESERVING: plain HTTP relay requests still proxy exactly as before
# ---------------------------------------------------------------------------


def test_http_relay_unchanged(monkeypatch):
    """AC6 (preserving): the plain HTTP relay path forwards a request
    through one PS Direct guest leg and returns the guest's response
    exactly as before. Passes against the current code."""
    cfg = Config(allowed_vm_patterns=["test-*"],
                 destructive=DestructivePolicy(relay=True))
    body = json.dumps({"Browser": "Chrome/126"}).encode()
    responses = [pswindows.PSResult(stdout=json.dumps({
        "status": 200, "content_type": "application/json",
        "body_b64": base64.b64encode(body).decode()}), returncode=0)]

    def rec(script, **kwargs):
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script),
                                      returncode=0)
        assert responses, "AC6: an unexpected extra guest forward leg ran"
        return responses.pop(0)

    monkeypatch.setattr(pswindows, "run_ps", rec)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)
    with urllib.request.urlopen(out["url"] + "/json/version", timeout=10) as resp:
        assert resp.status == 200
        assert json.loads(resp.read().decode())["Browser"] == "Chrome/126"
        assert resp.headers.get("X-Hyperv-Relay") == out["relay_id"]


# ---------------------------------------------------------------------------
# AC8 — the accessibility snapshot lists nodes with refs
# ---------------------------------------------------------------------------


def test_snapshot_lists_nodes_with_refs(cdp_stack):
    """AC8: hyperv_cdp_snapshot returns every node of the accessibility
    tree with a ref, and renders one text line per node with its role,
    name and state."""
    cdp_stack.fake.ax_tree = ax_tree(with_ok=True)
    env = _call_tool(cdp_stack.mod, "hyperv_cdp_snapshot",
                     {"relay_id": cdp_stack.out["relay_id"],
                      "target_id": "page-1"})
    assert env.get("ok") is True, f"AC8: {json.dumps(env)[:300]}"
    nodes = env.get("nodes") or []
    assert len(nodes) == 4, (  # count before detail
        f"AC8: every node of the 4-node tree must be listed; got {len(nodes)}")
    refs = [n.get("ref") for n in nodes]
    assert all(isinstance(r, str) and r for r in refs), (
        f"AC8: every listed node must carry a non-empty ref; got {refs!r}")
    assert len(set(refs)) == len(refs), (
        "AC8: refs must be unique addresses")
    lines = env.get("lines") or []
    assert len(lines) == len(nodes), (
        f"AC8: one text line per node; got {len(lines)} lines for "
        f"{len(nodes)} nodes")
    # strict=True: the one-line-per-node contract above already proved the
    # lengths match, so a silent truncation here would hide a real defect.
    for node, line in zip(nodes, lines, strict=True):
        line_text = str(line).lower()
        assert str(node.get("role", "")).lower() in line_text, (
            f"AC8: the line must carry the node's role; node {node!r} line {line!r}")
        assert str(node.get("name", "")).lower() in line_text, (
            f"AC8: the line must carry the node's name; node {node!r} line {line!r}")
    joined = "\n".join(str(line) for line in lines).lower()
    assert "focusable" in joined, (
        "AC8: the rendered lines must carry the node state")


# ---------------------------------------------------------------------------
# AC9 — a click by ref resolves the box itself
# ---------------------------------------------------------------------------


def test_click_by_ref_resolves_the_box_itself(cdp_stack):
    """AC9: a click on a ref scrolls the node into view, reads its content
    box, and dispatches pressed and released events at the CENTRE of that
    box — the caller supplies no coordinates."""
    cdp_stack.fake.ax_tree = ax_tree(with_ok=True)
    ok_ref = _snapshot_ref(cdp_stack, "OK")
    cdp_stack.fake.commands.clear()
    env = _call_tool(cdp_stack.mod, "hyperv_cdp_input",
                     {"relay_id": cdp_stack.out["relay_id"],
                      "target_id": "page-1", "ref": ok_ref})
    assert env.get("ok") is True, f"AC9: {json.dumps(env)[:300]}"
    methods = [c[0] for c in cdp_stack.fake.commands]
    dispatches = [m for m in methods if m == "Input.dispatchMouseEvent"]
    assert len(dispatches) == 2, (  # count before detail
        f"AC9: a ref click is one pressed and one released event; saw "
        f"{methods}")
    assert "DOM.scrollIntoViewIfNeeded" in methods, (
        f"AC9: the node must be scrolled into view first; saw {methods}")
    assert "DOM.getContentQuads" in methods, (
        f"AC9: the box must be read from the protocol; saw {methods}")
    assert (methods.index("DOM.scrollIntoViewIfNeeded")
            < methods.index("DOM.getContentQuads")
            < methods.index("Input.dispatchMouseEvent")), (
        f"AC9: scroll, then box, then dispatch; saw {methods}")
    # the fake's quad is a 10,20 -> 110,70 box: centre (60, 45)
    for method, params in cdp_stack.fake.commands:
        if method == "Input.dispatchMouseEvent":
            assert abs(params.get("x", -1) - 60.0) < 1, (
                f"AC9: the click must land at the box centre x=60; got {params!r}")
            assert abs(params.get("y", -1) - 45.0) < 1, (
                f"AC9: the click must land at the box centre y=45; got {params!r}")


# ---------------------------------------------------------------------------
# AC10 — a stale ref dispatches nothing
# ---------------------------------------------------------------------------


def test_stale_ref_dispatches_nothing(cdp_stack):
    """AC10: a ref that does not belong to the latest snapshot of its
    target is refused with stale_ref and no input event is dispatched."""
    cdp_stack.fake.ax_tree = ax_tree(with_ok=True)
    ok_ref = _snapshot_ref(cdp_stack, "OK")
    # the page changes: the OK button is gone from the latest tree
    cdp_stack.fake.ax_tree = ax_tree(with_ok=False)
    cdp_stack.fake.commands.clear()
    env = _refuse_tool(cdp_stack.mod, "hyperv_cdp_input",
                       {"relay_id": cdp_stack.out["relay_id"],
                        "target_id": "page-1", "ref": ok_ref})
    assert env.get("ok") is False, "AC10: a stale ref must be refused"
    assert env.get("error_class") == "stale_ref", (
        f"AC10: the refusal must be error_class stale_ref; got "
        f"{env.get('error_class')!r} ({json.dumps(env)[:200]})")
    inputs = [c for c in cdp_stack.fake.commands if c[0].startswith("Input.")]
    assert len(inputs) == 0, (  # count: nothing dispatched
        f"AC10: input was dispatched under a stale ref: {inputs}")


# ---------------------------------------------------------------------------
# AC11 — the tools never close the app or create targets
# ---------------------------------------------------------------------------


def test_tools_never_close_or_create_targets(cdp_stack):
    """AC11: across every CDP tool, Browser.close (quits an Electron app)
    and Target.createTarget (unsupported there) are never sent."""
    relay_id = cdp_stack.out["relay_id"]
    cdp_stack.fake.ax_tree = ax_tree(with_ok=True)
    cdp_stack.fake.commands.clear()
    results = [
        _call_tool(cdp_stack.mod, "hyperv_cdp_targets", {"relay_id": relay_id}),
        _call_tool(cdp_stack.mod, "hyperv_cdp_eval",
                   {"relay_id": relay_id, "target_id": "page-1",
                    "expression": "1"}),
        _call_tool(cdp_stack.mod, "hyperv_cdp_input",
                   {"relay_id": relay_id, "target_id": "page-1",
                    "x": 10, "y": 20}),
        _call_tool(cdp_stack.mod, "hyperv_cdp_snapshot",
                   {"relay_id": relay_id, "target_id": "page-1"}),
    ]
    ok_ref = _snapshot_ref(cdp_stack, "OK")
    results.append(_call_tool(cdp_stack.mod, "hyperv_cdp_input",
                              {"relay_id": relay_id, "target_id": "page-1",
                               "ref": ok_ref}))
    assert len(results) == 5
    assert all(r.get("ok") is True for r in results), (
        "AC11: every tool must succeed against the fake endpoint")
    assert cdp_stack.fake.commands, (  # count first: the tools really talked
        "AC11: no CDP commands were exchanged — the check would be vacuous")
    forbidden = {"Browser.close", "Target.createTarget"}
    sent = {method for method, _params in cdp_stack.fake.commands}
    assert not (sent & forbidden), (
        f"AC11: forbidden method(s) sent to the attached application: "
        f"{sorted(sent & forbidden)}; every method seen: {sorted(sent)}")


# ---------------------------------------------------------------------------
# AC37 — ref identity is the nodeId, not the ref string
# ---------------------------------------------------------------------------


def test_ref_identity_is_the_node_id(cdp_stack):
    """AC37: a ref addresses a NODE, not a position in one snapshot's list.
    When the page replaces the node (a different nodeId wearing the same
    name), the old ref is refused with stale_ref and dispatches nothing —
    identity is the nodeId the live tree reports, so a re-created node needs a
    fresh snapshot rather than silently receiving the old ref's click."""
    cdp_stack.fake.ax_tree = ax_tree(with_ok=True)
    ok_ref = _snapshot_ref(cdp_stack, "OK")
    # the page changes: the OK button is a DIFFERENT node with the same name
    nodes = ax_tree(with_ok=True)
    for node in nodes:
        if node["nodeId"] == "btn-ok":
            node["nodeId"] = "btn-ok-2"
            node["backendDOMNodeId"] = 424242
    cdp_stack.fake.ax_tree = nodes
    cdp_stack.fake.commands.clear()
    env = _refuse_tool(cdp_stack.mod, "hyperv_cdp_input",
                       {"relay_id": cdp_stack.out["relay_id"],
                        "target_id": "page-1", "ref": ok_ref})
    assert env.get("ok") is False, "AC37: the replaced node's old ref must be refused"
    assert env.get("error_class") == "stale_ref", (
        f"AC37: expected stale_ref; got {env.get('error_class')!r}")
    inputs = [c for c in cdp_stack.fake.commands if c[0].startswith("Input.")]
    assert len(inputs) == 0, (  # count: nothing dispatched
        f"AC37: input was dispatched under a replaced node's ref: {inputs}")
    # and a fresh snapshot of the new node works
    fresh = _snapshot_ref(cdp_stack, "OK")
    assert fresh != ok_ref, "AC37: the replacement node must carry a new ref"
    env2 = _call_tool(cdp_stack.mod, "hyperv_cdp_input",
                      {"relay_id": cdp_stack.out["relay_id"],
                       "target_id": "page-1", "ref": fresh})
    assert env2.get("ok") is True, f"AC37: {json.dumps(env2)[:300]}"


# ---------------------------------------------------------------------------
# AC38 — the documented cap counts UTF-8 bytes, not characters
# ---------------------------------------------------------------------------


def test_eval_cap_counts_utf8_bytes(cdp_stack):
    """AC38: the 1 MiB cap is BYTES of UTF-8, not Python characters — a cap
    measured in characters lets a twice-as-large multi-byte payload through
    under the same number."""
    relay_id = cdp_stack.out["relay_id"]
    # 512 Ki characters of a two-byte code point = 1 MiB of characters but
    # 2 MiB of bytes, so it must come back truncated.
    cdp_stack.fake.eval_value = "\u00e9" * (600 * 1024)
    env = _call_tool(cdp_stack.mod, "hyperv_cdp_eval",
                     {"relay_id": relay_id, "target_id": "page-1",
                      "expression": "big"})
    assert env.get("ok") is True, f"AC38: {json.dumps(env)[:300]}"
    assert env.get("truncated") is True, (
        "AC38: a 1 MiB-character (2 MiB-byte) value exceeds the byte cap and "
        "must be reported truncated")
    returned = env.get("value")
    assert isinstance(returned, str), "AC38: the value must come back as text"
    assert len(returned.encode("utf-8")) <= 1024 * 1024, (
        f"AC38: the returned value must fit the byte cap; got "
        f"{len(returned.encode('utf-8'))} bytes")
    assert 0 < len(returned) < 600 * 1024, (
        "AC38: the over-cap value must come back shortened")
