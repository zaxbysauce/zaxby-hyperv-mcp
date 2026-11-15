"""Issue #127: the Chrome DevTools Protocol channel over a tcp relay.

Four first-class tools replace the hand-written PowerShell
`ClientWebSocket` client the Electron/WebView2 campaign carried (issue
#127's observed behaviour: `hyperv_guest_run_ps` was called 5,036 times in
one month, mostly for that client). They ride the byte-stream relay of
issue #135, so every byte goes over the Hyper-V socket: NO PowerShell
process sits in the data path, and the `relay` policy category is the only
gate (AC5).

The channel is plain RFC 6455 over the relay's loopback listener plus a
minimal CDP client:

* ``targets``     reads ``/json/list`` (discovery only — it never creates a
  target).
* ``evaluate``    runs ``Runtime.evaluate`` and returns the value, truncated
  at ``_MAX_VALUE_BYTES`` with ``truncated=true``.
* ``input``       dispatches ``Input.dispatchMouseEvent`` at a coordinate, or
  at the centre of a snapshot ref's content box (``DOM.scrollIntoViewIfNeeded``
  then ``DOM.getContentQuads``).
* ``snapshot``    renders ``Accessibility.getFullAXTree``: one entry per node
  with a ref, plus one compact text line per node.

Two disciplines are load-bearing:

* ``Browser.close`` and ``Target.createTarget`` are NEVER sent. The first
  quits the attached Electron application and the second is unsupported
  there (AC11); these tools read, evaluate and dispatch input, nothing else.
* A snapshot ref is an address into the LATEST snapshot of its target. A ref
  that does not resolve there is refused with ``error_class "stale_ref"``
  and dispatches nothing (AC10) — the ``hyperv_ui_act`` discipline, same
  shape, same actionable hint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
import urllib.parse
from typing import Any

from . import policy, relay

#: Per-connection deadline for the relay socket (connect, read, write).
_TIMEOUT_S = 30.0
#: The documented size cap on a returned expression value (AC3). A value over
#: it comes back shortened with ``truncated=true``; the caller asks for a
#: narrower expression rather than moving megabytes through the tool result.
_MAX_VALUE_BYTES = 1024 * 1024
#: Frame sanity bound: a DevTools frame larger than this is a protocol fault,
#: not a payload to buffer. It sits well above the value cap on purpose — a
#: value whose FRAME exceeds it is REFUSED (the endpoint is misbehaving),
#: while a value over the cap but inside this bound is returned truncated.
_MAX_FRAME_BYTES = 8 * 1024 * 1024
_WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Ref -> node-id addresses for the latest snapshot of each target, keyed by
# relay_id so a stopped relay's state dies with the registry entry: every
# public call prunes the relay ids the registry no longer knows.
_SNAP_LOCK = threading.Lock()
_SNAPSHOTS: dict[str, dict[str, dict[str, Any]]] = {}

# ---------------------------------------------------------------------------
# socket plumbing
# ---------------------------------------------------------------------------


class _SockReader:
    """Buffered reader over a blocking socket with per-read deadlines."""

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.buf = b""

    def _fill(self, timeout: float) -> str:
        # The timeout is scoped to THIS read and restored afterwards: leaving
        # the socket at the read's sub-second value would make the write legs
        # that follow (`_ws_send`'s sendall, the pong reply) fail far sooner
        # than the documented per-connection deadline.
        previous = self.conn.gettimeout()
        self.conn.settimeout(max(0.01, timeout))
        try:
            chunk = self.conn.recv(65536)
        except TimeoutError:
            return "timeout"
        except OSError:
            return "closed"
        finally:
            try:
                self.conn.settimeout(previous)
            except OSError:
                pass
        if not chunk:
            return "closed"
        self.buf += chunk
        return "data"

    def read_exact(self, n: int, timeout: float = _TIMEOUT_S) -> bytes | None:
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

    def read_until(self, marker: bytes, timeout: float = _TIMEOUT_S) -> bytes | None:
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

    def read_to_eof(self, timeout: float = _TIMEOUT_S) -> bytes:
        """Everything left until the peer closes (no Content-Length leg)."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._fill(min(0.5, remaining)) == "closed":
                break
        out, self.buf = self.buf, b""
        return out


def _close(sock: Any) -> None:
    """Close a relay socket so the guest stream sees a clean EOF."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _accept_key(key: str) -> str:
    return base64.b64encode(
        hashlib.sha1(key.encode("ascii") + _WS_MAGIC).digest()).decode("ascii")


def _ws_send(sock: Any, obj: Any) -> None:
    """One masked text frame (RFC 6455: a client MUST mask)."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
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


def _frame_header(opcode: int, payload: bytes) -> bytes:
    """An UNMASKED server-to-client frame header (RFC 6455 section 5)."""
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + n.to_bytes(2, "big")
    else:
        head += bytes([127]) + n.to_bytes(8, "big")
    return head


def _ws_recv(reader: _SockReader, sock: Any, want_id: Any,
             timeout: float = _TIMEOUT_S) -> dict:
    """The reply whose ``id`` is ``want_id``; pings are answered inline.

    A close frame, an over-long frame or the deadline raises: a CDP session
    that cannot answer is a transport failure, never an empty result.
    Continuation frames are accumulated (RFC 6455 permits fragmentation) and
    control frames are answered through the same length encoder the request
    path uses, so an oversized ping cannot desync the stream.
    """
    deadline = time.monotonic() + timeout
    fragments: list[bytes] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"the DevTools endpoint did not answer request {want_id!r}")
        hdr = reader.read_exact(2, timeout=remaining)
        if hdr is None:
            raise ConnectionError("the DevTools endpoint closed mid-frame")
        opcode = hdr[0] & 0x0F
        masked = bool(hdr[1] & 0x80)
        length = hdr[1] & 0x7F
        if length == 126:
            ext = reader.read_exact(2, timeout=remaining)
            if ext is None:
                raise ConnectionError("truncated WebSocket frame header")
            length = int.from_bytes(ext, "big")
        elif length == 127:
            ext = reader.read_exact(8, timeout=remaining)
            if ext is None:
                raise ConnectionError("truncated WebSocket frame header")
            length = int.from_bytes(ext, "big")
        if length > _MAX_FRAME_BYTES:
            raise ValueError(
                f"WebSocket frame of {length} bytes exceeds the "
                f"{_MAX_FRAME_BYTES}-byte sanity bound")
        mask = reader.read_exact(4, timeout=remaining) if masked else b""
        payload = reader.read_exact(length, timeout=remaining)
        if payload is None:
            raise ConnectionError("truncated WebSocket frame payload")
        if masked and mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:
            raise ConnectionError("the DevTools endpoint closed the session")
        if opcode == 0x9:
            try:
                # Control frames are capped at 125 bytes by RFC 6455; a peer
                # that sends more is misbehaving, and echoing it with the
                # single-byte length form would corrupt the stream.
                if len(payload) <= 125:
                    sock.sendall(_frame_header(0xA, payload) + payload)
            except Exception:
                pass
            continue
        if opcode == 0x0:
            fragments.append(payload)
            continue
        if opcode not in (0x1, 0x2):
            continue
        try:
            msg = json.loads(b"".join(fragments + [payload]).decode("utf-8"))
        except ValueError:
            fragments = []
            continue
        fragments = []
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg
        # A response to another id (or a notification) is dropped: the client
        # is strictly one outstanding request per session.


class _CdpSession:
    """One WebSocket session to one target, one outstanding request at a time.

    The session is the unit of lifetime: every tool call opens its own, so a
    long-lived DevTools socket is never shared between calls and a crashed
    session cannot poison the next one.
    """

    def __init__(self, entry: dict[str, Any], path: str) -> None:
        sock = socket.create_connection(
            (str(entry["bind"]), int(entry["host_port"])), timeout=_TIMEOUT_S)
        try:
            self._sock = sock
            self._reader = _SockReader(sock)
            self._next_id = 1
            self._handshake(entry, path)
        except BaseException:
            # A constructor that fails must not leak the socket (and the relay
            # bridge behind it): `with` never binds the object, so __exit__
            # never runs and closure would otherwise depend on refcount GC.
            _close(sock)
            raise

    def _handshake(self, entry: dict[str, Any], path: str) -> None:
        host = f"{entry['bind']}:{entry['host_port']}"
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(request.encode("ascii"))
        head = self._reader.read_until(b"\r\n\r\n", timeout=_TIMEOUT_S)
        if head is None:
            raise ConnectionError("the DevTools endpoint closed during the "
                                  "WebSocket handshake")
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0]:
            raise ConnectionError(
                f"the WebSocket upgrade was refused: {lines[0]!r}")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        if headers.get("sec-websocket-accept", "").lower() != _accept_key(key).lower():
            raise ConnectionError(
                "the WebSocket handshake answer does not match the key — the "
                "bytes were not carried intact through the relay")

    def call(self, method: str, params: dict | None = None) -> dict:
        """One CDP command; a protocol error answer raises ValueError."""
        msg_id = self._next_id
        self._next_id += 1
        _ws_send(self._sock, {"id": msg_id, "method": method,
                              "params": params or {}})
        reply = _ws_recv(self._reader, self._sock, msg_id)
        if "error" in reply:
            err = reply.get("error") or {}
            detail = err.get("message") or json.dumps(err)[:200]
            raise ValueError(f"{method} was refused by the endpoint: {detail}")
        return reply

    def close(self) -> None:
        _close(self._sock)

    def __enter__(self) -> _CdpSession:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# relay lookup
# ---------------------------------------------------------------------------


def _prune_snapshots() -> None:
    with _SNAP_LOCK:
        dead = [k for k in _SNAPSHOTS if relay.lookup_entry(k) is None]
        for key in dead:
            _SNAPSHOTS.pop(key, None)


def _require_relay(cfg, relay_id: str, owner: str | None = None) -> dict[str, Any]:
    """The live tcp relay entry this call addresses, or a refusal.

    The `relay` policy category is the gate (AC5) and it fires BEFORE the
    registry is consulted: a disabled relay category must not answer as an
    existence oracle for relay ids.
    """
    policy.require_category(
        cfg, "relay",
        f"relay CDP traffic into the guest behind {relay_id!r}")
    entry = relay.lookup_entry(relay_id)
    if entry is None or entry.get("in_flight"):
        raise ValueError(f"unknown relay_id {relay_id!r}")
    if owner is not None and entry.get("owner") != owner:
        raise ValueError(f"unknown relay_id {relay_id!r}")
    if entry.get("stopped"):
        raise ValueError(f"relay {relay_id!r} is stopped")
    if entry.get("kind") != "tcp":
        raise ValueError(
            f"relay {relay_id!r} is kind {entry.get('kind')!r}; the CDP "
            "channel needs the byte-stream relay (start one with "
            "kind='tcp')")
    return entry


def _http_get(entry: dict[str, Any], path: str) -> tuple[int, bytes]:
    """One plain HTTP GET carried over the relay's raw byte stream."""
    sock = socket.create_connection(
        (str(entry["bind"]), int(entry["host_port"])), timeout=_TIMEOUT_S)
    try:
        reader = _SockReader(sock)
        host = f"{entry['bind']}:{entry['host_port']}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii"))
        head = reader.read_until(b"\r\n\r\n", timeout=_TIMEOUT_S)
        if head is None:
            raise ConnectionError(
                "the guest endpoint closed before answering the HTTP request")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        length = headers.get("content-length", "")
        if length.isdigit():
            body = reader.read_exact(int(length), timeout=_TIMEOUT_S) or b""
        else:
            body = reader.read_to_eof(timeout=_TIMEOUT_S)
        return status, body
    finally:
        _close(sock)


def _json_listing(entry: dict[str, Any]) -> list[dict]:
    """The DevTools target listing, rewritten to ride the relay's listener.

    A stock client reads its socket URL from the listing, so the
    guest-loopback host:port is replaced with the relay's own — that is what
    makes the returned `webSocketDebuggerUrl` dialable from the host.
    """
    status, body = _http_get(entry, "/json/list")
    if status != 200:
        raise ValueError(
            f"the DevTools target listing answered HTTP {status}")
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise ValueError("the DevTools target listing is not JSON") from exc
    if not isinstance(data, list):
        raise ValueError("the DevTools target listing is not a list")
    host = f"{entry['bind']}:{entry['host_port']}"
    out: list[dict] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        url = str(item.get("webSocketDebuggerUrl") or "")
        if url:
            parsed = urllib.parse.urlsplit(url)
            item["webSocketDebuggerUrl"] = urllib.parse.urlunsplit(
                (parsed.scheme or "ws", host, parsed.path, parsed.query, ""))
        out.append(item)
    return out


def _target_path(entry: dict[str, Any], target_id: str) -> str:
    """The WebSocket path of `target_id` in the live listing.

    Discovery only: a target that is not listed is refused, never created
    (AC11). The browser-level target is never dialled either — the four
    tools address page targets.
    """
    for row in _json_listing(entry):
        if str(row.get("id") or "") == target_id:
            url = str(row.get("webSocketDebuggerUrl") or "")
            path = urllib.parse.urlsplit(url).path
            if path:
                return path
    raise ValueError(
        f"unknown target_id {target_id!r}: the DevTools listing does not "
        "carry it (the tools never create targets)")


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def targets(cfg, relay_id: str, *, owner: str | None = None) -> dict:
    """List the attached application's DevTools targets (AC11: read-only)."""
    _prune_snapshots()
    entry = _require_relay(cfg, relay_id, owner)
    listing = _json_listing(entry)
    return {"ok": True, "relay_id": relay_id,
            "targets": [
                {"id": str(row.get("id") or ""),
                 "type": str(row.get("type") or ""),
                 "title": str(row.get("title") or ""),
                 "url": str(row.get("url") or ""),
                 "webSocketDebuggerUrl": str(row.get("webSocketDebuggerUrl") or "")}
                for row in listing
            ]}


def evaluate(cfg, relay_id: str, target_id: str, expression: str,
             *, owner: str | None = None) -> dict:
    """Run one expression in the target and return its value (AC3)."""
    _prune_snapshots()
    entry = _require_relay(cfg, relay_id, owner)
    if not str(expression or "").strip():
        raise ValueError("expression must not be empty")
    path = _target_path(entry, target_id)
    with _CdpSession(entry, path) as session:
        reply = session.call("Runtime.evaluate",
                             {"expression": expression, "returnByValue": True})
    result = reply.get("result") or {}
    if not isinstance(result, dict):
        raise ValueError("Runtime.evaluate answered without a result object")
    if result.get("exceptionDetails"):
        details = result["exceptionDetails"]
        text = (details.get("text") if isinstance(details, dict) else None) or str(details)
        raise ValueError(f"the expression threw: {text[:300]}")
    value = result.get("result")
    value = value.get("value") if isinstance(value, dict) else value
    capped = _cap_value(value)
    return {"ok": True, "relay_id": relay_id, "target_id": target_id,
            "value": capped["value"], "truncated": capped["truncated"]}


def input_event(cfg, relay_id: str, target_id: str, x: float | None = None,
                y: float | None = None, ref: str = "",
                *, owner: str | None = None) -> dict:
    """Dispatch a click at a coordinate, or at a snapshot ref's box centre.

    A ref must resolve to a node that is STILL in the target's live
    accessibility tree; otherwise the call is refused with
    `error_class "stale_ref"` and nothing is dispatched (AC10).
    """
    _prune_snapshots()
    entry = _require_relay(cfg, relay_id, owner)
    path = _target_path(entry, target_id)
    if ref:
        node_id = _ref_node_id(relay_id, target_id, ref)
        with _CdpSession(entry, path) as session:
            if node_id is None:
                # A ref no snapshot ever minted: the caller must look again.
                return _stale_ref(relay_id, target_id, ref)
            # The ref is re-validated against the LIVE tree before anything is
            # dispatched: a page that dropped the node makes the ref stale,
            # and a stale ref must reach the guest as nothing at all (AC10).
            live = _live_nodes(
                session.call("Accessibility.getFullAXTree"))
            node = live.get(str(node_id or ""))
            if node is None:
                return _stale_ref(relay_id, target_id, ref)
            session.call("DOM.scrollIntoViewIfNeeded",
                         {"nodeId": node.get("backendDOMNodeId")})
            quads = (session.call("DOM.getContentQuads",
                                  {"nodeId": node.get("backendDOMNodeId")})
                     .get("result") or {}).get("quads") or []
            if not quads:
                raise ValueError(
                    "the node has no content box: it is not laid out (hidden, "
                    "or not in the viewport)")
            cx, cy = _box_centre(quads[0])
            for kind in ("mousePressed", "mouseReleased"):
                session.call("Input.dispatchMouseEvent",
                             {"type": kind, "x": cx, "y": cy,
                              "button": "left", "clickCount": 1})
        return {"ok": True, "relay_id": relay_id, "target_id": target_id,
                "ref": ref, "x": cx, "y": cy}
    if x is None or y is None:
        raise ValueError(
            "give x and y for a coordinate click, or ref for a click on a "
            "snapshot node")
    with _CdpSession(entry, path) as session:
        for kind in ("mousePressed", "mouseReleased"):
            session.call("Input.dispatchMouseEvent",
                         {"type": kind, "x": float(x), "y": float(y),
                          "button": "left", "clickCount": 1})
    return {"ok": True, "relay_id": relay_id, "target_id": target_id,
            "x": float(x), "y": float(y)}


def snapshot(cfg, relay_id: str, target_id: str,
             *, owner: str | None = None) -> dict:
    """One accessibility snapshot: every node with a ref, plus text lines.

    The refs minted here are the addresses `input_event(ref=...)` accepts
    until the next snapshot of the same target.
    """
    _prune_snapshots()
    entry = _require_relay(cfg, relay_id, owner)
    path = _target_path(entry, target_id)
    with _CdpSession(entry, path) as session:
        reply = session.call("Accessibility.getFullAXTree")
    nodes = (reply.get("result") or {}).get("nodes") or []
    if not isinstance(nodes, list):
        raise ValueError("Accessibility.getFullAXTree answered without nodes")
    out: list[dict] = []
    refs: dict[str, Any] = {}
    lines: list[str] = []
    for index, raw in enumerate(nodes, start=1):
        if not isinstance(raw, dict):
            continue
        node_id = str(raw.get("nodeId") or "")
        role = str((raw.get("role") or {}).get("value") or "")
        name = str((raw.get("name") or {}).get("value") or "")
        props = {
            str(p.get("name") or ""): p.get("value")
            for p in (raw.get("properties") or [])
            if isinstance(p, dict) and str(p.get("name") or "")
        }
        digest = hashlib.sha256(
            f"{node_id}#{index}".encode("utf-8", "replace")).hexdigest()[:10]
        ref = f"ax-{index}-{digest}"
        # The ref addresses the node by its nodeId: the live-tree validation
        # in input_event looks the node up by exactly that, and takes the
        # backendDOMNodeId from the node it finds (the value can move between
        # snapshots even while the nodeId is stable).
        refs[ref] = node_id
        out.append({"ref": ref, "role": role, "name": name,
                    "backendDOMNodeId": raw.get("backendDOMNodeId"),
                    "properties": props})
        lines.append(_render_line(index, role, name, props))
    with _SNAP_LOCK:
        _SNAPSHOTS.setdefault(relay_id, {})[target_id] = {"refs": refs}
    return {"ok": True, "relay_id": relay_id, "target_id": target_id,
            "nodes": out, "lines": lines}


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _cap_value(value: Any) -> dict[str, Any]:
    """Apply the documented size cap to a returned expression value.

    The cap is BYTES of UTF-8, not Python characters: a 1 MiB cap measured in
    characters lets a 2 MiB multi-byte payload through under the name of the
    same number. A string is capped on its own encoding. A non-string value is
    serialized first and capped as its JSON text, because that is the form the
    caller receives — an object that does not fit comes back as a truncated
    JSON PREFIX, which is exactly why `truncated` exists (the caller asks for
    a narrower expression rather than parsing half an object).
    """
    if isinstance(value, str):
        encoded = value.encode("utf-8", "replace")
        if len(encoded) <= _MAX_VALUE_BYTES:
            return {"value": value, "truncated": False}
        # Cut on a character boundary so the caller never receives half a
        # code point.
        return {"value": encoded[:_MAX_VALUE_BYTES].decode(
            "utf-8", "ignore"), "truncated": True}
    try:
        text = json.dumps(value, separators=(",", ":"))
    except (TypeError, ValueError):
        text = str(value)
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= _MAX_VALUE_BYTES:
        return {"value": value, "truncated": False}
    return {"value": text.encode("utf-8", "replace")[:_MAX_VALUE_BYTES].decode(
        "utf-8", "ignore"), "truncated": True}


def _box_centre(quad: Any) -> tuple[float, float]:
    """The centre of a CDP content quad (four x,y corners, flat)."""
    if not isinstance(quad, (list, tuple)) or len(quad) < 8:
        raise ValueError("the endpoint returned no usable content quad")
    xs = [float(v) for v in quad[0::2]]
    ys = [float(v) for v in quad[1::2]]
    return (min(xs) + max(xs)) / 2.0, (min(ys) + max(ys)) / 2.0


def _ref_node_id(relay_id: str, target_id: str, ref: str) -> Any:
    """The node id a ref addresses in the target's latest snapshot."""
    with _SNAP_LOCK:
        state = _SNAPSHOTS.get(relay_id, {}).get(target_id) or {}
        return state.get("refs", {}).get(ref)


def _live_nodes(reply: dict) -> dict[str, dict]:
    """The target's current accessibility nodes, keyed by nodeId."""
    nodes = (reply.get("result") or {}).get("nodes") or []
    if not isinstance(nodes, list):
        return {}
    return {str(n.get("nodeId") or ""): n
            for n in nodes if isinstance(n, dict)}


def _stale_ref(relay_id: str, target_id: str, ref: str) -> dict:
    """The stale-ref refusal.

    A MODULE envelope rather than a raise, so its own error_class survives the
    tool wrapper's classify taxonomy — the same passthrough hyperv_ui_act
    relies on. It is returned BEFORE any input is dispatched.
    """
    return {"ok": False,
            "error_class": "stale_ref",
            "error": (
                f"ref {ref!r} does not resolve in the live accessibility tree "
                f"of target {target_id!r} — take a fresh "
                "hyperv_cdp_snapshot and re-address the node by its new ref"),
            "relay_id": relay_id, "target_id": target_id}


def _render_line(index: int, role: str, name: str, props: dict) -> str:
    """One compact line: index, role, name and the node's boolean state."""
    state = " ".join(
        f"{key}={'true' if value else 'false'}" if isinstance(value, bool)
        else f"{key}={value}"
        for key, value in sorted(props.items())
    )
    head = f"{index}. {role or 'node'} {name!r}"
    return f"{head} [{state}]" if state else head
