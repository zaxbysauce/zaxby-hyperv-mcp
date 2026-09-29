"""Host-to-guest HTTP relay over PowerShell Direct (AC12, plan D2a).

A loopback-only host listener forwards each HTTP request through one PS
Direct Invoke-WebRequest to http://127.0.0.1:<guest_port><path> INSIDE the
guest — reaching guest-local endpoints (DevTools HTTP APIs, test web
servers) with zero dependence on the guest's external addresses and with no
guest-side component. HTTP only: WebSocket / raw TCP proxying is out of
scope (disclosed in the README).

Lock policy: the relay lifecycle tools are audited tool calls, but the
per-request PS Direct legs deliberately SKIP vm_lock (pinned in the plan) —
a proxied request must not fail because an unrelated tool call holds the
VM. Credential lifetime: the stored credential set lives until
relay_stop/eviction/process exit; stop nulls the field.
"""

from __future__ import annotations

import base64
import json
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import policy, pswindows
from .config import Config
from .credentials import CredentialSet
from .diagnostics import build_guest_script

_LOOPBACK_BINDS = {"127.0.0.1", "localhost", "::1"}
_MAX_BODY_BYTES = 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_REQUEST_TIMEOUT_S = 30

_relays: dict[str, dict[str, Any]] = {}
_relays_lock = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def clear_registry_for_tests() -> None:
    """Test seam: stop and drop all relay entries (unit suites call this)."""
    with _relays_lock:
        entries = list(_relays.values())
        _relays.clear()
    for entry in entries:
        _shutdown_server(entry)


def _shutdown_server(entry: dict[str, Any]) -> None:
    server = entry.get("server")
    thread = entry.get("thread")
    if server is not None:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)


def _new_counters() -> dict[str, int]:
    return {
        "requests": 0, "ok": 0, "errors": 0,
        "bytes_in": 0, "bytes_out": 0,
    }


# -- per-request PS Direct leg ------------------------------------------------

_FORWARD_HEADER_ALLOWLIST = ("accept", "authorization", "user-agent")


def _forward_script(guest_port: int, method: str, path: str,
                    headers: dict[str, str], body: bytes) -> str:
    url = f"http://127.0.0.1:{guest_port}{path}"
    fwd_headers = {
        k: v for k, v in headers.items()
        if k.lower() in _FORWARD_HEADER_ALLOWLIST
    }
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v
            break
    headers_b64 = pswindows.utf8_b64(json.dumps(fwd_headers))
    body_b64 = base64.b64encode(body).decode("ascii") if body else ""
    return f"""
$headersB64 = '{headers_b64}'
$bodyB64 = '{body_b64}'
$method = {pswindows.ps_quote(method.upper())}
$url = {pswindows.ps_quote(url)}
$contentType = {pswindows.ps_quote(content_type)}
try {{
    $h = @{{}}
    ($headersB64 | ConvertFrom-Json).PSObject.Properties | ForEach-Object {{ $h[$_.Name] = [string]$_.Value }}
    $body = $null
    if ($bodyB64 -ne '') {{ $body = [Convert]::FromBase64String($bodyB64) }}
    $sp = @{{
        Uri          = $url
        Method       = $method
        Headers      = $h
        Body         = $body
        UseBasicParsing = $true
        TimeoutSec   = {_REQUEST_TIMEOUT_S}
        ErrorAction  = 'Stop'
    }}
    if ($contentType -ne '') {{ $sp['ContentType'] = $contentType }}
    $resp = Invoke-WebRequest @sp
    $ct = ''
    if ($resp.Headers -and $resp.Headers['Content-Type']) {{ $ct = [string]$resp.Headers['Content-Type'] }}
    if ($resp.RawContentStream.Length -gt {int(_MAX_RESPONSE_BYTES)}) {{ throw 'guest response exceeds relay limit' }}
    $bytes = $resp.RawContentStream.ToArray()
    [PSCustomObject]@{{
        status      = [int]$resp.StatusCode
        content_type = $ct
        body_b64    = [Convert]::ToBase64String($bytes)
    }} | ConvertTo-Json -Compress
}} catch {{
    $sc = 0
    if ($null -ne $_.Exception.Response) {{ $sc = [int]$_.Exception.Response.StatusCode }}
    [PSCustomObject]@{{ error = $_.Exception.Message; status = $sc }} | ConvertTo-Json -Compress
}}
""".strip()


def _run_forward(script: str, cred: CredentialSet) -> dict:
    result = pswindows.run_ps(
        script, timeout_s=_REQUEST_TIMEOUT_S + 20,
        stdin_b64=pswindows.utf8_b64(cred.password),
    )
    if result.timed_out:
        return {"error": "guest request timed out", "status": 0}
    try:
        pswindows.check_result(result)
        return json.loads(result.stdout.strip() or "{}")
    except Exception as exc:
        return {"error": pswindows.redact(str(exc)), "status": 0}


# -- HTTP listener -------------------------------------------------------------


class _RelayHandler(BaseHTTPRequestHandler):
    """Forwarding handler; `context` is set per relay via a subclass."""

    context: dict[str, Any]
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # keep stderr quiet; counters replace logs

    def _bump(self, key: str, amount: int = 1) -> None:
        with self.context["counter_lock"]:
            self.context["counters"][key] += amount

    def _reply(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Hyperv-Relay", self.context["relay_id"])
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _forward(self) -> None:
        ctx = self.context
        self._bump("requests")
        try:
            # The relay forwards ONLY path-absolute targets. An
            # authority-form target ("GET @evil.example/ HTTP/1.1") or an
            # absolute-form URL would let a caller steer the guest-side
            # request to an attacker-chosen host via userinfo tricks
            # (review round 1, critical): reject before building anything.
            if not self.path.startswith("/"):
                self._bump("errors")
                self._reply(
                    400,
                    b'{"ok":false,"error":"only path-absolute targets are forwarded"}',
                    "application/json",
                )
                return
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                self._bump("errors")
                self._reply(
                    411,
                    b'{"ok":false,"error":"chunked bodies are not supported; send Content-Length"}',
                    "application/json",
                )
                return
            body = b""
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                if length > _MAX_BODY_BYTES:
                    self._bump("errors")
                    self._reply(413, b'{"ok":false,"error":"body exceeds relay limit"}',
                                "application/json")
                    return
                body = self.rfile.read(length)
            headers = {
                k: v for k, v in self.headers.items()
                if k.lower() in _FORWARD_HEADER_ALLOWLIST or k.lower() == "content-type"
            }
            inner = _forward_script(
                ctx["guest_port"], self.command, self.path, headers, body,
            )
            script = build_guest_script(ctx["vm_name"], inner, ctx["cred"])
            self._bump("bytes_in", len(body))
            outcome = _run_forward(script, ctx["cred"])
        except Exception as exc:
            self._bump("errors")
            self._reply(502, json.dumps({"ok": False, "error": str(exc)}).encode(),
                        "application/json")
            return
        if "error" in outcome:
            self._bump("errors")
            err = outcome.get("error", "")
            guest_status = int(outcome.get("status") or 0)
            detail = json.dumps({"ok": False, "error": err, "guest_status": guest_status})
            # A guest-side HTTP error passes its real status through (a
            # DevTools-style 404 reaches the caller as 404); transport
            # failures surface as 502.
            self._reply(guest_status if guest_status > 0 else 502,
                        detail.encode(), "application/json")
            return
        self._bump("ok")
        payload = base64.b64decode(outcome.get("body_b64") or "")
        self._bump("bytes_out", len(payload))
        self._reply(
            int(outcome.get("status") or 502),
            payload,
            str(outcome.get("content_type") or "application/octet-stream"),
        )

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def do_PUT(self) -> None:
        self._forward()

    def do_DELETE(self) -> None:
        self._forward()

    def do_PATCH(self) -> None:
        self._forward()

    def do_HEAD(self) -> None:
        self._forward()

    def do_OPTIONS(self) -> None:
        self._forward()


class _RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# -- public API ------------------------------------------------------------------


def relay_start(
    cfg: Config,
    vm_name: str,
    guest_port: int,
    *,
    host_port: int = 0,
    bind: str = "127.0.0.1",
    cred: CredentialSet | None = None,
) -> dict:
    """Start a loopback HTTP relay to the guest's 127.0.0.1:guest_port."""
    if not vm_name:
        raise ValueError("vm_name is required")
    if cred is None:
        raise ValueError("guest credentials are required")
    if not 1 <= int(guest_port) <= 65535:
        raise ValueError("guest_port must be 1..65535")
    if not 0 <= int(host_port) <= 65535:
        raise ValueError("host_port must be 0..65535 (0 = ephemeral)")
    if bind.lower() not in _LOOPBACK_BINDS:
        raise ValueError(f"refusing non-loopback bind {bind!r}: the relay is loopback-only")
    policy.vm_allowed(cfg, vm_name)
    policy.require_category(cfg, "relay", f"relay HTTP requests into guest '{vm_name}'")

    with _relays_lock:
        for entry in _relays.values():
            if not entry.get("stopped") and entry["vm_name"].casefold() == vm_name.casefold() \
                    and entry["guest_port"] == guest_port:
                raise ValueError(
                    f"a relay to {vm_name}:{guest_port} already exists ({entry['relay_id']})"
                )

    context: dict[str, Any] = {
        "cfg": cfg,
        "vm_name": vm_name,
        "guest_port": int(guest_port),
        "cred": cred,
        "counters": _new_counters(),
        "counter_lock": threading.Lock(),
    }
    handler = type("BoundRelayHandler", (_RelayHandler,), {"context": context})
    try:
        server = _RelayServer((bind, int(host_port)), handler)
    except OSError as exc:
        raise RuntimeError(f"could not bind {bind}:{host_port or 0}: {exc}") from None
    relay_id = f"relay-{guest_port}-{uuid.uuid4().hex[:8]}"
    context["relay_id"] = relay_id
    thread = threading.Thread(
        target=server.serve_forever, name=f"hyperv-relay-{relay_id}", daemon=True,
    )
    thread.start()
    entry = {
        "relay_id": relay_id,
        "vm_name": vm_name,
        "guest_port": int(guest_port),
        "bind": bind,
        "host_port": server.server_address[1],
        "server": server,
        "thread": thread,
        "context": context,
        "started_at": _utc_now_iso(),
        "stopped": False,
    }
    with _relays_lock:
        _relays[relay_id] = entry
    return {
        "ok": True,
        "relay_id": relay_id,
        "vm_name": vm_name,
        "guest_port": int(guest_port),
        "bind": bind,
        "host_port": entry["host_port"],
        "url": f"http://{bind}:{entry['host_port']}",
        "started_at": entry["started_at"],
    }


def relay_status(cfg: Config, relay_id: str = "") -> dict:
    with _relays_lock:
        if relay_id:
            entry = _relays.get(relay_id)
            if entry is None:
                raise ValueError(f"unknown relay_id {relay_id!r}")
            selected = [entry]
        else:
            selected = list(_relays.values())
    rows = []
    for entry in selected:
        with entry["context"]["counter_lock"]:
            counters = dict(entry["context"]["counters"])
        rows.append({
            "relay_id": entry["relay_id"],
            "vm_name": entry["vm_name"],
            "guest_port": entry["guest_port"],
            "bind": entry["bind"],
            "host_port": entry["host_port"],
            "url": f"http://{entry['bind']}:{entry['host_port']}",
            "started_at": entry["started_at"],
            "stopped": bool(entry["stopped"]),
            "thread_alive": bool(entry["thread"].is_alive()),
            "counters": counters,
        })
    return {"ok": True, "relays": rows}


def relay_stop(cfg: Config, relay_id: str) -> dict:
    if not relay_id:
        raise ValueError("relay_id is required")
    with _relays_lock:
        entry = _relays.get(relay_id)
        if entry is None:
            raise ValueError(f"unknown relay_id {relay_id!r}")
        already = bool(entry["stopped"])
        entry["stopped"] = True
    if not already:
        _shutdown_server(entry)
        with _relays_lock:
            entry["context"]["cred"] = None
    return {
        "ok": True,
        "relay_id": relay_id,
        "host_port": entry["host_port"],
        "stopped": True,
        **({"note": "was already stopped"} if already else {}),
    }
