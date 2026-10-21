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
relay_stop/EVICTION/process exit; stop nulls the field and cap-time
eviction nulls an evicted entry's field before deleting it.

Ownership and listener auth (issue #11): a relay belongs to the agent
that started it (`owner`, the bearer token's client_id; None = the
unattributed local principal on stdio/anonymous/direct-module paths) —
status/stop from a different agent get the SAME `unknown relay_id`
response as an absent id, and listings show only the caller's own relays.
Each relay start mints a per-relay secret (>=128 bits, secrets.token_urlsafe)
returned ONLY inside the starting agent's `relay_start` result, embedded
in the returned url as a capability path prefix (`/<secret>/`). The
listener verifies and strips that prefix (constant-time, byte-wise)
before any forwarding; any other request gets 401 with the connection
closed and no PowerShell leg. The secret never appears in relay_status
rows (their urls are identifiers, not request-capable), logs, or audit
rows, and is stripped before the guest-side URL is built.

Registry discipline (issue #11, mirroring guestjobs): the registry is
capped at _MAX_RELAYS, the duplicate-target check and an in-flight
placeholder reservation share ONE critical section (concurrent duplicate
starts admit exactly one — the loser is rejected before binding), the
listener binds outside the lock and a bind failure releases the
placeholder, and stopped entries are evicted oldest-first at reservation
time (credential nulled before delete).

Identity (issue #8): relay_start resolves the target ONCE via
vmident.resolve and stores the resolved GUID (`vm_id`) alongside the
display name; every per-request leg builds its guest script from that
stored GUID, so a VM rename after start can never retarget the relay, and
the duplicate-relay check compares the resolved GUID (plus guest_port),
not the mutable name.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import consolebench, credentials, policy, pswindows, statestore, vmident
from .config import Config
from .credentials import CredentialError, CredentialSet
from .diagnostics import build_guest_script

_LOOPBACK_BINDS = {"127.0.0.1", "localhost", "::1"}
_MAX_BODY_BYTES = 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Remote-mode single-hop caps: a base64'd request AND its base64'd response
# must each fit one WS-Man envelope (~500 KiB default) with headroom.
_REMOTE_BODY_BYTES = 192 * 1024
_REMOTE_RESPONSE_BYTES = 192 * 1024
_REQUEST_TIMEOUT_S = 30
_MAX_RELAYS = 16

# Process-local write-through cache by design (issue #22): the authoritative
# copy of anything whose lifetime exceeds this process lives in the durable
# state store, and this dict is the fast in-process view of it. It stays a real
# dict because existing tests read and poke it directly.
_relays: dict[str, dict[str, Any]] = {}
_relays_lock = threading.Lock()


def _store(cfg: Config) -> statestore.Store:
    """The durable store for this config, cached per process by resolved path."""
    return statestore.store_for(cfg)


def _cred_ref(cred: CredentialSet | None) -> str:
    """The credential reference a row records. Never the secret itself."""
    if cred is None:
        return "inline"
    return str(getattr(cred, "source", "inline") or "inline")


def _row(entry: dict[str, Any], state: str) -> statestore.RelayRow:
    """Project a registry entry onto a store row. The per-relay secret and the
    live credential are deliberately absent: neither is ever persisted."""
    return statestore.RelayRow(
        relay_id=str(entry["relay_id"]),
        vm_name=str(entry.get("vm_name") or ""),
        vm_id=str(entry.get("vm_id") or ""),
        guest_port=int(entry.get("guest_port") or 0),
        bind=str(entry.get("bind") or "127.0.0.1"),
        host_port=int(entry.get("host_port") or 0),
        started_at=str(entry.get("started_at") or ""),
        state=state,
        cred_ref=str(entry.get("cred_ref") or _cred_ref(entry.get("context", {}).get("cred"))),
        owner=entry.get("owner"),
    )


class _DeadThread:
    """Stand-in `thread` for a restored relay: it has no listener, so it is
    never alive. Exists so a status row's shape is identical whether the relay
    is live in this process or restored from the store."""

    def is_alive(self) -> bool:
        return False


def _restored_entry(cfg: Config, row: statestore.RelayRow,
                    owner: str | None) -> dict[str, Any] | None:
    """Rebuild a process-local entry from a persisted row (issue #22).

    Returns None for an absent row and for a foreign one, so the caller raises
    the SAME `unknown relay_id` ValueError either way — no existence oracle.
    The synthesized context is never used to serve a request: an interrupted
    relay has no listener.
    """
    if owner is not None and (row.owner or None) != owner:
        return None
    cred = None
    if row.cred_ref != "inline":
        try:
            cred = credentials.resolve_guest()
        except CredentialError:
            # A restored relay's credential is only needed to STOP it, and a
            # stop of an interrupted relay performs no guest leg. Leave it None
            # and let the request path (which no longer exists) be the only
            # thing that would have needed it.
            cred = None
    context: dict[str, Any] = {
        "cfg": cfg,
        "vm_name": row.vm_name,
        "vm_id": row.vm_id,
        "guest_port": row.guest_port,
        "cred": cred,
        "secret": "",
        "counters": _new_counters(),
        "latency": _new_latency(),
        "counter_lock": threading.Lock(),
        "relay_id": row.relay_id,
    }
    return {
        "relay_id": row.relay_id,
        "vm_name": row.vm_name,
        "vm_id": row.vm_id,
        "guest_port": row.guest_port,
        "bind": row.bind,
        "host_port": row.host_port,
        "server": None,
        "thread": _DeadThread(),
        "context": context,
        "owner": row.owner,
        "started_at": row.started_at,
        "stopped": row.state == statestore.RELAY_STOPPED,
        "row_state": row.state,
        "cred_ref": row.cred_ref,
    }


def _restore_relay(cfg: Config, relay_id: str,
                   owner: str | None) -> dict[str, Any] | None:
    """Rebuild a relay entry from a persisted row, or None if there is none.

    A restored relay's listener is gone by construction, so the row's persisted
    state is normalized to `interrupted` here unless it was already stopped.
    """
    row = _store(cfg).relay_get(relay_id)
    if row is None:
        return None
    entry = _restored_entry(cfg, row, owner)
    if entry is None:
        return None
    if entry.get("row_state") == statestore.RELAY_ACTIVE:
        entry["row_state"] = statestore.RELAY_INTERRUPTED
    return entry


def _restored_rows(cfg: Config, owner: str | None) -> list[dict[str, Any]]:
    """Every store row this principal may see, as restored entries."""
    out: list[dict[str, Any]] = []
    for row in _store(cfg).relay_rows():
        if row.state == statestore.RELAY_STOPPED:
            continue
        entry = _restored_entry(cfg, row, owner)
        if entry is not None:
            out.append(entry)
    return out


def _row_state(store: statestore.Store, relay_id: str) -> str:
    """A store row's state, or "" when there is no row (in-memory only)."""
    row = store.relay_get(relay_id)
    return row.state if row is not None else ""


def _started_at(entry: dict[str, Any] | None, store: statestore.Store,
                relay_id: str) -> str:
    """Oldest-first eviction key across the union of the two views."""
    if entry is not None:
        return str(entry.get("started_at") or "")
    row = store.relay_get(relay_id)
    return row.started_at if row is not None else ""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def clear_registry_for_tests() -> None:
    """Test seam: stop and drop all relay entries (unit suites call this)."""
    with _relays_lock:
        entries = list(_relays.values())
        _relays.clear()
    for entry in entries:
        _shutdown_server(entry)


def peek_vm_name(relay_id: str, cfg: Config | None = None) -> str:
    """Read-only vm_name lookup for audit rows (issue #10).

    Unlike the inline get-and-raise in relay_status/relay_stop this never
    raises: an unknown, empty, or in-flight placeholder id reads as ""
    (an honest absence — the issue #11 guard keeps placeholder state out
    of any audit row, mirroring guestjobs.peek_vm_name), so a relay call's
    audit row can name the VM even when the tool leg itself fails.
    Read-only by design — it never touches credentials or stop state.
    """
    key = relay_id or ""
    with _relays_lock:
        entry = _relays.get(key)
    if entry is not None:
        if entry.get("in_flight"):
            return ""
        return str(entry.get("vm_name") or "")
    # issue #22: after a restart the entry only exists in the store, and the
    # pre-dispatch audit path still wants to name the VM.
    if cfg is not None:
        row = _store(cfg).relay_get(key)
        if row is not None:
            return str(row.vm_name or "")
    return ""


def _shutdown_server(entry: dict[str, Any]) -> None:
    server = entry.get("server")
    thread = entry.get("thread")
    if server is not None:
        try:
            server.shutdown()
        except Exception:
            pass
        try:
            # Separate from shutdown(): a shutdown failure must not skip
            # the only close of the listening socket (PR review round 2,
            # PRR-008).
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


#: How many request latencies a relay keeps. A fixed-capacity ring, so a
#: long-lived relay cannot grow the store without bound: `deque(maxlen=...)`
#: evicts the oldest sample on append, which makes the bound structural rather
#: than a check that could drift from the implementation.
_LATENCY_CAP = 1024


def _new_latency() -> dict[str, Any]:
    """A relay's per-request latency store.

    The store is a bounded ring of the guest leg's elapsed milliseconds. It is
    guarded by the SAME lock the counters already use — the ambient
    `counter_lock`, not one this function hands back — so no new lock is
    introduced and the lock ordering is unchanged.
    """
    return {"samples": deque(maxlen=_LATENCY_CAP), "cap": _LATENCY_CAP}


# -- per-request PS Direct leg ------------------------------------------------

_FORWARD_HEADER_ALLOWLIST = ("accept", "authorization", "user-agent")


def _forward_script(guest_port: int, method: str, path: str,
                    headers: dict[str, str], body: bytes,
                    response_cap: int = _MAX_RESPONSE_BYTES) -> str:
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
    $headersJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($headersB64))
    ($headersJson | ConvertFrom-Json).PSObject.Properties | ForEach-Object {{ $h[$_.Name] = [string]$_.Value }}
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
    if ($resp.RawContentStream.Length -gt {int(response_cap)}) {{ throw 'guest response exceeds relay limit' }}
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


def _run_forward(cfg, script: str, cred: CredentialSet) -> dict:
    """relay's guest-leg choke (issue #43): composes the remote hop from the
    relay's start-time cfg before spawning; identity in local mode."""
    script, stdin = pswindows.compose_remote(
        cfg, script, payload_lines=1, stdin_b64=pswindows.utf8_b64(cred.password),
    )
    result = pswindows.run_ps(
        script, timeout_s=_REQUEST_TIMEOUT_S + 20,
        stdin_b64=stdin,
    )
    # The elapsed time rides along on EVERY return path, so the handler can
    # attribute it to this relay whichever way the leg ended. It is deliberately
    # NOT part of the payload the caller sees.
    duration_ms = int(result.duration_ms)
    if result.timed_out:
        return {
            "error": "guest request timed out", "status": 0,
            "_duration_ms": duration_ms,
        }
    try:
        pswindows.check_result(result)
        payload = json.loads(result.stdout.strip() or "{}")
    except Exception as exc:
        return {
            "error": pswindows.redact(str(exc)), "status": 0,
            "_duration_ms": duration_ms,
        }
    payload["_duration_ms"] = duration_ms
    return payload


# -- HTTP listener -------------------------------------------------------------


class _RelayHandler(BaseHTTPRequestHandler):
    """Forwarding handler; `context` is set per relay via a subclass."""

    context: dict[str, Any]
    protocol_version = "HTTP/1.1"
    # Socket-level timeout (StreamRequestHandler.setup applies it): a client
    # that stalls mid-request cannot park a handler thread forever (review
    # round: slowloris / threads surviving relay_stop).
    timeout = _REQUEST_TIMEOUT_S

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # keep stderr quiet; counters replace logs

    def _bump(self, key: str, amount: int = 1) -> None:
        with self.context["counter_lock"]:
            self.context["counters"][key] += amount

    def _record_request(self, ok: bool, duration_ms: int) -> None:
        """Record one COMPLETED guest leg: its outcome counter and its latency.

        Every leg that RAN is recorded, whichever way it ended — a guest
        404/500, a transport failure and a PS Direct timeout all contribute a
        sample. Recording only the successes would leave p95 and p99
        structurally blind to exactly the slow tail issue #88 was opened to
        expose.

        `counters.requests` is bumped before the listener guards, so a request
        rejected at the guard — a missing or wrong secret (401), a
        non-path-absolute target (400), a bad Content-Length (400), an
        oversized body (413) or a relay stopped mid-flight (503) — is counted
        but contributes NO sample, because no guest leg ran and there is no
        duration to attribute. So `latency.samples` counts guest-leg attempts,
        not requests: it equals `counters.requests` only when nothing was
        rejected at the guard, and it is bounded by `counters.ok +
        counters.errors` in general.

        The counter and the sample are updated under ONE lock acquisition, so a
        `relay_status` snapshot taken between them cannot observe the counter
        incremented while the sample is still missing.

        The duration is `PSResult.duration_ms`, which the guest leg already
        computes and which issue #20's collector already reads everywhere else
        — the relay was the one path that discarded it, because its per-request
        legs run outside any `auditlog.operation`.
        """
        with self.context["counter_lock"]:
            self.context["counters"]["ok" if ok else "errors"] += 1
            self.context["latency"]["samples"].append(int(duration_ms))

    def _reply(
        self, status: int, payload: bytes, content_type: str, *, close: bool = False,
    ) -> None:
        if close:
            # Error paths may leave an unread request body buffered; keeping
            # the connection alive would let those bytes be parsed as the
            # NEXT request (desync / request smuggling past the guards —
            # review round 2, N1). Close instead of draining untrusted input.
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Hyperv-Relay", self.context["relay_id"])
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _reply_error(self, status: int, message: str) -> None:
        self._bump("errors")
        self._reply(
            status,
            json.dumps({"ok": False, "error": message}).encode("utf-8"),
            "application/json",
            close=True,
        )

    def _forward(self) -> None:
        ctx = self.context
        self._bump("requests")
        try:
            # Capability check FIRST (issue #11): the caller must present
            # the relay's secret as the first url path segment, exactly as
            # relay_start returned it (url = http://<bind>:<port>/<secret>/).
            # The segment is compared byte-wise and constant-time (a
            # str-vs-str compare_digest would raise TypeError on a
            # non-ASCII segment — request targets are latin-1-decoded and
            # attacker-chosen — and surface as 502 instead of 401).
            # Anything else is rejected with the connection closed and NO
            # guest leg. The remainder (everything after the secret's
            # closing slash, VERBATIM — never re-slash-joined) then flows
            # through the existing path-absolute / chunked / Content-Length
            # guards unchanged: an appended path brings its own leading
            # slash, so `url + "/json/version"` forwards as
            # `/json/version`, while a smuggled `@host` target still 400s.
            raw = self.path
            first_slash = raw.find("/", 1)
            if first_slash == -1:
                supplied, remainder = raw[1:], ""
            else:
                # The secret segment closes at first_slash; everything
                # AFTER it is the verbatim remainder (url + "/path"
                # arrivals carry their own leading slash there, so the
                # forwarded path is byte-identical to a bare-path request
                # against the pre-#11 listener).
                supplied, remainder = raw[1:first_slash], raw[first_slash + 1:]
            if (not supplied or not remainder or not secrets.compare_digest(
                supplied.encode("utf-8"), str(ctx["secret"]).encode("utf-8"),
            )):
                self._reply_error(401, "relay secret required")
                return
            self.path = remainder
            # The relay forwards ONLY path-absolute targets. An
            # authority-form target ("GET @evil.example/ HTTP/1.1") or an
            # absolute-form URL would let a caller steer the guest-side
            # request to an attacker-chosen host via userinfo tricks
            # (review round 1, critical): reject before building anything.
            if not self.path.startswith("/"):
                self._reply_error(400, "only path-absolute targets are forwarded")
                return
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                self._reply_error(
                    411, "chunked bodies are not supported; send Content-Length",
                )
                return
            body = b""
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0:
                # A negative Content-Length would make rfile.read() block
                # until EOF (review round 3 question, adopted).
                self._reply_error(400, "invalid Content-Length")
                return
            if length:
                if length > _MAX_BODY_BYTES:
                    self._reply_error(413, "body exceeds relay limit")
                    return
                if length > _REMOTE_BODY_BYTES and pswindows.hyperv_host(ctx["cfg"]):
                    # Remote mode: the whole body crosses one WS-Man hop;
                    # keep it under the ~500 KiB MaxEnvelopeSizeKB instead of
                    # failing mid-forward with an opaque transport error.
                    self._reply_error(
                        413,
                        "body exceeds the remote-mode relay limit "
                        f"({_REMOTE_BODY_BYTES} bytes); use local mode for "
                        "large payloads",
                    )
                    return
                body = self.rfile.read(length)
            headers = {
                k: v for k, v in self.headers.items()
                if k.lower() in _FORWARD_HEADER_ALLOWLIST or k.lower() == "content-type"
            }
            inner = _forward_script(
                ctx["guest_port"], self.command, self.path, headers, body,
                response_cap=(
                    _REMOTE_RESPONSE_BYTES
                    if pswindows.hyperv_host(ctx["cfg"])
                    else _MAX_RESPONSE_BYTES
                ),
            )
            cred = ctx["cred"]
            if cred is None:
                # relay_stop nulled the credential while this request was in
                # flight; answer with a clean signal instead of leaking the
                # internal AttributeError from psdirect_prefix.
                self._reply_error(503, "relay is stopped")
                return
            script = build_guest_script(ctx["vm_id"], inner, cred, ctx["cfg"])
            self._bump("bytes_in", len(body))
            outcome = _run_forward(ctx["cfg"], script, cred)
        except Exception as exc:
            self._reply_error(502, str(exc))
            return
        if "error" in outcome:
            err = outcome.get("error", "")
            guest_status = int(outcome.get("status") or 0)
            detail = json.dumps({"ok": False, "error": err, "guest_status": guest_status})
            # A guest-side HTTP error passes its real status through (a
            # DevTools-style 404 reaches the caller as 404); transport
            # failures surface as 502. Both close: the envelope path does
            # not mirror the caller's framing guarantees.
            self._record_request(False, outcome.get("_duration_ms") or 0)
            self._reply(
                guest_status if guest_status > 0 else 502,
                detail.encode("utf-8"), "application/json", close=True,
            )
            return
        self._record_request(True, outcome.get("_duration_ms") or 0)
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
    vm_name: str = "",
    guest_port: int = 0,
    vm_id: str = "",
    *,
    host_port: int = 0,
    bind: str = "127.0.0.1",
    cred: CredentialSet | None = None,
    owner: str | None = None,
) -> dict:
    """Start a loopback HTTP relay to the guest's 127.0.0.1:guest_port.

    The VM may be addressed by `vm_name` or `vm_id` (exactly one required;
    vmident.resolve enforces identity and policy). The stored GUID addresses
    every per-request leg, and the duplicate check compares it, so renames
    never fork or retarget a relay.

    Issue #11: `owner` records the starting agent (None = the unattributed
    local principal); the returned `url` is a capability URL embedding the
    relay's per-relay secret (`/<secret>/` prefix) — the ONLY place the
    secret is ever returned. The duplicate check and the registry
    reservation share one critical section, so concurrent duplicate starts
    admit exactly one (the loser is rejected before binding); the registry
    is capped at _MAX_RELAYS and stopped entries are evicted oldest-first
    (credential nulled) to make room.
    """
    if cred is None:
        raise ValueError("guest credentials are required")
    if not 1 <= int(guest_port) <= 65535:
        raise ValueError("guest_port must be 1..65535")
    if not 0 <= int(host_port) <= 65535:
        raise ValueError("host_port must be 0..65535 (0 = ephemeral)")
    if bind.lower() not in _LOOPBACK_BINDS:
        raise ValueError(f"refusing non-loopback bind {bind!r}: the relay is loopback-only")
    policy.require_category(cfg, "relay", f"relay HTTP requests into guest '{vm_name or vm_id}'")
    # Resolve once (VM policy runs inside vmident.resolve on the governing
    # name — caller-supplied or resolved from the GUID).
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)

    relay_id = f"relay-{guest_port}-{secrets.token_hex(16)}"
    secret = secrets.token_urlsafe(16)

    # ONE critical section owns the duplicate check AND the reservation
    # (issue #11, FND-10): the in-flight placeholder counts as a live
    # target for the duplicate scan (stopped entries skipped) and against
    # the cap, so two concurrent starts for the same vm/port admit exactly
    # one — the loser raises here, before binding anything. At capacity,
    # stopped entries are evicted oldest-first (credential nulled before
    # delete, mirroring guestjobs._reserve_slot).
    # Issue #22: the store write transaction is the OUTER lock and
    # `_relays_lock` the inner one — the process-wide order that keeps a
    # concurrent register or stop from deadlocking against this path. The cap
    # counts the UNION of the in-memory view and the store rows, because
    # separate stdio server processes share one store and tests inject entries
    # straight into `_relays`.
    store = _store(cfg)
    with store.transaction():
        with _relays_lock:
            for entry in _relays.values():
                if not entry.get("stopped") and entry["vm_id"] == ref.id \
                        and entry["guest_port"] == guest_port:
                    raise ValueError(
                        f"a relay to {ref.name}:{guest_port} already exists ({entry['relay_id']})"
                    )
            known = set(_relays) | {r.relay_id for r in store.relay_rows()}
            if len(known) >= _MAX_RELAYS:
                # A key present LOCALLY is judged on its local stopped flag.
                # A key with NO local entry is judged on its store row, and is
                # evictable when that row is stopped OR interrupted: its
                # listener died with a previous process, nothing can bring it
                # back, and leaving it would let 16 restarts permanently fill
                # the cap. Consulting the store for a key that IS local would
                # evict a relay whose listener is alive here, because a peer's
                # open() flips this process's active rows to `interrupted`
                # (implementation review, round 2).
                def _evictable(key: str) -> bool:
                    entry = _relays.get(key)
                    if entry is not None:
                        return bool(entry.get("stopped"))
                    return _row_state(store, key) in (
                        statestore.RELAY_STOPPED, statestore.RELAY_INTERRUPTED,
                    )

                evictable = sorted(
                    (k for k in known if _evictable(k)),
                    key=lambda k: _started_at(_relays.get(k), store, k),
                )
                for key in evictable[: max(1, len(known) - _MAX_RELAYS + 1)]:
                    evicted = _relays.get(key)
                    if evicted is not None:
                        evicted["context"]["cred"] = None
                        del _relays[key]
                    store.relay_delete(key)
                    known.discard(key)
            if len(known) >= _MAX_RELAYS:
                raise RuntimeError(
                    f"relay registry is full ({_MAX_RELAYS} active relays); "
                    "stop relays before starting more"
                )
            started_at = _utc_now_iso()
            _relays[relay_id] = {
                "relay_id": relay_id,
                "vm_name": ref.name,
                "vm_id": ref.id,
                "guest_port": int(guest_port),
                "owner": owner,
                "in_flight": True,
                "started_at": started_at,
                "stopped": False,
            }
            store.relay_upsert(statestore.RelayRow(
                relay_id=relay_id, vm_name=ref.name, vm_id=ref.id,
                guest_port=int(guest_port), bind=bind,
                started_at=started_at, state=statestore.RELAY_ACTIVE,
                cred_ref=_cred_ref(cred), owner=owner,
            ))

    def _release() -> None:
        with _relays_lock:
            current = _relays.get(relay_id)
            if current is not None and current.get("in_flight"):
                del _relays[relay_id]
        # Registry lock released first: store-lock is the outer order. A
        # stranded row would be invisible to status, unstoppable, cap-consuming
        # and would block this vm:guest_port forever via the duplicate scan.
        store.relay_delete(relay_id)

    try:
        context: dict[str, Any] = {
            "cfg": cfg,
            "vm_name": ref.name,
            "vm_id": ref.id,
            "guest_port": int(guest_port),
            "cred": cred,
            "secret": secret,
            "counters": _new_counters(),
            "latency": _new_latency(),
            "counter_lock": threading.Lock(),
        }
        handler = type("BoundRelayHandler", (_RelayHandler,), {"context": context})
        context["relay_id"] = relay_id
        server = _RelayServer((bind, int(host_port)), handler)
        thread = threading.Thread(
            target=server.serve_forever, name=f"hyperv-relay-{relay_id}", daemon=True,
        )
    except OSError as exc:
        _release()
        raise RuntimeError(f"could not bind {bind}:{host_port or 0}: {exc}") from None
    except BaseException:
        # Context/handler/thread construction and the bind itself sit inside
        # the release window: any failure here (Thread constructor under
        # resource exhaustion, a non-OSError from the server constructor)
        # must not strand the in-flight placeholder (PR review round 2,
        # NEW-B). A bound socket that never started serving dies with the
        # frame on CPython.
        _release()
        raise
    try:
        thread.start()
        entry = {
            "relay_id": relay_id,
            "vm_name": ref.name,
            "vm_id": ref.id,
            "guest_port": int(guest_port),
            "bind": bind,
            "host_port": server.server_address[1],
            "server": server,
            "thread": thread,
            "context": context,
            "owner": owner,
            "started_at": _utc_now_iso(),
            "stopped": False,
        }
        with _relays_lock:
            _relays[relay_id] = entry
        # Registry lock released first: store-lock is the outer order.
        store.relay_upsert(_row(entry, statestore.RELAY_ACTIVE))
    except BaseException:
        # No exception between the reservation and the registration may
        # strand the in-flight placeholder (it is invisible to status,
        # unstoppable, and would consume a cap slot and block this
        # vm:guest_port forever via the duplicate scan — implementation
        # review round 1, Finding 1, widened to the construction window by
        # PR-review round 2, NEW-B) nor leak the bound socket. server_close
        # (not shutdown: a failed start never entered serve_forever, and
        # shutdown would wait on a loop that will never run) releases the
        # listener; the placeholder release mirrors guestjobs job_start's
        # reserve-to-register window.
        _release()
        try:
            server.server_close()
        except Exception:
            pass
        raise
    host_port_actual = entry["host_port"]
    return {
        "ok": True,
        "relay_id": relay_id,
        "vm_name": ref.name,
        "guest_port": int(guest_port),
        "bind": bind,
        "host_port": host_port_actual,
        # Capability URL (issue #11): the per-relay secret rides as the
        # first path segment; requests without it get 401 at the listener.
        "url": f"http://{bind}:{host_port_actual}/{secret}/",
        "started_at": entry["started_at"],
    }


def relay_status(cfg: Config, relay_id: str = "", *, owner: str | None = None) -> dict:
    """List the calling principal's relays (or one by id).

    Issue #11: a non-None owner sees only its OWN relays — a foreign or
    unknown id is the SAME `unknown relay_id` ValueError, and in-flight
    placeholders (starts still binding) are invisible. None (stdio/
    anonymous/direct module calls) is the unattributed local principal
    and skips the ownership filter. Row urls are IDENTIFIERS: the
    capability secret appears only in the starting agent's relay_start
    result.
    """
    # The store is read with _relays_lock RELEASED: the process-wide order is
    # store-lock > registry-lock, and taking Store._lock under _relays_lock
    # deadlocks AB-BA against relay_start's reservation (implementation review,
    # round 1). The local view is read under the lock, then the store, then the
    # lock again only to consult the local view — mirroring guestjobs._lookup.
    with _relays_lock:
        local = dict(_relays)
    if relay_id:
        entry = local.get(relay_id)
        if entry is None:
            # issue #22: the entry died with a previous process. A row that is
            # not in the LOCAL registry is reported interrupted — its listener
            # died with the process that started it, because this process did
            # not start it. The fallback fires ONLY on local absence: an
            # in-flight placeholder (a start still binding) is invisible here
            # exactly as at base, and an owner mismatch stays `unknown`.
            entry = _restore_relay(cfg, relay_id, owner)
            if entry is None:
                raise ValueError(f"unknown relay_id {relay_id!r}")
        elif entry.get("in_flight") or (
            owner is not None and entry.get("owner") != owner
        ):
            raise ValueError(f"unknown relay_id {relay_id!r}")
        selected = [entry]
    else:
        selected = [
            e for e in local.values()
            if not e.get("in_flight")
            and (owner is None or e.get("owner") == owner)
        ]
        # Union with the store's non-stopped rows, deduplicated by relay_id
        # with the local entry taking priority, so a relay restored after a
        # restart is visible rather than silently omitted and a relay that is
        # mid-bind in this process is not double-counted. `local_ids` is the RAW
        # local key set, not the filtered selection: a mid-bind placeholder is
        # invisible in `selected`, and excluding only the filtered set would
        # publish its store row as a ghost with a dead thread while by-id
        # answers `unknown relay_id` for the very same id.
        local_ids = set(local)
        selected.extend(
            e for e in _restored_rows(cfg, owner)
            if e["relay_id"] not in local_ids
        )
    rows = []
    for entry in selected:
        with entry["context"]["counter_lock"]:
            counters = dict(entry["context"]["counters"])
            # Snapshot only. `list(deque)` is atomic with respect to appends
            # under the GIL, so the copy is consistent without holding the lock
            # for the O(n log n) percentile work below — the lock is on the
            # request hot path, and `relay_status` is a reporting path.
            latency_samples = list(entry["context"]["latency"]["samples"])
            latency_cap = entry["context"]["latency"]["cap"]
        latency = _latency_summary(latency_samples, latency_cap)
        restored = entry.get("row_state") not in (None, statestore.RELAY_ACTIVE)
        rows.append({
            "relay_id": entry["relay_id"],
            "vm_name": entry["vm_name"],
            "guest_port": entry["guest_port"],
            "bind": entry["bind"],
            "host_port": entry["host_port"],
            "url": f"http://{entry['bind']}:{entry['host_port']}/",
            "started_at": entry["started_at"],
            "stopped": bool(entry["stopped"]),
            "thread_alive": False if restored else bool(entry["thread"].is_alive()),
            "counters": counters,
            # Additive: the existing `counters` contract is unchanged, exactly
            # as issue #20's `timing` object was additive to the audit record.
            "latency": latency,
            # Additive (issue #22): a restored relay's listener is gone, so the
            # row says so instead of leaving the caller to infer it from
            # thread_alive on a relay it can no longer reach.
            "state": ("stopped" if entry.get("stopped")
                      else "interrupted" if restored else "active"),
        })
    return {"ok": True, "relays": rows}


def _latency_summary(samples: list[int], cap: int) -> dict[str, Any]:
    """Percentiles over a relay's recorded request latencies.

    Takes an already-snapshotted sample list and the published cap, and holds
    no lock: the caller snapshots under `counter_lock` and computes outside it,
    so the percentile work never extends the lock's hold time.

    Nearest-rank, reusing `consolebench.pct` so the relay and the soak
    benchmark cannot drift on what a percentile means. An empty store reports
    nulls rather than zeros, so "no requests yet" is distinguishable from
    "requests were instantaneous". The nulls mean specifically that no request
    has been RECORDED — see `_record_request`, which records every completed
    request including the errored ones.
    """
    if not samples:
        return {
            "cap": cap, "samples": 0,
            "p50_ms": None, "p95_ms": None, "p99_ms": None,
        }
    return {
        "cap": cap,
        "samples": len(samples),
        "p50_ms": consolebench.pct(samples, 0.50),
        "p95_ms": consolebench.pct(samples, 0.95),
        "p99_ms": consolebench.pct(samples, 0.99),
    }


def relay_stop(cfg: Config, relay_id: str, *, owner: str | None = None) -> dict:
    """Stop a relay: close the loopback listener and release the stored
    credentials. Issue #11: a non-None owner may stop only its OWN relay
    — a foreign or unknown id is the SAME `unknown relay_id` ValueError
    (no existence oracle); an in-flight placeholder (start still binding)
    is invisible. The stopped entry stays in the registry (visible as
    stopped in relay_status) until cap-time eviction."""
    if not relay_id:
        raise ValueError("relay_id is required")
    # Same lock discipline as relay_status: read the local view under the
    # lock, release, then read the store. No store call runs while
    # _relays_lock is held.
    with _relays_lock:
        entry = _relays.get(relay_id)
    if entry is None:
        # issue #22: a relay restored from the store has no listener to shut
        # down; report it as already stopped rather than unknown. Only local
        # absence falls through — an in-flight placeholder stays invisible and
        # an owner mismatch stays `unknown`.
        entry = _restore_relay(cfg, relay_id, owner)
        if entry is None:
            raise ValueError(f"unknown relay_id {relay_id!r}")
        already = bool(entry["stopped"])
        entry["stopped"] = True
    else:
        if entry.get("in_flight") or (
            owner is not None and entry.get("owner") != owner
        ):
            raise ValueError(f"unknown relay_id {relay_id!r}")
        # The read and the write are ONE critical section, so exactly one of
        # two racing stops observes already=False (issue #11, PRR-027b). The
        # store is not touched here: store-lock is the outer order, and taking
        # it under _relays_lock is the deadlock round 1 found.
        with _relays_lock:
            already = bool(entry["stopped"])
            entry["stopped"] = True
    recorded_ref = entry.get("cred_ref") or _cred_ref(
        entry.get("context", {}).get("cred")
    )
    if not already:
        _shutdown_server(entry)
        with _relays_lock:
            entry["context"]["cred"] = None
        # Registry lock released first: store-lock is the outer order. An
        # interrupted relay has no listener, so its shutdown is a no-op. The
        # reference is captured before the live credential is nulled, so the
        # persisted provenance is not silently rewritten to "inline".
        row = _row(entry, statestore.RELAY_STOPPED)
        _store(cfg).relay_upsert(statestore.RelayRow(
            **{**row.as_dict(), "cred_ref": recorded_ref}
        ))
    return {
        "ok": True,
        "relay_id": relay_id,
        "host_port": entry["host_port"],
        "stopped": True,
        **({"note": "was already stopped"} if already else {}),
    }
