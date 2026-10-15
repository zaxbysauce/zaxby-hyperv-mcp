"""Thin stdio -> streamable-HTTP proxy: the shared-controller front door.

ENH-09 (issue #13): every MCP client that launches `hyperv-mcp` used to get a
complete private server (own per-VM locks, job/relay registries, audit sink).
In the default deployment this module instead bridges the client's stdio
transport to the ONE shared streamable-HTTP controller (`hyperv-mcp-http`),
so coordination primitives cover every agent. The proxy performs no Hyper-V
work: it calls no bootstrap(), registers no tools, touches no pswindows, and
holds no locks or registries of its own — it forwards MCP messages unchanged
in both directions, authenticated with the agent's own token.

Failure contract (frozen by tests/unit/test_b03_stdio_proxy.py): a pending
request never waits forever — an unreachable controller (connection refused)
or a mid-session disconnect turns into a JSON-RPC error (code -32000) for
each outstanding request id, names the token environment variable on stderr
(rejections only), never echoes the token, and the proxy exits non-zero.
Connection failures surface as a RAISED exception group when the upstream
client context unwinds (probe-verified: post failures cancel the transport
task group and re-raise at its boundary), so the emit path is driven from
that raised group as well as from exception items on the upstream read
stream and from failures inside the client->upstream reader task itself.

A REJECTED token (HTTP 401/403) no longer surfaces as a status-bearing
exception: mcp 2.x collapses any non-2xx response into a generic JSON-RPC
error delivered on the read stream, which the proxy forwards to the client
(the code is the SDK's INTERNAL_ERROR, not -32000) and annotates with a
one-line stderr hint naming the token environment variable. The status-based
classification is not recoverable at this layer; the hint is the operator
signal. See README "Shared controller" for the user-facing wording.

Tokens come only from the environment: the variable named by
`http.token_env`, or — when `http.agents` is configured — the single set
agent variable (exactly one; more than one is a refusal, because the child
could not know which principal it presents). A missing token is NOT a
refusal: the proxy simply presents no Authorization header and the
controller's 401 becomes the standard error reply. Auto-start additionally
requires every configured agent variable to be present in the environment
(the spawned controller validates them all at startup), so a partial set
fails fast with a named-variable refusal instead of a 15 s port timeout.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

import anyio
import httpx2
from mcp.client.streamable_http import streamable_http_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
)

EXIT_TRANSPORT_FAILURE = 1
PROXY_ERROR_CODE = -32000
# The frozen AC1/AC2 contract answers outstanding ids within 10 s: connect
# failures must surface well inside that window. read=None because the
# transport's GET stream is a long-lived SSE — a finite read timeout would
# kill idle sessions; the pinned failure modes are connect/status failures
# on the POST path.
UPSTREAM_CONNECT_TIMEOUT_S = 5.0
UPSTREAM_WRITE_TIMEOUT_S = 30.0
# One budget for the WHOLE auto-start (spawn + listen wait): the 15 s in the
# README and the operator message is a wall-clock deadline, not per-phase.
AUTOSTART_WAIT_S = 15.0
LISTEN_PROBE_TIMEOUT_S = 0.5
# The controller log resets when it outgrows this (bounded retention; a
# detached controller's stderr is unbounded by nature).
MAX_CONTROLLER_LOG_BYTES = 5 * 1024 * 1024

if sys.version_info >= (3, 11):
    BaseExceptionGroupType = BaseExceptionGroup  # noqa: F821 - 3.11 builtin
else:  # pragma: no cover - 3.10 path; the backport ships with anyio
    from exceptiongroup import BaseExceptionGroup as BaseExceptionGroupType  # type: ignore[attr-defined,no-redef] # noqa: I001


_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000

# Fixed source for the WMI-branch logging wrapper: Win32_Process.Create
# cannot redirect stdio, so the WMI-created process is a tiny python that
# re-spawns the controller with stdout/stderr bound to the per-user log file.
# argv contract: python -c <this> <controller_python> <host> <port> <log_path>
# (sys.argv[1..4] from -c's perspective: ['-c', python, host, port, log]).
_WMI_LOG_WRAPPER = "\n".join([
    "import os, subprocess, sys",
    "log = open(sys.argv[4], 'a', encoding='utf-8', errors='replace')",
    "subprocess.Popen([sys.argv[1], '-m', 'hyperv_mcp.http_entry', '--host', sys.argv[2], '--port', sys.argv[3]],",
    "                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,",
    "                 env=dict(os.environ),",
    "                 creationflags=0x00000008 | 0x00000200 | 0x08000000)",
])


class ProxyRefused(Exception):
    """Operator-facing refusal (bad URL, ambiguous agent identity,
    auto-start precondition or failure).

    The message is printed to stderr; it must never contain token material.
    """


def is_loopback_host(host: str) -> bool:
    """True for any loopback host: the literal localhost or any 127/8/::1
    address (ipaddress.is_loopback covers the whole loopback range)."""
    if not host:
        return False
    if host.strip("[]").lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _connect_host(host: str) -> str:
    """The address a client should CONNECT to for a controller bound to
    host. A wildcard bind (0.0.0.0 / ::) is reachable over loopback, and a
    loopback connect keeps the cleartext-allowed path intact."""
    bare = host.strip("[]")
    if bare in ("0.0.0.0", "0"):
        return "127.0.0.1"
    if bare in ("::", "::0"):
        return "::1"
    return bare


def default_controller_url(host: str, port: int) -> str:
    """The controller URL for default (no --proxy) mode, derived from the
    configured bind address: wildcard binds map to loopback and IPv6
    literals get the brackets urlparse requires."""
    target = _connect_host(host)
    if ":" in target and not target.startswith("["):
        target = f"[{target}]"
    return f"http://{target}:{port}/mcp"


def validate_proxy_url(url: str) -> str:
    """Refuse anything but a well-formed http(s) controller URL; cleartext
    http is loopback-only because the bearer token would otherwise cross the
    network in cleartext, and embedded userinfo (user:pass@) is refused so
    credentials never ride the URL into stderr diagnostics. Returns the URL
    unchanged when acceptable."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ProxyRefused(f"invalid controller URL {url!r}: {exc}") from None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProxyRefused(
            f"invalid controller URL {url!r}: expected http://host:port/mcp "
            "or https://host:port/mcp"
        )
    if parsed.username or parsed.password:
        raise ProxyRefused(
            "controller URLs must not embed credentials (user:pass@host); "
            "the proxy takes its token from the environment only, and a "
            "credential in the URL would be echoed to stderr on failure"
        )
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname or ""):
        raise ProxyRefused(
            f"refusing cleartext http:// to non-loopback host {parsed.hostname!r}: "
            "the bearer token would leave this machine unencrypted; use a "
            "loopback controller address over http, or https:// for any "
            "remote host"
        )
    return url


def resolve_proxy_token(cfg) -> tuple[str | None, str]:
    """Resolve the bearer token the proxy presents, from the environment
    only. Returns (token_or_None, source_env_var_name).

    When http.agents is configured, the proxy identifies as exactly ONE
    agent: the single agent env var present in the environment. None set
    falls through to the legacy shared token_env variable; more than one is
    a refusal (ambiguous identity — the controller could not attribute this
    proxy's rows). A missing token is not an error here: the proxy presents
    no Authorization header and the controller's 401 becomes the standard
    error reply. Token values are never logged, echoed, or embedded in
    errors.
    """
    agents = getattr(cfg.http, "agents", None) or {}
    if agents:
        present = [
            (agent_id, env_name)
            for agent_id, env_name in sorted(agents.items())
            if os.environ.get(env_name, "").strip()
        ]
        if len(present) > 1:
            names = ", ".join(f"{agent_id} ({env_name})" for agent_id, env_name in present)
            raise ProxyRefused(
                "multiple agent token environment variables are set "
                f"({names}); a proxy must present exactly one agent's "
                "token, so unset all but one"
            )
        if len(present) == 1:
            agent_id, env_name = present[0]
            return os.environ[env_name].strip(), env_name
    env_name = cfg.http.token_env
    value = os.environ.get(env_name, "").strip()
    return (value or None), env_name


def port_listening(host: str, port: int, timeout_s: float = LISTEN_PROBE_TIMEOUT_S) -> bool:
    """Whether a TCP listener accepts connections at the connect target for
    this (possibly wildcard) bind address right now."""
    try:
        with socket.create_connection((_connect_host(host), port), timeout=timeout_s):
            return True
    except OSError:
        return False


def ensure_controller(cfg) -> None:
    """Start the shared controller detached from this process tree and wait
    (bounded by one wall-clock AUTOSTART_WAIT_S budget) for its port. The
    child inherits THIS process's environment — including the token
    variables — but never carries token material on its command line (only
    --host/--port). Concurrent first launches converge: the bind loser exits
    cleanly and this proxy connects to the winner once its port accepts.
    Explicit --proxy invocations never reach this path.

    The controller MUST survive this proxy's death: the client library's
    stdio shutdown wraps the proxy in a kill-on-terminate Job Object and
    terminates the whole job when the proxy outlives stdin, and JOB
    MEMBERSHIP IS INHERITED — a controller spawned directly by this process
    would be job members and die with it (probe-verified 2026-10-12,
    DETACHED_PROCESS notwithstanding). Two mechanisms sever that link:
    CREATE_BREAKAWAY_FROM_JOB when the job permits it, else creation via
    WMI Win32_Process.Create, whose children belong to the WMI service —
    outside this job entirely — with the environment carried in the CIM
    startup block (no token ever on a command line). Every spawn failure
    (timeout, OSError, unbreakable job, WMI refusal, unwritable log dir)
    surfaces as ProxyRefused so main() can print one clean operator error
    instead of a traceback, and the controller's stdout/stderr always lands
    in the per-user log file on BOTH spawn branches. In http.agents mode
    every agent variable must already be in this environment (the spawned
    controller validates them at startup), so a partial set fails fast here
    rather than timing out the port wait; outside agents mode the shared
    http.token_env variable must already be set, because the spawned
    controller inherits this environment and dies immediately without it —
    refusing here turns a guaranteed spawn-death loop into one clean error.
    Callers probe the port first (server.main does); this function assumes
    it is not listening and is not re-entrant against a live controller."""
    agents = getattr(cfg.http, "agents", None) or {}
    if agents:
        missing = sorted(
            {env_name for env_name in agents.values() if not os.environ.get(env_name, "").strip()}
        )
        if missing:
            note = (
                "start hyperv-mcp-http manually from a shell that has the "
                "agent token variable set"
            )
            if len(agents) > 1:
                # resolve_proxy_token also refuses a proxy environment with
                # more than one agent var set (ambiguous identity), so a
                # multi-agent deployment cannot satisfy both sides at once:
                # auto-start is unsupported there, by design.
                note = (
                    "auto-start is unsupported with multiple agents: the "
                    "controller requires every agent token variable while a "
                    "proxy may present exactly one — start hyperv-mcp-http "
                    "manually from a shell that has all of them"
                )
            raise ProxyRefused(
                "auto-start with http.agents requires every agent token "
                f"variable in this environment; missing: {', '.join(missing)}. "
                f"{note}"
            )
    if not agents and not os.environ.get(cfg.http.token_env, "").strip():
        # The spawned controller inherits THIS environment and refuses to
        # start without its token variable, so a tokenless spawn is a
        # guaranteed immediate death: every client reconnect would repeat
        # it (observed as an 87-spawn failure storm in one day), each
        # attempt a fresh process this side of the port wait. Fail fast
        # with the variable name instead; a controller started MANUALLY
        # with --allow-anonymous is unaffected because auto-start only
        # runs while the port is not listening.
        raise ProxyRefused(
            f"auto-start needs {cfg.http.token_env} set in this environment: "
            "the controller refuses to start without it, so the spawn would "
            "die immediately. Generate a token "
            '(python -c "import secrets; print(secrets.token_urlsafe(32))") '
            "and export it in this session; persist it for this user with "
            f"setx {cfg.http.token_env} YOUR-TOKEN (setx applies to new "
            "processes only); or start hyperv-mcp-http manually from a "
            "shell that has it. If a manually started controller "
            "(e.g. --allow-anonymous) is still coming up, wait for it to "
            "bind or pass --proxy. Token values are never printed or "
            "logged."
        )
    deadline = time.monotonic() + AUTOSTART_WAIT_S
    log_path = _controller_log_path(cfg.http.port)
    host = cfg.http.host
    port = str(cfg.http.port)
    if os.name != "nt":
        # No job-object inheritance on POSIX: plain detached spawn.
        try:
            log = open(log_path, "a", encoding="utf-8", errors="replace")  # noqa: SIM115 - lives for the detached child
        except OSError as exc:
            raise ProxyRefused(f"cannot open the controller log {log_path}: {exc}") from None
        try:
            subprocess.Popen(  # noqa: S603 - fixed argv, no shell, no secrets in argv
                [sys.executable, "-m", "hyperv_mcp.http_entry",
                 "--host", host, "--port", port],
                stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, env=dict(os.environ),
                start_new_session=True,
            )
        except OSError as exc:
            log.close()
            raise ProxyRefused(f"could not spawn the controller process: {exc}") from None
        try:
            log.close()
        except OSError:
            pass
        while time.monotonic() < deadline:
            if port_listening(host, int(port)):
                return
            time.sleep(0.25)
        raise ProxyRefused(_autostart_timeout_message(host, port))
    spawner = "\n".join([
        "import base64, os, subprocess, sys",
        "host, port, log_path = sys.argv[1], sys.argv[2], sys.argv[3]",
        "wrapper = sys.argv[4]",
        "argv = [sys.executable, '-m', 'hyperv_mcp.http_entry', '--host', host, '--port', port]",
        "log = open(log_path, 'a', encoding='utf-8', errors='replace')",
        "try:",
        f"    flags = {_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW | _CREATE_BREAKAWAY_FROM_JOB}",
        "    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,",
        "                     stderr=subprocess.STDOUT, env=dict(os.environ),",
        "                     creationflags=flags)",
        "    print('breakaway')",
        "except OSError:",
        "    # The job forbids breakaway (mcp's stdio job uses default flags).",
        "    # Create a WMI-launched LOGGING WRAPPER via Win32_Process.Create:",
        "    # the WMI service is outside this job, so the wrapper — and the",
        "    # controller it re-spawns with stdout/stderr bound to the log —",
        "    # never become job members. The environment (token variables",
        "    # included) rides in the CIM startup block; the command line is",
        "    # only python -c <wrapper source> python host port log (the",
        "    # wrapper source itself contains no secrets).",
        "    wmi_argv = [sys.executable, '-c', wrapper, sys.executable, host, port, log_path]",
        "    cmdline = subprocess.list2cmdline(wmi_argv)",
        "    ps = '\\n'.join([",
        "        \"$ErrorActionPreference = 'Stop'\",",
        "        \"$cmd = '\" + cmdline.replace(\"'\", \"''\") + \"'\",",
        "        \"$envs = [string[]](Get-ChildItem env: | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })\",",
        "        \"$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ ShowWindow = [UInt16]0; EnvironmentVariables = $envs }\",",
        "        \"$out = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd; ProcessStartupInformation = $startup }\",",
        "        \"if ($out.ReturnValue -ne 0) { throw ('WMI Create failed: ' + $out.ReturnValue) }\",",
        "        \"Write-Output 'wmi'\",",
        "    ])",
        "    encoded = base64.b64encode(ps.encode('utf-16-le')).decode('ascii')",
        "    run = subprocess.run(['powershell', '-NoProfile', '-EncodedCommand', encoded],",
        "                         capture_output=True, text=True)",
        "    if not (run.stdout or '').strip().endswith('wmi'):",
        "        raise SystemExit('WMI spawn failed: ' + (run.stderr or run.stdout or '')[-300:])",
        "    print('wmi')",
    ])
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no secrets in argv
            [sys.executable, "-c", spawner, host, port, log_path, _WMI_LOG_WRAPPER],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ),
            creationflags=_CREATE_NO_WINDOW,
            timeout=max(1.0, deadline - time.monotonic()),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ProxyRefused(
            f"the controller spawner did not finish within {AUTOSTART_WAIT_S:.0f}s "
            f"(WMI/CIM hung?); check the controller log for this port"
        ) from None
    except OSError as exc:
        raise ProxyRefused(f"could not launch the controller spawner: {exc}") from None
    marker = ((result.stdout or "").strip().splitlines() or [""])[-1].strip()
    if marker not in ("wmi", "breakaway"):
        # The spawner could not sever job inheritance; say so loudly instead
        # of shipping a controller that dies with this client.
        detail = (result.stderr or result.stdout or "no output").strip()[-400:]
        raise ProxyRefused(
            "could not auto-start the controller outside this client's job "
            f"object: {detail}"
        )
    while time.monotonic() < deadline:
        if port_listening(cfg.http.host, cfg.http.port):
            return
        time.sleep(0.25)
    raise ProxyRefused(_autostart_timeout_message(cfg.http.host, str(cfg.http.port)))


def _autostart_timeout_message(host: str, port: str) -> str:
    return (
        f"the auto-started controller did not accept connections on "
        f"{host}:{port} within {AUTOSTART_WAIT_S:.0f}s; check the "
        f"controller log for this port and start hyperv-mcp-http manually "
        f"if needed"
    )


def _controller_log_path(port: int) -> str:
    base = ""
    try:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.getcwd()
        log_dir = os.path.join(base, "hyperv-mcp")
        os.makedirs(log_dir, exist_ok=True)
    except OSError as exc:
        raise ProxyRefused(
            f"cannot create the controller log directory under {base!r}: {exc}"
        ) from None
    path = os.path.join(log_dir, f"http-controller-{port}.log")
    try:
        if os.path.getsize(path) > MAX_CONTROLLER_LOG_BYTES:
            os.remove(path)  # bounded retention: start fresh, never rotate secrets
    except OSError:
        pass  # absent or locked: never block auto-start on a size hint
    return path


def _request_id_of(message: SessionMessage):
    """The JSON-RPC message a SessionMessage carries, across SDK shapes.

    mcp 1.x wrapped every message in a JSONRPCMessage union model whose
    `.root` held the concrete request/response/error. mcp 2.x made
    JSONRPCMessage a plain type union and its transports carry the concrete
    message directly, so the wrapper level is gone (issue #16)."""
    inner = getattr(message, "message", None)
    return getattr(inner, "root", None) or inner


def _error_reply(request_id, note: str) -> SessionMessage:
    # 2.x JSONRPCMessage is a plain union: the concrete error IS the message.
    return SessionMessage(
        message=JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=ErrorData(code=PROXY_ERROR_CODE, message=note),
        )
    )


def _note_upstream_error(root, token_env_name: str, noted: list) -> None:
    """Name the token environment variable when the controller answers one
    of OUR requests with a JSON-RPC error.

    mcp 1.x surfaced a controller rejection (e.g. HTTP 401) as a transport
    exception, so the proxy could classify it by status. mcp 2.x collapses
    any non-2xx response into a generic JSON-RPC error delivered on the read
    stream, so the status is no longer observable here; an error answer to a
    request the proxy itself sent is the observable signal, and the token
    env var is the first thing an operator should check. Emitted once per
    session.

    The remote error TEXT is deliberately not printed: it is
    controller-controlled data with no redaction pass on this path (the
    bearer token is not in the redaction registry), so echoing it would put
    attacker-shapeable text — and potentially the token itself — into the
    operator's stderr and the client's logs. Only the SDK's numeric error
    code is printed. The caller fires this only for errors whose id the
    proxy has outstanding, so unrelated stream noise cannot trigger it."""
    if noted:
        return
    noted.append(True)
    error = getattr(root, "error", None)
    code = getattr(error, "code", None)
    print(
        f"hyperv-mcp proxy: the controller answered a request with a "
        f"JSON-RPC error (code {code}); if this is an authentication "
        f"failure, check the {token_env_name} environment variable, then "
        f"retry. The full error was forwarded to the client.",
        file=sys.stderr,
    )


def _iter_group_exceptions(exc: BaseException) -> list[BaseException]:
    """Flatten (possibly nested) exception groups into leaf exceptions;
    a plain (non-group) exception is its own single leaf."""
    causes = getattr(exc, "exceptions", None)
    if not causes:
        return [exc]
    leaves: list[BaseException] = []
    for cause in causes:
        if isinstance(cause, BaseExceptionGroupType):
            leaves.extend(_iter_group_exceptions(cause))
        else:
            leaves.append(cause)
    return leaves


def _http_status_of(exc: BaseException | None) -> int | None:
    """The HTTP status the failure carries, when it carries one (group or
    single exception with an attached httpx response)."""
    if exc is None:
        return None
    for leaf in _iter_group_exceptions(exc):
        response = getattr(leaf, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int):
            return status
    return None


def _describe_failure(exc: BaseException | None) -> str:
    if exc is None:
        return "session ended"
    leaves = _iter_group_exceptions(exc)
    if len(leaves) == 1 and leaves[0] is exc:
        return f"{type(exc).__name__}: {exc}"
    return "; ".join(f"{type(leaf).__name__}: {leaf}" for leaf in leaves[:3])


class _UpstreamClosed(Exception):
    """The upstream read stream ended while the session was still up."""


async def _run_proxy(
    url: str,
    token: str | None,
    token_env_name: str,
) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    timeout = httpx2.Timeout(
        UPSTREAM_CONNECT_TIMEOUT_S, read=None, write=UPSTREAM_WRITE_TIMEOUT_S, pool=5.0
    )
    outstanding: set = set()
    # Reader-first: the stdio reader starts BEFORE the upstream context is
    # entered and records every request id the moment it is read. Messages
    # read before the upstream is connected are buffered here and flushed in
    # order once the upstream write stream exists.
    buffered: list[SessionMessage] = []
    upstream: list = []  # [write_stream] once connected
    noted_upstream_error: list = []  # once-per-session stderr note

    async with stdio_server() as (client_read, client_write):

        async def read_client() -> None:
            try:
                async for message in client_read:
                    if isinstance(message, Exception):
                        # Malformed client input cannot be answered
                        # meaningfully here; the MCP client sees its own
                        # transport error.
                        continue
                    root = _request_id_of(message)
                    if isinstance(root, JSONRPCRequest):
                        outstanding.add(root.id)
                    elif isinstance(root, (JSONRPCResponse, JSONRPCError)):
                        outstanding.discard(root.id)
                    if upstream:
                        await upstream[0].send(message)
                    else:
                        buffered.append(message)
            except (anyio.get_cancelled_exc_class(), KeyboardInterrupt, SystemExit):
                # Clean shutdown (client EOF cancels the group) and process
                # interrupts are not transport failures.
                raise
            except BaseException as exc:  # noqa: BLE001 - contract conversion
                # A failure in the client->upstream direction (e.g. send on a
                # stream the host task has already unwound) must still answer
                # every outstanding id: a task-group child exception would
                # otherwise surface only at the group's __aexit__, AFTER the
                # emit handlers, breaking the "never waits forever" contract.
                # The emit path hard-exits, so this never returns.
                await _fail_outstanding(client_write, outstanding, exc, token_env_name, url)
            # Client closed stdin: the session is over for the client. Exit
            # promptly — lingering on the upstream SSE stream leaves the
            # process for the CLIENT library's tree-kill escalation, which
            # would take the auto-started controller (a former child) down
            # with it.
            tg.cancel_scope.cancel()

        async with anyio.create_task_group() as tg:
            tg.start_soon(read_client)
            try:
                # httpx2 is the SDK's own HTTP stack (mcp 2.x); its client is
                # what streamable_http_client speaks.
                async with httpx2.AsyncClient(headers=headers, timeout=timeout) as hc:
                    # mcp 2.x yields (read_stream, write_stream); 1.x yielded
                    # a third value (the session-id getter), which the SDK
                    # removed with the session-id transport change (issue #16).
                    async with streamable_http_client(
                        url, http_client=hc
                    ) as (upstream_read, upstream_write):
                        upstream.append(upstream_write)
                        for message in buffered:
                            await upstream_write.send(message)
                        buffered.clear()
                        async for item in upstream_read:
                            if isinstance(item, Exception):
                                raise _UpstreamClosed(str(item)) from item
                            root = _request_id_of(item)
                            if isinstance(root, (JSONRPCResponse, JSONRPCError)):
                                # Only an error answering a request the proxy
                                # itself sent is a signal about OUR session
                                # (e.g. a rejected token); unrelated stream
                                # noise must not trigger the operator note.
                                answers_ours = root.id in outstanding
                                outstanding.discard(root.id)
                                if isinstance(root, JSONRPCError) and answers_ours:
                                    _note_upstream_error(
                                        root, token_env_name, noted_upstream_error
                                    )
                            await client_write.send(item)
                        raise _UpstreamClosed("controller closed the session stream")
            except BaseExceptionGroupType as eg:
                await _fail_outstanding(client_write, outstanding, eg, token_env_name, url)
            except _UpstreamClosed:
                await _fail_outstanding(client_write, outstanding, None, token_env_name, url)
            finally:
                upstream.clear()  # no sends on a stream the unwound context closed
                tg.cancel_scope.cancel()
        return 0


_EMITTED = [False]  # single event loop: check-and-set at entry is atomic


async def _fail_outstanding(
    client_write,
    outstanding: set,
    exc: BaseException | None,
    token_env_name: str,
    url: str,
) -> None:
    """Answer every outstanding request id with the JSON-RPC error contract
    and explain on stderr. Never echoes token material. Always hard-exits
    (the stdio server cannot unwind while the client keeps stdin open), so
    this function never returns. Idempotent: if read_client and the host
    task both fail within the same scheduling window, only the first caller
    emits (the set is single-threaded and cleared before exit)."""
    if _EMITTED[0]:
        os._exit(EXIT_TRANSPORT_FAILURE)
    _EMITTED[0] = True
    status = _http_status_of(exc)
    if status in (401, 403):
        print(
            f"hyperv-mcp proxy: the controller rejected the bearer token "
            f"(HTTP {status}); check the {token_env_name} environment "
            "variable, then retry.",
            file=sys.stderr,
        )
        note = "controller rejected the proxy's bearer token"
    else:
        print(
            f"hyperv-mcp proxy: cannot reach the controller at {url}: "
            f"{_describe_failure(exc)}",
            file=sys.stderr,
        )
        note = "proxy transport failure"
    for request_id in list(outstanding):
        try:
            await client_write.send(_error_reply(request_id, note))
        except Exception:  # noqa: BLE001 - client may already be gone
            break
    outstanding.clear()
    # The stdio server cannot unwind while the client keeps stdin open (its
    # reader blocks on the pipe), so a failed proxy flushes and hard-exits:
    # the client already holds the error reply and there is nothing to clean
    # up by design (no locks, no registries). The sleep gives mcp's stdio
    # writer task its scheduled slice; flushing both wrapper and raw buffer
    # covers the bytes mcp wrote through its own TextIOWrapper over the same
    # underlying buffer before os._exit kills the writer thread.
    await anyio.sleep(0.2)
    try:
        sys.stdout.flush()
        sys.stdout.buffer.flush()
        sys.stderr.flush()
    except (OSError, ValueError, AttributeError):
        pass
    os._exit(EXIT_TRANSPORT_FAILURE)


def run_proxy(url: str, token: str | None, token_env_name: str) -> int:
    """Run the stdio <-> streamable-HTTP bridge until the client disconnects
    (exit 0) or the upstream fails (error replies, exit 1)."""
    return anyio.run(_run_proxy, url, token, token_env_name)
