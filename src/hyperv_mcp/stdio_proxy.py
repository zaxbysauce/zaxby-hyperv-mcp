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
request never waits forever — an unreachable controller (connection refused),
a rejected token (HTTP 401/403), or a mid-session disconnect turns into a
JSON-RPC error (code -32000) for each outstanding request id, names the token
environment variable on stderr (rejections only), never echoes the token, and
the proxy exits non-zero. Connection and rejection failures surface as a
RAISED exception group when the upstream client context unwinds (probe-
verified: post failures cancel the transport task group and re-raise at its
boundary), so the emit path is driven from that raised group as well as from
exception items on the upstream read stream.

Tokens come only from the environment: the variable named by
`http.token_env`, or — when `http.agents` is configured — the single set
agent variable (exactly one; more than one is a refusal, because the child
could not know which principal it presents). A missing token is NOT a
refusal: the proxy simply presents no Authorization header and the
controller's 401 becomes the standard error reply.
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
import httpx
from mcp.client.streamable_http import streamable_http_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
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
AUTOSTART_WAIT_S = 15.0
LISTEN_PROBE_TIMEOUT_S = 0.5

if sys.version_info >= (3, 11):
    BaseExceptionGroupType = BaseExceptionGroup  # noqa: F821 - 3.11 builtin
else:  # pragma: no cover - 3.10 path; the backport ships with anyio
    from exceptiongroup import BaseExceptionGroup as BaseExceptionGroupType  # type: ignore[attr-defined,no-redef] # noqa: I001


_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000


class ProxyRefused(Exception):
    """Operator-facing refusal (bad URL, ambiguous agent identity).

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


def validate_proxy_url(url: str) -> str:
    """Refuse anything but a well-formed http(s) controller URL; cleartext
    http is loopback-only because the bearer token would otherwise cross the
    network in cleartext. Returns the URL unchanged when acceptable."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProxyRefused(
            f"invalid controller URL {url!r}: expected http://host:port/mcp "
            "or https://host:port/mcp"
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
    """Whether a TCP listener accepts connections at host:port right now."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def ensure_controller(cfg) -> None:
    """Start the shared controller detached from this process tree and wait
    (bounded) for its port. The child inherits THIS process's environment —
    including the token variables — but never carries token material on its
    command line (only --host/--port). Concurrent first launches converge:
    the bind loser exits cleanly and this proxy connects to the winner once
    its port accepts. Explicit --proxy invocations never reach this path.

    The controller MUST survive this proxy's death: the client library's
    stdio shutdown wraps the proxy in a kill-on-terminate Job Object and
    terminates the whole job when the proxy outlives stdin, and JOB
    MEMBERSHIP IS INHERITED — a controller spawned directly by this process
    would be job members and die with it (probe-verified 2026-10-12,
    DETACHED_PROCESS notwithstanding). Two mechanisms sever that link:
    CREATE_BREAKAWAY_FROM_JOB when the job permits it, else creation via
    WMI Win32_Process.Create, whose children belong to the WMI service —
    outside this job entirely — with the environment carried in the CIM
    startup block (no token ever on a command line). The controller logs to
    a per-user file so a silent death always leaves evidence."""
    log_path = _controller_log_path(cfg.http.port)
    host = cfg.http.host
    port = str(cfg.http.port)
    if os.name != "nt":
        # No job-object inheritance on POSIX: plain detached spawn.
        log = open(log_path, "a", encoding="utf-8", errors="replace")  # noqa: SIM115 - lives for the detached child
        try:
            subprocess.Popen(  # noqa: S603 - fixed argv, no shell, no secrets in argv
                [sys.executable, "-m", "hyperv_mcp.http_entry",
                 "--host", host, "--port", port],
                stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, env=dict(os.environ),
                start_new_session=True,
            )
        finally:
            log.close()
        deadline = time.monotonic() + AUTOSTART_WAIT_S
        while time.monotonic() < deadline:
            if port_listening(host, int(port)):
                return
            time.sleep(0.25)
        raise ProxyRefused(_autostart_timeout_message(host, port))
    spawner = "\n".join([
        "import base64, os, subprocess, sys",
        "host, port, log_path = sys.argv[1], sys.argv[2], sys.argv[3]",
        "argv = [sys.executable, '-m', 'hyperv_mcp.http_entry', '--host', host, '--port', port]",
        "log = open(log_path, 'a', encoding='utf-8', errors='replace')",
        "try:",
        "    flags = 0x00000008 | 0x00000200 | 0x08000000 | 0x01000000",
        "    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,",
        "                     stderr=subprocess.STDOUT, env=dict(os.environ),",
        "                     creationflags=flags)",
        "    print('breakaway')",
        "except OSError:",
        "    # The job forbids breakaway (mcp's stdio job uses default flags).",
        "    # Create the controller via WMI: the WMI service is outside this",
        "    # job, so the controller never becomes a job member. The",
        "    # environment (token variables included) rides in the CIM startup",
        "    # block - never on a command line.",
        "    cmdline = subprocess.list2cmdline(argv)",
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
        "    if 'wmi' not in (run.stdout or ''):",
        "        raise SystemExit('WMI spawn failed: ' + (run.stderr or run.stdout or '')[-300:])",
        "    print('wmi')",
    ])
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no secrets in argv
        [sys.executable, "-c", spawner, host, port, log_path],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=dict(os.environ),
        creationflags=_CREATE_NO_WINDOW,
        timeout=AUTOSTART_WAIT_S,
        check=False,
    )
    if "wmi" not in (result.stdout or "") and "breakaway" not in (result.stdout or ""):
        # The spawner could not sever job inheritance; say so loudly instead
        # of shipping a controller that dies with this client.
        detail = (result.stderr or result.stdout or "no output").strip()[-400:]
        raise ProxyRefused(
            "could not auto-start the controller outside this client's job "
            f"object: {detail}"
        )
    deadline = time.monotonic() + AUTOSTART_WAIT_S
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
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.getcwd()
    log_dir = os.path.join(base, "hyperv-mcp")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, f"http-controller-{port}.log")


def _request_id_of(message: SessionMessage):
    root = getattr(getattr(message, "message", None), "root", None)
    return root


def _error_reply(request_id, note: str) -> SessionMessage:
    return SessionMessage(
        message=JSONRPCMessage(
            root=JSONRPCError(
                jsonrpc="2.0",
                id=request_id,
                error=ErrorData(code=PROXY_ERROR_CODE, message=note),
            )
        )
    )


def _iter_group_exceptions(exc: BaseException) -> list[BaseException]:
    """Flatten (possibly nested) exception groups into leaf exceptions."""
    leaves: list[BaseException] = []
    for cause in getattr(exc, "exceptions", ()) or ():
        if isinstance(cause, BaseExceptionGroupType):
            leaves.extend(_iter_group_exceptions(cause))
        else:
            leaves.append(cause)
    return leaves


def _http_status_of(eg: BaseException) -> int | None:
    """The HTTP status the transport group carries, when it carries one."""
    for leaf in _iter_group_exceptions(eg):
        response = getattr(leaf, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int):
            return status
    return None


def _describe_group(eg: BaseException) -> str:
    leaves = _iter_group_exceptions(eg)
    if leaves:
        return "; ".join(f"{type(leaf).__name__}: {leaf}" for leaf in leaves[:3])
    return type(eg).__name__


class _UpstreamClosed(Exception):
    """The upstream read stream ended while the session was still up."""


async def _run_proxy(
    url: str,
    token: str | None,
    token_env_name: str,
) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    timeout = httpx.Timeout(
        UPSTREAM_CONNECT_TIMEOUT_S, read=None, write=UPSTREAM_WRITE_TIMEOUT_S, pool=5.0
    )
    outstanding: set = set()
    # Reader-first: the stdio reader starts BEFORE the upstream context is
    # entered and records every request id the moment it is read. Messages
    # read before the upstream is connected are buffered here and flushed in
    # order once the upstream write stream exists.
    buffered: list[SessionMessage] = []
    upstream: list = []  # [write_stream] once connected

    async with stdio_server() as (client_read, client_write):

        async def read_client() -> None:
            async for message in client_read:
                if isinstance(message, Exception):
                    # Malformed client input cannot be answered meaningfully
                    # here; the MCP client sees its own transport error.
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
            # Client closed stdin: the session is over for the client. Exit
            # promptly — lingering on the upstream SSE stream leaves the
            # process for the CLIENT library's tree-kill escalation, which
            # would take the auto-started controller (a former child) down
            # with it.
            tg.cancel_scope.cancel()

        exit_code = 0
        async with anyio.create_task_group() as tg:
            tg.start_soon(read_client)
            try:
                async with httpx.AsyncClient(headers=headers, timeout=timeout) as hc:
                    async with streamable_http_client(
                        url, http_client=hc
                    ) as (upstream_read, upstream_write, _get_session_id_unused):
                        upstream.append(upstream_write)
                        for message in buffered:
                            await upstream_write.send(message)
                        buffered.clear()
                        async for item in upstream_read:
                            if isinstance(item, Exception):
                                raise _UpstreamClosed(str(item)) from item
                            root = _request_id_of(item)
                            if isinstance(root, (JSONRPCResponse, JSONRPCError)):
                                outstanding.discard(root.id)
                            await client_write.send(item)
                        raise _UpstreamClosed("controller closed the session stream")
            except BaseExceptionGroupType as eg:
                exit_code = await _fail_outstanding(
                    client_write, outstanding, eg, token_env_name, url
                )
            except _UpstreamClosed:
                exit_code = await _fail_outstanding(
                    client_write, outstanding, None, token_env_name, url
                )
            finally:
                tg.cancel_scope.cancel()
        return exit_code


async def _fail_outstanding(
    client_write,
    outstanding: set,
    eg: BaseExceptionGroupType | None,
    token_env_name: str,
    url: str,
) -> int:
    """Answer every outstanding request id with the JSON-RPC error contract
    and explain on stderr. Never echoes token material."""
    status = _http_status_of(eg) if eg is not None else None
    if status in (401, 403):
        print(
            f"hyperv-mcp proxy: the controller rejected the bearer token "
            f"(HTTP {status}); check the {token_env_name} environment "
            "variable, then retry.",
            file=sys.stderr,
        )
        note = "controller rejected the proxy's bearer token"
    else:
        detail = _describe_group(eg) if eg is not None else "session ended"
        print(
            f"hyperv-mcp proxy: cannot reach the controller at {url}: {detail}",
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
    # up by design (no locks, no registries). Give the stdio writer task its
    # scheduled slice first so the reply bytes reach the pipe.
    await anyio.sleep(0.2)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
    os._exit(EXIT_TRANSPORT_FAILURE)


def run_proxy(url: str, token: str | None, token_env_name: str) -> int:
    """Run the stdio <-> streamable-HTTP bridge until the client disconnects
    (exit 0) or the upstream fails (error replies, exit 1)."""
    return anyio.run(_run_proxy, url, token, token_env_name)
