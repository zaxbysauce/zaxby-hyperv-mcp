"""Run the hyperv-mcp FastMCP server over streamable-http (hardened).

Adopted from 0xntpower/hyperv-mcp commit 08a721f2 (elevated launcher idea),
with hardening: a bearer token is REQUIRED by default, the default bind is
loopback-only, and the effective policy + credential configuration is printed
at startup.

A stdio MCP server inherits its client's token, so it can never hold more
privilege than the client. Running the same FastMCP object over
streamable-http decouples the two: launch this once from a shell whose token
can drive Hyper-V (Hyper-V Administrators membership — preferred, no UAC —
or an elevated shell), and point clients at the endpoint.

WARNING: anyone who can reach the endpoint AND holds the token can invoke
every tool, including destructive ones. Keep the bind on loopback and treat
the token as a host secret.

    hyperv-mcp-http [--host 127.0.0.1] [--port 8787] [--allow-anonymous]
"""

from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import sys

from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import Config, ConfigError
from .server import VERSION, bootstrap, configure_http_auth, get_mcp


def _elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _StaticTokenVerifier(TokenVerifier):
    """Single shared-token verifier for a loopback research endpoint."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if token and secrets.compare_digest(token, self._token):
            return AccessToken(token=token, client_id="local-cli", scopes=[])
        return None


class _MultiTokenVerifier(TokenVerifier):
    """Per-agent bearer tokens (issue #10): each configured agent's token
    verifies to that agent's own client_id, so audit rows can name the
    caller. Compares the presented token against EVERY pair with
    secrets.compare_digest (constant-time per pair, no dict keyed by the
    secret); duplicate token values are refused at startup, so at most one
    pair can match."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        matched: str | None = None
        for agent_id, expected in self._pairs:
            if secrets.compare_digest(token, expected):
                matched = agent_id
        if matched is None:
            return None
        return AccessToken(token=token, client_id=matched, scopes=[])


def _resolve_agent_tokens(
    agents: dict[str, str], legacy_token: str
) -> tuple[int, list[tuple[str, str]]]:
    """Resolve per-agent token values from the environment (issue #10).

    Returns (rc, pairs). rc 0 carries the (agent_id, token) pairs; the legacy
    shared token joins them as ("local-cli", ...) when its env var is also
    set, so single-token deployments keep working alongside per-agent tokens.
    rc 2 means startup must abort: a missing/blank agent token variable, or a
    collision — two agents (or an agent and the legacy token) resolving to the
    same value would reintroduce the identity collapse this scheme removes.
    Errors name agent ids, never token values.
    """
    pairs: list[tuple[str, str]] = []
    for agent_id in sorted(agents):
        value = os.environ.get(agents[agent_id], "")
        if not value.strip():
            print(
                f"ERROR: agent '{agent_id}' token environment variable "
                f"{agents[agent_id]} is not set. Generate a token "
                "(python -c \"import secrets; print(secrets.token_urlsafe(32))\") "
                "and export it before starting.",
                file=sys.stderr,
            )
            return 2, []
        pairs.append((agent_id, value))
    if legacy_token:
        pairs.append(("local-cli", legacy_token))
    owner: dict[str, str] = {}
    for agent_id, value in pairs:
        if value in owner:
            print(
                f"ERROR: token collision: '{owner[value]}' and '{agent_id}' "
                "resolve to the same bearer token. Give each agent its own "
                "token (token values are never printed).",
                file=sys.stderr,
            )
            return 2, []
        owner[value] = agent_id
    return 0, pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hyperv-mcp-http",
        description="Hyper-V MCP server over streamable-http (bearer-token protected)",
    )
    parser.add_argument("--host", default=None, help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="port (default 8787)")
    parser.add_argument(
        "--allow-anonymous", action="store_true",
        help="run WITHOUT a bearer token — any local process could invoke every tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    ns = parser.parse_args(argv)

    # Config loads FIRST: the token env-var name itself is configurable
    # (http.token_env), so it cannot be resolved before the config exists.
    try:
        cfg = Config.load()
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2
    token_env = cfg.http.token_env
    token = os.environ.get(token_env, "")

    verifier: TokenVerifier | None = None
    if ns.allow_anonymous:
        print(
            "WARNING: --allow-anonymous is set. Every local process that can "
            "reach this endpoint may invoke ALL tools, including destructive "
            "ones. This is only acceptable on a disposable research host.",
            file=sys.stderr,
        )
    elif cfg.http.agents:
        # Per-agent tokens take over the endpoint; the legacy shared token is
        # not required (agents-only mode starts fine without it) but joins the
        # pair list when its variable is also set.
        rc, pairs = _resolve_agent_tokens(cfg.http.agents, token)
        if rc != 0:
            return rc
        verifier = _MultiTokenVerifier(pairs)
    elif not token:
        print(
            f"ERROR: {token_env} is not set. Generate a token "
            f"(python -c \"import secrets; print(secrets.token_urlsafe(32))\") "
            "and pass it via the environment, or pass --allow-anonymous "
            "explicitly if you accept an unauthenticated endpoint.",
            file=sys.stderr,
        )
        return 2
    else:
        verifier = _StaticTokenVerifier(token)

    if verifier is not None:
        configure_http_auth(verifier)
    cfg = bootstrap()

    host = ns.host or cfg.http.host
    port = ns.port or cfg.http.port
    if not isinstance(port, int) or not (1 <= port <= 65535):
        print(f"ERROR: --port must be an integer in 1..65535 (got {port!r})", file=sys.stderr)
        return 2

    print(f"hyperv-mcp {VERSION} (streamable-http)", file=sys.stderr)
    print(f"elevated:            {_elevated()}", file=sys.stderr)
    for name in (
        "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_PASSWORD_FILE",
        "HYPERV_GUEST_VICTIM_USERNAME", "HYPERV_GUEST_VICTIM_PASSWORD",
        "HYPERV_GUEST_VICTIM_PASSWORD_FILE",
    ):
        print(f"{name:20}{'set' if os.environ.get(name) else 'NOT SET'}", file=sys.stderr)
    elevated = _elevated()
    if not elevated:
        print(
            "NOTE: not elevated. Hyper-V cmdlets work without UAC when this "
            "process token carries the Hyper-V Administrators group; otherwise "
            "launch from an elevated shell.",
            file=sys.stderr,
        )
    print(f"endpoint:            http://{host}:{port}/mcp", file=sys.stderr)
    if isinstance(verifier, _MultiTokenVerifier):
        auth_desc = f"per-agent bearer tokens ({len(cfg.http.agents)} agent(s))"
    else:
        auth_desc = "bearer token" if verifier else "ANONYMOUS (--allow-anonymous)"
    print(f"auth:                {auth_desc}", file=sys.stderr)

    if host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"WARNING: binding to {host} exposes the endpoint beyond this "
            "machine. The bearer token(s) are the only identity on this "
            "endpoint (per agent when http.agents is configured; one shared "
            "principal otherwise) — prefer an SSH tunnel or a reverse proxy "
            "with auth.",
            file=sys.stderr,
        )

    mcp = get_mcp()
    mcp.settings.host = host
    mcp.settings.port = port
    try:
        mcp.run(transport="streamable-http")
    except OSError as exc:
        # e.g. port already bound — surface a clean operator error, not a traceback.
        print(f"ERROR: streamable-http server failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
