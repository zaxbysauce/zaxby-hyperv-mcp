"""Frozen acceptance checks for issue #69 (transport security): a
non-loopback bind must arm mcp's DNS-rebinding protection explicitly, and
the loopback bind must keep mcp 2.x's automatic protection.

Verified against mcp 2.3.0: streamable_http_app auto-enables
TransportSecurityMiddleware ONLY for host in ("127.0.0.1", "localhost",
"::1"); any other bind with transport_security=None leaves
enable_dns_rebinding_protection at its False default, so a foreign Host
header is routed (the gap the fix closes — the http_entry helper computes
TransportSecuritySettings from the bind host and hands it to mcp.run).

Token -> AC map:
  test_nonloopback_bind_arms_dns_rebinding_protection
      The bind-host helper returns TransportSecuritySettings (never None)
      for "0.0.0.0" and "192.168.1.50", with
      enable_dns_rebinding_protection True and allowed_hosts covering the
      bind host (exact entry or host:* form); feeding the helper's product
      to the REAL streamable app on a non-loopback bind rejects a foreign
      Host header with 421 Misdirected Request.
  test_loopback_bind_keeps_protection
      The helper returns None for "127.0.0.1" (mcp 2.x's auto-enable stays
      in charge), and the real app built with transport_security=None on a
      loopback bind still answers a foreign Host header with 421 — the
      no-regression half.

The seam is probed arm's-length (issue #57's FILE-5 pattern): the fix may
name its helper _transport_security_for, transport_security_settings or
build_transport_security (probed in that order via getattr on
hyperv_mcp.http_entry; the helper takes the bind host string and returns
None or a TransportSecuritySettings). At base none of those names exists,
so both checks fail by naming the missing seam. The real-app legs use
starlette's TestClient only — no real sockets, fully deterministic.
"""

from mcp.server.transport_security import TransportSecuritySettings

from hyperv_mcp import http_entry

SEAM_NAMES = (
    "_transport_security_for",
    "transport_security_settings",
    "build_transport_security",
)


def _settings_seam():
    for name in SEAM_NAMES:
        seam = getattr(http_entry, name, None)
        if callable(seam):
            return seam
    raise AssertionError(
        "hyperv_mcp.http_entry exposes no transport-security settings seam "
        f"(probed {', '.join(SEAM_NAMES)}); issue #69 requires a bind-host "
        "helper that arms mcp's DNS-rebinding protection for non-loopback "
        "binds and preserves 2.x auto-enable on loopback"
    )


def _allowed_hosts_cover(allowed_hosts, host: str) -> bool:
    """The allowlist covers the bind host via an exact entry or a host:*
    form (the two spellings TransportSecurityMiddleware matches)."""
    for entry in allowed_hosts or []:
        if entry == host or entry.startswith(host + ":"):
            return True
    return False


def _foreign_host_status(host: str, transport_security) -> int:
    """GET /mcp with a foreign Host header through the REAL streamable
    app (starlette TestClient, lifespan included; no real sockets)."""
    from mcp.server import MCPServer
    from starlette.testclient import TestClient

    app = MCPServer("probe").streamable_http_app(
        host=host, transport_security=transport_security
    )
    with TestClient(app) as client:
        response = client.get("/mcp", headers={"Host": "evil.example.com"})
    return response.status_code


def _assert_run_call_is_wired(seam_name: str) -> None:
    """Plan-critic round-2 blocker: the wiring pin is SEAM-VALUED — the
    transport_security keyword must call the seam itself, not pass None or
    an unrelated literal. Structural AST pin over http_entry's source
    (driving a real uvicorn serve needs a live host)."""
    import ast
    from pathlib import Path

    source = Path(http_entry.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    mains = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "main"
    ]
    assert mains, "http_entry.main not found"
    run_calls = [
        node
        for node in ast.walk(mains[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert run_calls, "http_entry.main never calls mcp .run()"

    def _kw_value_is_seam_call(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == seam_name
        )

    wired = [
        node
        for node in run_calls
        for kw in node.keywords
        if kw.arg == "transport_security" and _kw_value_is_seam_call(kw.value)
    ]
    assert wired, (
        "http_entry.main's mcp .run() call does not pass the seam's settings "
        f"(transport_security must be a {seam_name}(...) call, never None "
        "or an unrelated literal); the transport stays unprotected"
    )


def test_nonloopback_bind_arms_dns_rebinding_protection():
    seam = _settings_seam()
    seam_name = next(
        name for name in SEAM_NAMES if getattr(http_entry, name, None) is seam
    )
    _assert_run_call_is_wired(seam_name)
    for host in ("0.0.0.0", "192.168.1.50"):
        settings = seam(host)
        assert settings is not None, (
            f"transport-security helper returned None for non-loopback bind {host!r}"
        )
        assert isinstance(settings, TransportSecuritySettings), type(settings)
        assert settings.enable_dns_rebinding_protection is True, (
            f"DNS-rebinding protection not armed for bind {host!r}"
        )
        assert _allowed_hosts_cover(settings.allowed_hosts, host), (
            f"allowed_hosts does not cover the bind host {host!r}: "
            f"{settings.allowed_hosts!r}"
        )

    # IPv6 bind hosts produce BRACKETED allowlist forms only (the matcher's
    # precedent shape, lowlevel/server.py "[::1]:*"; a bare-colon form
    # would be misparsed as host:port by the matcher).
    v6 = seam("2001:db8::1")
    assert v6 is not None, "IPv6 bind must be armed, not None"
    assert _allowed_hosts_cover(v6.allowed_hosts, "[2001:db8::1]"), (
        f"IPv6 bracketed allowlist form missing for 2001:db8::1: "
        f"{v6.allowed_hosts!r}"
    )
    assert not any(
        entry.startswith("2001:db8::1:") for entry in (v6.allowed_hosts or [])
    ), f"unbracketed IPv6 host:port form present: {v6.allowed_hosts!r}"

    # Configured public hosts (http.allowed_hosts) extend BOTH allowed_hosts
    # and allowed_origins (plan-critic round-2 blocker 1: the SDK's
    # middleware independently rejects uncovered Origins with 403).
    configured = seam("0.0.0.0", ("lab.example.com",))
    assert configured is not None, "configured call must still arm protection"
    assert _allowed_hosts_cover(configured.allowed_hosts, "lab.example.com"), (
        f"configured host missing from allowed_hosts: {configured.allowed_hosts!r}"
    )
    origins = set(configured.allowed_origins or [])
    assert {
        "http://lab.example.com:*",
        "https://lab.example.com:*",
    } <= origins, f"configured Origin forms missing: {sorted(origins)!r}"

    status = _foreign_host_status("0.0.0.0", seam("0.0.0.0"))
    assert status == 421, (
        f"foreign Host header accepted on a non-loopback bind (status {status}); "
        "the helper's settings did not arm the real app"
    )
    # Legitimate client leg (plan-critic round-1 blocker 4): a Host header
    # COVERED by the allowlist must pass the middleware (any status other
    # than the middleware's 421 rejection).
    from mcp.server import MCPServer
    from starlette.testclient import TestClient

    app = MCPServer("probe").streamable_http_app(
        host="0.0.0.0", transport_security=seam("0.0.0.0")
    )
    with TestClient(app) as client:
        ok_status = client.get("/mcp", headers={"Host": "0.0.0.0:8787"}).status_code
    assert ok_status != 421, (
        "a covered Host header (0.0.0.0:8787) was rejected with 421; the "
        "allowlist does not admit the bind host's own forms"
    )

    # Configured Host+Origin real-app leg (plan-critic round-2 blocker 1):
    # a client presenting a CONFIGURED host with a matching Origin passes
    # both the Host and Origin validators (neither 421 nor the Origin 403).
    app_cfg = MCPServer("probe").streamable_http_app(
        host="0.0.0.0", transport_security=configured
    )
    with TestClient(app_cfg) as client:
        cfg_status = client.get(
            "/mcp",
            headers={
                "Host": "lab.example.com:8787",
                "Origin": "http://lab.example.com:8787",
            },
        ).status_code
    assert cfg_status not in (421, 403), (
        f"a configured Host+Origin client was browser-rejected (status {cfg_status}); "
        "the configured forms did not cover the real request"
    )


def test_loopback_bind_keeps_protection():
    seam = _settings_seam()
    assert seam("127.0.0.1") is None, (
        "loopback bind must keep transport_security=None so mcp 2.x's "
        "auto-enable stays in charge"
    )
    status = _foreign_host_status("127.0.0.1", None)
    assert status == 421, (
        f"mcp 2.x auto-enable regressed on loopback (status {status})"
    )
