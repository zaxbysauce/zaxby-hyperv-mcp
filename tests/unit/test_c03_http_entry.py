"""Acceptance checks for issue #16, part 3 — the HTTP entry point against the
REAL server object.

AC6 (main(["--port", "8899"]) hands the transport streamable-http,
127.0.0.1, 8899) and AC13 (http.token_env and http.port from config are
honoured). Sibling c03 files: test_c03_tool_concurrency.py (AC1-AC5),
test_c03_sdk_port.py (AC7-AC9), test_c03_tool_surface.py (AC10-AC12).

Both checks drive the real bootstrap and only replace `run` on the returned
server object with a recorder; host/port are read from the run(**kw) call OR
the object's settings, so the same check holds on both SDK generations.
"""

import importlib


def _run_entry_with_recorder(monkeypatch, http_entry, argv, environ: dict) -> tuple:
    """Reload the server module pristine, let http_entry.main bootstrap the
    REAL server, and intercept the object's `run`; returns
    (rc, {transport, host, port}, [verifiers])."""
    import hyperv_mcp.server as srv

    importlib.reload(srv)  # pristine: main() must be allowed to bootstrap
    state: dict = {}

    def record_run(*args, **kwargs):
        settings = getattr(state["mcp"], "settings", None)
        state["transport"] = kwargs.get("transport") or (args[0] if args else None)
        state["host"] = kwargs.get("host") or getattr(settings, "host", None)
        state["port"] = kwargs.get("port") or getattr(settings, "port", None)
        return 0

    real_get_mcp = http_entry.get_mcp

    def wrap_get_mcp():
        mcp = real_get_mcp()
        state["mcp"] = mcp
        mcp.run = record_run
        return mcp

    monkeypatch.setattr(http_entry, "get_mcp", wrap_get_mcp)
    verifiers = []
    monkeypatch.setattr(http_entry, "configure_http_auth", lambda v: verifiers.append(v))
    for key, value in environ.items():
        monkeypatch.setenv(key, value)
    rc = http_entry.main(argv)
    captured = {k: state.get(k) for k in ("transport", "host", "port")}
    return rc, captured, verifiers


def test_ac6_http_entry_binds_streamable_http(monkeypatch):
    """AC6: http_entry.main(["--port", "8899"]) against the REAL server object
    (only `run` replaced) hands the transport streamable-http, 127.0.0.1, 8899."""
    import hyperv_mcp.http_entry as http_entry

    rc, captured, _ = _run_entry_with_recorder(
        monkeypatch,
        http_entry,
        ["--port", "8899"],
        {"HYPERV_MCP_HTTP_TOKEN": "c03-test-token"},
    )
    assert (rc, captured) == (
        0,
        {"transport": "streamable-http", "host": "127.0.0.1", "port": 8899},
    ), f"AC6: rc={rc}, captured={captured!r}"


def test_ac13_http_entry_honors_token_env_and_port(tmp_path, monkeypatch):
    """AC13: the HTTP entry point honours http.token_env and http.port from
    config (the custom token variable authenticates; no default-variable
    refusal; the recorded port is the configured one)."""
    import json

    import hyperv_mcp.http_entry as http_entry

    doc = {"http": {"token_env": "CUSTOM_HTTP_TOKEN", "port": 8844}}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    rc, captured, verifiers = _run_entry_with_recorder(
        monkeypatch,
        http_entry,
        [],
        {
            "HYPERV_MCP_CONFIG": str(p),
            "CUSTOM_HTTP_TOKEN": "custom-token",
        },
    )
    assert rc == 0, f"AC13: rc={rc} (custom token_env must authenticate, not refuse)"
    assert verifiers and verifiers[0] is not None, (
        "AC13: no token verifier was installed from CUSTOM_HTTP_TOKEN"
    )
    assert captured["transport"] == "streamable-http", (
        f"AC13: transport {captured.get('transport')!r} != 'streamable-http'"
    )
    assert captured["port"] == 8844, f"AC13: port {captured.get('port')!r} != 8844 (config http.port ignored)"
