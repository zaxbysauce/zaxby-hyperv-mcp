"""HTTP entry tests: custom token_env honored, safe refusals (no server run)."""

import json

import pytest

import hyperv_mcp.http_entry as http_entry
from hyperv_mcp.config import Config


class _FakeSettings:
    def __init__(self):
        self.host = None
        self.port = None


class _FakeMcp:
    """Records the transport and, across SDK generations, the bind target:
    mcp 1.x configured the bind through settings (http_entry assigned
    settings.host/port before run); 2.x passes host/port to run(**kwargs)."""

    def __init__(self):
        self.settings = _FakeSettings()
        self.run_calls = []
        self.run_kwargs = []

    def run(self, transport="stdio", **kwargs):
        self.run_calls.append(transport)
        self.run_kwargs.append(kwargs)
        return 0

    def bind_port(self):
        for kwargs in reversed(self.run_kwargs):
            if "port" in kwargs:
                return kwargs["port"]
        return self.settings.port


@pytest.fixture()
def fake_server(monkeypatch):
    fake = _FakeMcp()
    monkeypatch.setattr(http_entry, "bootstrap", lambda: http_entry.Config.load())
    monkeypatch.setattr(http_entry, "get_mcp", lambda: fake)
    monkeypatch.setattr(http_entry, "configure_http_auth", lambda v: None)
    return fake


def test_custom_token_env_honored(tmp_path, monkeypatch, fake_server, capsys):
    """Critic fix: http.token_env from config selects the token variable."""
    doc = {"http": {"token_env": "CUSTOM_HTTP_TOKEN", "port": 8844}}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("CUSTOM_HTTP_TOKEN", "custom-token")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(p))
    rc = http_entry.main([])
    assert rc == 0
    assert fake_server.run_calls == ["streamable-http"]
    assert fake_server.bind_port() == 8844


def test_default_token_env_missing_refuses(tmp_path, monkeypatch, fake_server, capsys):
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.delenv("CUSTOM_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(tmp_path / "absent.json"))
    rc = http_entry.main([])
    assert rc == 2
    assert "HYPERV_MCP_HTTP_TOKEN" in capsys.readouterr().err


def test_whitespace_token_env_refuses(tmp_path, monkeypatch, fake_server, capsys):
    """A whitespace-only shared token counts as missing, matching the
    stdio-proxy auto-start guard's strip semantics (PRR-001): the refusal
    message claims the controller 'refuses to start without it', so it must
    be true for '   ' too."""
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "   ")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(tmp_path / "absent.json"))
    rc = http_entry.main([])
    assert rc == 2
    assert "HYPERV_MCP_HTTP_TOKEN" in capsys.readouterr().err
    assert fake_server.run_calls == []


def test_padded_token_env_binds_stripped(tmp_path, monkeypatch, fake_server):
    """A padded token value must bind the STRIPPED verifier so the proxy's
    stripped presentation can match (PRR-001: previously the raw padded
    value bound a verifier no conforming client could ever satisfy, leaving
    a permanent-401 controller holding the port)."""
    captured: dict = {}

    def _capture(verifier):
        captured["verifier"] = verifier

    monkeypatch.setattr(http_entry, "configure_http_auth", _capture)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "  padded-token  ")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(tmp_path / "absent.json"))
    rc = http_entry.main([])
    assert rc == 0
    assert fake_server.run_calls == ["streamable-http"]
    assert captured["verifier"]._token == "padded-token"


def test_allow_anonymous_runs_without_token(tmp_path, monkeypatch, fake_server):
    monkeypatch.delenv("HYPERV_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(tmp_path / "absent.json"))
    rc = http_entry.main(["--allow-anonymous"])
    assert rc == 0
    assert fake_server.run_calls == ["streamable-http"]


def test_config_load_direct():
    cfg = Config()
    assert cfg.http.token_env == "HYPERV_MCP_HTTP_TOKEN"
