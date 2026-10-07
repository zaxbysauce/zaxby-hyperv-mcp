"""Acceptance checks for issue 5 (trace 5-ps51-sanitized-env).

AC1/AC2 assert the EFFECTIVE child environment of the PowerShell spawn in
pswindows.run_ps: the recorded env= mapping when the spawn supplies one,
otherwise the inherited os.environ at spawn time (that inheritance is the
defect under test). AC3/AC4 assert the hyperv_server_info provenance tool.
These checks fail against the current source and must pass unchanged once
the fix lands. No real process, VM, network or secret is used anywhere.
"""

import asyncio
import importlib
import json
import os
import re

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows
from hyperv_mcp.config import Config

PS51_SYSTEM_MODULES = r"C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
PS51_HOME = r"C:\Windows\System32\WindowsPowerShell\v1.0"
PWSH7_MODULE_ENTRIES = [
    r"C:\Users\probe-user\Documents\PowerShell\Modules",
    r"C:\Program Files\PowerShell\Modules",
    r"C:\Program Files\PowerShell\7\Modules",
]
GUEST_PASSWORD_SENTINEL = "DUMMY-SENTINEL-guest-password-value"
VICTIM_PASSWORD_SENTINEL = "DUMMY-SENTINEL-victim-password-value"
HTTP_TOKEN_SENTINEL = "DUMMY-SENTINEL-http-token-value"


def _norm_path(value):
    return value.strip().rstrip("\\").lower().replace("/", "\\")


def _is_pwsh7_module_entry(entry):
    """A PSModulePath entry is a PowerShell 7 (pwsh7) entry when it lies
    under a PowerShell 7 install directory (.../PowerShell/7/...), equals
    the pwsh7 program-files shared module directory, or is a pwsh7 user
    Documents module directory. Windows PowerShell 5.1 directories
    (WindowsPowerShell) never match."""
    norm = _norm_path(entry)
    if "\\powershell\\7\\" in "\\" + norm + "\\":
        return True
    if norm == _norm_path(r"C:\Program Files\PowerShell\Modules"):
        return True
    return norm.endswith("\\documents\\powershell\\modules")


def _env_has(env, name):
    """Case-insensitive key membership (Windows env var names)."""
    return any(key.upper() == name.upper() for key in env)


def _env_get(env, name):
    for key in env:
        if key.upper() == name.upper():
            return env[key]
    return None


class _FakeChildProcess:
    """Stands in for the Popen object run_ps drives; nothing really spawns."""

    pid = 4242
    _handle = 0
    returncode = 0

    def communicate(self, input=None, timeout=None):
        return b"", b""

    def kill(self):
        return None


def _record_effective_child_env(monkeypatch):
    """Intercept the run_ps spawn and capture the environment the spawned
    child would receive: kwargs["env"] when the spawn supplies one, else the
    inherited os.environ (that inheritance IS the bug). monkeypatch restores
    Popen and the job/resume helpers after the test."""
    seen = {}

    def recording_popen(argv, *args, **kwargs):
        seen["argv"] = list(argv)
        env_kwarg = kwargs.get("env")
        seen["env_kwarg"] = env_kwarg
        if env_kwarg is None:
            seen["effective_env"] = dict(os.environ)
        else:
            seen["effective_env"] = dict(env_kwarg)
        return _FakeChildProcess()

    monkeypatch.setattr(pswindows.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(pswindows, "_make_kill_on_close_job", lambda: None)
    monkeypatch.setattr(pswindows, "_resume_process", lambda pid: True)
    return seen


def _seed_secret_env(monkeypatch):
    """Set dummy sentinel values (never real credentials) for the three
    secret variable names the child environment must not carry; returns the
    configured HTTP token variable name."""
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", GUEST_PASSWORD_SENTINEL)
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_PASSWORD", VICTIM_PASSWORD_SENTINEL)
    token_name = Config().http.token_env
    monkeypatch.setenv(token_name, HTTP_TOKEN_SENTINEL)
    return token_name


def _fake_provenance_run_ps(monkeypatch):
    """Stub the PowerShell provenance probe so AC4 spawns nothing and stays
    deterministic. Probe-script contract: a script mentioning two or more of
    the probe markers (PSEdition, PSVersion, PSModulePath, PSHOME) or using
    ConvertTo-Json gets a compact JSON object with all four answers; a
    single-marker script gets that one field as plain text."""
    answers = {
        "path": PS51_HOME,
        "edition": "Desktop",
        "version": "5.1.19041.4990",
        "psmodulepath": os.environ.get("PSModulePath", ""),
    }
    combined = json.dumps(answers)

    def fake_run_ps(script, *args, **kwargs):
        low = script.lower()
        markers = [m for m in ("psedition", "psversion", "psmodulepath", "pshome") if m in low]
        if len(markers) >= 2 or "convertto-json" in low:
            return pswindows.PSResult(stdout=combined, returncode=0)
        if "psedition" in low:
            return pswindows.PSResult(stdout=answers["edition"], returncode=0)
        if "psversion" in low:
            return pswindows.PSResult(stdout=answers["version"], returncode=0)
        if "psmodulepath" in low:
            return pswindows.PSResult(stdout=answers["psmodulepath"], returncode=0)
        if "pshome" in low:
            return pswindows.PSResult(stdout=answers["path"], returncode=0)
        return pswindows.PSResult(stdout=combined, returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)


def test_child_psmodulepath_has_no_pwsh7_entries(monkeypatch):
    """AC1: the child PSModulePath carries no PowerShell 7 module entries
    and still contains the Windows PowerShell 5.1 system module directory."""
    pswindows.init(Config(max_output_bytes=1024 * 1024))
    module_path = ";".join(
        PWSH7_MODULE_ENTRIES + [PS51_SYSTEM_MODULES, r"C:\Program Files\WindowsPowerShell\Modules"]
    )
    monkeypatch.setenv("PSModulePath", module_path)
    seen = _record_effective_child_env(monkeypatch)

    result = pswindows.run_ps("Write-Output 'psmodulepath-probe'", timeout_s=30)

    assert result.ok(), result.stderr
    child_module_path = _env_get(seen["effective_env"], "PSModulePath") or ""
    pwsh7_entries = [
        entry for entry in child_module_path.split(";") if entry.strip() and _is_pwsh7_module_entry(entry)
    ]
    assert pwsh7_entries == [], (
        f"run_ps child PSModulePath still contains PowerShell 7 module entries: {pwsh7_entries}"
    )
    assert _norm_path(PS51_SYSTEM_MODULES) in _norm_path(child_module_path), (
        "run_ps child PSModulePath lost the Windows PowerShell 5.1 system "
        f"module directory {PS51_SYSTEM_MODULES!r}; child PSModulePath: "
        f"{child_module_path!r}"
    )


def test_child_env_carries_no_server_secrets(monkeypatch):
    """AC2: none of HYPERV_GUEST_PASSWORD, HYPERV_GUEST_VICTIM_PASSWORD or
    the configured HTTP token variable survives into the child env."""
    pswindows.init(Config(max_output_bytes=1024 * 1024))
    token_name = _seed_secret_env(monkeypatch)
    seen = _record_effective_child_env(monkeypatch)

    result = pswindows.run_ps("Write-Output 'secrets-probe'", timeout_s=30)

    assert result.ok(), result.stderr
    child_env = seen["effective_env"]
    secret_names = ["HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_VICTIM_PASSWORD", token_name]
    leaked = sorted(name for name in secret_names if _env_has(child_env, name))
    assert leaked == [], f"run_ps child environment still carries secret names: {leaked}"


def test_server_info_tool_registered():
    """AC3: a bootstrapped server registers hyperv_server_info and the tool
    inventory counts exactly 55 tools."""
    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({})
        tools = asyncio.run(mod.get_mcp().list_tools())
        names = sorted(tool.name for tool in tools)
        assert "hyperv_server_info" in names, (
            f"hyperv_server_info is not registered; tool inventory has "
            f"{len(names)} tools, expected 55 including hyperv_server_info"
        )
        assert len(names) == 55, (
            f"tool inventory is {len(names)} tools; expected exactly 55 "
            "(54 existing tools plus hyperv_server_info)"
        )
    finally:
        importlib.reload(server_module)


def test_server_info_reports_provenance_without_secrets(monkeypatch, tmp_path):
    """AC4: hyperv_server_info returns full provenance (version, git
    revision, PowerShell path/edition/version/psmodulepath, config path and
    sha256, SDK and protocol versions, feature flags) with no secret values
    in the serialized response."""
    config_file = tmp_path / "server-info-config.json"
    config_file.write_text(json.dumps({"allowed_vm_patterns": ["probe-vm"]}), encoding="utf-8")
    _seed_secret_env(monkeypatch)

    mod = importlib.reload(server_module)
    try:
        mod.bootstrap({"HYPERV_MCP_CONFIG": str(config_file)})
        _fake_provenance_run_ps(monkeypatch)
        mcp = mod.get_mcp()

        try:
            raw = asyncio.run(mcp.call_tool("hyperv_server_info", {}))
        except Exception as exc:
            pytest.fail(
                f"mcp.call_tool('hyperv_server_info') raised "
                f"{type(exc).__name__}: {exc}; is the tool registered?"
            )

        content = raw[0] if isinstance(raw, tuple) else raw
        if not isinstance(content, list) and hasattr(content, "content"):
            content = content.content  # in-process call_tool returns a CallToolResult
        text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
        assert text_blocks, "hyperv_server_info returned no text content"
        response_text = "".join(getattr(block, "text", "") for block in text_blocks)
        try:
            payload = json.loads(response_text)
        except ValueError as exc:
            pytest.fail(
                f"hyperv_server_info response is not JSON text ({exc}); "
                f"response starts with: {response_text[:120]!r}"
            )
        assert isinstance(payload, dict), (
            f"hyperv_server_info response is not a JSON object; got {type(payload).__name__}"
        )

        required = (
            "version",
            "git_revision",
            "powershell",
            "config_path",
            "config_sha256",
            "mcp_sdk_version",
            "protocol_version",
            "feature_flags",
        )
        missing = [field for field in required if field not in payload]
        assert missing == [], f"hyperv_server_info response is missing fields: {missing}"

        assert payload["version"] == mod.VERSION, (
            f"hyperv_server_info version {payload['version']!r} does not equal server.VERSION {mod.VERSION!r}"
        )
        assert isinstance(payload["git_revision"], str) and payload["git_revision"], (
            "hyperv_server_info git_revision is empty"
        )
        assert re.fullmatch(r"[0-9a-f]{64}", str(payload["config_sha256"])), (
            f"hyperv_server_info config_sha256 is not a 64-hex-char digest: {payload['config_sha256']!r}"
        )

        powershell = payload["powershell"]
        assert isinstance(powershell, dict), "hyperv_server_info powershell provenance is not an object"
        ps_keys = ("path", "edition", "version", "psmodulepath")
        ps_missing = [key for key in ps_keys if key not in powershell]
        assert ps_missing == [], f"hyperv_server_info powershell provenance is missing keys: {ps_missing}"
        for key in ps_keys:
            value = powershell[key]
            assert isinstance(value, str) and value, f"hyperv_server_info powershell.{key} is empty"

        serialized = response_text + json.dumps(payload, default=str, sort_keys=True)
        sentinels = (
            ("HYPERV_GUEST_PASSWORD", GUEST_PASSWORD_SENTINEL),
            ("HYPERV_GUEST_VICTIM_PASSWORD", VICTIM_PASSWORD_SENTINEL),
            ("HTTP token", HTTP_TOKEN_SENTINEL),
        )
        for name, sentinel in sentinels:
            assert sentinel not in serialized, (
                f"hyperv_server_info serialized response contains the {name} secret sentinel value"
            )
    finally:
        importlib.reload(server_module)
