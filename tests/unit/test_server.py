"""Server-level tests: tool schemas per credential mode, entry points."""

import asyncio
import dataclasses
import hashlib
import importlib
import json
import re
import subprocess
from pathlib import Path

import pytest

import hyperv_mcp.server as server_module

CRED_TOOLS = {
    "hyperv_configure_kdnet", "hyperv_configure_kdcom",
    "hyperv_guest_run", "hyperv_guest_run_ps",
    "hyperv_guest_put", "hyperv_guest_get",
    "hyperv_guest_read_file", "hyperv_guest_list_dir",
    "hyperv_diagnose_vm_access", "hyperv_repair_guest_access",
    "hyperv_guest_job_start", "hyperv_wait_guest_recovery",
    "hyperv_relay_start", "hyperv_capture_evidence",
}
TOOL_NAMES = {
    "hyperv_list_vms", "hyperv_get_vm_info", "hyperv_start_vm", "hyperv_stop_vm",
    "hyperv_reset_vm", "hyperv_checkpoint_create", "hyperv_checkpoint_list",
    "hyperv_checkpoint_restore", "hyperv_checkpoint_remove",
    "hyperv_configure_kdnet", "hyperv_configure_kdcom",
    "hyperv_guest_run", "hyperv_guest_run_ps", "hyperv_guest_put",
    "hyperv_guest_get", "hyperv_guest_read_file", "hyperv_guest_list_dir",
    "hyperv_victim_run", "hyperv_victim_run_ps",
    # console (WMI screenshot / keyboard / mouse)
    "hyperv_console_screenshot", "hyperv_console_get_display_info",
    "hyperv_console_type_text", "hyperv_console_press_key",
    "hyperv_console_key_combo", "hyperv_console_type_scancodes",
    "hyperv_console_mouse_move", "hyperv_console_click",
    "hyperv_console_button", "hyperv_console_scroll",
    "hyperv_console_wait_frame_change", "hyperv_console_capture_sequence",
    # VM / media preparation
    "hyperv_vm_create", "hyperv_vm_disk_add", "hyperv_vm_disk_list",
    "hyperv_vm_media_attach", "hyperv_vm_media_detach", "hyperv_vm_media_list",
    "hyperv_vm_firmware_get", "hyperv_vm_firmware_set_boot_order",
    "hyperv_vm_tpm_set", "hyperv_vm_secureboot_set", "hyperv_vm_network_set",
    # orchestration
    "hyperv_wait_vm_state",
    # server provenance (read-only)
    "hyperv_server_info",
    # guest access diagnostics / repair / jobs / recovery / relay / evidence
    "hyperv_diagnose_vm_access", "hyperv_repair_guest_access",
    "hyperv_guest_job_start", "hyperv_guest_job_status",
    "hyperv_guest_job_output", "hyperv_guest_job_stop",
    "hyperv_wait_guest_recovery",
    "hyperv_relay_start", "hyperv_relay_status", "hyperv_relay_stop",
    "hyperv_capture_evidence",
}
CONFIRM_TOOLS = {
    "hyperv_stop_vm", "hyperv_reset_vm", "hyperv_checkpoint_restore",
    "hyperv_checkpoint_remove", "hyperv_configure_kdnet",
    "hyperv_configure_kdcom", "hyperv_guest_run_ps", "hyperv_guest_run",
    "hyperv_guest_put",
    "hyperv_vm_create", "hyperv_vm_disk_add",
    "hyperv_vm_firmware_set_boot_order", "hyperv_vm_tpm_set",
    "hyperv_vm_secureboot_set",
    "hyperv_repair_guest_access",
}


@pytest.fixture()
def fresh_server():
    def make(environ: dict) -> type(server_module):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _schemas(mod):
    mcp = mod.get_mcp()
    tools = asyncio.run(mcp.list_tools())
    return {t.name: t.inputSchema for t in tools}


def test_tool_inventory_registered(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    assert set(schemas) == TOOL_NAMES
    assert len(schemas) == 55


def test_every_vm_tool_schema_has_vm_id(fresh_server):
    """Issue #8 (server layer): every tool that addresses a VM by name must
    also accept vm_id as an equally-optional alternative (exactly one of the
    two identifies the VM; the module layer raises ValueError when neither
    is given). hyperv_vm_create addresses nothing — it CREATES a VM from a
    fresh `name` — so it stays name-only."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    vm_tools = {
        name for name, schema in schemas.items()
        if "vm_name" in schema.get("properties", {})
    }
    missing = sorted(
        name for name in vm_tools
        if "vm_id" not in schemas[name].get("properties", {})
    )
    assert missing == []
    for name in vm_tools:
        assert "vm_name" not in schemas[name].get("required", []), (
            f"{name}: vm_name must be optional so vm_id-only calls validate"
        )
    create_props = schemas["hyperv_vm_create"].get("properties", {})
    assert "vm_id" not in create_props, (
        "hyperv_vm_create creates a VM; it must not pretend to address one by GUID"
    )
    assert "name" in schemas["hyperv_vm_create"].get("required", [])


def test_no_password_params_by_default(fresh_server):
    """F4 regression: username/password must be absent from tool schemas."""
    mod = fresh_server({})
    for name, schema in _schemas(mod).items():
        props = schema.get("properties", {})
        assert "username" not in props, name
        assert "password" not in props, name


def test_inline_credential_mode_exposes_params(tmp_path, fresh_server):
    doc = {"allow_inline_credentials": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    schemas = _schemas(mod)
    for name in CRED_TOOLS:
        props = schemas[name].get("properties", {})
        assert "username" in props, name
        assert "password" in props, name
    # non-cred tools never gain them
    props = schemas["hyperv_list_vms"].get("properties", {})
    assert "password" not in props


def test_tpm_secureboot_enabled_required_in_schema(fresh_server):
    """PRR-001: `enabled` must be semantically required — omission+confirm must
    never silently DISABLE TPM/SecureBoot. The keyword-only no-default param
    makes FastMCP publish required:["enabled"] (probe-verified)."""
    mod = fresh_server({})
    schemas = _schemas(mod)
    for name in ("hyperv_vm_tpm_set", "hyperv_vm_secureboot_set"):
        required = schemas[name].get("required", [])
        assert "enabled" in required, f"{name}: enabled must be schema-required"
        # defaulted siblings stay optional
        assert "confirm" not in required
    assert "template" not in schemas["hyperv_vm_secureboot_set"].get("required", [])


def test_destructive_tools_have_confirm_param(fresh_server):
    mod = fresh_server({})
    schemas = _schemas(mod)
    confirmed = {n for n, sch in schemas.items() if "confirm" in sch.get("properties", {})}
    assert confirmed == CONFIRM_TOOLS, (
        f"confirm-param set drifted: extra={confirmed - CONFIRM_TOOLS}, missing={CONFIRM_TOOLS - confirmed}"
    )


def test_interactive_tools_have_no_confirm_param(fresh_server):
    """Console input + reversible media ops must NOT force a human prompt."""
    mod = fresh_server({})
    for name in ("hyperv_console_type_text", "hyperv_console_press_key",
                 "hyperv_console_mouse_move", "hyperv_console_click",
                 "hyperv_vm_media_attach", "hyperv_vm_media_detach",
                 "hyperv_vm_network_set"):
        props = _schemas(mod)[name].get("properties", {})
        assert "confirm" not in props, name


def test_mdt_config_still_loads(tmp_path, fresh_server):
    """The user's existing 7-category config (schema_version 1) must keep
    loading unchanged after the additive category extension."""
    doc = {
        "schema_version": 1,
        "allowed_vm_patterns": ["Deployment Test", "Deployment Test 2"],
        "guest_read_roots": ["C:\\", "D:\\"],
        "destructive": {
            "stop": True, "reset": True, "checkpoint_restore": True,
            "checkpoint_remove": True, "kd_reboot": True,
            "elevated_exec": True, "guest_write": True,
            "require_confirm": True,
        },
        "allow_inline_credentials": False,
    }
    p = tmp_path / "hyperv-mcp-mdt.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    cfg = mod.CFG
    assert cfg.destructive.stop is True
    assert cfg.destructive.console_input is False  # new fields default safely
    assert cfg.destructive.media is False
    assert cfg.destructive.vm_provision is False


def test_mdt_config_with_new_categories(tmp_path, fresh_server):
    doc = {
        "schema_version": 1,
        "allowed_vm_patterns": ["Deployment Test", "Deployment Test 2", "ZAC"],
        "destructive": {
            "console_input": True, "media": True, "vm_provision": True,
            "require_confirm": True,
        },
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    assert mod.CFG.destructive.console_input is True


def test_check_env_exit_zero(fresh_server, capsys):
    mod = fresh_server({})
    rc = mod.main(["--check-env"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hyperv-mcp 0.4.0" in out
    assert "DENY ALL" in out


def _ps_available() -> bool:
    try:
        subprocess.run(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "-NonInteractive", "-NoProfile", "-Command", "$null"],
            capture_output=True, timeout=60, check=False,
        )
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ps_available(), reason="Windows PowerShell not available")
def test_check_env_prints_provenance(fresh_server, capsys, monkeypatch):
    """ENH-16: --check-env prints runtime provenance (PowerShell
    path/edition/version/psmodulepath, config path + sha256, git revision)
    and still exits 0.

    F-044: sentinel secret values seeded into the server environment must
    never appear in the CLI output.
    """
    guest_sentinel = "DUMMY-SENTINEL-checkenv-guest-password"
    token_sentinel = "DUMMY-SENTINEL-checkenv-http-token"
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", guest_sentinel)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", token_sentinel)

    mod = fresh_server({})
    rc = mod.main(["--check-env"])
    assert rc == 0
    out = capsys.readouterr().out
    for prefix in (
        "powershell.path ", "powershell.edition ", "powershell.version ",
        "powershell.psmodulepath ", "config.path ", "config.sha256 ",
        "git.revision ",
    ):
        assert prefix in out, f"--check-env output is missing the {prefix.strip()!r} line"
    assert guest_sentinel not in out, "--check-env printed the guest-password sentinel"
    assert token_sentinel not in out, "--check-env printed the http-token sentinel"

    ps_path = re.search(r"^powershell\.path (.+)$", out, re.M)
    assert ps_path and ps_path.group(1).strip(), "powershell.path line has no value"
    path_value = ps_path.group(1).strip()
    assert path_value.lower().endswith("powershell.exe") or path_value.lower() == "powershell", (
        f"powershell.path does not name a PowerShell executable: {path_value!r}"
    )
    edition = re.search(r"^powershell\.edition (\S+)$", out, re.M)
    assert edition and edition.group(1) in ("Desktop", "Core"), (
        f"powershell.edition is not Desktop/Core: {out!r}"
    )
    version = re.search(r"^powershell\.version (\S+)$", out, re.M)
    assert version and re.fullmatch(r"(\d[0-9A-Za-z.\-+]*|unknown)", version.group(1)), (
        f"powershell.version is neither a version string nor 'unknown': "
        f"{version.group(1) if version else None!r}"
    )
    psm = re.search(r"^powershell\.psmodulepath (.+)$", out, re.M)
    assert psm and "windowspowershell\\v1.0\\modules" in psm.group(1).lower(), (
        f"powershell.psmodulepath lost the 5.1 system module directory: "
        f"{psm.group(1) if psm else None!r}"
    )
    sha = re.search(r"^config\.sha256 (\S+)$", out, re.M)
    assert sha and re.fullmatch(r"[0-9a-f]{64}", sha.group(1)), (
        f"config.sha256 is not a 64-hex digest: {sha.group(1) if sha else None!r}"
    )

    # F-015: probe git FIRST and, whenever the probe succeeds, require the
    # printed revision to equal the probed HEAD and be a full object id, so an
    # always-"unknown" implementation can no longer pass this test. A missing
    # git binary counts as a failed probe (git-less hosts must not error).
    rev = re.search(r"^git\.revision (\S+)$", out, re.M)
    assert rev, "git.revision line missing from --check-env output"
    revision = rev.group(1)
    try:
        probe = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True, text=True, timeout=10,
        )
    except OSError:
        probe = None
    if probe is not None and probe.returncode == 0:
        head = probe.stdout.strip()
        assert re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head), (
            f"test probe returned an unexpected HEAD shape: {head!r}"
        )
        assert revision == head, (
            f"--check-env git.revision {revision!r} does not match the "
            f"checkout HEAD {head!r}"
        )
    else:
        assert revision == "unknown", (
            f"git probe failed yet git.revision is {revision!r}, expected 'unknown'"
        )


def test_check_env_config_sha256_matches_file_bytes(tmp_path, monkeypatch, capsys):
    """F-013 (test_a01_ps_environment.py is frozen; CLI-surface sibling): the
    printed config.sha256 must equal the real SHA-256 of the config file
    bytes, not merely be 64-hex shaped."""
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"allowed_vm_patterns": ["probe-vm"]}), encoding="utf-8")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(p))
    mod = importlib.reload(server_module)
    try:
        rc = mod.main(["--check-env"])
        assert rc == 0
        out = capsys.readouterr().out
    finally:
        importlib.reload(server_module)
    sha = re.search(r"^config\.sha256 ([0-9a-f]{64})$", out, re.M)
    assert sha, f"config.sha256 line missing or malformed: {out!r}"
    assert sha.group(1) == hashlib.sha256(p.read_bytes()).hexdigest(), (
        "config.sha256 does not equal the digest of the config file bytes"
    )


def test_server_info_feature_flags_match_config(fresh_server):
    """F-040 (test_a01_ps_environment.py is frozen; sibling): the
    feature_flags payload values must mirror the live config, not merely be
    present."""
    mod = fresh_server({})
    payload = mod._server_info_payload(mod.CFG)
    flags = payload["feature_flags"]
    assert flags["unrestricted"] == mod.CFG.unrestricted
    assert flags["allow_inline_credentials"] == mod.CFG.allow_inline_credentials
    assert flags["verify_sha256"] == mod.CFG.verify_sha256
    assert flags["destructive"] == dataclasses.asdict(mod.CFG.destructive)


def test_git_revision_spawns_with_sanitized_env(monkeypatch, fresh_server):
    """F-042: the git provenance probe is a spawn site; capture its env=
    kwarg and prove secrets and GIT_DIR redirections never ride along."""
    mod = fresh_server({})
    captured = {}
    real_run = mod.subprocess.run

    def fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return real_run(argv, **kwargs)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "DUMMY-SENTINEL-git-env")
    monkeypatch.setenv("GIT_DIR", r"Z:\unrelated\.git")

    revision = mod._git_revision()

    env = captured.get("env")
    assert env is not None, "_git_revision spawned without env="
    assert not any(k.upper() == "HYPERV_GUEST_PASSWORD" for k in env), (
        "git probe child env carries HYPERV_GUEST_PASSWORD"
    )
    assert not any(k.upper() == "GIT_DIR" for k in env), (
        "git probe child env carries GIT_DIR redirection"
    )
    if revision != "unknown":
        assert re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision)


def test_check_env_config_error_exit_two(tmp_path, monkeypatch, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{broken", encoding="utf-8")
    monkeypatch.setenv("HYPERV_MCP_CONFIG", str(p))
    mod = importlib.reload(server_module)
    rc = mod.main(["--check-env"])
    assert rc == 2
    assert "CONFIG ERROR" in capsys.readouterr().err
    importlib.reload(server_module)


def test_version_flag(fresh_server, capsys):
    mod = fresh_server({})
    with pytest.raises(SystemExit) as exc:
        mod.main(["--version"])
    assert exc.value.code == 0
    assert "0.4.0" in capsys.readouterr().out


def test_mcp_compat_import_bootstraps(fresh_server):
    mod = fresh_server({})
    # PEP 562 module getattr used by `from hyperv_mcp.server import mcp`
    mcp = mod.mcp
    assert mcp is mod.get_mcp()


def test_unknown_attr_raises(fresh_server):
    mod = fresh_server({})
    name = "mcp_does_not_exist"
    with pytest.raises(AttributeError):
        getattr(mod, name)  # exercises PEP 562 module __getattr__


def test_state_enum_single_source():
    """Review PRR-020 pin: the Hyper-V state enum lives only in lifecycle.py;
    server.py validates against lifecycle.VALID_STATES and console's dead
    duplicate is gone."""
    from hyperv_mcp import console, lifecycle

    assert lifecycle.VALID_STATES == (
        "Off", "Running", "Saved", "Paused", "Starting", "Stopping", "Resuming", "Pausing",
    )
    assert lifecycle._VALID_STATES is lifecycle.VALID_STATES
    assert not hasattr(console, "_STATE_ENUM")


def test_credential_error_envelope_at_tool_layer(fresh_server, tmp_path):
    """PRR-018: a CredentialError raised inside a registered guest tool must
    surface as {ok: false, error_class: "credential"} — CredentialError
    subclasses RuntimeError, so without this envelope mapping a handler
    removal silently relabels credential failures as transport. Drives the
    REAL registered tool (env-only mode: no guest credentials configured)
    through mcp.call_tool."""
    import json as _json

    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    mcp = mod.get_mcp()

    import asyncio

    result = asyncio.run(mcp.call_tool(
        "hyperv_capture_evidence",
        {"vm_name": "test-vm", "ui_tree": True},
    ))
    content = result[0] if isinstance(result, tuple) else result
    text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
    assert text_blocks, "expected a text envelope for the credential failure"
    envelope = _json.loads(text_blocks[0].text)
    assert envelope["ok"] is False
    assert envelope["error_class"] == "credential"


def _envelope_from_call(mcp, tool: str, args: dict) -> dict:
    result = asyncio.run(mcp.call_tool(tool, args))
    content = result[0] if isinstance(result, tuple) else result
    text_blocks = [c for c in content if getattr(c, "type", "") == "text"]
    assert text_blocks, f"expected a text envelope for {tool}"
    return json.loads(text_blocks[0].text)


@pytest.fixture()
def unrestricted_server(tmp_path, fresh_server):
    doc = {"allowed_vm_patterns": ["test-*"], "unrestricted": True}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    mod = fresh_server({"HYPERV_MCP_CONFIG": str(p)})
    return mod.get_mcp()


def test_media_error_envelope_maps_invalid(unrestricted_server, tmp_path):
    """PRR-020: MediaError subclasses RuntimeError; without the explicit
    clause a missing-ISO fault (caller/vm-state, not transport) is mislabeled
    "transport" by the catch-all. Drives the real registered tool through
    mcp.call_tool; the fault fires before any PowerShell leg."""
    envelope = _envelope_from_call(
        unrestricted_server, "hyperv_vm_media_attach",
        {"vm_name": "test-vm", "iso_path": str(tmp_path / "nope.iso")},
    )
    assert envelope["ok"] is False
    assert envelope["error_class"] == "invalid"
    assert "nope.iso" in envelope["error"]


def test_mouse_move_omission_is_invalid_envelope(unrestricted_server):
    """PRR-014: omitting x/y on hyperv_console_mouse_move must surface as
    {ok:false, error_class:"invalid"} — it must never mean (0,0)."""
    envelope = _envelope_from_call(unrestricted_server, "hyperv_console_mouse_move", {})
    assert envelope["ok"] is False
    assert envelope["error_class"] == "invalid"
    assert "x and y are required" in envelope["error"]
