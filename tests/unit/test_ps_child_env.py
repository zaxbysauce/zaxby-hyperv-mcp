"""Unit tests for pswindows.child_env() — the FND-03 child environment sanitizer.

The frozen acceptance checks (tests/unit/test_a01_ps_environment.py) assert the
EFFECTIVE environment at the run_ps spawn; these tests pin child_env()'s
individual branches directly: secret-name removal (fixed names, the configured
HTTP token name, and a custom-configured token name), PSModulePath
filtering/normalization, absence handling, the pre-init fallback, and the
_taskkill_tree spawn. Dummy sentinel values only — no real credentials.
"""

import os

from hyperv_mcp import pswindows
from hyperv_mcp.config import Config, HttpPolicy

PS51 = pswindows.PS51_SYSTEM_MODULES
PWSH7_ENTRIES = [
    r"C:\Users\probe-user\Documents\PowerShell\Modules",
    r"C:\Program Files\PowerShell\Modules",
    r"C:\Program Files\PowerShell\7\Modules",
]
USER_51_MODULES = r"C:\Users\brett\Documents\WindowsPowerShell\Modules"
PROGRAM_FILES_51_MODULES = r"C:\Program Files\WindowsPowerShell\Modules"


def _env_get(env, name):
    """Case-insensitive key lookup (Windows env names may arrive in any case)."""
    for key in env:
        if key.upper() == name.upper():
            return env[key]
    return None


def _env_has(env, name):
    return _env_get(env, name) is not None


def _split(env):
    value = _env_get(env, "PSModulePath") or ""
    return [entry for entry in value.split(";") if entry.strip()]


def _seed_fixed_secrets(monkeypatch):
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "sentinel-guest-password")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD_FILE", "sentinel-guest-password-file")
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_PASSWORD", "sentinel-victim-password")
    monkeypatch.setenv("HYPERV_GUEST_VICTIM_PASSWORD_FILE", "sentinel-victim-password-file")


def test_child_env_drops_all_fixed_secret_names(monkeypatch):
    """All four _SECRET_ENV_NAMES are removed regardless of configured state."""
    _seed_fixed_secrets(monkeypatch)
    env = pswindows.child_env()
    leaked = sorted(
        name for name in (
            "HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_PASSWORD_FILE",
            "HYPERV_GUEST_VICTIM_PASSWORD", "HYPERV_GUEST_VICTIM_PASSWORD_FILE",
        ) if _env_has(env, name)
    )
    assert leaked == [], f"child_env leaked fixed secret names: {leaked}"


def test_child_env_drops_default_http_token(monkeypatch):
    """With no configured override the default HTTP token name is removed."""
    monkeypatch.setattr(pswindows, "_config", None)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sentinel-http-token")
    env = pswindows.child_env()
    assert not _env_has(env, "HYPERV_MCP_HTTP_TOKEN")


def test_child_env_drops_custom_configured_token_env(monkeypatch):
    """A non-default http.token_env name is honored (case-insensitive)."""
    monkeypatch.setattr(
        pswindows, "_config",
        Config(http=HttpPolicy(token_env="CUSTOM_HTTP_TOKEN")),
    )
    monkeypatch.setenv("custom_http_token", "sentinel-custom-token")
    env = pswindows.child_env()
    assert not _env_has(env, "CUSTOM_HTTP_TOKEN"), (
        "child_env kept the configured http.token_env name"
    )


def test_child_env_secret_removal_is_case_insensitive(monkeypatch):
    """Secret keys are matched by uppercasing the actual key, not by exact
    spelling; a lowercase key must still be removed."""
    monkeypatch.setattr(os, "environ", {
        "hyperv_guest_password": "sentinel",
        "HyperV_Guest_Victim_Password": "sentinel",
        "hyperv_probe_marker": "not-a-secret-name",
        "Path": r"C:\Windows",
    })
    monkeypatch.setattr(pswindows, "_config", None)
    env = pswindows.child_env()
    assert not _env_has(env, "HYPERV_GUEST_PASSWORD")
    assert not _env_has(env, "HYPERV_GUEST_VICTIM_PASSWORD")
    # Control: a non-secret name in odd case must survive.
    assert _env_get(env, "hyperv_probe_marker") == "not-a-secret-name"


def test_child_env_absent_psmodulepath_stays_absent(monkeypatch):
    """No PSModulePath in the parent environment => none in the child."""
    monkeypatch.delenv("PSModulePath", raising=False)
    monkeypatch.delenv("PSMODULEPATH", raising=False)
    assert not any(k.upper() == "PSMODULEPATH" for k in os.environ), (
        "test setup: host PSModulePath could not be removed"
    )
    env = pswindows.child_env()
    assert not any(k.upper() == "PSMODULEPATH" for k in env)


def test_child_env_removes_key_when_all_entries_are_pwsh7(monkeypatch):
    """A PSModulePath with nothing but pwsh7 entries is dropped entirely
    rather than handed to a 5.1 child empty or poisoned."""
    monkeypatch.setenv("PSModulePath", ";".join(PWSH7_ENTRIES + ["", "   "]))
    env = pswindows.child_env()
    assert not _env_has(env, "PSModulePath")


def test_child_env_filters_pwsh7_and_appends_51_system_dir(monkeypatch):
    """pwsh7 entries are dropped; surviving 5.1 entries are kept and the 5.1
    system module directory is appended when it is not already present."""
    monkeypatch.setenv(
        "PSModulePath",
        ";".join(PWSH7_ENTRIES + [USER_51_MODULES, PROGRAM_FILES_51_MODULES]),
    )
    env = pswindows.child_env()
    entries = _split(env)
    assert entries, "child PSModulePath became empty"
    assert not any(pswindows._is_pwsh7_module_entry(e) for e in entries), (
        f"child PSModulePath still carries pwsh7 entries: {entries}"
    )
    assert USER_51_MODULES in entries, "5.1 user module directory was dropped"
    assert PROGRAM_FILES_51_MODULES in entries, "5.1 program-files modules dropped"
    assert pswindows._norm_path(PS51) in {pswindows._norm_path(e) for e in entries}, (
        "5.1 system module directory not appended"
    )
    # The canonical constant is appended when missing, exactly once.
    normalized = [pswindows._norm_path(e) for e in entries]
    assert normalized.count(pswindows._norm_path(PS51)) == 1


def test_child_env_does_not_duplicate_existing_51_system_dir(monkeypatch):
    """When the 5.1 system directory is already present it is not appended a
    second time."""
    monkeypatch.setenv(
        "PSModulePath",
        ";".join([PS51, PROGRAM_FILES_51_MODULES, USER_51_MODULES]),
    )
    env = pswindows.child_env()
    normalized = [pswindows._norm_path(e) for e in _split(env)]
    assert normalized.count(pswindows._norm_path(PS51)) == 1


def test_child_env_51_dir_comparison_is_normalization_adversarial(monkeypatch):
    """Case, slash direction, trailing separators and padding must all count
    as 'already present' (no duplicate append) while every pwsh7 spelling is
    still filtered."""
    already_present_spellings = [
        PS51.lower(),
        PS51.upper(),
        PS51.replace("\\", "/"),
        PS51 + "\\",
        f"  {PS51}  ",
    ]
    for spelling in already_present_spellings:
        monkeypatch.setenv("PSModulePath", ";".join([spelling, PROGRAM_FILES_51_MODULES]))
        env = pswindows.child_env()
        normalized = [pswindows._norm_path(e) for e in _split(env)]
        assert normalized.count(pswindows._norm_path(PS51)) == 1, (
            f"spelling {spelling!r} was not recognized as the 5.1 system "
            f"module directory; child entries: {_split(env)!r}"
        )

    pwsh7_spellings = [
        r"c:\program files\powershell\modules",
        r"C:/Program Files/PowerShell/Modules",
        r"C:\Program Files\PowerShell\7\Modules\\",
        r"C:\Users\PROBE-USER\documents\powershell\modules",
    ]
    for spelling in pwsh7_spellings:
        monkeypatch.setenv("PSModulePath", ";".join([spelling, USER_51_MODULES]))
        env = pswindows.child_env()
        assert not any(pswindows._is_pwsh7_module_entry(e) for e in _split(env)), (
            f"pwsh7 spelling {spelling!r} survived filtering: {_split(env)!r}"
        )


def test_child_env_keeps_username_like_entries(monkeypatch):
    """Entries that merely contain a user profile or 'PowerShell' substring
    are not over-filtered."""
    monkeypatch.setenv(
        "PSModulePath",
        ";".join([
            r"C:\Users\brett\Documents\WindowsPowerShell\Modules",
            r"C:\Program Files\WindowsPowerShell\Modules",
            PS51,
        ]),
    )
    env = pswindows.child_env()
    entries = _split(env)
    assert r"C:\Users\brett\Documents\WindowsPowerShell\Modules" in entries
    assert r"C:\Program Files\WindowsPowerShell\Modules" in entries


def test_child_env_drops_empty_entries(monkeypatch):
    """Empty and whitespace-only segments never reach the child."""
    monkeypatch.setenv(
        "PSModulePath",
        ";".join([PROGRAM_FILES_51_MODULES, "", "   ", PS51]),
    )
    env = pswindows.child_env()
    entries = _split(env)
    assert all(entry.strip() for entry in entries)
    # The gap itself is gone: joined value has no doubled separators.
    value = _env_get(env, "PSModulePath")
    assert ";;" not in value
    assert not any(part == "" for part in value.split(";"))


def test_child_env_works_before_init(monkeypatch):
    """_config is None before pswindows.init(): the default token name is
    still honored and sanitization must not raise."""
    monkeypatch.setattr(pswindows, "_config", None)
    _seed_fixed_secrets(monkeypatch)
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sentinel-http-token")
    env = pswindows.child_env()
    assert not _env_has(env, "HYPERV_GUEST_PASSWORD")
    assert not _env_has(env, "HYPERV_MCP_HTTP_TOKEN")


def test_taskkill_tree_spawns_with_sanitized_env(monkeypatch):
    """The timeout kill path (subprocess.run) must receive child_env() too —
    it was the second unfiltered spawn site in FND-03."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["env"] = kwargs.get("env")

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(pswindows.subprocess, "run", fake_run)
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "sentinel-guest-password")
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sentinel-http-token")

    pswindows._taskkill_tree(4242)

    assert captured["argv"][:3] == ["taskkill", "/T", "/F"]
    assert captured["env"] is not None, "_taskkill_tree spawned without env="
    assert not _env_has(captured["env"], "HYPERV_GUEST_PASSWORD")
    assert not _env_has(captured["env"], "HYPERV_MCP_HTTP_TOKEN")
