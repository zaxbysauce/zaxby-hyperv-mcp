"""Unit tests for pswindows.child_env() — the FND-03 child environment sanitizer.

The frozen acceptance checks (tests/unit/test_a01_ps_environment.py) assert the
EFFECTIVE environment at the run_ps spawn; these tests pin child_env()'s
individual branches directly: secret-name removal (fixed names, the configured
HTTP token name, and a custom-configured token name), PSModulePath
filtering/normalization, absence handling, the pre-init fallback, and the
_taskkill_tree spawn. Dummy sentinel values only — no real credentials.
"""

import os
import re
from pathlib import Path

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


def _local_canon(value: str) -> str:
    """Test-local path canonicalizer, deliberately independent of
    pswindows._norm_path: the dedup and absence assertions below must stay
    discriminating even if the production normalizer regresses (a
    self-referential oracle cannot catch the bug it shares with the code)."""
    return value.strip().lower().replace("/", "\\").rstrip("\\")


def test_child_env_51_dir_comparison_is_normalization_adversarial(monkeypatch):
    """Case, slash direction, trailing separators and padding must all count
    as 'already present' (no duplicate append) while every pwsh7 spelling is
    still filtered. Assertions are deliberately NOT self-referential: pwsh7
    absence is checked literally (kept entries pass through verbatim) and the
    dedup count uses a test-local canonicalizer, so reverting the production
    _norm_path/_is_pwsh7_module_entry fixes fails this test."""
    already_present_spellings = [
        PS51.lower(),
        PS51.upper(),
        PS51.replace("\\", "/"),
        PS51 + "\\",
        # Trailing FORWARD slash (F-001/F-020): slash conversion must happen
        # before trailing-separator stripping or this spelling duplicates the
        # 5.1 system directory in the child PSModulePath.
        PS51.replace("\\", "/") + "/",
        f"  {PS51}  ",
    ]
    for spelling in already_present_spellings:
        monkeypatch.setenv("PSModulePath", ";".join([spelling, PROGRAM_FILES_51_MODULES]))
        env = pswindows.child_env()
        normalized = [_local_canon(e) for e in _split(env)]
        assert normalized.count(_local_canon(PS51)) == 1, (
            f"spelling {spelling!r} was not recognized as the 5.1 system "
            f"module directory; child entries: {_split(env)!r}"
        )

    pwsh7_spellings = [
        r"c:\program files\powershell\modules",
        r"C:/Program Files/PowerShell/Modules",
        # Trailing forward slash (F-001): rstrip must run after slash
        # conversion or the trailing separator defeats the equality checks.
        r"C:/Program Files/PowerShell/Modules/",
        r"C:/Users/probe-user/Documents/PowerShell/Modules/",
        r"C:\Program Files\PowerShell\7\Modules\\",
        r"C:\Users\PROBE-USER\documents\powershell\modules",
        # Preview/daily installs (F-002) and versioned side-by-side roots.
        r"C:\Program Files\PowerShell\7-preview\Modules",
        r"C:\Program Files\PowerShell\7-daily\Modules",
        r"C:\Program Files\PowerShell\7.4.6\Modules",
        r"C:/Program Files/PowerShell/7-preview/",
        # Nested install parent: every "\powershell\" segment occurrence must
        # be checked, not just the first.
        r"C:\PowerShell\PowerShell\7\Modules",
    ]
    for spelling in pwsh7_spellings:
        monkeypatch.setenv("PSModulePath", ";".join([spelling, USER_51_MODULES]))
        env = pswindows.child_env()
        entries = _split(env)
        # Literal absence: kept entries pass through verbatim, so if the
        # filter misses this spelling the exact string survives into the
        # child — no predicate call needed (the predicate is the code under
        # test and cannot certify itself).
        assert spelling not in entries, (
            f"pwsh7 spelling {spelling!r} survived filtering (literal match): "
            f"{entries!r}"
        )
        assert not any(pswindows._is_pwsh7_module_entry(e) for e in entries), (
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


def test_child_env_strips_custom_token_env_plus_default_name(monkeypatch):
    """F-006: customizing http.token_env must not re-enable the literal
    default HYPERV_MCP_HTTP_TOKEN name — both are stripped together."""
    monkeypatch.setattr(
        pswindows, "_config",
        Config(http=HttpPolicy(token_env="CUSTOM_HTTP_TOKEN")),
    )
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sentinel-default-token")
    monkeypatch.setenv("CUSTOM_HTTP_TOKEN", "sentinel-custom-token")
    env = pswindows.child_env()
    assert not _env_has(env, "HYPERV_MCP_HTTP_TOKEN"), (
        "child_env kept the default token name while token_env was customized"
    )
    assert not _env_has(env, "CUSTOM_HTTP_TOKEN")


def test_child_env_strips_padded_configured_token_env(monkeypatch):
    """F-017: a whitespace-padded token_env value must still match the real
    variable name (trimmed before the case-insensitive union)."""
    monkeypatch.setattr(
        pswindows, "_config",
        Config(http=HttpPolicy(token_env="  HYPERV_MCP_HTTP_TOKEN  ")),
    )
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sentinel-padded-token-env")
    env = pswindows.child_env()
    assert not _env_has(env, "HYPERV_MCP_HTTP_TOKEN"), (
        "a padded http.token_env defeated the child-env secret strip"
    )


def test_child_env_strips_git_probe_env_names(monkeypatch):
    """F-003: inherited GIT_DIR/GIT_WORK_TREE would redirect the git
    provenance probe; child_env strips them."""
    monkeypatch.setattr(pswindows, "_config", None)
    monkeypatch.setenv("GIT_DIR", r"Z:\unrelated\.git")
    monkeypatch.setenv("GIT_WORK_TREE", r"Z:\unrelated")
    env = pswindows.child_env()
    assert not _env_has(env, "GIT_DIR")
    assert not _env_has(env, "GIT_WORK_TREE")


def test_child_env_preserves_ordinary_entries(monkeypatch):
    """F-014 (positive preservation): PATH/TEMP/SystemRoot markers must
    survive child_env so a fix that strips ordinary child-env entries fails
    the suite instead of silently breaking bare-name resolution in children."""
    monkeypatch.setattr(pswindows, "_config", None)
    monkeypatch.setenv("PATH", r"C:\probe-path-marker")
    monkeypatch.setenv("TEMP", r"C:\probe-temp-marker")
    monkeypatch.setenv("SystemRoot", r"C:\probe-systemroot-marker")
    env = pswindows.child_env()
    assert _env_get(env, "PATH") == r"C:\probe-path-marker"
    assert _env_get(env, "TEMP") == r"C:\probe-temp-marker"
    assert _env_get(env, "SystemRoot") == r"C:\probe-systemroot-marker"


def test_taskkill_tree_spawn_psmodulepath_is_sanitized(monkeypatch):
    """F-042 (defense in depth): the taskkill-site child env must also carry
    the sanitized PSModulePath, not only stripped secrets."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(pswindows.subprocess, "run", fake_run)
    monkeypatch.setenv(
        "PSModulePath",
        ";".join(PWSH7_ENTRIES + [PS51, PROGRAM_FILES_51_MODULES]),
    )
    pswindows._taskkill_tree(4242)
    env = captured["env"]
    assert env is not None
    entries = _split(env)
    assert entries, "taskkill-site child PSModulePath became empty"
    assert not any(pswindows._is_pwsh7_module_entry(e) for e in entries), (
        f"taskkill-site child PSModulePath still carries pwsh7 entries: {entries}"
    )
    assert pswindows._norm_path(PS51) in {pswindows._norm_path(e) for e in entries}


class _FakeChildProcess:
    """Stands in for the Popen object run_ps drives; nothing really spawns."""

    pid = 4242
    _handle = 0
    returncode = 0

    def communicate(self, input=None, timeout=None):
        return b"", b""

    def kill(self):
        return None


def test_run_ps_child_psmodulepath_per_entry_membership(monkeypatch):
    """F-027 / cub-05 sibling equivalent: the frozen AC1 asserts 5.1-dir
    presence with a substring check over the joined PSModulePath, which can
    false-pass on superstring entries produced by join corruption. This test
    runs the same spawn capture but asserts PER-ENTRY (set) membership.
    tests/unit/test_a01_ps_environment.py is frozen and cannot be edited."""
    seen = {}

    def recording_popen(argv, *args, **kwargs):
        env_kwarg = kwargs.get("env")
        seen["env"] = dict(env_kwarg) if env_kwarg is not None else dict(os.environ)
        return _FakeChildProcess()

    monkeypatch.setattr(pswindows.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(pswindows, "_make_kill_on_close_job", lambda: None)
    monkeypatch.setattr(pswindows, "_resume_process", lambda pid: True)
    superstring = PS51 + r"\Backup"
    monkeypatch.setenv(
        "PSModulePath",
        ";".join([superstring, PS51, PROGRAM_FILES_51_MODULES]),
    )
    pswindows.init(Config(max_output_bytes=1024 * 1024))

    result = pswindows.run_ps("Write-Output 'per-entry-probe'", timeout_s=30)

    assert result.ok(), result.stderr
    child_module_path = _env_get(seen["env"], "PSModulePath") or ""
    entries = {pswindows._norm_path(e) for e in child_module_path.split(";") if e.strip()}
    assert pswindows._norm_path(PS51) in entries, (
        "run_ps child PSModulePath lost the 5.1 system module directory as an "
        f"exact (normalized) entry; entries: {sorted(entries)!r}"
    )


def test_secret_env_names_agree_across_sources(monkeypatch):
    """F-030 (anti-drift): every secret-looking env name hardcoded under src/
    (credentials, http_entry, server, pswindows) must be stripped by
    child_env(), so adding a credential variable without updating
    _SECRET_ENV_NAMES fails here instead of leaking silently."""
    pattern = re.compile(r"\bHYPERV_[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET)[A-Z0-9_]*\b")
    names: set[str] = set()
    src_dir = Path(pswindows.__file__).resolve().parent
    for fname in ("credentials.py", "http_entry.py", "server.py", "pswindows.py"):
        names |= set(pattern.findall((src_dir / fname).read_text(encoding="utf-8")))
    assert names, "scan found no secret-name literals — the scan regex drifted"
    monkeypatch.setattr(pswindows, "_config", None)
    for env_name in sorted(names):
        monkeypatch.setenv(env_name, "sentinel-agreement")
    env = pswindows.child_env()
    leaked = [n for n in sorted(names) if _env_has(env, n)]
    assert leaked == [], f"child_env does not strip cross-module secret names: {leaked}"


def test_host_powershell_path_pwsh7_configuration(monkeypatch):
    """F-009 (routed critic required_change, characterization): with
    host_powershell_path pointed at a pwsh7 executable, find_powershell
    returns it while child_env still hands the child a 5.1-only PSModulePath.
    This pins the documented limitation (README, child_env docstring): the
    pwsh7 child loses its pwsh7 module directories on every spawn. A future
    shell-aware child_env must change this test deliberately, not silently."""
    pwsh7_exe = r"C:\Program Files\PowerShell\7\pwsh.exe"
    cfg = Config(max_output_bytes=1024 * 1024, host_powershell_path=pwsh7_exe)
    pswindows.init(cfg)
    assert pswindows.find_powershell(cfg.host_powershell_path) == pwsh7_exe, (
        "find_powershell must honor the configured pwsh7 host path"
    )
    monkeypatch.setenv("PSModulePath", ";".join(PWSH7_ENTRIES + [USER_51_MODULES]))
    env = pswindows.child_env()
    entries = _split(env)
    assert not any(pswindows._is_pwsh7_module_entry(e) for e in entries), (
        "pwsh7-configured host: child PSModulePath unexpectedly kept pwsh7 entries"
    )
    assert pswindows._norm_path(PS51) in {pswindows._norm_path(e) for e in entries}, (
        "pwsh7-configured host: child PSModulePath is not 5.1-shaped (the "
        "documented limitation this test pins)"
    )


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
