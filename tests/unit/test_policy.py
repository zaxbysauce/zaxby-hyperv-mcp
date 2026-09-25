"""Policy tests: path canonicalization hostility matrix + VM allowlists."""

import pytest

from hyperv_mcp.config import Config
from hyperv_mcp.policy import (
    PolicyDenied,
    canonicalize_windows_path,
    check_guest_read,
    check_guest_write,
    check_host_read,
    check_host_write,
    require_destructive,
    vm_allowed,
)

# ---------------------------------------------------------------------------
# canonicalization
# ---------------------------------------------------------------------------

def test_empty_and_whitespace_paths_rejected():
    for bad in ("", "   "):
        with pytest.raises(PolicyDenied):
            canonicalize_windows_path(bad)


def test_drive_relative_path_rejected():
    with pytest.raises(PolicyDenied, match="drive-relative"):
        canonicalize_windows_path("C:foo\\bar")
    with pytest.raises(PolicyDenied):
        canonicalize_windows_path("C:")


def test_long_path_prefix_stripped():
    cp = canonicalize_windows_path("\\\\?\\C:\\lab\\file.txt")
    assert cp.normalized.lower() == "c:\\lab\\file.txt"


def test_unc_prefix_and_unc_paths():
    cp = canonicalize_windows_path("\\\\?\\UNC\\server\\share\\f.txt")
    assert cp.normalized.startswith("\\\\server\\share")
    cp2 = canonicalize_windows_path("\\\\server\\share\\f.txt")
    assert cp2.normalized.lower() == "\\\\server\\share\\f.txt"


def test_dotdot_collapse():
    cp = canonicalize_windows_path("C:\\lab\\sub\\..\\file.txt")
    assert cp.normalized.lower() == "c:\\lab\\file.txt"


def test_mixed_separators_normalized():
    cp = canonicalize_windows_path("C:/lab/sub/../file.txt")
    assert cp.normalized.lower() == "c:\\lab\\file.txt"


def test_realpath_resolves_junctions(tmp_path):
    """A directory junction escaping the root must be caught (Windows)."""
    import subprocess

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(real)],
        capture_output=True,
    )
    if proc.returncode != 0:
        pytest.skip("junction creation unavailable on this host")
    secret = real / "secret.txt"
    secret.write_text("x", encoding="utf-8")
    cp = canonicalize_windows_path(str(link / "secret.txt"))
    # The resolved form points into .../real, NOT through the junction path.
    assert "real" in cp.exists_prefix_resolved.lower()


# ---------------------------------------------------------------------------
# host/guest root checks
# ---------------------------------------------------------------------------

def test_deny_when_no_roots_configured(deny_all_cfg, tmp_path):
    with pytest.raises(PolicyDenied, match="no host_read_roots"):
        check_host_read(deny_all_cfg, str(tmp_path / "f.txt"))


def test_unrestricted_bypasses(unrestricted_cfg, tmp_path):
    check_host_read(unrestricted_cfg, str(tmp_path / "anywhere.txt"))
    check_guest_write(unrestricted_cfg, "D:\\anything\\goes.bin")


def test_within_root_allowed(tmp_path):
    cfg = Config(host_read_roots=[str(tmp_path)])
    check_host_read(cfg, str(tmp_path / "sub" / "file.txt"))


def test_outside_root_denied(tmp_path):
    cfg = Config(host_read_roots=[str(tmp_path / "inside")])
    with pytest.raises(PolicyDenied, match="outside"):
        check_host_read(cfg, str(tmp_path / "outside.txt"))


def test_root_prefix_boundary_case(tmp_path):
    """C:\\foo must not authorize C:\\foobar."""
    root = tmp_path / "foo"
    root.mkdir()
    foobar = tmp_path / "foobar.txt"
    foobar.write_text("x", encoding="utf-8")
    cfg = Config(host_read_roots=[str(root)])
    with pytest.raises(PolicyDenied):
        check_host_read(cfg, str(foobar))


def test_case_insensitive_roots(tmp_path):
    cfg = Config(host_read_roots=[str(tmp_path).upper()])
    check_host_read(cfg, str(tmp_path / "File.TXT"))


def test_dotdot_escape_caught(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    cfg = Config(host_read_roots=[str(inside)])
    escape = str(inside / ".." / "outside.txt")
    with pytest.raises(PolicyDenied):
        check_host_read(cfg, escape)


def test_write_root_checked_again(tmp_path):
    cfg = Config(host_write_roots=[str(tmp_path / "w")])
    with pytest.raises(PolicyDenied):
        check_host_write(cfg, str(tmp_path / "other.bin"))
    check_host_write(cfg, str(tmp_path / "w" / "ok.bin"))


def test_guest_roots_checked_host_side():
    cfg = Config(guest_read_roots=["C:\\guest-data"], guest_write_roots=["C:\\guest-tmp"])
    check_guest_read(cfg, "C:\\guest-data\\dump.dmp")
    check_guest_write(cfg, "c:\\GUEST-TMP\\poc.exe")
    with pytest.raises(PolicyDenied):
        check_guest_read(cfg, "C:\\Windows\\System32\\config\\SAM")
    with pytest.raises(PolicyDenied):
        check_guest_write(cfg, "C:\\Users\\Administrator\\startup.cmd")


def test_nonexistent_guest_destination_allowed_inside_root():
    cfg = Config(guest_write_roots=["C:\\guest-tmp"])
    check_guest_write(cfg, "C:\\guest-tmp\\new\\dir\\file.bin")


# ---------------------------------------------------------------------------
# VM allowlist
# ---------------------------------------------------------------------------

def test_vm_denied_when_no_patterns(deny_all_cfg):
    with pytest.raises(PolicyDenied, match="no allowed_vm_patterns"):
        vm_allowed(deny_all_cfg, "anything")


def test_vm_pattern_match_case_insensitive():
    cfg = Config(allowed_vm_patterns=["test-vm-*"])
    vm_allowed(cfg, "Test-VM-01")
    with pytest.raises(PolicyDenied):
        vm_allowed(cfg, "prod-db-01")


def test_vm_wildcard_arg_needs_explicit_pattern():
    """A '*' vm_name must not match unless '*' is an explicit pattern."""
    cfg = Config(allowed_vm_patterns=["test-vm-*"])
    with pytest.raises(PolicyDenied):
        vm_allowed(cfg, "*")
    vm_allowed(Config(allowed_vm_patterns=["*"]), "*")


def test_hostile_vm_names_rejected_unless_allowed():
    cfg = Config(allowed_vm_patterns=["test-vm-*"])
    for hostile in ("*", "a*[b", "x?y", "`", "vm' with quote"):
        with pytest.raises(PolicyDenied):
            vm_allowed(cfg, hostile)
    with pytest.raises(PolicyDenied):
        vm_allowed(cfg, "")


def test_unrestricted_allows_hostile_names(unrestricted_cfg):
    vm_allowed(unrestricted_cfg, "*")


# ---------------------------------------------------------------------------
# destructive gates
# ---------------------------------------------------------------------------

def test_destructive_denied_by_category():
    cfg = Config()
    with pytest.raises(PolicyDenied, match="destructive:stop"):
        require_destructive(cfg, "stop", confirm=True, detail="stop VM")


def test_destructive_confirm_required():
    cfg = Config()
    cfg.destructive.stop = True
    with pytest.raises(PolicyDenied, match="confirm=true"):
        require_destructive(cfg, "stop", confirm=False, detail="stop VM")
    require_destructive(cfg, "stop", confirm=True, detail="stop VM")


def test_destructive_confirm_can_be_disabled():
    cfg = Config()
    cfg.destructive.stop = True
    cfg.destructive.require_confirm = False
    require_destructive(cfg, "stop", confirm=False, detail="stop VM")


def test_unrestricted_still_requires_confirm():
    """Critic fix: unrestricted skips category switches, NOT the confirm gate."""
    cfg = Config(unrestricted=True)
    with pytest.raises(PolicyDenied, match="confirm=true"):
        require_destructive(cfg, "stop", confirm=False, detail="stop VM")
    require_destructive(cfg, "stop", confirm=True, detail="stop VM")


def test_unrestricted_with_confirm_disabled_allows():
    cfg = Config(unrestricted=True)
    cfg.destructive.require_confirm = False
    require_destructive(cfg, "reset", confirm=False, detail="reset VM")


def test_restricted_category_with_confirm_disabled_allows():
    cfg = Config()
    cfg.destructive.stop = True
    cfg.destructive.require_confirm = False
    require_destructive(cfg, "stop", confirm=False, detail="stop VM")


def test_drive_root_guest_read_allowed():
    r"""Critic fix: a drive-root root ("C:\") must authorize descendants."""
    cfg = Config(guest_read_roots=["C:\\"])
    check_guest_read(cfg, r"C:\Windows\Temp\f.txt")
    check_guest_read(cfg, r"c:\anything")


def test_exact_root_equality_allowed():
    cfg = Config(guest_read_roots=[r"C:\Windows\Temp"])
    check_guest_read(cfg, r"C:\Windows\Temp")
    check_guest_read(cfg, r"C:\Windows\Temp\sub")


def test_drive_relative_root_never_matches():
    """A policy-invalid root ("C:") must not degrade into a loose prefix."""
    cfg = Config(host_read_roots=["C:"])
    with pytest.raises(PolicyDenied):
        check_host_read(cfg, r"C:\Windows\System32\config\SAM")
