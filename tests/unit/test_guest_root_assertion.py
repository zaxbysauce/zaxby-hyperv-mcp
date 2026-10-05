r"""Real-PS execution lane for the in-guest root-assertion fragment.

Runs the REAL filetransfer._guest_root_assertion (not a hand-reconstructed
copy) under Windows PowerShell 5.1 with a try/catch termination wrapper, so
throw semantics, GetFullPath quirks, error classification, and the
below-root reparse walk are exercised for real — a mocked unit test happily
accepts a fragment real PowerShell would reject or fail-open on.

Junction cases need a real NTFS volume (tmp_path) and cmd mklink; the
platform gate is deterministic (sys.platform), never PATH probing.
"""

import string
import subprocess
import sys

import pytest

from hyperv_mcp import filetransfer, pswindows
from hyperv_mcp.config import Config

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="real PS 5.1 fragment execution needs Windows",
)

# Original acceptance cases: containment semantics against real PowerShell.
CASES = [
    ("C:\\Windows\\Temp\\sub\\f.txt", ["C:\\"], "ALLOW"),                     # drive root
    ("c:\\anything", ["C:\\"], "ALLOW"),                                     # case + drive root
    ("C:\\Windows\\Temp", ["C:\\Windows\\Temp"], "ALLOW"),                   # exact root
    ("C:\\Windows\\Temp\\sub\\f", ["C:\\Windows\\Temp"], "ALLOW"),           # descendant
    ("C:\\Windows\\System32\\config\\SAM", ["C:\\Windows\\Temp"], "DENY"),
    ("C:\\TempX\\evil", ["C:\\Temp"], "DENY"),                               # boundary: C:\TempX vs C:\Temp
]


def _run_fragment(fragment: str) -> tuple[str, str]:
    """Execute the fragment under try/catch; return (verdict, detail).

    ALLOW = fragment completed; DENY = it threw (detail carries the message);
    ERROR = the script itself failed (parse error, runner failure) — always
    a test failure, never a silent pass.
    """
    wrapped = (
        "try {\n" + fragment + "\n'ALLOW'\n} catch {\n"
        "'DENY: ' + $_.Exception.Message\n}"
    )
    pswindows.init(Config())
    result = pswindows.run_ps(wrapped, timeout_s=60)
    out = (result.stdout or "").strip()
    if out == "ALLOW":
        return "ALLOW", out
    if out.startswith("DENY"):
        return "DENY", out
    return "ERROR", f"rc={result.returncode} stdout={out!r} stderr={(result.stderr or '')!r}"


def _assert_verdict(path: str, roots: list[str], expected: str) -> str:
    fragment = filetransfer._guest_root_assertion(path, roots, "write")
    verdict, detail = _run_fragment(fragment)
    assert verdict != "ERROR", detail
    assert verdict == expected, (path, roots, detail)
    return detail


def _mkjunction(link, target) -> None:
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        errors="replace",
    )
    assert proc.returncode == 0, f"mklink /J failed: {(proc.stdout + proc.stderr).strip()}"


@pytest.mark.parametrize("path,roots,expected", CASES)
def test_guest_root_assertion(path, roots, expected):
    _assert_verdict(path, roots, expected)


def test_nonexistent_tail_allowed(tmp_path):
    """Missing components are legal (put creates parents after this runs);
    a missing component cannot be a reparse point."""
    root = tmp_path / "g-root"
    root.mkdir()
    _assert_verdict(str(root / "newdir" / "deep" / "f.bin"), [str(root)], "ALLOW")


def test_below_root_junction_denied(tmp_path):
    """A junction planted INSIDE an allowed root must not be traversable."""
    root = tmp_path / "g-root"
    root.mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    _mkjunction(root / "esc", target)
    detail = _assert_verdict(str(root / "esc" / "f.bin"), [str(root)], "DENY")
    assert "reparse point" in detail, detail


def test_at_root_junction_allowed(tmp_path):
    """A reparse AT the root is the operator's own spelling of the root
    (documented contract: only components strictly below are walked)."""
    target = tmp_path / "real-root"
    target.mkdir()
    link = tmp_path / "root-link"
    _mkjunction(link, target)
    _assert_verdict(str(link / "f.bin"), [str(link)], "ALLOW")


def test_above_root_junction_allowed(tmp_path):
    """A junction ABOVE the root is likewise the operator's spelling: the
    walk is anchored at the matched root, not at the drive root."""
    real = tmp_path / "sub"
    real.mkdir()
    _mkjunction(tmp_path / "sub-link", real)
    _assert_verdict(
        str(tmp_path / "sub-link" / "g-root" / "f.bin"),
        [str(tmp_path / "sub-link" / "g-root")],
        "ALLOW",
    )


def test_missing_drive_fails_closed():
    """A Get-Item failure other than "item does not exist" (missing drive,
    access denied) must deny — an inspection error is never evidence of
    "no reparse here" (fail-open walk regression pin)."""
    import os

    absent = next(
        (letter for letter in string.ascii_uppercase if not os.path.isdir(f"{letter}:\\")),
        None,
    )
    if absent is None:
        pytest.skip("no absent drive letter available to probe")
    detail = _assert_verdict(f"{absent}:\\g\\f.bin", [f"{absent}:\\g"], "DENY")
    assert "cannot inspect" in detail, detail


def test_long_path_denied_as_policy_on_ps51(tmp_path):
    """PS 5.1 GetFullPath throws on >260-char paths; that throw must surface
    as a policy denial (fail closed), not a transport error."""
    long_path = str(tmp_path) + "\\" + "x" * 260 + "\\f.txt"
    assert len(long_path) > 260
    detail = _assert_verdict(long_path, [str(tmp_path)], "DENY")
    assert "cannot be canonicalized" in detail, detail


def test_unc_walk_anchors_at_share_not_drive_root():
    r"""UNC containment is real: the walk acc starts at \\server\share,
    never at a bare "\" (the drive-root split seed would make the UNC walk
    root-relative and meaningless). Unreachable components read as absent,
    so the containment check itself decides allow/deny."""
    fragment = filetransfer._guest_root_assertion(
        r"\\server\share\f", [r"\\server\share"], "write"
    )
    assert "$policyWalk" in fragment
    assert "$policyParts" not in fragment, "drive-root split seed resurrected for UNC"
    verdict, detail = _run_fragment(fragment)
    assert verdict != "ERROR", detail
    assert verdict == "ALLOW", detail
    _assert_verdict(r"\\server\other\f", [r"\\server\share"], "DENY")


def test_long_prefix_input_is_normalized_host_side():
    r"""\?\-prefixed input is stripped before it reaches the guest — PS 5.1
    GetFullPath would THROW on the literal prefix, turning a valid host-
    canonicalized path into a spurious denial."""
    fragment = filetransfer._guest_root_assertion(
        r"\\?\C:\g-write\f", ["C:\\g-write"], "write"
    )
    assert "\\\\?\\" not in fragment, r"\\?\ prefix leaked into guest script"


def test_no_roots_means_no_fragment():
    """unrestricted mode passes no roots; the fragment must be empty so the
    open path stays usable (policy.py: every check passes)."""
    assert filetransfer._guest_root_assertion("C:\\x", [], "write") == ""


def test_walk_anchored_at_matched_root_not_drive_root():
    """Structural pin for the walk anchor: the fragment splits the path at
    the matched root ($policyWalk), never at the drive root
    ($policyParts[0] — the PRR-004/PRR-005 defect shape)."""
    fragment = filetransfer._guest_root_assertion(
        r"C:\g-write\sub\f.bin", ["C:\\g-write"], "write"
    )
    assert "$policyWalk" in fragment
    assert "$policyParts" not in fragment
