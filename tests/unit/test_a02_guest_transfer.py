"""Guest transfer acceptance checks (issue #6, AC1-AC7).

Captured-script checks pin where guest_put/guest_get render the guest
root-assertion fragment and which staging names they use; policy checks pin
the error_class of an in-guest policy denial and the semantics of guest-axis
path checks against host reparse resolution. The script-scanning helpers are
adapted from the issue trace's reproduction probe.
"""

import json
import os
import re
import subprocess
import sys

import pytest

from hyperv_mcp import filetransfer, policy, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
MARKER = "$policyPath = [System.IO.Path]::GetFullPath("


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        # Exhaustion = failure: a silent ok here would mask a tool issuing
        # more PowerShell runs than the test scripted responses for.
        item = (
            self.responses.pop(0)
            if self.responses
            else pswindows.PSResult(returncode=1, stderr="FakePS: fixture exhausted (no scripted response)")
        )
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def rooted_cfg(tmp_path):
    src = tmp_path / "host-src"
    src.mkdir()
    dst = tmp_path / "host-dst"
    dst.mkdir()
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_read_roots=[str(src)],
        host_write_roots=[str(dst)],
        guest_read_roots=["C:\\g-read"],
        guest_write_roots=["C:\\g-write"],
    )
    cfg.destructive.guest_write = True
    cfg.destructive.require_confirm = False
    return cfg


def _scan_spans(script):
    """Brace-match every `-ScriptBlock { ... }` body, skipping quotes/comments."""
    opens = {m.end() - 1 for m in re.finditer(r"-ScriptBlock\s*\{", script)}
    spans, stack, i, n = [], [], 0, len(script)
    while i < n:
        c = script[i]
        if c == "#":
            j = script.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "'":
            i += 1
            while i < n:
                if script[i] == "'":
                    if i + 1 < n and script[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if c == '"':
            i += 1
            while i < n:
                if script[i] == "`":
                    i += 2
                    continue
                if script[i] == '"':
                    if i + 1 < n and script[i + 1] == '"':
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if c == "{":
            stack.append(i)
        elif c == "}":
            if stack:
                start = stack.pop()
                if start in opens:
                    spans.append((start, i))
        i += 1
    return spans


def assertion_placement(script):
    """(outside_guest, inside_guest) occurrence counts for the assertion marker."""
    spans = _scan_spans(script)
    outside = inside = 0
    for m in re.finditer(re.escape(MARKER), script):
        if any(start < m.start() < end for start, end in spans):
            inside += 1
        else:
            outside += 1
    return (outside, inside)


def staged_destination(script, session_kw):
    """The single-quoted -Destination literal of a Copy-Item line."""
    m = re.search(rf"Copy-Item -{session_kw} .*?-Destination ('(?:[^']|'')*')", script, re.S)
    assert m is not None, f"Copy-Item -{session_kw} destination not found in script"
    return m.group(1)[1:-1].replace("''", "'")


def _outcome(check, cfg, path):
    try:
        check(cfg, path)
    except policy.PolicyDenied:
        return "denied"
    return "allowed"


def test_put_root_assertion_runs_inside_guest(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    payload = {
        "ok": True,
        "bytes_copied": 1,
        "bytes_local": 1,
        "bytes_remote": 1,
        "sha256_local": None,
        "sha256_remote": None,
    }
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg,
        "test-vm-a",
        str(src),
        r"C:\g-write\a.bin",
        confirm=True,
        verify=False,
        cred=CRED,
    )
    # put runs the assertion TWICE, both inside guest -ScriptBlocks: before
    # dir creation/copy, and again immediately before the final Move-Item so
    # the move re-checks the boundary after the staging window.
    assert assertion_placement(fake.scripts[0]) == (0, 2)
    script = fake.scripts[0]
    markers = [m.start() for m in re.finditer(re.escape(MARKER), script)]
    assert len(markers) == 2
    move_at = script.index("Move-Item -LiteralPath")
    assert markers[1] < move_at, "re-walk must precede the final Move-Item"


def test_get_root_assertion_runs_inside_guest(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "a.bin"
    payload = {"ok": True, "bytes_copied": 1, "bytes_remote": 1, "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_get(
        rooted_cfg,
        "test-vm-a",
        r"C:\g-read\a.bin",
        str(dest),
        verify=True,
        cred=CRED,
    )
    assert assertion_placement(fake.scripts[0]) == (0, 1)


def test_put_staging_name_unique_per_transfer(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    payload = {
        "ok": True,
        "bytes_copied": 1,
        "bytes_local": 1,
        "bytes_remote": 1,
        "sha256_local": None,
        "sha256_remote": None,
    }
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)] * 2)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    for _ in range(2):
        filetransfer.guest_put(
            rooted_cfg,
            "test-vm-a",
            str(src),
            r"C:\g-write\a.bin",
            confirm=True,
            verify=False,
            cred=CRED,
        )
    first = staged_destination(fake.scripts[0], "ToSession")
    second = staged_destination(fake.scripts[1], "ToSession")
    assert first != second


def test_get_staging_name_unique_per_transfer(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "f.bin"
    payload = {"ok": True, "bytes_copied": 5, "bytes_remote": 5, "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)] * 2)
    monkeypatch.setattr(pswindows, "run_ps", fake)
    for vm in ("test-vm-a", "test-vm-b"):
        filetransfer.guest_get(
            rooted_cfg,
            vm,
            r"C:\g-read\f.bin",
            str(dest),
            verify=True,
            cred=CRED,
        )
    first = staged_destination(fake.scripts[0], "FromSession")
    second = staged_destination(fake.scripts[1], "FromSession")
    assert first != second


def test_in_guest_policy_denial_maps_to_policy_class(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    fake = FakePS(
        [
            pswindows.PSResult(
                returncode=1,
                stderr="policy: guest write denied (reparse point in path inside root)",
            )
        ]
    )
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg,
        "test-vm-a",
        str(src),
        r"C:\g-write\a.bin",
        confirm=True,
        verify=False,
        cred=CRED,
    )
    assert out["ok"] is False
    assert out["error_class"] == "policy"


def test_guest_axes_do_not_use_host_realpath(monkeypatch):
    real_realpath = os.path.realpath

    def seam(path):
        if str(path).casefold() == r"c:\elsewhere\x.bin".casefold():
            return r"C:\g-write\x.bin"
        return real_realpath(path)

    monkeypatch.setattr(policy.os.path, "realpath", seam)
    cfg = Config(guest_write_roots=["C:\\g-write"])
    assert _outcome(policy.check_guest_write, cfg, r"C:\elsewhere\x.bin") == "denied"


def test_put_destination_equal_to_root_denied(monkeypatch, rooted_cfg, tmp_path):
    """A destination spelled exactly like a configured root is refused.

    The staging sibling would land in dirname(dest) — at the root that is
    OUTSIDE the boundary — so the transfer must fail before staging.
    """
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    fake = FakePS([])  # denial must happen before any PowerShell runs
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(policy.PolicyDenied, match="root"):
        filetransfer.guest_put(
            rooted_cfg,
            "test-vm-a",
            str(src),
            r"C:\g-write",
            confirm=True,
            verify=False,
            cred=CRED,
        )
    assert fake.scripts == []


def test_unrestricted_mode_skips_in_guest_assertion(monkeypatch, rooted_cfg, tmp_path):
    """unrestricted=True disables host checks, so the guest assertion must
    not contradict it by still denying host-allowed paths (policy.py:
    'unrestricted=True -> every check passes')."""
    cfg = rooted_cfg
    cfg.unrestricted = True
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    payload = {
        "ok": True,
        "bytes_copied": 1,
        "bytes_local": 1,
        "bytes_remote": 1,
        "sha256_local": None,
        "sha256_remote": None,
    }
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        cfg,
        "test-vm-a",
        str(src),
        r"C:\g-write\a.bin",
        confirm=True,
        verify=False,
        cred=CRED,
    )
    assert MARKER not in fake.scripts[0]


def test_put_staging_is_sibling_with_bounded_component(monkeypatch, rooted_cfg, tmp_path):
    """Staging is a fixed-size uuid sibling of the destination directory.

    Deriving the staging name from the full destination name would push a
    legal 216-char component past NTFS's 255-char limit; the sibling name
    must stay 39 chars (uuid4 hex 32 + suffix 7) no matter how long dest is.
    """
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    dest = "C:\\g-write\\" + "d" * 216  # legal at base, overflows if suffixed
    payload = {
        "ok": True,
        "bytes_copied": 1,
        "bytes_local": 1,
        "bytes_remote": 1,
        "sha256_local": None,
        "sha256_remote": None,
    }
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg,
        "test-vm-a",
        str(src),
        dest,
        confirm=True,
        verify=False,
        cred=CRED,
    )
    staged = staged_destination(fake.scripts[0], "ToSession")
    parent, name = os.path.split(staged)
    assert parent == "C:\\g-write"
    assert name.endswith(".mcptmp")
    assert len(name) == 39, f"staging component must be uuid+suffix (39 chars), got {len(name)}"


@pytest.mark.skipif(sys.platform != "win32", reason="junction probes need Windows cmd mklink")
def test_guest_axes_ignore_real_host_junction_windows(tmp_path):
    g_write = tmp_path / "g-write"
    g_write.mkdir()
    link = tmp_path / "link"
    mk = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(g_write)],
        capture_output=True,
        text=True,
        errors="replace",
    )
    assert mk.returncode == 0, f"mklink /J failed: {(mk.stdout + mk.stderr).strip()}"
    guest_cfg = Config(guest_write_roots=[str(g_write)])
    host_cfg = Config(host_write_roots=[str(g_write)])
    try:
        assert _outcome(policy.check_guest_write, guest_cfg, str(link / "x.bin")) == "denied"
        assert _outcome(policy.check_guest_write, guest_cfg, str(g_write / "x.bin")) == "allowed"
        assert _outcome(policy.check_host_write, host_cfg, str(link / "x.bin")) == "allowed"
    finally:
        subprocess.run(["cmd", "/c", "rmdir", str(link)], capture_output=True)
