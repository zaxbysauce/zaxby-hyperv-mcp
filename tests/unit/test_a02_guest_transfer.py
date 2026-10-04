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
import shutil
import subprocess

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
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(returncode=0)
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
    assert assertion_placement(fake.scripts[0]) == (0, 1)


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


@pytest.mark.skipif(shutil.which("cmd") is None, reason="junctions need cmd /c mklink /J")
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
