"""File transfer tests with mocked PowerShell: integrity, policy, validation."""

import json
import subprocess
import sys

import pytest

from hyperv_mcp import filetransfer, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


VM_GUID = "e953c649-1234-5678-9abc-def012345678"


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        # The by-name resolution leg (vmident) is content-served: it precedes
        # every transfer op now (issue #8) and carries no test payload.
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
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


def test_put_success_byte_counts_and_staging(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "tool.exe"
    src.write_bytes(b"MZ")
    payload = {"ok": True, "bytes_copied": 2, "bytes_local": 2, "bytes_remote": 2,
               "sha256_local": None, "sha256_remote": None}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\tool.exe",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["ok"] and out["bytes_copied"] == 2
    assert out["vm_name"] == "test-vm"  # resolved display name (PRR-005)
    script = fake.scripts[1]
    assert "-LiteralPath" in script
    assert ".mcptmp" in script
    assert "Move-Item" in script
    assert "-ToSession" in script


def test_put_policy_denials(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))

    # vm pattern (checked first)
    with pytest.raises(PolicyDenied, match="vm"):
        filetransfer.guest_put(rooted_cfg, "prod-db", str(src), r"C:\g-write\f", cred=CRED)
    # host read outside roots
    with pytest.raises(PolicyDenied, match="host read"):
        filetransfer.guest_put(rooted_cfg, "test-vm", str(outside), r"C:\g-write\f", cred=CRED)
    # guest write outside roots
    with pytest.raises(PolicyDenied, match="guest write"):
        filetransfer.guest_put(rooted_cfg, "test-vm", str(src), r"C:\Windows\f", cred=CRED)


def test_put_guest_write_gate_requires_category(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.bin").write_bytes(b"x")
    cfg = Config(
        allowed_vm_patterns=["test-*"],
        host_read_roots=[str(src)],
        guest_write_roots=["C:\\g-write"],
    )
    with pytest.raises(PolicyDenied, match="guest_write"):
        filetransfer.guest_put(cfg, "test-vm", str(src / "a.bin"), r"C:\g-write\f", confirm=True, cred=CRED)


def test_put_missing_source_no_ps_call(monkeypatch, rooted_cfg, tmp_path):
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(tmp_path / "host-src" / "nope.bin"), r"C:\g-write\f",
        confirm=True, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "not_found"
    assert fake.scripts == []


def test_put_sha_mismatch_detected(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x" * 10)
    # Hash-before-move: the PS body throws on mismatch BEFORE the destination
    # is replaced; the runner maps the thrown text to error_class "integrity".
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="SHA-256 mismatch (staged copy differs from source)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=True, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "integrity"


def test_put_verify_branch_emits_real_boolean_guard(monkeypatch, rooted_cfg, tmp_path):
    """Round-2 regression: the PS body must compare hashes directly — a
    bareword `$doVerify = true` is a command invocation on PS 5.1 (assigns
    $null), which silently disabled the entire mismatch guard."""
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x" * 10)
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="SHA-256 mismatch (staged copy differs from source)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=True, cred=CRED,
    )
    script = fake.scripts[1]
    assert "$doVerify" not in script  # no bareword boolean variable at all
    assert "if ($shaLocal -ne $shaStaged)" in script
    # Copy-Item must sit INSIDE the staging-cleanup try (leak-on-copy regression).
    copy_at = script.index("Copy-Item -ToSession")
    try_at = script.index("try {")
    assert try_at < copy_at


def test_put_sha_match_passes(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x" * 10)
    payload = {"ok": True, "bytes_copied": 10, "sha256_local": "AAA", "sha256_remote": "AAA"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=True, cred=CRED,
    )
    assert out["ok"] is True


def test_put_fails_closed_when_guest_denies_staging(monkeypatch, rooted_cfg, tmp_path):
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(returncode=1, stderr="Access is denied")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "transport"


def test_get_creates_local_parents_and_verifies(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "deep" / "dir" / "out.bin"
    payload = {"ok": True, "bytes_copied": 5, "bytes_remote": 5,
               "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), verify=True, cred=CRED,
    )
    assert out["ok"]
    assert dest.parent.is_dir()
    assert "-FromSession" in fake.scripts[1]


def test_get_guest_read_outside_roots_denied(monkeypatch, rooted_cfg, tmp_path):
    monkeypatch.setattr(pswindows, "run_ps", FakePS([]))
    with pytest.raises(PolicyDenied, match="guest read"):
        filetransfer.guest_get(
            rooted_cfg, "test-vm", r"C:\Windows\System32\config\SAM",
            str(tmp_path / "host-dst" / "sam.hive"), cred=CRED,
        )


def test_get_sha_mismatch(monkeypatch, rooted_cfg, tmp_path):
    dest = tmp_path / "host-dst" / "out.bin"
    # Hash-before-move: PS throws on mismatch; runner maps to integrity.
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="SHA-256 mismatch (staged copy differs from guest source)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), verify=True, cred=CRED,
    )
    assert out["error_class"] == "integrity"


def test_read_file_max_bytes_validation(rooted_cfg):
    for bad in (0, -1, -100):
        with pytest.raises(ValueError, match="max_bytes"):
            filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", bad, cred=CRED)


def test_read_file_slice_script_bounded(monkeypatch, rooted_cfg):
    """F9 regression: bounded Open+Read, never ReadAllBytes+slice."""
    payload = {"content_b64": "QUJD", "bytes_read": 3, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", 3, cred=CRED)
    assert out["ok"] and out["bytes_read"] == 3
    script = fake.scripts[1]
    assert "[System.IO.File]::Open(" in script
    assert "ReadAllBytes" not in script
    assert "0..($maxb - 1)" not in script


def test_read_file_content_decodable(monkeypatch, rooted_cfg):
    import base64
    payload = {"content_b64": base64.b64encode(b"hello").decode(),
               "bytes_read": 5, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert base64.b64decode(out["content_b64"]) == b"hello"


def test_list_dir_shape(monkeypatch, rooted_cfg):
    payload = [{"name": "a.txt", "is_dir": False, "size_bytes": 3, "modified": "2026-01-01T00:00:00Z"}]
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read", cred=CRED)
    assert out["ok"] and out["entries"][0]["name"] == "a.txt"


def test_list_dir_empty(monkeypatch, rooted_cfg):
    fake = FakePS([pswindows.PSResult(stdout="[]", returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read\empty", cred=CRED)
    assert out == {"ok": True, "vm_name": "test-vm", "entries": []}


def test_guest_root_assertion_embedded_when_roots_set(monkeypatch, rooted_cfg):
    payload = {"content_b64": "", "bytes_read": 0, "truncated": False}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert "policy: guest read denied" in fake.scripts[1]
    assert "GetFullPath" in fake.scripts[1]


def test_timeout_mapping(monkeypatch, rooted_cfg, tmp_path):
    """Timeout maps to the timeout class AND triggers the best-effort guest
    staged-file cleanup the script's own catch could not run (PRR-008)."""
    src = tmp_path / "host-src" / "big.bin"
    src.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(timed_out=True), pswindows.PSResult(returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\big.bin",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["error_class"] == "timeout" and out["ok"] is False
    assert len(fake.scripts) == 3, "resolve + transfer + exactly one cleanup run"
    cleanup = fake.scripts[2]
    assert "Remove-Item" in cleanup and ".mcptmp" in cleanup


# ---------------------------------------------------------------------------
# issue #6: failure-class mappers, ordering pins, parse validity
# ---------------------------------------------------------------------------

def test_read_file_policy_denial_maps_to_policy_class(monkeypatch, rooted_cfg):
    """AC5 leg: guest_read_file's mapper must classify policy text, not transport."""
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="policy: guest read denied (path outside configured roots)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert out["ok"] is False and out["error_class"] == "policy"


def test_list_dir_policy_denial_maps_to_policy_class(monkeypatch, rooted_cfg):
    """AC5 leg: guest_list_dir's mapper must classify policy text, not transport."""
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="policy: guest read denied (path outside configured roots)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read", cred=CRED)
    assert out["ok"] is False and out["error_class"] == "policy"


def test_failure_class_branches():
    """Single classifier: integrity first, policy second, invalid destination,
    transport default."""
    assert filetransfer._failure_class(
        "SHA-256 mismatch (staged copy differs from source)") == "integrity"
    assert filetransfer._failure_class(
        "policy: guest write denied (reparse point in path inside root)") == "policy"
    assert filetransfer._failure_class(
        "invalid destination: C:\\g-write\\dir is an existing directory") == "invalid"
    assert filetransfer._failure_class("Access is denied") == "transport"
    # precedence: integrity text wins even if a policy fragment co-occurs
    assert filetransfer._failure_class(
        "SHA-256 mismatch ... policy: ...") == "integrity"
    # policy wins over invalid destination text
    assert filetransfer._failure_class(
        "policy: guest write denied (... invalid destination ...)") == "policy"


def test_put_assertion_precedes_dir_creation(monkeypatch, rooted_cfg, tmp_path):
    """AC1 ordering: the guest assertion block is the FIRST statement of the
    body — C1's placement tuple (0, 1) alone would also pass if the block
    were moved after dir creation, so pin the order explicitly."""
    from test_a02_guest_transfer import MARKER

    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    payload = {"ok": True, "bytes_copied": 1, "bytes_local": 1, "bytes_remote": 1,
               "sha256_local": None, "sha256_remote": None}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    script = fake.scripts[1]
    assert script.index(MARKER) < script.index("New-Item")


def test_get_assertion_precedes_copy_from_session(monkeypatch, rooted_cfg, tmp_path):
    """AC2 ordering: assertion before Copy-Item -FromSession (placement tuple
    alone does not capture body order — see the plan's ordering pins)."""
    from test_a02_guest_transfer import MARKER

    dest = tmp_path / "host-dst" / "a.bin"
    payload = {"ok": True, "bytes_copied": 1, "bytes_remote": 1,
               "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([pswindows.PSResult(stdout=json.dumps(payload), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest),
        verify=True, cred=CRED,
    )
    script = fake.scripts[1]
    assert script.index(MARKER) < script.index("Copy-Item -FromSession")


@pytest.mark.skipif(sys.platform != "win32", reason="parse validity needs real Windows PowerShell")
def test_put_get_scripts_parse_clean(monkeypatch, rooted_cfg, tmp_path):
    """Generated put/get scripts must parse under real PS 5.1's parser —
    mocked-subprocess unit tests happily accept scripts real PowerShell
    would reject (zmem 334b6cdc)."""
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    dest = tmp_path / "host-dst" / "a.bin"
    put_payload = {"ok": True, "bytes_copied": 1, "bytes_local": 1, "bytes_remote": 1,
                   "sha256_local": None, "sha256_remote": None}
    get_payload = {"ok": True, "bytes_copied": 1, "bytes_remote": 1,
                   "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps(put_payload), returncode=0),
        pswindows.PSResult(stdout=json.dumps(get_payload), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest),
        verify=True, cred=CRED,
    )
    parser = (
        "$src = [Console]::In.ReadToEnd(); "
        "$toks = $null; $errs = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseInput("
        "$src, [ref]$toks, [ref]$errs); "
        "if ($errs -and $errs.Count) { "
        "$errs | ForEach-Object { $_.ToString() }; exit 1 }"
    )
    for label, script in (("put", fake.scripts[1]), ("get", fake.scripts[3])):
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", parser],
            input=script, capture_output=True, text=True, timeout=60,
            errors="replace",
        )
        assert proc.returncode == 0, f"{label} script failed PS parse: {proc.stdout}{proc.stderr}"


def test_put_get_assert_wrappers_pin_terminating_erroraction(monkeypatch, rooted_cfg, tmp_path):
    """Implementation-review round 1 (mutation M1): the in-guest assertion
    wrapper must carry `-ErrorAction Stop` — plan 07 marks it REQUIRED, not
    cosmetic: without the flag a remote `throw` surfaces as a non-terminating
    error record, so a denial could fall through to dir-creation/copy.
    Static pin on the rendered wrapper (the parse test proves syntax only,
    and AC8's real-VM leg stays host-gated), matching the repo's existing
    `-ErrorAction Stop` script-pin convention (test_media)."""
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    dest = tmp_path / "host-dst" / "a.bin"
    put_payload = {"ok": True, "bytes_copied": 1, "bytes_local": 1, "bytes_remote": 1,
                   "sha256_local": None, "sha256_remote": None}
    get_payload = {"ok": True, "bytes_copied": 1, "bytes_remote": 1,
                   "sha256_local": "S", "sha256_remote": "S"}
    fake = FakePS([
        pswindows.PSResult(stdout=json.dumps(put_payload), returncode=0),
        pswindows.PSResult(stdout=json.dumps(get_payload), returncode=0),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest),
        verify=True, cred=CRED,
    )
    for label, script, path, roots, category in (
        ("put", fake.scripts[1], r"C:\g-write\a.bin",
         rooted_cfg.guest_write_roots, "write"),
        ("get", fake.scripts[3], r"C:\g-read\a.bin",
         rooted_cfg.guest_read_roots, "read"),
    ):
        fragment = filetransfer._guest_root_assertion(path, roots, category)
        assert fragment, f"{label}: roots configured, fragment must be non-empty"
        wrapper = (
            "Invoke-Command -Session $s -ScriptBlock {\n"
            + fragment
            + "\n} -ErrorAction Stop\n"
        )
        assert wrapper in script, (
            f"{label} assertion wrapper lost its terminating -ErrorAction Stop"
        )


# ---------------------------------------------------------------------------
# issue #6 feedback round: invalid-destination input, prune, timeout cleanup,
# transport classification for read_file/list_dir, dest==root refusal
# ---------------------------------------------------------------------------

def test_get_local_directory_destination_rejected(monkeypatch, rooted_cfg, tmp_path):
    """A directory destination is invalid input, rejected host-side before
    any PowerShell runs — a staged file inside the directory would be a
    silent orphan."""
    d = tmp_path / "host-dst" / "somedir"
    d.mkdir()
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(d), cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "invalid"
    assert fake.scripts == []


def test_put_container_check_classified_invalid_and_precedes_copy(monkeypatch, rooted_cfg, tmp_path):
    """The in-guest container check runs BEFORE the copy (no staged file is
    created inside the container) and its throw maps to error_class
    "invalid", not transport."""
    src = tmp_path / "host-src" / "a.bin"
    src.write_bytes(b"x")
    fake = FakePS([pswindows.PSResult(
        returncode=1,
        stderr="invalid destination: C:\\g-write\\dir is an existing directory")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_put(
        rooted_cfg, "test-vm", str(src), r"C:\g-write\dir\a.bin",
        confirm=True, verify=False, cred=CRED,
    )
    assert out["ok"] is False and out["error_class"] == "invalid"
    script = fake.scripts[1]
    assert "PathType Container" in script
    assert script.index("PathType Container") < script.index("Copy-Item -ToSession")


def test_get_denied_vm_name_creates_no_directories(monkeypatch, rooted_cfg, tmp_path):
    """PRR-010: guest_get resolves identity BEFORE creating the local
    destination dirs — a call rejected at resolve (denied VM name) must not
    orphan host directories (the failure cleanup only runs post-resolve)."""
    dest = tmp_path / "host-dst" / "newdir" / "out.bin"
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="vm"):
        filetransfer.guest_get(
            rooted_cfg, "prod-db", r"C:\g-read\a.bin", str(dest), cred=CRED,
        )
    assert fake.scripts == []       # denied name spawns no PowerShell
    assert not dest.parent.exists()  # and no directory was created at all


def test_get_denied_leaves_no_created_dirs(monkeypatch, rooted_cfg, tmp_path):
    """Directories THIS call created are pruned when the transfer fails; a
    pre-existing directory is never touched."""
    dest = tmp_path / "host-dst" / "newdir" / "out.bin"
    fake = FakePS([pswindows.PSResult(
        returncode=1, stderr="policy: guest read denied (path outside configured roots)")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), cred=CRED,
    )
    assert out["error_class"] == "policy"
    assert not (tmp_path / "host-dst" / "newdir").exists()
    assert (tmp_path / "host-dst").exists()


def test_get_timeout_removes_host_staged_file(monkeypatch, rooted_cfg, tmp_path):
    """A host timeout kills the script before its own catch runs; the
    Python side must still remove the host staged file."""
    dest = tmp_path / "host-dst" / "out.bin"
    staged = tmp_path / "host-dst" / "fixed.mcptmp"
    monkeypatch.setattr(filetransfer, "_staging_path", lambda d: str(staged))
    staged.write_bytes(b"partial")
    fake = FakePS([pswindows.PSResult(timed_out=True)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_get(
        rooted_cfg, "test-vm", r"C:\g-read\a.bin", str(dest), verify=False, cred=CRED,
    )
    assert out["error_class"] == "timeout"
    assert not staged.exists()


def test_read_file_failure_defaults_to_transport(monkeypatch, rooted_cfg):
    fake = FakePS([pswindows.PSResult(returncode=1, stderr="Access is denied")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_read_file(rooted_cfg, "test-vm", r"C:\g-read\f", cred=CRED)
    assert out["ok"] is False and out["error_class"] == "transport"


def test_list_dir_failure_defaults_to_transport(monkeypatch, rooted_cfg):
    fake = FakePS([pswindows.PSResult(returncode=1, stderr="Access is denied")])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = filetransfer.guest_list_dir(rooted_cfg, "test-vm", r"C:\g-read", cred=CRED)
    assert out["ok"] is False and out["error_class"] == "transport"


def test_get_destination_equal_to_host_root_denied(monkeypatch, rooted_cfg, tmp_path):
    """A host destination spelled exactly like a configured root is refused:
    the staged sibling would land outside host_write_roots."""
    fake = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied, match="root"):
        filetransfer.guest_get(
            rooted_cfg, "test-vm", r"C:\g-read\a.bin",
            str(tmp_path / "host-dst"), cred=CRED,
        )
    assert fake.scripts == []


def test_makedirs_tracked_returns_created_dirs_leaf_first(tmp_path):
    """The caller prunes the returned list FORWARD, so it must be leaf
    first: with two or more created levels, removing the root first fails
    (the child still exists) and the husks survive (closeout-review
    finding 2 - a regression the fix wave introduced)."""
    from hyperv_mcp.filetransfer import _makedirs_tracked

    target = tmp_path / "level1" / "level2" / "level3"
    created = _makedirs_tracked(str(target))
    assert len(created) == 3, created
    assert created == sorted(created, key=len, reverse=True), (
        f"the created directories are not leaf first: {created}"
    )
    assert created[0].endswith("level3"), created
    assert created[-1].endswith("level1"), created


def test_cleanup_failed_get_prunes_every_created_level(tmp_path):
    """The end-to-end consequence: a transfer that fails after creating
    two levels must leave NEITHER of them behind."""
    from hyperv_mcp.filetransfer import _cleanup_failed_get, _makedirs_tracked

    staged = tmp_path / "staged.bin"
    staged.write_bytes(b"x")
    # The caller creates the DESTINATION's parent chain, so the chain is
    # the two directory levels (the file itself is never a component).
    target = tmp_path / "level1" / "level2"
    created = _makedirs_tracked(str(target))
    assert len(created) == 2, created
    _cleanup_failed_get(str(staged), created)
    assert not staged.exists(), "the staged file survived the cleanup"
    assert not (tmp_path / "level1").exists(), (
        "a created level survived the cleanup: " + str(created)
    )


def test_makedirs_tracked_composes_a_unc_chain(monkeypatch):
    """A UNC path must be composed from the server+share DRIVE plus the
    remaining components - building it from the whole path would recreate
    the share inside itself ("\\\\srv\\share\\srv\\share\\newdir")
    and never create the requested directory (closeout-review finding 3).
    """
    from hyperv_mcp import filetransfer

    attempted: list = []

    def fake_isdir(path):
        return False

    def fake_mkdir(path):
        attempted.append(path)

    monkeypatch.setattr(filetransfer.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(filetransfer.os, "mkdir", fake_mkdir)
    filetransfer._makedirs_tracked("\\\\srv\\share\\newdir")
    # Exactly ONE component is created, under the share - never the share
    # rebuilt inside itself.
    assert attempted == ["\\\\srv\\share\\newdir"], attempted


def test_makedirs_tracked_fails_loudly_on_a_file_component(tmp_path):
    """A FILE at a chain component is not a directory: the chain cannot be
    built, so the call must fail instead of walking past it (and the
    prefix this call created must be pruned)."""
    from hyperv_mcp.filetransfer import _makedirs_tracked

    # A file at the FINAL component.
    leaf_file = tmp_path / "leaf"
    leaf_file.write_bytes(b"x")
    with pytest.raises(OSError):
        _makedirs_tracked(str(leaf_file))
    assert not (tmp_path / "leaf").is_dir()

    # A file at a MIDDLE component: the chain cannot be built at all.
    middle_file = tmp_path / "middle"
    middle_file.write_bytes(b"x")
    with pytest.raises(OSError):
        _makedirs_tracked(str(middle_file / "leaf"))


def test_a_concurrent_creator_s_component_is_never_pruned(tmp_path, monkeypatch):
    """The OWNERSHIP rule, deterministically: a component another transfer
    created (here: os.mkdir raises FileExistsError because the other
    worker won the race) is NOT recorded as ours and is NOT removed when
    our own create fails.

    This is the deterministic pin for PRR-002. The racy probe
    (`.zcode/pr-review/pr114-review-20261102/probe_prune_ownership.py`)
    demonstrated the mechanism but could report a defect on CORRECT code
    (its own thread created the component it then called 'the other
    worker's'), so it is not cited as the pin."""
    from hyperv_mcp import filetransfer

    head = tmp_path / "head"
    middle = head / "middle"
    target = middle / "leaf<blocked>"   # the invalid final component

    real_mkdir = filetransfer.os.mkdir

    def fake_mkdir(path, *args, **kwargs):
        if str(path).endswith("middle"):
            # The OTHER worker wins the race: the directory exists, and our
            # mkdir sees FileExistsError.
            real_mkdir(path)
            raise FileExistsError(path)
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(filetransfer.os, "mkdir", fake_mkdir)
    with pytest.raises(OSError):
        filetransfer._makedirs_tracked(str(target))

    assert middle.exists(), (
        "the concurrent creator's directory was pruned: the ownership rule "
        "was broken"
    )
    # The parent we created survives too - and it MUST: the empty-only
    # prune (os.rmdir) refuses a directory that still holds the other
    # worker's component, which is exactly the point of the ownership
    # rule (the pre-fix snapshot prune removed that component and then
    # the parent as well).
