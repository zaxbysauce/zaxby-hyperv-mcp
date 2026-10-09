"""Transfer-builder runtime-matrix guard (PR #47 feedback round).

The original remote-transfer tests asserted script TEXT only (FakePS never
executes) with verify=True and implicit-auth fixtures — the runtime matrix
(creds × verify × chunk-count) was almost entirely dark, which is how
PRR-001..PRR-006 shipped. This file closes the structural half of that gap
on every Windows host (parse lane) plus deterministic shape pins:

- every emitted builder script must PARSE (Parser::ParseInput) — the
  verify=False put branch shipped a literal ``{{`` / ``{fragment}`` parse
  error (PRR-005) that text asserts cannot see;
- implicit-auth scripts must never reference ``$__hostcred`` (PRR-006);
- the get chunk leg must seek (PRR-002) and its meta hop must NOT
  ConvertTo-Json (PRR-003);
- the get staging cleanup must come after the read loop (PRR-001);
- every hop leg carries -ErrorAction Stop (PRR-004);
- the put staging file is pre-created (zero-byte source, cubic C8).

Runtime execution of these scripts stays with the GITHUB_ACTIONS-gated
lane in test_remote_extra.py (dev hosts only).
"""

import subprocess

import pytest

from hyperv_mcp import filetransfer, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

HOST = "h.lan"
CRED = CredentialSet("Administrator", "placeholder-pass")


def _matrix_cfg() -> Config:
    return Config.from_dict({
        "hyperv": {"host": HOST},
        "allowed_vm_patterns": ["test-*"],
        "guest_read_roots": ["C:\\g-read"],
        "guest_write_roots": ["C:\\g-write"],
    })


@pytest.fixture()
def _scrub_host_creds(monkeypatch):
    for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)


def _builders(creds: bool, verify: bool, monkeypatch, tmp_path):
    if creds:
        pw = tmp_path / "host.pw"
        pw.write_text("host-pw-abc", encoding="utf-8")
        monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
        monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw))
    else:
        for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
            monkeypatch.delenv(var, raising=False)
    cfg = _matrix_cfg()
    put, put_stdin = filetransfer._remote_put_script(
        cfg, CRED, "guid", "'C:/s'", "'C:/d'", "'C:/st'", "FRAGMENT-MARKER",
        "ASSERT-MARKER\n", verify,
    )
    get, get_stdin = filetransfer._remote_get_script(
        cfg, CRED, "guid", "'C:/r'", "'C:/l'", "'C:/st'", "ASSERT-MARKER\n", verify,
    )
    return (put, put_stdin), (get, get_stdin)


def _parse_errors(script: str) -> list[str]:
    probe = (
        "$errs = $null; "
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "[Console]::In.ReadToEnd(), [ref]$null, [ref]$errs) | Out-Null; "
        "if ($errs) { $errs | ForEach-Object { $_.Message } } else { 'PARSE-OK' }"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", probe],
        input=script, capture_output=True, text=True, timeout=60,
    )
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


@pytest.mark.parametrize("creds", [True, False])
@pytest.mark.parametrize("verify", [True, False])
def test_transfer_scripts_parse_all_matrix_cells(creds, verify, monkeypatch, tmp_path):
    """PRR-005: the verify=False put branch shipped a literal-{{ parse error
    that no test saw. Parse EVERY builder emission in the matrix."""
    (put, _), (get, _) = _builders(creds, verify, monkeypatch, tmp_path)
    for name, script in (("put", put), ("get", get)):
        problems = _parse_errors(script)
        assert problems == ["PARSE-OK"], f"{name} (creds={creds}, verify={verify}): {problems[:5]}"


def test_implicit_auth_never_references_hostcred(monkeypatch, tmp_path):
    """PRR-006: _hop emitted -Credential $__hostcred with the variable never
    defined when no HYPERV_HOST_* pair resolves."""
    (put, _), (get, _) = _builders(False, True, monkeypatch, tmp_path)
    assert "$__hostcred" not in put
    assert "$__hostcred" not in get
    # The guest session credential is still there (that one is intentional).
    assert "-Credential $gcred" in put and "-Credential $gcred" in get


def test_explicit_auth_hops_carry_hostcred(monkeypatch, tmp_path):
    (put, put_stdin), (get, get_stdin) = _builders(True, True, monkeypatch, tmp_path)
    assert "-Credential $__hostcred" in put and "-Credential $__hostcred" in get
    # Two-line stdin: host password first, guest payload second.
    assert len(put_stdin.split("\n")) == 2 and len(get_stdin.split("\n")) == 2


def test_get_chunk_leg_seeks_and_meta_is_live_object(monkeypatch, tmp_path):
    """PRR-002/PRR-003: the chunk leg must seek to its offset, and the meta
    hop must return a live object (no ConvertTo-Json stringify)."""
    (_put, _), (get, _) = _builders(True, True, monkeypatch, tmp_path)
    assert "$fs.Seek($o, 'Begin')" in get
    meta_start = get.index("$__get = ")
    meta_end = get.index("$outB64 = ''")
    meta_block = get[meta_start:meta_end]
    assert "ConvertTo-Json" not in meta_block
    assert "[PSCustomObject]@{ len =" in meta_block
    # Short-read handling: the read loop must accumulate (PRR-002).
    assert "$read += $n2" in get


def test_get_staging_cleanup_follows_the_read_loop(monkeypatch, tmp_path):
    """PRR-001/PRR-007: the remote staging file must be removed after (not
    before) the chunk read loop, on every exit path."""
    (_put, _), (get, _) = _builders(False, True, monkeypatch, tmp_path)
    loop_at = get.index("while ($off -lt $__get.len)")
    cleanup_at = get.index("Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue")
    assert cleanup_at > loop_at
    # The cleanup must be in a finally so failures also sweep.
    finally_at = get.rindex("} finally {", 0, cleanup_at)
    assert finally_at < cleanup_at


def test_every_hop_leg_carries_erroraction_stop(monkeypatch, tmp_path):
    """PRR-004: a hop leg without -ErrorAction Stop swallows failures as
    non-terminating errors and continues (the silent 0-byte enabler)."""
    for creds in (True, False):
        (put, _), (get, _) = _builders(creds, True, monkeypatch, tmp_path)
        for name, script in (("put", put), ("get", get)):
            segments = script.split("Invoke-Command -ComputerName")[1:]
            for i, seg in enumerate(segments):
                # Everything up to the next hop (or EOF) must carry Stop...
                stop_here = "-ErrorAction Stop" in seg
                # ...unless a SilentlyContinue-only leg follows a throw (the
                # put failure-cleanup hop is deliberately best-effort).
                assert stop_here or "-ErrorAction SilentlyContinue" in seg, (
                    f"{name} hop #{i + 1} (creds={creds}) carries neither "
                    f"-ErrorAction Stop nor SilentlyContinue"
                )


def test_put_precreates_remote_staging(monkeypatch, tmp_path):
    """Cubic C8: a zero-byte source skips the append loop, so the staging
    file must be pre-created before the session leg reads it."""
    (put, _), _ = _builders(True, False, monkeypatch, tmp_path)
    assert "WriteAllText($p, '')" in put
    assert put.index("WriteAllText($p, '')") < put.index("while ($pos -lt $b64.Length)")


def test_verify_false_put_branch_is_interpolated(monkeypatch, tmp_path):
    """PRR-005 belt-and-braces: the verify=False branch must interpolate the
    guest-root fragment (FRAGMENT-MARKER) and carry no doubled braces."""
    (put, _), _ = _builders(False, False, monkeypatch, tmp_path)
    assert "FRAGMENT-MARKER" in put
    assert "{{" not in put and "{fragment" not in put


def test_get_chunk_loop_reassembles_multichunk_payload(
    monkeypatch, tmp_path
):
    """Reviewer round-5 F3: execute the get chunk loop + base64 reassembly
    under REAL PowerShell with a payload that CROSSES the chunk boundary
    (196608-byte raw chunks → 2 chunks). This is the exact defect class
    PRR-001/002/003 shipped in (no seek, per-chunk padding, dead length) —
    text asserts could not see it; this execution can.

    The transport hop is stripped to a local Invoke-Command, and the meta
    hop (which needs a real VM) is replaced by a stub object with the true
    file length — everything else is the builder's own emitted text.
    """
    import hashlib

    # 200,000 bytes: chunk 1 = 196,608, chunk 2 = 3,392 (crosses boundary).
    size = 200_000
    src = tmp_path / "remote-src.bin"
    payload = bytes((i * 7 + (i >> 8)) % 256 for i in range(0, size, 997))[: size % 997 or size]
    payload = (payload * (size // len(payload) + 1))[:size]
    src.write_bytes(payload)

    cfg = _matrix_cfg()
    get, _stdin = filetransfer._remote_get_script(
        cfg, CRED, "guid", "'C:/r'", "'C:/l'", "'C:/st'", "ASSERT-MARKER\n", True
    )
    # Assemble an executable tail: local verify def (verbatim) + a stub for
    # the meta hop's result object (the meta hop itself needs a real VM, so
    # its statement is REPLACED — otherwise it would overwrite the stub with
    # a failed connection's $null) + the builder's own chunk loop, cleanup,
    # verify invocation, and result envelope, all with the transport hop
    # stripped to a local Invoke-Command.
    verify_start = get.index("$__verifyGet = {")
    meta_start = get.index("$__get = ")
    loop_start = get.index("$outB64 = ''")
    stub = (
        f"$__get = [PSCustomObject]@{{ len = {size}; "
        f"bytes_remote = {size}; sha_remote = "
        # Get-FileHash returns UPPERCASE hex (production compares like with
        # like); .upper() keeps this stub consistent with that contract.
        f"'{hashlib.sha256(payload).hexdigest().upper()}' }}\n"
    )
    hop = pswindows.hop_line(cfg)
    assert hop in get, "chunk legs must use the shared hop line"
    harness = (
        get[verify_start:meta_start]
        + stub
        + get[loop_start:]
    ).replace(hop, "Invoke-Command")
    assert "New-PSSession" not in harness, "meta hop must be fully replaced"

    # Materialize the "remote" staging file at the PowerShell TEMP path the
    # chunk loop reads (the tag is embedded in the generated script). This
    # is what makes the seek/padding assertions real: with the original
    # PRR-002 defect the second chunk re-reads offset 0 and the byte
    # comparison below fails.
    import os as _os
    import re as _re

    m = _re.search(r"hyperv-mcp-get-([0-9a-f]{16})\.bin", get)
    assert m, "staging tag not found in generated get script"
    staging = _os.path.join(_os.environ.get("TEMP", _os.environ.get("TMP", "")),
                            f"hyperv-mcp-get-{m.group(1)}.bin")
    with open(staging, "wb") as fh:
        fh.write(payload)

    staged = tmp_path / "staged.bin"
    final = tmp_path / "final.bin"
    harness = harness.replace("'C:/st'", f"'{staged}'").replace(
        "'C:/l'", f"'{final}'"
    )
    encoded = pswindows.encode_command(pswindows._PS_PIN + harness)
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr[-500:]}"
    import json

    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result["ok"] is True, result
    assert result["bytes_local"] == size, result
    assert result["sha256_local"] == result["sha256_remote"], result
    assert final.read_bytes() == payload, (
        "reassembled destination differs from the source payload"
    )
    # Proof the loop actually crossed the chunk boundary: two base64 chunks
    # were consumed (196608 raw + 3392 raw).
    assert size > 196608
