"""PR #166 review fixes (FB-002 / FB-007 / FB-008) — repair apply-outcome and
verification channels.

Every pin here was run RED against the unfixed code and GREEN after the fix
(the RED/GREEN evidence is in the PR feedback thread):

FB-002  the NEW apply-outcome channel must not assert application from a
    blank apply result: a zero-exit, empty-stdout leg parses to {} on the
    non-pooled path (no action receipt), so the change reports `failed`
    with an explicit "apply result unavailable; effect unconfirmed" detail
    while the READBACK still evaluates independently (a healthy readback
    may report the observed state — it just never verifies the apply).
FB-007  repair verification must not certify from a blank readback (the
    probe sections are absent, not clean), and a rewrite certifies only
    when the REQUESTED replacement appears in the OBSERVED config — a
    different healthy non-stale binding does not verify the requested
    rewrite.
FB-008  two stale config lines sharing one OLD address each receive their
    own per-line replacement: replacements bind to config-line OCCURRENCES
    (the old address-keyed $map could not even represent the case — real
    Windows PowerShell 5.1 parse-rejects it with DuplicateKeyInHashLiteral).
    The parse/functional proofs below drive the REAL powershell.exe (the
    test skips when no PowerShell is on PATH).

What is faked: PowerShell only (the test_repair.py FakePS canned-leg
pattern); the FB-008 proofs stub just the config path and Restart-Service
in an otherwise verbatim generated script.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from hyperv_mcp import pswindows, repair
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
VM_GUID = "e953c649-1234-5678-9abc-def012345678"


class FakePS:
    """Canned-leg run_ps fake (the test_repair.py pattern). A response item
    that is an Exception is raised instead of returned."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(payload):
    return pswindows.PSResult(stdout=json.dumps(payload), returncode=0)


def _guid_result():
    return pswindows.PSResult(stdout=VM_GUID, returncode=0)


def _host():
    return {"state": "Running", "vm_id": VM_GUID, "uptime_s": 1,
            "memory_mb": 1, "cpu_usage": 1}


def _guest(status="Running", listen="0.0.0.0", fw=True):
    return {
        "identity": {"hostname": "W"},
        "ip_addresses": {"ipv4": [{"interface": "E", "address": "10.0.0.5",
                                   "prefix": 24}], "ipv6": []},
        "ssh": {
            "service": {"present": True, "status": status, "start_type": "Automatic"},
            "agent_service": {"present": False},
            "config_present": True, "effective_ports": [22],
            "config_listen": [listen],
            "listeners": [{"address": listen, "port": 22}],
        },
        "winrm": {"service": {"present": True, "status": "Running",
                              "start_type": "Automatic"},
                  "listeners": [], "tcp_listeners": []},
        "firewall": {"ssh22_allowed": fw, "winrm5985_allowed": True},
    }


def _stale_guest():
    guest = _guest(listen="192.168.50.20")
    guest["ssh"]["listeners"] = [{"address": "192.168.50.20", "port": 22}]
    return guest


def _decode_inner(script: str) -> str:
    import base64

    m = re.search(r"\$enc = '([A-Za-z0-9+/=]+)'", script)
    assert m, "the apply leg must carry the base64-encoded inner script"
    return base64.b64decode(m.group(1)).decode("utf-8")


def _rewrite_change(out):
    matches = [c for c in out["changes"]
               if c["action"] == "rewrite_stale_ssh_bindings"]
    assert matches, f"expected the rewrite change; got {out['changes']!r}"
    return matches[0]


# ---------------------------------------------------------------------------
# FB-002 — the apply-outcome channel must not certify an empty apply result
# ---------------------------------------------------------------------------


def test_fb002_blank_apply_result_is_not_certified(monkeypatch):
    """FB-002 (a)+(c): a zero-exit apply leg with EMPTY stdout (and its
    explicit '{}' twin) carries no action receipt — apply_outcome must NOT
    be 'applied', the change carries the "apply result unavailable; effect
    unconfirmed" detail, verified stays False, and the healthy readback is
    still evaluated independently (postcondition satisfied, never enough to
    verify an unproven apply)."""
    cfg = Config(unrestricted=True)
    healthy = _guest(listen="10.0.0.5")

    for blank in ("", "{}"):
        fake = FakePS([
            _guid_result(),
            _ok(_host()), _ok(_stale_guest()),
            pswindows.PSResult(stdout=blank, returncode=0),  # apply: no receipt
            _ok(_host()), _ok(healthy),
        ])
        monkeypatch.setattr(pswindows, "run_ps", fake)
        out = repair.repair_guest_access(
            cfg, "test-vm", apply=True, confirm=True, cred=CRED,
            intended_bindings=["10.0.0.5"],
        )
        change = _rewrite_change(out)
        assert change["apply_outcome"] != "applied", (
            f"FB-002: a blank apply result ({blank!r}) must not certify "
            f"application; got {change!r}"
        )
        assert change["apply_outcome"] == "failed", change
        assert change["applied"] is False, change
        error = (change.get("error") or "").lower()
        assert "apply result unavailable" in error and "unconfirmed" in error, (
            f"FB-002: the unconfirmed detail must be explicit; got {change!r}"
        )
        assert change["verified"] is False, (
            f"FB-002: an unproven apply is never verified; got {change!r}"
        )
        # (c) the healthy readback still reports what it reports.
        assert change["observation"] == "positive", change
        assert change["postcondition"] == "satisfied", (
            f"FB-002 (c): the readback channel stays independent of the apply "
            f"outcome; got {change!r}"
        )


def test_fb002_real_receipt_still_applies(monkeypatch):
    """FB-002 (b): the happy-path receipt shape (backup+replaced) still
    applies and verifies end to end."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": "C:/ProgramData/ssh/sshd_config.bak-20261121",
             "replaced": 1}),
        _ok(_host()), _ok(_guest(listen="10.0.0.5")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["apply_outcome"] == "applied" and change["applied"] is True
    assert change["verified"] is True, change
    assert out["backup_path"].endswith(".bak-20261121")


def test_fb002_zero_change_receipt_is_not_missing(monkeypatch):
    """FB-002: a VALID zero-change receipt is not treated as missing — key
    PRESENCE is the test, not the values: enabled_rules=[] (nothing needed
    enabling) and replaced=0 (the stale address lives only on the runtime
    listener; the documented 0-replacement backup+restart) are receipts."""
    cfg = Config(unrestricted=True)

    # Firewall arm: the action ran and enabled zero rules.
    fake = FakePS([
        _guid_result(), _ok(_host()), _ok(_guest(fw=False)),
        _ok({"port": "22", "enabled_rules": []}),
        _ok(_host()), _ok(_guest(fw=True)),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True,
                                     cred=CRED)
    fw_change = [c for c in out["changes"]
                 if c["action"] == "enable_existing_firewall_rules"][0]
    assert fw_change["apply_outcome"] == "applied" and \
        fw_change["applied"] is True, fw_change

    # Rewrite arm: listener-only stale line -> 0 config replacements.
    listener_only = _guest()
    listener_only["ssh"]["config_listen"] = []
    listener_only["ssh"]["listeners"] = [
        {"address": "192.168.50.20", "port": 22}]
    still = json.loads(json.dumps(listener_only))
    fake2 = FakePS([
        _guid_result(), _ok(_host()), _ok(listener_only),
        _ok({"backup": "C:/zero.bak", "replaced": 0}),
        _ok(_host()), _ok(still),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake2)
    out2 = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out2)
    assert change["apply_outcome"] == "applied" and change["applied"] is True, (
        f"FB-002: a zero-change receipt (replaced=0) is a receipt; got {change!r}"
    )
    # The documented listener-only behavior: the binding is still present.
    assert change["verified"] is False, change


def _service_change(out):
    matches = [c for c in out["changes"] if c["action"] == "start_service"]
    assert matches, f"expected a start_service change; got {out['changes']!r}"
    return matches[0]


def _firewall_change(out):
    matches = [c for c in out["changes"]
               if c["action"] == "enable_existing_firewall_rules"]
    assert matches, f"expected a firewall change; got {out['changes']!r}"
    return matches[0]


def test_fb002_malformed_receipt_values_are_not_certified(monkeypatch):
    """FB-002 (PR #166 review, wave 3): the receipt check validated KEYS
    only, so a malformed receipt ({"backup": null, "replaced": null}) passed
    and a healthy readback then verified the change — the apply-outcome
    channel asserted application from a receipt whose values carry no
    evidence. The action-specific receipt's usable VALUES must be validated
    while the legitimate zero-change receipt (pinned above) stays valid:
      (a) rewrite  {"backup": null, "replaced": null}            rejected
      (d) service  {"service": null, "status": null}             rejected
          service  {"service": "sshd", "status": "Running"}      valid
      (e) firewall {"port": null, "enabled_rules": null}         rejected
    ((b)/(c) and the firewall positive arm are pinned above.)"""
    cfg = Config(unrestricted=True)

    # (a) rewrite: keys present, values unusable — NOT certified, and a
    # healthy readback must not rescue it (verified derives from applied).
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": None, "replaced": None}),  # malformed receipt
        _ok(_host()), _ok(_guest(listen="10.0.0.5")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["apply_outcome"] == "failed", (
        f"FB-002: a malformed rewrite receipt (null values) must not certify "
        f"application; got {change!r}"
    )
    assert change["applied"] is False, change
    error = (change.get("error") or "").lower()
    assert "apply result unavailable" in error and "unconfirmed" in error, (
        f"FB-002: the malformed receipt must yield the same disclosed "
        f"unconfirmed outcome as a missing one; got {change!r}"
    )
    assert change["verified"] is False, change
    assert change["postcondition"] == "satisfied", change
    assert "backup_path" not in out, out

    # (d, negative) start_service: keys present, values unusable.
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_guest(status="Stopped")),
        _ok({"service": None, "status": None}),  # malformed receipt
        _ok(_host()), _ok(_guest(status="Running")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True,
                                     cred=CRED)
    change = _service_change(out)
    assert change["apply_outcome"] == "failed" and change["applied"] is False, (
        f"FB-002: a malformed service receipt (null values) must not certify "
        f"application; got {change!r}"
    )
    assert (change.get("error") or "").lower().find("unconfirmed") >= 0, change
    assert change["verified"] is False, change

    # (d, positive) start_service: a well-formed receipt still applies and
    # verifies end to end (the value check must not over-reject).
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_guest(status="Stopped")),
        _ok({"service": "sshd", "status": "Running"}),
        _ok(_host()), _ok(_guest(status="Running")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True,
                                     cred=CRED)
    change = _service_change(out)
    assert change["apply_outcome"] == "applied" and change["applied"] is True, (
        f"FB-002: a well-formed service receipt must still apply; got {change!r}"
    )
    assert change["verified"] is True, change

    # (e) firewall: keys present, values unusable.
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_guest(fw=False)),
        _ok({"port": None, "enabled_rules": None}),  # malformed receipt
        _ok(_host()), _ok(_guest(fw=True)),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(cfg, "test-vm", apply=True, confirm=True,
                                     cred=CRED)
    change = _firewall_change(out)
    assert change["apply_outcome"] == "failed" and change["applied"] is False, (
        f"FB-002: a malformed firewall receipt (null values) must not "
        f"certify application; got {change!r}"
    )
    assert (change.get("error") or "").lower().find("unconfirmed") >= 0, change
    assert change["verified"] is False, change


# ---------------------------------------------------------------------------
# FB-007 — verification certifies only present, requested evidence
# ---------------------------------------------------------------------------


def test_fb007_blank_readback_yields_unknown(monkeypatch):
    """FB-007 (a): a valid apply receipt followed by a blank-but-successful
    verify probe (the probe sections are absent, not clean) must not
    certify: observation not positive, postcondition unknown, verified
    False."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": "C:/b.bak", "replaced": 1}),
        _ok(_host()),
        pswindows.PSResult(stdout="", returncode=0),  # blank verify readback
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["apply_outcome"] == "applied", change
    assert change["observation"] != "positive", (
        f"FB-007: a blank readback is absent evidence, never a positive "
        f"observation; got {change!r}"
    )
    assert change["postcondition"] == "unknown", (
        f"FB-007 (a): a blank readback must yield unknown; got {change!r}"
    )
    assert change["verified"] is False, change


def test_fb007_requested_address_readback_verifies(monkeypatch):
    """FB-007 (b): a readback showing the REQUESTED address certifies the
    rewrite (control arm — must keep verifying)."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": "C:/b.bak", "replaced": 1}),
        _ok(_host()), _ok(_guest(listen="10.0.0.5")),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["observation"] == "positive"
    assert change["postcondition"] == "satisfied"
    assert change["verified"] is True, change


def test_fb007_different_healthy_binding_does_not_verify(monkeypatch):
    """FB-007 (c): a readback carrying only a DIFFERENT healthy non-stale
    address must NOT verify the requested rewrite — the requested
    replacement is definitively absent from the observed config."""
    cfg = Config(unrestricted=True)
    other = _guest(listen="10.0.0.6")
    other["ip_addresses"]["ipv4"].append(
        {"interface": "E", "address": "10.0.0.6", "prefix": 24})
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": "C:/b.bak", "replaced": 1}),
        _ok(_host()), _ok(other),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["observation"] == "positive", (
        f"FB-007 (c): the readback WAS observed; got {change!r}"
    )
    assert change["postcondition"] == "unsatisfied", (
        f"FB-007 (c): a different healthy binding does not satisfy the "
        f"requested rewrite; got {change!r}"
    )
    assert change["verified"] is False, (
        f"FB-007 (c): a different healthy binding must not verify the "
        f"requested rewrite; got {change!r}"
    )
    detail = change.get("postcondition_detail") or {}
    assert detail.get("requested_bindings_missing") == ["10.0.0.5"], detail
    # Listener evidence is reported separately from the config evidence.
    assert detail.get("listener_bindings") == ["10.0.0.6"], detail


# ---------------------------------------------------------------------------
# FB-008 — repeated old addresses: occurrence-bound replacements
# ---------------------------------------------------------------------------


def test_fb008_duplicate_lines_get_respective_replacements(monkeypatch):
    """FB-008 (a): two stale config lines sharing one OLD address receive
    their RESPECTIVE per-line replacements (never a silently de-duplicated
    instruction), through the full apply flow."""
    cfg = Config(unrestricted=True)
    dup = _stale_guest()
    dup["ssh"]["config_listen"] = ["192.168.50.20", "192.168.50.20"]
    fixed = _guest(listen="10.0.0.5")
    fixed["ssh"]["config_listen"] = ["10.0.0.5", "10.0.0.6"]
    fixed["ssh"]["listeners"] = [{"address": "10.0.0.5", "port": 22}]
    fixed["ip_addresses"]["ipv4"].append(
        {"interface": "E", "address": "10.0.0.6", "prefix": 24})
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(dup),
        _ok({"backup": "C:/dup.bak", "replaced": 2}),
        _ok(_host()), _ok(fixed),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5", "10.0.0.6"],  # one per line
    )
    change = _rewrite_change(out)
    assert change["apply_outcome"] == "applied" and change["applied"] is True
    assert change["verified"] is True, change
    # The emitted edit carries one occurrence pair per stale line.
    inner = _decode_inner(fake.scripts[3])
    assert "@{'192.168.50.20' = '10.0.0.5'}" in inner, (
        f"FB-008: the first occurrence's replacement must be bound "
        f"individually; got:{inner}"
    )
    assert "@{'192.168.50.20' = '10.0.0.6'}" in inner, (
        f"FB-008: the second occurrence's replacement must be bound "
        f"individually (not discarded); got:{inner}"
    )
    pairs = re.findall(r"'([0-9a-fA-F.:]+)' = '([0-9a-fA-F.:]+)'", inner)
    assert pairs == [("192.168.50.20", "10.0.0.5"),
                     ("192.168.50.20", "10.0.0.6")], inner


def _find_powershell():
    return shutil.which("powershell") or shutil.which("pwsh")


def _ps_run(tmp_path, posh, script_text, args=()):
    """Write script_text to a temp .ps1 and run it with the real PowerShell.
    Returns (proc, script_path)."""
    target = tmp_path / f"fb008-{abs(hash(script_text)) % 10 ** 8}.ps1"
    target.write_text(script_text, encoding="utf-8")
    proc = subprocess.run(
        [posh, "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(target), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=90,
    )
    return proc, target


def _ps_parse_errors(tmp_path, posh, script_text):
    """Parse script_text with the REAL PowerShell parser (no execution);
    returns the list of parse-error messages (empty == parses cleanly)."""
    target = tmp_path / "fb008-target.ps1"
    target.write_text(script_text, encoding="utf-8")
    checker = (
        "param([string]$Target)\n"
        "$text = [System.IO.File]::ReadAllText($Target)\n"
        "$errs = $null; $toks = $null\n"
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "$text, [ref]$toks, [ref]$errs) | Out-Null\n"
        "if ($errs -and $errs.Count -gt 0) {\n"
        "    foreach ($e in $errs) { Write-Output ('PARSE-ERROR: ' + $e.Message) }\n"
        "    exit 1\n"
        "}\n"
        "Write-Output 'PARSE-OK'\n"
        "exit 0\n"
    )
    proc, _ = _ps_run(tmp_path, posh, checker, args=(str(target),))
    if proc.returncode == 0:
        return []
    return [ln for ln in (proc.stdout or "").splitlines()
            if ln.startswith("PARSE-ERROR")]


def _ps_execute_rewrite(tmp_path, posh, script, config_lines):
    """Execute the generated rewrite script against a temp config, stubbing
    ONLY the config path and Restart-Service (functions shadow cmdlets).
    Returns (proc, config_path)."""
    cfg_file = tmp_path / "sshd_config"
    cfg_file.write_text("\n".join(config_lines) + "\n", encoding="ascii")
    shadow = "function Restart-Service { param($Name, $Force, $ErrorAction) }\n"
    body = script.replace(
        "'" + repair._SSHD_CFG + "'",
        "'" + str(cfg_file).replace("'", "''") + "'",
    )
    proc, _ = _ps_run(tmp_path, posh, shadow + body)
    return proc, cfg_file


def test_fb008_duplicate_script_parses_and_replaces_under_real_powershell(tmp_path):
    """FB-008 (a)+(c): the generated rewrite script for TWO stale lines
    sharing one address PARSES under real Windows PowerShell 5.1 (the old
    address-keyed $map died with DuplicateKeyInHashLiteral) and executes
    with per-occurrence semantics: first occurrence -> first replacement,
    second -> second, unrelated directives untouched."""
    posh = _find_powershell()
    if not posh:
        pytest.skip("no PowerShell on PATH for the FB-008 parse/functional proof")
    script = repair._apply_stale_binding_script(
        ["192.168.50.20", "192.168.50.20"], ["10.0.0.5", "10.0.0.6"],
    )
    # (c) the EXACT generated text must parse.
    errors = _ps_parse_errors(tmp_path, posh, script)
    assert errors == [], (
        f"FB-008: the duplicate-address rewrite script must parse under "
        f"real PowerShell; got {errors}"
    )
    # (a) functional proof on the same script (path + restart stubbed).
    proc, cfg_file = _ps_execute_rewrite(
        tmp_path, posh, script,
        ["# header", "ListenAddress 192.168.50.20", "Port 22",
         "ListenAddress 192.168.50.20"],
    )
    assert proc.returncode == 0, (
        f"FB-008: the rewrite script must execute; stdout={proc.stdout!r} "
        f"stderr={proc.stderr!r}"
    )
    lines = cfg_file.read_text(encoding="utf-8").splitlines()
    assert lines == ["# header", "ListenAddress 10.0.0.5", "Port 22",
                     "ListenAddress 10.0.0.6"], (
        f"FB-008: each repeated source line must receive its respective "
        f"replacement, unrelated directives untouched; got {lines}"
    )
    payload = json.loads((proc.stdout or "").strip().splitlines()[-1])
    assert payload["replaced"] == 2, payload


def test_fb008_distinct_addresses_still_work(tmp_path):
    """FB-008 (b): the distinct-address case keeps working — the pairs are
    emitted, the script parses, and each line gets its replacement
    (control arm)."""
    script = repair._apply_stale_binding_script(
        ["192.168.50.20", "192.168.51.21"], ["10.0.0.5", "10.0.0.6"],
    )
    pairs = re.findall(r"'([0-9a-fA-F.:]+)' = '([0-9a-fA-F.:]+)'", script)
    assert pairs == [("192.168.50.20", "10.0.0.5"),
                     ("192.168.51.21", "10.0.0.6")], script
    posh = _find_powershell()
    if not posh:
        pytest.skip("no PowerShell on PATH for the FB-008 parse/functional proof")
    assert _ps_parse_errors(tmp_path, posh, script) == [], script
    proc, cfg_file = _ps_execute_rewrite(
        tmp_path, posh, script,
        ["ListenAddress 192.168.50.20", "ListenAddress 192.168.51.21"],
    )
    assert proc.returncode == 0, (
        f"FB-008 (b): stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    lines = cfg_file.read_text(encoding="utf-8").splitlines()
    assert lines == ["ListenAddress 10.0.0.5", "ListenAddress 10.0.0.6"], lines
    payload = json.loads((proc.stdout or "").strip().splitlines()[-1])
    assert payload["replaced"] == 2, payload


# ---------------------------------------------------------------------------
# Wave 4 — FB-007's readback-fields gate in ISOLATION
# ---------------------------------------------------------------------------


def _guest_without_readback_fields(**kw):
    """A POSITIVE-observation guest whose ssh section lacks the rewrite
    readback fields (config_listen / listeners absent, not errored) — the
    sibling absent-section guard in _verify_observation must NOT fire, so
    only the readback-fields gate can protect."""
    guest = _guest(**kw)
    guest["ssh"].pop("config_listen")
    guest["ssh"].pop("listeners")
    return guest


@pytest.mark.parametrize("with_requested", [True, False])
def test_fb007_readback_fields_gate_alone(with_requested):
    """FB-007 wave 4 (b), unit level: a POSITIVE observation whose rewrite
    readback fields are ABSENT must yield postcondition 'unknown' — the
    readback can neither satisfy nor refute. The shipped blank-readback pin
    is also caught by the sibling absent-section guard in _verify_observation,
    so it does not isolate this gate; this pin does (premise asserted: the
    observation IS positive). RED under the readback-fields-only mutation;
    GREEN at head."""
    report = {"ps_direct": {"available": True},
              "guest": _guest_without_readback_fields()}
    assert repair._verify_observation(report) == "positive", (
        "wave-4 premise: the sibling guard (_verify_observation) must NOT "
        "fire here, so only the readback-fields gate can protect"
    )
    item = {"action": "rewrite_stale_ssh_bindings",
            "verify_finding": "ssh_stale_binding"}
    if with_requested:
        item["intended_bindings"] = ["10.0.0.5"]
    change = {"applied": True, "verify_detail": ""}
    repair._evaluate_change(item, change, report, "positive", set())
    assert change["postcondition"] == "unknown", (
        f"FB-007 (wave 4): without usable rewrite readback fields the "
        f"postcondition must be 'unknown' (the readback can neither satisfy "
        f"nor refute); got {change!r}"
    )
    assert change["verified"] is False, change


def test_fb007_readback_fields_gate_alone_end_to_end(monkeypatch):
    """FB-007 wave 4 (b), end to end: a real apply receipt, then a verify
    leg whose ssh section carries no config_listen / listeners (all probe
    sections present and clean — a positive observation). The change record
    must answer postcondition 'unknown', never a verdict from an empty
    readback. RED under the readback-fields-only mutation; GREEN at head."""
    cfg = Config(unrestricted=True)
    fake = FakePS([
        _guid_result(),
        _ok(_host()), _ok(_stale_guest()),
        _ok({"backup": "C:/wave4.bak", "replaced": 1}),
        _ok(_host()), _ok(_guest_without_readback_fields()),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = repair.repair_guest_access(
        cfg, "test-vm", apply=True, confirm=True, cred=CRED,
        intended_bindings=["10.0.0.5"],
    )
    change = _rewrite_change(out)
    assert change["apply_outcome"] == "applied", change
    assert change["observation"] == "positive", (
        f"wave-4 premise (the verify leg's sections are all present and "
        f"clean): got {change!r}"
    )
    assert change["postcondition"] == "unknown", (
        f"FB-007 (wave 4): a readback without the rewrite fields must yield "
        f"'unknown'; got {change!r}"
    )
    assert change["verified"] is False, change
