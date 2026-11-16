"""Issue #138 acceptance checks (trace 135-127-138-gui-electron-drivability):
the test-image profile on hyperv_ui_helper_provision — seven guest settings,
each recorded before it changes, all restored at teardown.

ACs carried:
  AC1  test_profile_requires_ui_provision                NEW-SURFACE
  AC2  test_profile_requires_confirm                     NEW-SURFACE
  AC3  test_unknown_setting_is_rejected                  NEW-SURFACE
  AC4  test_default_profile_covers_every_setting         NEW-SURFACE
  AC5  test_unselected_settings_are_untouched            NEW-SURFACE
  AC6  test_previous_value_is_recorded_before_the_change NEW-SURFACE
  AC7  test_reapply_keeps_the_original_record            NEW-SURFACE
  AC8  test_teardown_restores_every_recorded_setting     NEW-SURFACE
  AC9  test_no_profile_no_change                         PRESERVING (passes
       against the current code; the spec is new, so its recorded base leg
       is the file-absence signature, but the behaviour it pins — opt-in
       provisioning unchanged — is green today and must stay green)

AC10 (the Windows PowerShell 5.1 parse lane for the generated profile
scripts) lives in tests/unit/test_script_parse.py::test_parse_test_profile_scripts
— per intake finding 1 the issue names a test_script_parse_new.py that does
not exist; the repo already carries the parse lane for exactly this.

The closed setting set these checks freeze (claim 4's table):
  no_display_timeout, no_sleep, no_auto_update, no_lock_on_resume,
  no_inactivity_lock, no_screen_saver, uac_on_desktop
with ["default"] selecting all seven. The restore record lives at
C:\\ProgramData\\hyperv-mcp\\test-profile\\restore.json.

What is faked: uia._run_uia_leg (records every inner guest script, serves
a successful helper frame — the test_f05 idiom) and pswindows.run_ps
(serves the by-name resolution leg). No PowerShell runs, no guest is
touched.
"""

from __future__ import annotations

import json
import os
import re

import pytest

from hyperv_mcp import pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")

VM_GUID = "e953c649-1234-5678-9abc-def012345678"

# The documented set: setting name -> the tokens a generated leg for that
# setting must carry (compared case-insensitively). A powercfg setting is
# identified by its GUID ALIAS, because that is what both the forward change
# and the restore address it by ('powercfg /setacvalueindex SCHEME_CURRENT
# <sub> <alias> <index>'). The issue's claim-4 table names the friendly
# setting names (monitor-timeout-ac, ...); AC51 pins the alias contract
# directly, including that the restore writes the recorded index through the
# RAW-INDEX command rather than '/change', which reads its value as MINUTES.
SETTINGS = {
    "no_display_timeout": ("videoidle",),
    "no_sleep": ("standbyidle", "/h off"),
    "no_auto_update": ("windowsupdate\\au", "noautoupdate"),
    "no_lock_on_resume": ("consolelock",),
    "no_inactivity_lock": ("inactivitytimeoutsecs",),
    "no_screen_saver": ("screensaveactive",),
    "uac_on_desktop": ("promptonsecuredesktop",),
}
# The RESTORE tokens, which are not the change tokens: no_sleep's change
# disables hibernation (/h off) while its restore re-enables it (/h on).
RESTORE_TOKENS = {
    "no_display_timeout": ("videoidle",),
    "no_sleep": ("standbyidle", "/h on"),
    "no_auto_update": ("noautoupdate",),
    "no_lock_on_resume": ("consolelock",),
    "no_inactivity_lock": ("inactivitytimeoutsecs",),
    "no_screen_saver": ("screensaveactive",),
    "uac_on_desktop": ("promptonsecuredesktop",),
}

ALL_TOKENS = tuple(
    token for tokens in SETTINGS.values() for token in tokens)

RESTORE_RECORD = "restore.json"

# a full record as the guest would hold it (AC8's served guest state)
# The shape the implementation records: a powercfg setting carries BOTH the AC
# and the DC index (the profile changes both, so recording one would restore the
# other to a value the guest never held) and no_sleep also carries the prior
# hibernation state. A registry setting carries its value, which may be null
# (the guest never had it) and is restored by DELETING the value.
RECORD_JSON = json.dumps({
    "no_display_timeout": {"kind": "powercfg", "ac": "10", "dc": "15"},
    "no_sleep": {"kind": "powercfg", "ac": "30", "dc": "30", "hibernate": "on"},
    "no_auto_update": {"kind": "registry", "value": None},
    "no_lock_on_resume": {"kind": "powercfg", "ac": "1", "dc": "1"},
    "no_inactivity_lock": {"kind": "registry", "value": "900"},
    "no_screen_saver": {"kind": "registry", "value": "1"},
    "uac_on_desktop": {"kind": "registry", "value": "1"},
})


class PSRecorder:
    """pswindows.run_ps stand-in: serves by-name resolution legs with the
    VM GUID and (for AC8) serves the restore-record read."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if ("Msvm_ComputerSystem" in script
                and script.rstrip().endswith("$vmTarget")):
            return pswindows.PSResult(stdout=VM_GUID, returncode=0)
        if RESTORE_RECORD in script and _reads(script):
            return pswindows.PSResult(stdout=RECORD_JSON, returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


def _reads(script: str) -> bool:
    """The script reads existing state (rather than only writing it)."""
    return bool(re.search(
        r"get-content|get-itemproperty|get-item\b", script, re.IGNORECASE))


class LegRecorder:
    """uia._run_uia_leg stand-in (the f05 idiom): records every inner guest
    script and serves a successful helper frame; a script that reads the
    restore record is answered with the record text."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, cfg, script, *, stdin_b64=None, timeout_s=None,
                 **kwargs):
        self.scripts.append(script)
        result: dict = {}
        if RESTORE_RECORD in script and _reads(script):
            result = {"text": RECORD_JSON}
        frame: dict = {"ok": True, "result": result}
        # _TEST_PROFILE_RESTORE_INNER emits its own verdict. Falling through
        # to the generic frame left the key absent, and the host used to read
        # an absent key as "restored" -- the default RP-004 removed.
        if "profile_restored" in script:
            frame = {"ok": True, "profile_restored": True, "unrestored": []}
        # A profile leg reports before/after itself: the host records what
        # the leg said, so the recorder must SAY something. Serving a frame
        # with neither key made AC49's "the key is present" assertion pass
        # with None values -- a payload that drops either key entirely and
        # one that carries it faithfully were indistinguishable.
        named = re.search(r"setting = '([^']*)'", script)
        if named:
            if "Get-HypervMcpPowerIndices" in script:
                frame["before"] = {"ac": "300", "dc": "300"}
                frame["after"] = {"ac": "0", "dc": "0"}
                if named.group(1) == "no_sleep":
                    frame["before"]["hibernate"] = "on"
                    frame["after"]["hibernate"] = "off"
            else:
                frame["before"] = "1"
                frame["after"] = "0"
        return pswindows.PSResult(
            stdout=json.dumps({
                **frame,
                "session": {"session_id": 2, "interactive_user": "tester",
                            "locked": False},
            }),
            returncode=0,
        )


@pytest.fixture()
def legs(monkeypatch):
    """Both transport seams recorded; nothing real runs."""
    rec = LegRecorder()
    ps = PSRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", rec)
    monkeypatch.setattr(pswindows, "run_ps", ps)
    return rec, ps


_REAL_RUN_PS = pswindows.run_ps  # saved before any monkeypatching

_PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


@pytest.fixture()
def _ps_available():
    if not os.path.isfile(_PS_EXE):
        pytest.skip("Windows PowerShell not available")


# `powercfg /query SCHEME_CURRENT SUB_VIDEO` as the tool really prints it
# (Microsoft's own sample shape): ONE subgroup holding SEVERAL settings, each
# closing with its own "Current AC/DC Power Setting Index" pair, and the
# target setting (VIDEOIDLE) deliberately NOT last. A reader that collects to
# the end of the subgroup returns the LAST setting's indices (0|0) instead of
# the target's (900|0), which is the defect this check pins.
_SYNTHETIC_SUBGROUP = "\n".join([
    "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)",
    "  GUID Alias: SCHEME_MIN",
    "  Subgroup GUID: 7516b95f-f776-4464-8c53-06167f40cc99  (Display)",
    "    GUID Alias: SUB_VIDEO",
    "    Power Setting GUID: 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e  (Turn off display after)",
    "      GUID Alias: VIDEOIDLE",
    "      Minimum Possible Setting: 0x00000000",
    "      Maximum Possible Setting: 0xffffffff",
    "      Possible Settings increment: 0x00000001",
    "      Possible Settings units: Seconds",
    "    Current AC Power Setting Index: 0x00000384",
    "    Current DC Power Setting Index: 0x00000000",
    "",
    "    Power Setting GUID: f1fbfde2-a960-4165-9f88-50667911ce96  (Dimmed display brightness)",
    "      Minimum Possible Setting: 0x00000000",
    "      Maximum Possible Setting: 0x00000064",
    "      Possible Settings increment: 0x00000001",
    "      Possible Settings units: %",
    "    Current AC Power Setting Index: 0x00000032",
    "    Current DC Power Setting Index: 0x00000032",
    "",
    "    Power Setting GUID: fbd9aa66-9553-4097-ba44-ed6e9d65eab8  (Enable adaptive brightness)",
    "      GUID Alias: ADAPTBRIGHT",
    "      Possible Setting Index: 000",
    "      Possible Setting Friendly Name: Off",
    "      Possible Setting Index: 001",
    "      Possible Setting Friendly Name: On",
    "    Current AC Power Setting Index: 0x00000000",
    "    Current DC Power Setting Index: 0x00000000",
])


def _run_ps_script(script: str) -> str:
    """Execute a script under the real PS 5.1 and return its stdout.

    The script rides stdin as base64 (the repo's single-token transport):
    it never appears in a process command line, so nothing in it can be
    split on a space or stripped of quotes on the way in.
    """
    b64 = pswindows.utf8_b64(script)
    runner = (
        "$text = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String([Console]::In.ReadLine()))\n"
        "& ([ScriptBlock]::Create($text))\n"
    )
    result = _REAL_RUN_PS(runner, timeout_s=90, stdin_b64=b64)
    assert result.returncode == 0, (
        f"the harness script failed: {result.stdout}{result.stderr}")
    return result.stdout


def _blob(rec: LegRecorder) -> str:
    return "\n".join(rec.scripts)


def _profile_script(rec: LegRecorder, setting: str) -> str:
    """The leg that carries `setting`'s change (exactly one expected)."""
    token = SETTINGS[setting][0]
    matches = [s for s in rec.scripts if token in s.lower()]
    assert matches, (
        f"no generated script carries the {setting} change ({token!r}); "
        f"scripts captured: {[s[:60] for s in rec.scripts]}")
    return matches[0]


# ---------------------------------------------------------------------------
# AC1 — the ui_provision category gates the profile
# ---------------------------------------------------------------------------


def test_profile_requires_ui_provision(legs):
    """AC1: a test profile requested while ui_provision is disabled is
    refused before any PowerShell runs."""
    rec, ps = legs
    cfg = Config(allowed_vm_patterns=["p138-*"])  # ui_provision not granted
    with pytest.raises(PolicyDenied, match="ui_provision"):
        uia.provision_helper(cfg, "p138-vm", CRED, autologon=True,
                             confirm=True, test_profile=["no_sleep"])
    assert rec.scripts == [], "AC1: no guest leg may run under the denial"
    assert ps.scripts == [], "AC1: no PowerShell may run under the denial"


# ---------------------------------------------------------------------------
# AC2 — confirm is required
# ---------------------------------------------------------------------------


def test_profile_requires_confirm(legs):
    """AC2: a test profile requested without confirm is refused before any
    PowerShell runs."""
    rec, ps = legs
    granted = Config.from_dict({
        "allowed_vm_patterns": ["p138-*"],
        "destructive": {"ui_provision": True},
    })
    with pytest.raises(PolicyDenied, match="confirm"):
        uia.provision_helper(granted, "p138-vm", CRED, autologon=True,
                             confirm=False, test_profile=["no_sleep"])
    assert rec.scripts == [], "AC2: no guest leg may run without confirm"
    assert ps.scripts == [], "AC2: no PowerShell may run without confirm"


# ---------------------------------------------------------------------------
# AC3 — an unknown setting is rejected by name
# ---------------------------------------------------------------------------


def test_unknown_setting_is_rejected(legs):
    """AC3: a setting outside the documented set is rejected with an error
    naming the setting, before any PowerShell runs."""
    rec, ps = legs
    cfg = Config(unrestricted=True)
    with pytest.raises(ValueError, match="no_hibernat"):
        uia.provision_helper(cfg, "p138-vm", CRED, autologon=True,
                             confirm=True,
                             test_profile=["no_hibernat", "no_sleep"])
    assert rec.scripts == [], "AC3: no guest leg may run for a bad name"
    assert ps.scripts == [], "AC3: no PowerShell may run for a bad name"


# ---------------------------------------------------------------------------
# AC4 — the default profile covers every setting
# ---------------------------------------------------------------------------


def test_default_profile_covers_every_setting(legs):
    """AC4: the default profile generates, for EACH of the seven settings,
    the change the claim-4 table lists (universal: every setting, every
    token)."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["default"])
    blob = _blob(rec).lower()
    assert any(token in blob for token in ALL_TOKENS), (
        "AC4: the default profile generated no setting changes at all")
    missing = [
        f"{setting}:{token}"
        for setting, tokens in SETTINGS.items()
        for token in tokens
        if token not in blob
    ]
    assert not missing, (  # count of violations before their enumeration
        f"AC4: {len(missing)} table tokens missing from the default profile's "
        f"generated scripts: {missing}")


# ---------------------------------------------------------------------------
# AC5 — unselected settings are untouched
# ---------------------------------------------------------------------------


def test_unselected_settings_are_untouched(legs):
    """AC5: a profile selecting one setting generates its change and NO
    other setting's change (universal: every unselected token absent)."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["no_sleep"])
    blob = _blob(rec).lower()
    for token in SETTINGS["no_sleep"]:
        assert token in blob, (
            f"AC5: the selected setting's change is missing ({token!r})")
    violations = [
        f"{setting}:{token}"
        for setting, tokens in SETTINGS.items()
        if setting != "no_sleep"
        for token in tokens
        if token in blob
    ]
    assert not violations, (  # count before enumeration
        f"AC5: {len(violations)} unselected settings were touched: "
        f"{violations}")


# ---------------------------------------------------------------------------
# AC6 — the previous value is recorded BEFORE the change
# ---------------------------------------------------------------------------


def test_previous_value_is_recorded_before_the_change(legs):
    """AC6: within the generated leg for a setting, the current value is
    READ, then the restore record is WRITTEN, and only then is the change
    applied — asserted positionally in the script text."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["no_inactivity_lock"])
    script = _profile_script(rec, "no_inactivity_lock")
    read_at = _first_pos(script, [
        r"get-itempropertyvalue", r"get-itemproperty", r"getvalue\(",
    ])
    # The save CALL, not the first mention of the record path: the path is
    # assigned before anything else, so anchoring on it let a leg with no save
    # at all satisfy the order check.
    save_at = _first_pos(script, [r"save-hypervmcprestorerecord\s+\$recordpath"])
    change_at = _first_pos(script, [
        r"set-itemproperty", r"new-itemproperty", r"setvalue\(",
    ])
    assert read_at is not None, (
        "AC6: the leg never reads the setting's current value; the original "
        "would be lost")
    assert save_at is not None, (
        "AC6: the leg never CALLS Save-HypervMcpRestoreRecord; the original "
        "value is not persisted")
    assert change_at is not None, (
        "AC6: the leg never applies the setting's change")
    assert read_at < save_at < change_at, (
        f"AC6: order must be read ({read_at}) < save ({save_at}) < "
        f"change ({change_at}) — the change must be applied only after the "
        "original value is recorded")


def _first_pos(script: str, patterns) -> int | None:
    positions = [
        m.start()
        for pattern in patterns
        for m in re.finditer(pattern, script, re.IGNORECASE)
    ]
    return min(positions) if positions else None


# ---------------------------------------------------------------------------
# AC7 — a re-apply never overwrites the original record
# ---------------------------------------------------------------------------


def test_reapply_keeps_the_original_record(legs):
    """AC7: the record write is guarded on the setting not already being
    recorded, so applying the profile again cannot overwrite the true
    original with the profile's own value."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["no_inactivity_lock"])
    script = _profile_script(rec, "no_inactivity_lock")
    # The EXACT guard, not "some conditional that mentions the setting": an
    # inverted guard matches the loose regex, and an inverted guard writes the
    # record only when the setting is already recorded -- so a first apply
    # persists nothing and a re-apply overwrites the true original.
    guard = re.search(
        r"if\s*\(\s*-not\s+\$rec\.ContainsKey\(\s*'no_inactivity_lock'\s*\)\s*\)\s*\{",
        script,
    )
    assert guard, (
        "AC7: the leg has no 'if (-not $rec.ContainsKey(...))' guard on the "
        "setting — a re-apply would overwrite the original value")
    # ...and the save call must be INSIDE that block, or the guard is decor.
    block = script[guard.end():]
    nxt = re.search(r"^\s*\}", block, re.M)
    block = block[:nxt.start()] if nxt else block
    assert re.search(r"Save-HypervMcpRestoreRecord\s+\$recordPath", block,
                     re.IGNORECASE), (
        "AC7: the guarded block does not call Save-HypervMcpRestoreRecord — "
        "the guard protects no write")
    assert RESTORE_RECORD in script, "AC7: the leg never names the restore record"


# ---------------------------------------------------------------------------
# AC8 — teardown restores every recorded setting, then removes the record
# ---------------------------------------------------------------------------


def _strip_ps_comments(script: str) -> str:
    """The script with its PowerShell comments removed.

    A token search over the raw text is satisfied by the documentation alone:
    the restore script names each setting's command in the comment that
    explains it, so deleting the command itself leaves every token in place.
    """
    out_lines = []
    for line in script.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def test_teardown_restores_every_recorded_setting(legs):
    """AC8: with a full restore record in the guest, teardown generates a
    restore for EVERY recorded setting and then removes the record."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    out = uia.provision_helper(cfg, "p138-vm", CRED, teardown=True, confirm=True)
    blob = _blob(rec)
    lowered = blob.lower()
    assert RESTORE_RECORD in lowered, (
        "AC8: teardown never touched the restore record")
    # Comments stripped: the restore script documents each restore in a
    # comment naming the very command it replaces, so a token search over the
    # raw text is satisfied by the documentation alone. The restore must be
    # EXECUTABLE.
    bare = _strip_ps_comments(uia._TEST_PROFILE_RESTORE_INNER).lower()
    missing = [
        f"{setting}:{token}"
        for setting, tokens in RESTORE_TOKENS.items()
        for token in tokens
        if token not in bare
    ]
    assert not missing, (  # count before enumeration
        f"AC8: {len(missing)} recorded settings have no executable restore "
        f"generated: {missing}")
    # And the host must surface the restore's own verdict rather than
    # discarding it (TF-008).
    assert out.get("ok") is True, (
        f"AC8: a teardown whose restore leg reported success must report ok; "
        f"got {out}")
    assert out.get("profile_restored") is True, (
        f"AC8: the teardown result must carry the restore verdict; got {out}")
    removal = re.search(
        r"remove-item[\s\S]{0,200}" + RESTORE_RECORD
        + r"|" + RESTORE_RECORD + r"[\s\S]{0,200}remove-item",
        lowered,
    )
    assert removal, (
        "AC8: teardown must remove the restore record after restoring it")
    last_change = max(lowered.find(token) for token in ALL_TOKENS)
    assert removal.start() > last_change, (
        "AC8: the record must be removed only after every restore ran")


# ---------------------------------------------------------------------------
# AC9 — PRESERVING: no profile requested, nothing changes
# ---------------------------------------------------------------------------


def test_no_profile_no_change(legs):
    """AC9 (preserving): a provision call with no test_profile behaves
    exactly as before — the normal legs run, no profile setting is touched.
    Passes against the current code."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    out = uia.provision_helper(cfg, "p138-vm", CRED, autologon=True,
                               confirm=True)
    assert out.get("ok") is True, (
        f"AC9: provisioning without a profile must succeed as before: "
        f"{json.dumps(out, default=str)[:300]}")
    assert rec.scripts, "AC9: provisioning must still drive its guest legs"
    blob = _blob(rec).lower()
    violations = [token for token in ALL_TOKENS if token in blob]
    assert not violations, (  # count before enumeration
        f"AC9: a request without test_profile touched profile settings: "
        f"{violations}")


# ---------------------------------------------------------------------------
# AC42 — the record carries AC, DC and the prior hibernation state
# ---------------------------------------------------------------------------


def test_record_carries_ac_dc_and_hibernation(legs):
    """AC42: the profile changes BOTH the AC and the DC power index, so the
    record must carry both (recording one would restore the other to a value
    the guest never held), and `no_sleep` also disables hibernation, so the
    prior hibernation state must be recorded too."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["no_sleep"])
    script = _profile_script(rec, "no_sleep")
    lowered = script.lower()
    # The read must produce both indices -- pinned as the exact recorded
    # shape, not as the bare substrings "ac"/"dc" that unrelated text
    # ($ErrorActionPreference, /setdcvalueindex) already satisfies.
    assert ("$entry = [pscustomobject]@{ kind = 'powercfg'; ac = $pair[0]; "
            "dc = $pair[1] }") in lowered, (
        "AC42: the powercfg read must record BOTH the AC and the DC index; "
        f"got {script[-400:]!r}")
    assert "$before = [pscustomobject]@{ ac = $pair[0]; dc = $pair[1] }" in lowered, (
        "AC42: the leg's reported original must carry both indices; "
        f"got {script[-400:]!r}")
    # the reader must fail closed rather than fabricate an original
    assert "throw" in lowered, (
        "AC42: a read that cannot determine the current value must fail "
        "closed, never record a fabricated original")
    # no_sleep disables hibernation, so its prior state must be recorded
    assert "hibernate" in lowered, (
        "AC42: no_sleep disables hibernation, so the prior hibernation state "
        "must be recorded for the restore")
    # the teardown must restore both indices and re-enable hibernation
    teardown = uia._TEST_PROFILE_RESTORE_INNER.lower()
    assert teardown.count("standbyidle") >= 2, (
        "AC42: teardown must restore the AC standby index")
    assert "setacvalueindex scheme_current sub_sleep standbyidle $e.ac" in teardown, (
        "AC42: teardown must write the recorded AC index back")
    assert "setdcvalueindex scheme_current sub_sleep standbyidle $e.dc" in teardown, (
        "AC42: teardown must write the recorded DC index back")
    assert "/h on" in teardown, (
        "AC42: teardown must re-enable hibernation when it was on")


# ---------------------------------------------------------------------------
# AC51 — the powercfg reader, restore unit and hibernation source
# ---------------------------------------------------------------------------


def test_powercfg_reader_and_restore_contract(_ps_available):
    """AC51: three invariants the mocked checks could not see, each of them
    confirmed against Microsoft's own documentation and sample output.

    (a) BLOCK BOUNDARY. `powercfg /query SCHEME_CURRENT <subgroup>` holds
        SEVERAL settings, each closing with its own AC/DC index pair. The
        reader must stop at the end of the TARGET setting's block, or it
        returns the LAST setting's indices. Executed here for real, against
        the synthetic subgroup above, with VIDEOIDLE deliberately not last:
        the correct answer is 900|0 and the unbounded reader answers 0|0.
    (b) UNIT. `powercfg /change <timeout> <value>` reads its value in
        MINUTES ("*value* Specifies the new value, in minutes.") while
        /query reports the index in SECONDS ("Possible Settings units:
        Seconds"), so the restore must write the recorded index through the
        raw-index command (/setacvalueindex) rather than /change -- feeding
        it seconds restores 60x the original timeout.
    (c) ARITY + HIBERNATION. The reader takes exactly two arguments (a
        three-argument call bound $subGuid='SCHEME_CURRENT' and never
        matched), and the prior hibernation state must come from
        HibernateEnabled, which is what `powercfg /h` itself writes --
        `powercfg /a` lists Hibernate under "not available on this system"
        when it is merely disabled, so a token match read a disabled
        hibernation as enabled.
    """
    pswindows.init(Config(unrestricted=True))

    # --- (a) the reader, executed against the synthetic subgroup ----------
    harness = "\n".join([
        "function Assert-HypervMcpNative($what) {",
        "    if ($LASTEXITCODE -ne 0) { throw \"$what failed\" }",
        "}",
        "$LASTEXITCODE = 0",
        "$script:queryLines = @'",
        _SYNTHETIC_SUBGROUP,
        "'@ -split \"\\r?\\n\"",
        "function powercfg { $script:queryLines }",
        uia._POWERCFG_READER,
        "$pair = Get-HypervMcpPowerIndices 'SUB_VIDEO' 'VIDEOIDLE'",
        "Write-Output ($pair[0] + '|' + $pair[1])",
    ])
    out = _run_ps_script(harness).strip()
    assert out == "900|0", (
        f"AC51(a): the reader must return the TARGET setting's indices "
        f"(AC 900 = 0x384, DC 0); got {out!r}. A reader that walks to the "
        f"end of the subgroup returns the LAST setting's indices instead.")

    # --- (c) the reader's arity, and the call's arity ---------------------
    declared = re.search(
        r"function\s+Get-HypervMcpPowerIndices\s*\(([^)]*)\)",
        uia._POWERCFG_READER)
    assert declared, "AC51(c): the reader function declaration is missing"
    params = [p for p in declared.group(1).split(",") if p.strip()]
    assert len(params) == 2, (
        f"AC51(c): the reader must declare exactly two parameters (subgroup, "
        f"alias); it declares {len(params)}: {params}")
    call = re.search(r"Get-HypervMcpPowerIndices([^\n]*)",
                     uia._profile_read_block("no_display_timeout"))
    assert call, "AC51(c): the generated read never calls the reader"
    passed = re.findall(r"'[^']*'", call.group(1))
    assert len(passed) == 2, (
        f"AC51(c): the read must pass exactly two arguments; it passes "
        f"{len(passed)}: {passed}. A third argument left the reader bound to "
        f"$subGuid='SCHEME_CURRENT', so it never matched the setting.")

    # --- (c) the hibernation prior state ---------------------------------
    sleep_read = uia._profile_read_block("no_sleep")
    assert "HibernateEnabled" in sleep_read, (
        "AC51(c): the prior hibernation state must be read from "
        "HibernateEnabled, which is what 'powercfg /h' itself writes")
    assert "powercfg /a" not in sleep_read, (
        "AC51(c): 'powercfg /a' cannot answer whether hibernation is ON -- "
        "it lists Hibernate under 'not available on this system' when it is "
        "merely disabled, so a token match reads disabled as enabled")

    # --- (b) the restore's unit ------------------------------------------
    restore = uia._TEST_PROFILE_RESTORE_INNER
    for setting, sub, alias in (("no_display_timeout", "SUB_VIDEO", "VIDEOIDLE"),
                                ("no_sleep", "SUB_SLEEP", "STANDBYIDLE")):
        assert (f"powercfg /setacvalueindex SCHEME_CURRENT {sub} {alias} "
                f"$e.ac" in restore), (
            f"AC51(b): the {setting} restore must write the recorded AC "
            f"index through /setacvalueindex, which takes the RAW index "
            f"/query reported")
        assert (f"powercfg /setdcvalueindex SCHEME_CURRENT {sub} {alias} "
                f"$e.dc" in restore), (
            f"AC51(b): the {setting} restore must write the recorded DC "
            f"index through /setdcvalueindex")
    for stale in ("/change monitor-timeout-ac", "/change monitor-timeout-dc",
                  "/change standby-timeout-ac", "/change standby-timeout-dc"):
        assert stale not in restore, (
            f"AC51(b): the restore must not use '{stale}' -- /change reads "
            f"its value in MINUTES while the recorded index is in SECONDS, "
            f"so it would restore 60x the original timeout")


# ---------------------------------------------------------------------------
# AC43 — the record write is atomic and a re-apply keeps the original
# ---------------------------------------------------------------------------


def test_record_write_is_atomic_and_reapply_keeps_the_original(legs):
    """AC43: the record is the ONLY copy of the guest's original state, so it
    is written through a temp file and renamed (a crash mid-write must not
    truncate it and destroy every prior entry), and the write is guarded so a
    re-apply cannot overwrite the true original with the profile's own value.
    Teardown removes the record only when every restore succeeded."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, autologon=True, confirm=True,
                         test_profile=["no_inactivity_lock"])
    script = _profile_script(rec, "no_inactivity_lock")
    lowered = script.lower()
    assert "gettempfilename" in lowered and "move-item" in lowered, (
        "AC43: the record must be written to a temp file and renamed")
    # The CALL, not merely the prelude's function definition: gettempfilename
    # and move-item both appear in Save-HypervMcpRestoreRecord's body, which
    # every leg carries whether or not it is ever invoked.
    assert re.search(r"save-hypervmcprestorerecord\s+\$recordpath", lowered), (
        "AC43: the leg must CALL Save-HypervMcpRestoreRecord; the prelude's "
        "definition alone persists nothing")
    guard = re.search(
        r"if\s*\(\s*-not\s+\$rec\.ContainsKey\(\s*'no_inactivity_lock'\s*\)\s*\)\s*\{",
        script,
    )
    assert guard, (
        "AC43: the record write must be guarded on the setting not already "
        "being recorded")
    block = script[guard.end():]
    nxt = re.search(r"^\s*\}", block, re.M)
    block = block[:nxt.start()] if nxt else block
    assert re.search(r"Save-HypervMcpRestoreRecord\s+\$recordPath", block,
                     re.IGNORECASE), (
        "AC43: the guarded block must contain the record write")
    teardown = uia._TEST_PROFILE_RESTORE_INNER.lower()
    assert "remove-item" in teardown, (
        "AC43: teardown must remove the record once every restore succeeded")
    assert "failed.count" in teardown, (
        "AC43: the record must be retained (and the failure reported) when "
        "any restore failed")


# ---------------------------------------------------------------------------
# AC49 — the result carries before/after/applied per setting
# ---------------------------------------------------------------------------


def test_profile_result_carries_before_after_applied(legs):
    """AC49 (review round): issue #138 claim 4.4 requires the result to carry,
    for each selected setting, `before`, `after` and `applied`, plus
    `reboot_required`. The leg is the only honest source for before/after, so
    the host must record what the leg reported — a names-only list loses the
    evidence the live-host leg is required to hold.

    The LegRecorder serves a frame whose before/after the check asserts on, so
    a payload that drops either key turns this red.
    """
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    out = uia.provision_helper(cfg, "p138-vm", CRED, autologon=True,
                               confirm=True, test_profile=["no_sleep"])
    assert out.get("ok") is True, f"AC49: {json.dumps(out, default=str)[:300]}"
    profile = out.get("test_profile")
    assert isinstance(profile, dict), (
        f"AC49: test_profile must map each setting to its evidence; got "
        f"{profile!r}")
    entry = profile.get("no_sleep")
    assert isinstance(entry, dict), (
        f"AC49: every selected setting must carry an entry; got {profile!r}")
    assert entry.get("applied") is True, (
        f"AC49: the applied setting must report applied; got {entry!r}")
    assert "before" in entry, (
        f"AC49: the entry must carry the guest's original value; got {entry!r}")
    assert "after" in entry, (
        f"AC49: the entry must carry the value the profile set; got {entry!r}")
    # The VALUES, not just the keys: a key present with None is what a leg
    # that stopped reporting it looks like, and it is indistinguishable from
    # a faithful one unless the assertion names what was served.
    assert entry.get("before") == {"ac": "300", "dc": "300", "hibernate": "on"}, (
        f"AC49: the host must record the leg's reported original; got "
        f"{entry.get('before')!r}")
    assert entry.get("after") == {"ac": "0", "dc": "0", "hibernate": "off"}, (
        f"AC49: the host must record the leg's reported new value; got "
        f"{entry.get('after')!r}")
    # ...and the leg must EMIT it: the spec's `after` expression is what the
    # generated script reports, so a leg that stops naming it loses the value
    # even though the host still forwards the key.
    script = _profile_script(rec, "no_sleep")
    expected_after = "after = " + uia.TEST_PROFILE_SETTINGS["no_sleep"]["after"]
    assert expected_after in script, (
        f"AC49: the leg must emit its after value ({expected_after!r}); the "
        f"generated script does not name it")
    assert out.get("reboot_required") is True, (
        "AC49: an applied profile must report that the guest needs a reboot "
        "before the new state is what a session sees")


# ---------------------------------------------------------------------------
# AC56 — a restore leg that reports a failure is surfaced, not swallowed
# ---------------------------------------------------------------------------


def test_failed_profile_restore_is_reported(monkeypatch):
    """AC56 (TF-008): a restore leg that reports a partial failure must come
    back as ok:false with error_class profile_restore_failed and the
    unrestored settings named.

    The host used to read an ABSENT profile_restored as True, so a degraded
    frame -- which is what _provision_leg_frame returns for any stdout that is
    not exactly one JSON document, i.e. any crash of the restore script --
    was reported as a clean restore while the guest kept the profile's values.
    """
    rec = LegRecorder()
    monkeypatch.setattr(uia, "_run_uia_leg", rec)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder())

    def failing_restore(cfg, script, *, stdin_b64=None, timeout_s=None,
                        **kwargs):
        rec.scripts.append(script)
        if "profile_restored" in script:
            return pswindows.PSResult(
                stdout=json.dumps({"ok": True, "profile_restored": False,
                                   "unrestored": ["no_sleep"]}),
                returncode=0)
        return rec(cfg, script, stdin_b64=stdin_b64, timeout_s=timeout_s,
                   **kwargs)

    monkeypatch.setattr(uia, "_run_uia_leg", failing_restore)
    out = uia.provision_helper(Config(unrestricted=True), "p138-vm", CRED,
                               teardown=True, confirm=True)
    assert out.get("ok") is False, (
        f"AC56: a failed restore must not report ok; got {out}")
    assert out.get("error_class") == "profile_restore_failed", (
        f"AC56: the error_class must name the profile restore; got "
        f"{out.get('error_class')!r}")
    assert out.get("unrestored_settings") == ["no_sleep"], (
        f"AC56: the unrestored settings must be named; got "
        f"{out.get('unrestored_settings')!r}")
    assert out.get("torn_down") is True, (
        "AC56: the rest of the teardown still ran; the failure is the "
        f"profile's, not the teardown's; got {out}")


def test_degraded_restore_frame_is_a_failure(monkeypatch):
    """AC56 (TF-008, the degraded-frame half): a restore leg whose stdout is
    not exactly one JSON document parses to {}, and a {} frame must be a
    FAILED restore -- never the default the host used to apply."""
    base = LegRecorder()

    def degraded_restore(cfg, script, *, stdin_b64=None, timeout_s=None,
                         **kwargs):
        if "profile_restored" in script:
            return pswindows.PSResult(stdout="", returncode=0)
        return base(cfg, script, stdin_b64=stdin_b64, timeout_s=timeout_s,
                    **kwargs)

    monkeypatch.setattr(uia, "_run_uia_leg", degraded_restore)
    monkeypatch.setattr(pswindows, "run_ps", PSRecorder())
    out = uia.provision_helper(Config(unrestricted=True), "p138-vm", CRED,
                               teardown=True, confirm=True)
    assert out.get("ok") is False, (
        f"AC56: an empty restore frame must not report ok; got {out}")
    assert out.get("error_class") == "profile_restore_failed", (
        f"AC56: a degraded frame is a failed restore; got "
        f"{out.get('error_class')!r}")
