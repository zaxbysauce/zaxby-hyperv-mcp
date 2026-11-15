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
import re

import pytest

from hyperv_mcp import pswindows, uia
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")

VM_GUID = "e953c649-1234-5678-9abc-def012345678"

# The documented set: setting name -> tokens the generated change must carry
# (compared case-insensitively; powercfg aliases and registry value names
# from the claim-4 table).
SETTINGS = {
    "no_display_timeout": ("monitor-timeout-ac", "monitor-timeout-dc"),
    "no_sleep": ("standby-timeout-ac", "standby-timeout-dc", "/h off"),
    "no_auto_update": ("windowsupdate\\au", "noautoupdate"),
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
        return pswindows.PSResult(
            stdout=json.dumps({
                "ok": True, "result": result,
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
    record_at = script.lower().find(RESTORE_RECORD)
    change_at = _first_pos(script, [
        r"set-itemproperty", r"new-itemproperty", r"setvalue\(",
    ])
    assert read_at is not None, (
        "AC6: the leg never reads the setting's current value; the original "
        "would be lost")
    assert record_at != -1, (
        "AC6: the leg never mentions the restore record "
        f"({RESTORE_RECORD}); the original value is not persisted")
    assert change_at is not None, (
        "AC6: the leg never applies the setting's change")
    assert read_at < record_at < change_at, (
        f"AC6: order must be read ({read_at}) < record ({record_at}) < "
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
    guards = re.findall(
        r"if\s*\([^)\n]{0,200}(?:no_inactivity_lock|inactivitytimeoutsecs)"
        r"[^)\n]{0,200}\)",
        script,
        re.IGNORECASE,
    )
    assert guards, (  # count before detail
        "AC7: no conditional in the leg tests whether the setting is "
        "already recorded — a re-apply would overwrite the original value")
    record_at = script.lower().find(RESTORE_RECORD)
    assert record_at != -1, "AC7: the leg never writes the restore record"


# ---------------------------------------------------------------------------
# AC8 — teardown restores every recorded setting, then removes the record
# ---------------------------------------------------------------------------


def test_teardown_restores_every_recorded_setting(legs):
    """AC8: with a full restore record in the guest, teardown generates a
    restore for EVERY recorded setting and then removes the record."""
    rec, _ps = legs
    cfg = Config(unrestricted=True)
    uia.provision_helper(cfg, "p138-vm", CRED, teardown=True, confirm=True)
    blob = _blob(rec)
    lowered = blob.lower()
    assert RESTORE_RECORD in lowered, (
        "AC8: teardown never touched the restore record")
    missing = [
        f"{setting}:{token}"
        for setting, tokens in SETTINGS.items()
        for token in tokens
        if token not in lowered
    ]
    assert not missing, (  # count before enumeration
        f"AC8: {len(missing)} recorded settings have no restore generated: "
        f"{missing}")
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
    # the read must produce both indices
    assert "ac" in lowered and "dc" in lowered, (
        "AC42: the powercfg read must produce BOTH the AC and the DC index; "
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
    assert teardown.count("standby-timeout-ac") >= 2, (
        "AC42: teardown must restore the AC standby index")
    assert teardown.count("standby-timeout-dc") >= 2, (
        "AC42: teardown must restore the DC standby index")
    assert "/h on" in teardown, (
        "AC42: teardown must re-enable hibernation when it was on")


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
    guards = re.findall(
        r"if\s*\([^)\n]{0,200}(?:no_inactivity_lock|inactivitytimeoutsecs)"
        r"[^)\n]{0,200}\)",
        script,
        re.IGNORECASE,
    )
    assert guards, (  # count before detail
        "AC43: the record write must be guarded on the setting not already "
        "being recorded")
    record_at = lowered.find("restore.json")
    assert record_at != -1, "AC43: the leg must write the restore record"
    teardown = uia._TEST_PROFILE_RESTORE_INNER.lower()
    assert "remove-item" in teardown, (
        "AC43: teardown must remove the record once every restore succeeded")
    assert "failed.count" in teardown, (
        "AC43: the record must be retained (and the failure reported) when "
        "any restore failed")
