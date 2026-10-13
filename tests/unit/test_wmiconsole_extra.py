"""Supplementary (NOT frozen) pins for issue #45: zero-spawn + result-shape
parity for the nine WMI-wired console ops the frozen c8 does not cover,
wait_frame_change/capture_sequence/get_display_info semantics on the WMI
path, click-at-origin parity, and the REAL connect_service credential flow
through the _locator seam (closing the c9 credential-tautology gap on
pywin32-less CI).

The frozen acceptance file is tests/unit/test_wmiconsole.py (byte-locked);
these tests reuse its fakes by import.
"""

from __future__ import annotations

import contextlib

import pytest
from test_wmiconsole import (  # noqa: F401  (same-directory import, --import-mode=prepend)
    GUID,
    FakeWMIService,
    _install_wmi,
    _ps,
)

from hyperv_mcp import console, credentials, vmlocks, wmiconsole
from hyperv_mcp.config import Config


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


def _recording_lock(recorder: list):
    real_lock = vmlocks.vm_lock

    @contextlib.contextmanager
    def wrapped(key, *args, **kwargs):
        # Issue #14: vm_lock gained mode=/wait_s=; record and pass through.
        recorder.append(key)
        with real_lock(key, *args, **kwargs):
            yield

    return wrapped


def test_press_key_key_combo_type_scancodes_zero_spawns(monkeypatch, unrestricted_cfg):
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)
    locked: list = []
    monkeypatch.setattr(vmlocks, "vm_lock", _recording_lock(locked))

    assert console.press_key(unrestricted_cfg, "vm1", "enter")["ok"] is True
    assert console.key_combo(unrestricted_cfg, "vm1", ["ctrl", "a"])["ok"] is True
    out = console.type_scancodes(unrestricted_cfg, "vm1", [0x1C, 0x9C])
    assert out["ok"] is True and out["scancodes_sent"] == 2

    assert stub.scripts == []
    assert any(key.casefold() == GUID for key in locked)
    names = [m[1] for m in svc.methods]
    assert names.count("TypeScancodes") == 3
    for r in (
        console.press_key(unrestricted_cfg, "vm1", "enter"),
        console.key_combo(unrestricted_cfg, "vm1", ["ctrl", "a"]),
        console.type_scancodes(unrestricted_cfg, "vm1", [0x1C]),
    ):
        assert r["timings"]["transport"] == "wmi"
        assert isinstance(r["timings"]["method_ms"], float)


def test_mouse_ops_zero_spawns_and_shapes(monkeypatch, unrestricted_cfg):
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    out = console.mouse_move(unrestricted_cfg, "vm1", 10, 20,
                             frame_width=320, frame_height=240)
    assert out["head_x"] == 10 and out["head_y"] == 20 and out["ok"] is True
    assert console.mouse_button(unrestricted_cfg, "vm1", 2, True)["ok"] is True
    assert console.scroll(unrestricted_cfg, "vm1", -1)["ok"] is True

    assert stub.scripts == []
    methods = {m[1]: m[2] for m in svc.methods}
    assert methods["SetAbsolutePosition"] == {
        "HorizontalPosition": 10, "VerticalPosition": 20}
    assert methods["SetButtonState"] == {"ButtonIndex": 2, "IsDown": True}
    assert methods["SetScrollPosition"] == {"ScrollPositionDelta": -1}


def test_click_at_origin_wmi_no_move_no_head_keys(monkeypatch, unrestricted_cfg):
    """The preserved PS contract: click(0,0) clicks at the CURRENT position
    with no SetAbsolutePosition and no head_x/head_y keys (test_console
    pins the PS side; this pins the WMI side)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)

    out = console.click(unrestricted_cfg, "vm1", 0, 0)
    assert out["ok"] is True
    assert "head_x" not in out and "head_y" not in out
    names = [m[1] for m in svc.methods]
    assert "SetAbsolutePosition" not in names
    assert "ClickButton" in names


def test_get_display_info_wmi_zero_spawns(monkeypatch, unrestricted_cfg):
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert stub.scripts == []
    assert out["ok"] is True and out["vm_name"] == "vm1"
    assert out["enabled_state"] == 2
    assert out["head_horizontal"] == 320 and out["head_vertical"] == 240
    assert out["keyboard_present"] is True and out["mouse_present"] is True
    assert out["keyboard_enabled"] is None  # property-less fake device objects
    assert out["timings"]["transport"] == "wmi"
    assert out["guest_channel"] == "ps_direct_unverified"


class _FlippingService(FakeWMIService):
    """Serves alternating captures so wait_frame_change observes a change."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tick = 0

    def exec_method(self, obj, name, in_params):
        if name == "GetVirtualSystemThumbnailImage":
            width = int(in_params.values["WidthPixels"])
            height = int(in_params.values["HeightPixels"])
            self._tick += 1
            self.captures.append((width, height))
            pixels = bytearray(b"\x5a\xa5" * (width * height))
            pixels[0] = self._tick & 0xFF
            from types import SimpleNamespace
            return SimpleNamespace(ReturnValue=self.method_rc,
                                   ImageData=b"\x00\x00\x00\x00" + bytes(pixels))
        return super().exec_method(obj, name, in_params)


def test_wait_frame_change_wmi_semantics(monkeypatch, unrestricted_cfg):
    svc = _FlippingService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    # First-poll-is-baseline: poll 1 is the baseline, poll 2 differs.
    out = console.wait_frame_change(unrestricted_cfg, "vm1", width=320, height=240,
                                    timeout_s=10, interval_s=1)
    assert stub.scripts == []
    assert out["stop_reason"] == "changed" and out["changed"] is True
    assert out["polls"] == 2
    assert out["width"] == 320 and out["height"] == 240
    assert isinstance(out["elapsed_ms"], int)
    assert "image" in out and "frame_hash" in out
    assert out["timings"]["transport"] == "wmi"

    # Supplied baseline: the very first poll already differs.
    first_hash = out["frame_hash"]
    out2 = console.wait_frame_change(unrestricted_cfg, "vm1",
                                     baseline_hash=first_hash,
                                     width=320, height=240, timeout_s=10, interval_s=1)
    assert out2["polls"] == 1 and out2["changed"] is True

    # Deadline: an EMPTY baseline with a frozen frame never differs and runs
    # out of polls bounded by max_polls (a supplied baseline that never
    # matches reports changed on poll 1 — that is the discriminating side).
    frozen = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: frozen)
    out3 = console.wait_frame_change(unrestricted_cfg, "vm1",
                                     baseline_hash="",
                                     width=320, height=240, timeout_s=10, interval_s=1)
    assert out3["stop_reason"] == "deadline" and out3["changed"] is False
    assert 2 <= out3["polls"] <= 10  # polls ran up to the max_polls bound
    # (ceil(10/1)); with real sleeps the wall-clock deadline (checked
    # between polls) can stop the loop earlier
    assert "image" not in out3
    # deadline keeps the LAST polled hash even when unchanged
    assert out3["frame_hash"] == console._frame_hash(
        b"\x00\x00\x00\x00" + b"\x5a\xa5" * (320 * 240))
    never_matches = console.wait_frame_change(unrestricted_cfg, "vm1",
                                              baseline_hash="00" * 32,
                                              width=320, height=240,
                                              timeout_s=10, interval_s=1)
    assert never_matches["stop_reason"] == "changed" and never_matches["polls"] == 1


def test_capture_sequence_wmi_semantics(monkeypatch, unrestricted_cfg):
    svc = _FlippingService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    out = console.capture_sequence(unrestricted_cfg, "vm1", count=3, interval_s=1,
                                   width=320, height=240)
    assert stub.scripts == []
    assert out["ok"] is True and len(out["frames"]) == 3
    assert [f["index"] for f in out["frames"]] == [0, 1, 2]
    # strict-zip byte-diff counts against the equal-length payloads
    assert out["frames"][0]["changed_bytes_vs_previous"] == 0
    assert out["frames"][1]["changed_bytes_vs_previous"] == 1
    assert out["frames"][2]["changed_bytes_vs_previous"] == 1
    # first and last images only
    assert len(out["images"]) == 2
    assert isinstance(out["elapsed_ms"], int)
    assert out["timings"]["transport"] == "wmi"


def test_real_connect_service_credential_flow(monkeypatch):
    """The REAL connect_service (only _locator faked) must derive the DCOM
    target from the caller's cfg and pass resolved HYPERV_HOST_* credentials
    to ConnectServer — on any box, with zero real COM (round-2 plan-critic
    gap: the frozen c9's credential assertions are satisfied by its own
    fake and pin nothing about the real implementation)."""
    calls: list = []

    class _FakeLocator:
        def ConnectServer(self, *args):
            calls.append(args)
            return "fake-service"

    monkeypatch.setattr(wmiconsole, "_locator", lambda: _FakeLocator())
    cred = credentials.CredentialSet("hostuser", "hostpass-xyz")
    monkeypatch.setattr(credentials, "resolve_host", lambda environ=None: cred)
    # Isolate the backend cache WITHOUT calling backend(): that would run
    # connect_service through the faked locator and pollute `calls` (the
    # empty-vs-populated cache state left by earlier tests is not something
    # this test should depend on).
    monkeypatch.setattr(wmiconsole, "_backends", {})

    remote = Config.from_dict({"hyperv": {"host": "nuc01"}, "unrestricted": True})
    svc = wmiconsole.connect_service(remote)
    assert svc == "fake-service"
    assert calls == [("nuc01", "root\\virtualization\\v2", "hostuser", "hostpass-xyz")]

    # implicit-auth remote: no complete credential pair -> 2-arg form
    monkeypatch.setattr(credentials, "resolve_host", lambda environ=None: None)
    assert wmiconsole.connect_service(remote) == "fake-service"
    assert calls[-1] == ("nuc01", "root\\virtualization\\v2")

    # local mode: '.' and no credentials consulted
    local = Config(unrestricted=True)
    assert wmiconsole.connect_service(local) == "fake-service"
    assert calls[-1] == (".", "root\\virtualization\\v2")

    # connect failures wrap as BackendUnavailable
    def boom():
        raise OSError("rpc unavailable")

    monkeypatch.setattr(wmiconsole, "_locator", boom)
    with pytest.raises(wmiconsole.BackendUnavailable, match="rpc unavailable"):
        wmiconsole.connect_service(remote)

    # and a VM missing from the WMI plane is BackendUnavailable (fallback class)
    class _EmptyNamespace:
        def ExecQuery(self, wql):
            return []

        def Get(self, path):
            raise KeyError(path)

    monkeypatch.setattr(wmiconsole, "_locator", lambda: _FakeLocator())
    be = wmiconsole.ConsoleWMI(_EmptyNamespace())
    with pytest.raises(wmiconsole.BackendUnavailable):
        be.resolve_vm(Config(unrestricted=True), vm_name="no-such-vm")


def test_resolve_miss_falls_back_to_powershell(monkeypatch, unrestricted_cfg):
    """A VM the WMI plane cannot resolve selects the PowerShell transport
    (keeps FakePS-stubbed callers and unusual hosts working)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    # The FakeWMIService serves its one VM for ANY name, so drive the miss
    # through the REAL backend object instead: empty namespace.
    class _Empty:
        def ExecQuery(self, wql):
            return []

        def Get(self, path):
            raise KeyError(path)

    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: _Empty())
    out = console.type_text(unrestricted_cfg, "vm1", "fallback")
    assert out["ok"] is True
    assert len(stub.scripts) >= 1
    assert out["timings"]["transport"] == "powershell"


# ---------------------------------------------------------------------------
# Review-fix regression pins (round-1 implementation review F1/F2/F3/F5):
# the fixes were probe-verified by the reviewer; these pins make any
# regression fail a committed test.
# ---------------------------------------------------------------------------

def test_f1_mouse_ops_hold_vm_lock(monkeypatch, unrestricted_cfg):
    """F1: every WMI mouse input op takes the per-VM lock (transport-agnostic
    exclusion; PS path has always taken it)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    locked: list = []
    monkeypatch.setattr(vmlocks, "vm_lock", _recording_lock(locked))

    console.mouse_move(unrestricted_cfg, "vm1", 5, 5, frame_width=320, frame_height=240)
    console.click(unrestricted_cfg, "vm1", 10, 10, frame_width=320, frame_height=240)
    console.click(unrestricted_cfg, "vm1", 0, 0)
    console.mouse_button(unrestricted_cfg, "vm1", 1, True)
    console.scroll(unrestricted_cfg, "vm1", 1)

    # Issue #14: console input additionally locks the (guid, "console")
    # tuple key; compare on the VM-key element only.
    def _vm_key(k):
        return k[0] if isinstance(k, tuple) else k

    mouse_locks = [k for k in locked if _vm_key(k).casefold() == GUID]
    assert len(mouse_locks) >= 5, locked


class _RenamingService(FakeWMIService):
    """F2 fake: simulates delete+recreate (new GUID for the same name) and
    rename (ElementName changes) between calls."""

    def __init__(self):
        super().__init__(guid=GUID, name="vm1")
        self._generation = 0
        self._rebound = False

    def ExecQuery(self, wql):
        text = " ".join(wql.split())
        if (self._rebound and "Msvm_ComputerSystem" in text
                and "ElementName" not in text and "Name =" in text):
            return []  # the OLD GUID is gone after the recreate
        if "Msvm_ComputerSystem" in text and "ElementName" in text:
            if self._rebound:
                # recreate: same name, new GUID+object
                self._generation += 1
                from test_wmiconsole import FakeWmiObject
                new_guid = GUID[:-1] + str(self._generation)
                obj = FakeWmiObject(
                    self,
                    f'Msvm_ComputerSystem.Name="{new_guid}"',
                    {"Name": new_guid, "ElementName": "vm1", "EnabledState": 2},
                )
                return [obj]
        return super().ExecQuery(wql)


def test_f2_name_cache_revalidates_recreate(monkeypatch, unrestricted_cfg):
    """F2: after the cached VM's object path dies (delete+recreate), the next
    by-name resolve re-queries and serves the NEW identity in the same call
    instead of a sticky BackendUnavailable."""
    svc = _RenamingService()
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)

    ref1 = be.resolve_vm(unrestricted_cfg, vm_name="vm1")
    assert ref1.id == GUID
    # VM recreated: old CS path no longer Get()s
    original_get = svc.Get

    def get_or_die(path):
        if path == svc._vm._props["Path_"].Path:
            raise KeyError(path)
        return original_get(path)

    svc.Get = get_or_die
    svc._rebound = True
    ref2 = be.resolve_vm(unrestricted_cfg, vm_name="vm1")
    assert ref2.id != GUID and ref2.name == "vm1"


def test_f2_name_cache_rename_self_heals(monkeypatch, unrestricted_cfg):
    """F2: a cached name whose live ElementName no longer matches falls
    through to a fresh by-name query (rename detected, no stale identity)."""
    svc = FakeWMIService(head=(320, 240))
    original_query = svc.ExecQuery

    def name_filtering_query(wql):
        text = " ".join(wql.split())
        if "Msvm_ComputerSystem" in text and "ElementName" in text:
            import re
            m = re.search(r"ElementName = '([^']*)'", text)
            if m and svc._vm._props["ElementName"].casefold() != m.group(1).casefold():
                return []
        return original_query(wql)

    svc.ExecQuery = name_filtering_query
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)

    assert be.resolve_vm(unrestricted_cfg, vm_name="vm1").id == GUID
    svc._vm._props["ElementName"] = "renamed-away"
    with pytest.raises(wmiconsole.BackendUnavailable):
        be.resolve_vm(unrestricted_cfg, vm_name="vm1")


def test_f3_identity_conflicts_raise_valueerror(monkeypatch, unrestricted_cfg):
    """F3: caller-input identity conflicts raise ValueError on the WMI path
    exactly like vmident.resolve (error_class 'invalid', not 'transport')."""
    svc = FakeWMIService(head=(320, 240))
    svc._vm._props["ElementName"] = "different-name"
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)

    with pytest.raises(ValueError, match="different VMs"):
        be.resolve_vm(unrestricted_cfg, vm_name="vm1", vm_id=GUID)

    svc._vm._props["ElementName"] = ""
    with pytest.raises(ValueError, match="empty name"):
        be.resolve_vm(unrestricted_cfg, vm_id=GUID)


def test_f3_ambiguous_identity_raises_valueerror(monkeypatch, unrestricted_cfg):
    svc = FakeWMIService(head=(320, 240))
    second = FakeWMIService(head=(320, 240))._vm
    original = svc.ExecQuery

    def two_rows(wql):
        text = " ".join(wql.split())
        if "Msvm_ComputerSystem" in text and "ElementName" in text:
            return [svc._vm, second]
        return original(wql)

    svc.ExecQuery = two_rows
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    with pytest.raises(ValueError, match="2 rows"):
        be.resolve_vm(unrestricted_cfg, vm_name="vm1")


def test_f5_display_info_reports_absent_devices(monkeypatch, unrestricted_cfg):
    """F5: a VM with no keyboard/mouse associations reports present=False
    (PS [bool]$kb parity) instead of erroring."""
    svc = FakeWMIService(head=(320, 240))

    original_assoc = svc.ExecQuery

    def no_devices(wql):
        text = " ".join(wql.split()).upper()
        if ("RESULTCLASS = MSVM_KEYBOARD" in text
                or "MSVM_SYNTHETICMOUSE" in text):
            return []
        return original_assoc(wql)

    svc.ExecQuery = no_devices
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)

    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["keyboard_present"] is False and out["mouse_present"] is False


# ---------------------------------------------------------------------------
# swarm-pr-review fixes (PRR-002/003/004/005/006/008/013/015/016/023/025):
# regression pins for the review findings, plus the frozen-file lock.
# ---------------------------------------------------------------------------

def test_frozen_acceptance_file_intact():
    """PRR-023: the byte-locked acceptance file's freeze is machine-checked
    in-repo (not just trace process). If the trace protocol SANCTIONED an
    amend of that file, update this hash with the amend.

    Hash updated by issue #14 (trace issue-14-vm-rw-locks): vm_lock gained
    mode=/wait_s= kwargs, so the recording_lock spy in test_wmiconsole.py
    was amended to pass them through (kwargs-only signature change; the
    test's assertions are untouched)."""
    import subprocess

    out = subprocess.run(
        ["git", "hash-object", "tests/unit/test_wmiconsole.py"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == "2cc7a73ce51ca4da4ededaa0fa486a319fa4beb8", out


def test_capture_guard_no_image_data(monkeypatch, unrestricted_cfg):
    """PRR-015: a capture whose result carries no ImageData is WMIError."""
    from types import SimpleNamespace

    from hyperv_mcp import wmiconsole

    class NoImageService(FakeWMIService):
        def exec_method(self, obj, name, in_params):
            if name == "GetVirtualSystemThumbnailImage":
                return SimpleNamespace(ReturnValue=0)
            return super().exec_method(obj, name, in_params)

    svc = NoImageService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    with pytest.raises(wmiconsole.WMIError, match="no image data"):
        be.capture(GUID, 320, 240)


def test_capture_guard_length_mismatch(monkeypatch, unrestricted_cfg):
    """PRR-015: a short thumbnail payload is a length-mismatch error, never
    a silently-corrupt image."""
    from types import SimpleNamespace

    from hyperv_mcp import wmiconsole

    class ShortService(FakeWMIService):
        def exec_method(self, obj, name, in_params):
            if name == "GetVirtualSystemThumbnailImage":
                return SimpleNamespace(ReturnValue=0, ImageData=b"\x00\x00")
            return super().exec_method(obj, name, in_params)

    svc = ShortService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    with pytest.raises(wmiconsole.WMIError, match="length mismatch"):
        be.capture(GUID, 320, 240)


@pytest.mark.parametrize("op_name", ["click", "mouse_button", "scroll", "type_text", "capture"])
def test_method_failure_is_console_error_no_ps(monkeypatch, unrestricted_cfg, op_name):
    """PRR-015/PRR-002: a non-zero WMI ReturnValue converts to ConsoleError
    with ZERO PowerShell sends on every input/capture op (not just
    type_text)."""
    from hyperv_mcp.console import ConsoleError

    svc = FakeWMIService(head=(320, 240))
    svc.method_rc = 5
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    calls = {
        "click": lambda: console.click(unrestricted_cfg, "vm1", 10, 10,
                                       frame_width=320, frame_height=240),
        "mouse_button": lambda: console.mouse_button(unrestricted_cfg, "vm1", 1, True),
        "scroll": lambda: console.scroll(unrestricted_cfg, "vm1", 1),
        "type_text": lambda: console.type_text(unrestricted_cfg, "vm1", "no send"),
        "capture": lambda: console.screenshot(unrestricted_cfg, "vm1",
                                              width=320, height=240),
    }
    with pytest.raises(ConsoleError, match="ReturnValue=9|ReturnValue=5"):
        calls[op_name]()
    assert stub.scripts == []


def test_by_id_resolve_wmi_success(monkeypatch, unrestricted_cfg):
    """PRR-015: the by-id WMI resolve SUCCESS path (policy on the resolved
    name, VMRef returned, zero PowerShell)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)
    out = console.type_text(unrestricted_cfg, vm_id=GUID, text="by id")
    assert out["ok"] is True and out["vm_name"] == "vm1"
    assert stub.scripts == []


def test_com_entry_points_join_mta_before_com(monkeypatch):
    """PRR-001 guard: connect_service and resolve_vm join the MTA BEFORE
    their first COM call — the order is pinned, so a revert re-breaks
    threaded workers loudly."""
    from hyperv_mcp import wmiconsole

    order: list[str] = []

    def fake_join():
        order.append("join")

    class FakeLocator:
        def ConnectServer(self, *a):
            order.append("connect")
            return "svc"

    monkeypatch.setattr(wmiconsole, "_COM_IMPORT_OK", True)
    monkeypatch.setattr(wmiconsole, "_ensure_thread_com", fake_join)
    monkeypatch.setattr(wmiconsole, "_locator", lambda: FakeLocator())

    wmiconsole.connect_service(Config(unrestricted=True))
    assert order == ["join", "connect"], order

    order.clear()
    be = wmiconsole.ConsoleWMI(object())
    monkeypatch.setattr(wmiconsole, "_com",
                        lambda op, fn, *a, **k: order.append("query") or [])
    with pytest.raises(wmiconsole.BackendUnavailable):
        be.resolve_vm(Config(unrestricted=True), vm_name="no-such-vm")
    assert order and order[0] == "join", order


def test_screenshot_wmi_size_fallback_chain(monkeypatch, unrestricted_cfg):
    """PRR-015: the WMI screenshot fallback chain retries smaller sizes on a
    WMIError and stays on the wmi transport (never touches PowerShell)."""

    class PickyService(FakeWMIService):
        def exec_method(self, obj, name, in_params):
            if name == "GetVirtualSystemThumbnailImage":
                w = int(in_params.values["WidthPixels"])
                if w != 320:
                    from types import SimpleNamespace
                    return SimpleNamespace(ReturnValue=9)
            return super().exec_method(obj, name, in_params)

    svc = PickyService(head=(1024, 768))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)
    _img, meta = console.screenshot(unrestricted_cfg, "vm1", width=1024, height=768)
    assert stub.scripts == []
    assert meta["timings"]["transport"] == "wmi"
    assert "failed" in meta["fallback_used"]


def test_stale_cs_recovery_drops_devices(monkeypatch, unrestricted_cfg):
    """PRR-006: a VMMS rebuild whose EnabledState is unchanged must still
    drop cached device paths (checkpoint-apply case) — the next input op
    re-resolves the keyboard instead of exec-ing a stale path forever."""

    class RebuiltService(FakeWMIService):
        def __init__(self):
            super().__init__(head=(320, 240))
            self._rebuilt = False

        def Get(self, path):
            if self._rebuilt and path == self._vm._props["Path_"].Path:
                raise KeyError(path)  # old CS path dead after rebuild
            return super().Get(path)

    svc = RebuiltService()
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    be.type_text(GUID, "warm")  # caches the keyboard path
    kb_queries = svc.counts["keyboard"]

    svc._rebuilt = True  # VMMS rebuild, EnabledState still 2
    assert be.type_text(GUID, "after rebuild")[0] is None
    assert svc.counts["keyboard"] > kb_queries  # devices were re-resolved


def test_midop_backendunavailable_is_console_error(monkeypatch, unrestricted_cfg):
    """PRR-002: a BackendUnavailable raised MID-operation (VM vanishes
    between resolve and op) surfaces as ConsoleError, not a raw escape."""

    class VanishingService(FakeWMIService):
        def ExecQuery(self, wql):
            if "Msvm_VirtualSystemManagementService" in wql:
                return []
            return super().ExecQuery(wql)

    from hyperv_mcp.console import ConsoleError

    svc = VanishingService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    with pytest.raises(ConsoleError):
        console.screenshot(unrestricted_cfg, "vm1", width=320, height=240)


def test_com_error_wrapped_as_wmi_error(monkeypatch, unrestricted_cfg):
    """PRR-005: a raw COM failure (e.g. pywintypes com_error) inside a WMI
    call becomes a structured WMIError, never an unclassified escape."""

    class ExplodingService(FakeWMIService):
        def Get(self, path):
            if "-mouse" in path:
                raise OSError("(-2147467259, 'Unspecified error')")
            return super().Get(path)

    from hyperv_mcp import wmiconsole

    svc = ExplodingService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    with pytest.raises(wmiconsole.WMIError, match="WMI"):
        be.mouse_move(GUID, 5, 5)


def test_rows_normalizer_shapes():
    """PRR-015: _rows handles the shapes real SWbem and fakes produce."""
    from hyperv_mcp import wmiconsole

    assert wmiconsole._rows(None) == []
    assert wmiconsole._rows([1, 2]) == [1, 2]

    class Blob:
        pass

    single = Blob()
    assert wmiconsole._rows(single) == [single]
    assert wmiconsole._rows("x") == ["x"]

    class OneShot:
        def __iter__(self):
            return iter([single])

    assert wmiconsole._rows(OneShot()) == [single]


def test_mouse_click_half_none_rejected():
    from hyperv_mcp import wmiconsole

    be = wmiconsole.ConsoleWMI(object())
    with pytest.raises(ValueError, match="both hx and hy"):
        be.mouse_click(GUID, 1, hx=5, hy=None)


def test_shutdown_clears_caches_and_memo(monkeypatch):
    """PRR-015: shutdown() drops backend entries, per-VM caches, and the
    negative-connect memo (nothing survives to a next process phase)."""
    from test_wmiconsole import FakeWmiObject

    from hyperv_mcp import wmiconsole

    be = wmiconsole.ConsoleWMI(object())
    be._seed_cache(GUID, FakeWmiObject(be, "fake://cs", {"Name": GUID}))
    monkeypatch.setattr(wmiconsole, "_backends", {"local": be})
    monkeypatch.setattr(
        wmiconsole, "_connect_failures",
        {"nuc01": (0.0, wmiconsole.BackendUnavailable("down"))},
    )
    wmiconsole.shutdown()
    assert wmiconsole._backends == {}
    assert wmiconsole._connect_failures == {}
    assert GUID not in be._vms


def test_negative_connect_memo_within_ttl(monkeypatch):
    """PRR-012: a failed connect is memoized per host key; a second
    backend() within the TTL re-raises without re-connecting."""

    calls: list = []

    def failing_connect(cfg):
        calls.append(cfg)
        raise wmiconsole.BackendUnavailable("dcom down")

    monkeypatch.setattr(wmiconsole, "connect_service", failing_connect)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})

    with pytest.raises(wmiconsole.BackendUnavailable):
        wmiconsole.backend(unrestricted := Config(unrestricted=True))
    with pytest.raises(wmiconsole.BackendUnavailable):
        wmiconsole.backend(unrestricted)
    assert len(calls) == 1  # memo served the second call


def test_host_key_separates_local_from_remote_dot(monkeypatch):
    """PRR-020: a remote cfg with hyperv.host='.' must not share the
    local-mode backend entry (different credential intents)."""
    assert wmiconsole._host_key(Config(unrestricted=True)) == "local"
    remote = Config.from_dict({"hyperv": {"host": "."}, "unrestricted": True})
    assert wmiconsole._host_key(remote) == "."


def test_cs_by_name_skips_host_computer_system(monkeypatch, unrestricted_cfg):
    """PRR-016: a VM name colliding with the host CS (non-GUID Name row,
    live-observed as ElementName='VSAN', Name='VSAN') resolves the VM, and
    the host row is never cached."""

    from test_wmiconsole import FakeWmiObject

    class HostCollisionService(FakeWMIService):
        def __init__(self):
            super().__init__(head=(320, 240))
            self._host = FakeWmiObject(
                self,
                'Msvm_ComputerSystem.CreationClassName="host"',
                {"Name": "vm1", "ElementName": "vm1", "EnabledState": 2},
            )

        def ExecQuery(self, wql):
            text = " ".join(wql.split())
            if "Msvm_ComputerSystem" in text and "ElementName" in text:
                return [self._host, self._vm]  # host row FIRST, non-GUID Name
            return super().ExecQuery(wql)

    svc = HostCollisionService()
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    ref = be.resolve_vm(unrestricted_cfg, vm_name="vm1")
    assert ref.id == GUID  # the VM row, not the hijacking host row
    assert GUID in be._vms and "CreationClassName" not in " ".join(be._vms)


def test_consolebench_soak_excludes_failures():
    """PRR-008: failed soak ops are counted, excluded from percentiles, and
    split per op."""
    from hyperv_mcp import consolebench

    def bad():
        raise RuntimeError("boom")

    def good():
        pass

    row = consolebench.run_soak([bad, good], agents=1, n=1)[0]
    assert row["errors"] == 1 and row["n"] == 1
    assert row["per_op_ms"][0] == [] and len(row["per_op_ms"][1]) == 1


def test_bench_last_result_enables_transport_verification():
    from hyperv_mcp import consolebench

    stats = consolebench.bench(lambda: {"timings": {"transport": "wmi"}}, 2)
    assert consolebench._transport_of(stats["last_result"]) == "wmi"
    assert consolebench._transport_of({"timings": {"transport": "powershell"}}) == "powershell"
    assert consolebench._transport_of(None) is None


def test_wmi_timings_reports_measured_rebind(monkeypatch, unrestricted_cfg):
    """PRR-003: the mouse ops thread the head-resolution phase dict into the
    breakdown, and backend methods measure rebind_ms (not hardcoded 0)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)

    # Deterministic clock: each monotonic() read advances 25 ms, so every
    # timed phase (rebind, then method) must report exactly 25.0 ms — a
    # hardcoded 0.0 or an omitted phase fails this assertion.
    class _FakeClock:
        def __init__(self):
            self._now = 0.0

        def monotonic(self):
            self._now += 0.025
            return self._now

    fake = _FakeClock()
    monkeypatch.setattr(wmiconsole.time, "monotonic", fake.monotonic)
    _r, t_move = be.mouse_move(GUID, 5, 5)
    assert t_move["rebind_ms"] == pytest.approx(25.0), t_move
    assert t_move["method_ms"] == pytest.approx(25.0), t_move

    from hyperv_mcp import console

    out = console.mouse_move(unrestricted_cfg, "vm1", 10, 20,
                             frame_width=320, frame_height=240)
    phases = [out["timings"]["rebind_ms"], out["timings"]["method_ms"]]
    assert all(isinstance(v, float) for v in phases)


def test_display_info_reports_none_for_null_head_resolution(monkeypatch, unrestricted_cfg):
    """PRR-004: a head present with NULL resolution reports None (PS $null
    parity), not 0."""
    svc = FakeWMIService(head=(320, 240))
    svc.set_head(0, 0)  # the live 'VM off' shape reads as null/0
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["head_horizontal"] is None and out["head_vertical"] is None


def test_display_info_absent_vs_failed_device(monkeypatch, unrestricted_cfg):
    """PRR-013: an ABSENT device reports present=False; a FAILED device
    lookup raises ConsoleError instead of laundering to absent."""

    class NoDevicesService(FakeWMIService):
        def ExecQuery(self, wql):
            text = " ".join(wql.split()).upper()
            if "MSVM_KEYBOARD" in text or "MSVM_SYNTHETICMOUSE" in text:
                return []
            return super().ExecQuery(wql)

    svc = NoDevicesService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["keyboard_present"] is False and out["mouse_present"] is False

    class FailedMouseProbeService(FakeWMIService):
        """MOUSE-ONLY probe failure: the keyboard ASSOCIATORS succeeds via
        super(), the mouse enumerate raises — so the ConsoleError this test
        demands can only come from the mouse channel (a reintroduced
        launder-to-absent catch would fail this test)."""

        def ExecQuery(self, wql):
            text = " ".join(wql.split()).upper()
            if "SELECT * FROM MSVM_SYNTHETICMOUSE" in text:
                raise OSError("rpc down")  # probe failure, NOT an empty result
            return super().ExecQuery(wql)

    failing = FailedMouseProbeService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: failing)
    from hyperv_mcp.console import ConsoleError

    with pytest.raises(ConsoleError):
        console.get_display_info(unrestricted_cfg, "vm1")


def test_type_text_multichunk_wmi(monkeypatch, unrestricted_cfg):
    """PRR-015: >512-char type_text chunks on the WMI path (chunks==2)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)
    out = console.type_text(unrestricted_cfg, "vm1", "a" * 600)
    assert out["chunks"] == 2
    typed = [m for m in svc.methods if m[1] == "TypeText"]
    assert len(typed) == 2


def test_vm_id_whitespace_only_rejected(monkeypatch, unrestricted_cfg):
    """PRR-019: a whitespace-only vm_id is rejected (vmident parity), not
    silently by-name resolved."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    be = wmiconsole.backend(unrestricted_cfg)
    with pytest.raises(ValueError, match="GUID"):
        be.resolve_vm(unrestricted_cfg, vm_name="vm1", vm_id="   ")
