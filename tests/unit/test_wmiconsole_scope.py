"""Acceptance checks for issue #78 (trace 75-76-78-81-83-84-collated):
the ConsoleWMI mouse-path resolution must be a SINGLE SystemName-scoped WMI
query with no per-device association walk, and a FAILED probe must surface as
a failure (never laundered to "absent"), while a genuinely ABSENT device
stays present=False for display_info.

Frozen-docstring wording note: the discriminating checks below are RED at the
pre-fix tree and GREEN after the fix; the absent-vs-failed preserve-leg is
GREEN at both ends.

RED at base for AC7/AC8 (wmiconsole.py emits the unscoped
``SELECT * FROM Msvm_SyntheticMouse`` enumeration plus one reverse
``ASSOCIATORS OF {mouse} WHERE ResultClass = Msvm_ComputerSystem`` per device
and launders a failed owner-probe via ``except WMIError: continue``); GREEN
after the scoped single-query fix. The fakes are reused from the frozen
test_wmiconsole.py by import (that file must never be modified)."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from test_wmiconsole import (  # noqa: F401  (same-directory import, --import-mode=prepend)
    GUID,
    FakeWMIService,
    _install_wmi,
    _ps,
)

from hyperv_mcp import console, wmiconsole
from hyperv_mcp.console import ConsoleError


class RecordingQueryService(FakeWMIService):
    """FakeWMIService that records every ExecQuery string it is asked to run
    (behavior unchanged: the super class serves the rows)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.queries: list[str] = []

    def ExecQuery(self, wql: str) -> list:
        self.queries.append(wql)
        return super().ExecQuery(wql)


def _scoped_mouse_queries(queries: list[str]) -> list[str]:
    """Queries that enumerate Msvm_SyntheticMouse scoped to THIS VM through a
    SystemName WQL filter carrying the VM's GUID (the live-validated shape:
    SELECT * FROM Msvm_SyntheticMouse WHERE SystemName='<guid>')."""
    return [
        q for q in queries
        if "msvm_syntheticmouse" in q.lower()
        and re.search(r"systemname\s*=\s*'" + re.escape(GUID) + r"'", q, re.I)
    ]


def _associator_queries(queries: list[str]) -> list[str]:
    return [q for q in queries if "ASSOCIATORS" in q.upper()]


def test_mouse_path_is_system_name_scoped(monkeypatch, unrestricted_cfg):
    """AC7: cold mouse-path resolution issues exactly ONE SystemName-scoped
    Msvm_SyntheticMouse query (WHERE SystemName='<guid>') and ZERO per-device
    association queries. RED at base (unscoped enumeration + one ASSOCIATORS
    walk per device), GREEN after the scoped-query fix."""
    svc = RecordingQueryService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    _ps(monkeypatch)  # any PowerShell fallback would betray itself below
    be = wmiconsole.backend(unrestricted_cfg)

    # Cold resolution through the public mouse-op seam (no cached mouse path:
    # fresh service, fresh backend).
    be.mouse_move(GUID, 5, 5)

    scoped = _scoped_mouse_queries(svc.queries)
    assoc = _associator_queries(svc.queries)
    assert len(scoped) == 1, (
        "AC7: mouse resolution must issue exactly ONE SystemName-scoped "
        f"Msvm_SyntheticMouse query; got {len(scoped)} in {svc.queries!r}"
    )
    assert assoc == [], (
        "AC7: mouse resolution must not run any per-device ASSOCIATORS walk; "
        f"got {assoc!r}"
    )


def test_failed_mouse_probe_surfaces_not_laundered(monkeypatch, unrestricted_cfg):
    """AC8: a FAILED mouse probe (transport failure on the mouse-discovery
    channel) raises through display_info as a ConsoleError — never a silent
    absent/mouse_present=False. The fake's enumerate succeeds serving one
    device and its ExecQuery fails with OSError exactly on the two discovery
    channels the code can use: the owner ASSOCIATORS walk (the current code
    path — launders to absent at base, so this is RED) and the SystemName-
    scoped query (the fixed code path — the failure must surface, GREEN)."""

    class ProbeFailureService(FakeWMIService):
        def ExecQuery(self, wql: str) -> list:
            text = " ".join(wql.split())
            if "ASSOCIATORS OF" in text.upper():
                found = re.search(r'ResultClass\s*=\s*"?(\w+)"?', text)
                if found and found.group(1) == "Msvm_ComputerSystem":
                    # the per-device owner walk (current code): transport down
                    raise OSError("rpc unavailable")
            if "Msvm_SyntheticMouse" in text and re.search(r"systemname", text, re.I):
                # the scoped query (fixed code): transport down there too
                raise OSError("rpc unavailable")
            return super().ExecQuery(wql)

    svc = ProbeFailureService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    # CUB-scope-114: match the probe's own failure text so the ConsoleError
    # is proven to come from the mouse channel, not some other error path.
    with pytest.raises(ConsoleError, match="rpc unavailable"):
        console.get_display_info(unrestricted_cfg, "vm1")
    assert stub.scripts == [], "a failed probe must not fall back to PowerShell"


def test_display_info_absent_devices_stay_present_false(monkeypatch, unrestricted_cfg):
    """AC8 preserve-leg: a VM whose keyboard/mouse lookups come back EMPTY
    reports present=False for both devices (absence is data, not an error) —
    the same absent-vs-failed contract test_wmiconsole_extra's
    absent-vs-failed pin holds, mirrored locally against this file's fakes so
    the scoped-query fix cannot quietly flip absence into an error.
    GREEN at base, GREEN after the fix."""

    class NoDevicesService(FakeWMIService):
        def ExecQuery(self, wql: str) -> list:
            text = " ".join(wql.split()).upper()
            if "MSVM_KEYBOARD" in text or "MSVM_SYNTHETICMOUSE" in text:
                return []
            return super().ExecQuery(wql)

    svc = NoDevicesService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["keyboard_present"] is False
    assert out["mouse_present"] is False
    assert stub.scripts == []


def test_display_info_reports_ps2_mouse_on_wmi_transport(monkeypatch, unrestricted_cfg):
    """PRR-101 fix pin: a VM with NO synthetic mouse but a PS/2 mouse reports
    mouse_ps2_present=True on the WMI transport too. Pre-fix the field was a
    constant False here (wmiconsole.display_info never probed Msvm_Ps2Mouse)
    while the PowerShell transport measured it — the diagnostic disagreed
    across transports. mouse_present stays the synthetic-only answer the
    input ops act on (issue #83 Design b); the probe must be the scoped
    SystemName query, mirroring _mouse_path."""

    class Ps2OnlyService(FakeWMIService):
        """No synthetic mouse (its query serves nothing), one PS/2 mouse;
        every query is recorded so the scoping assertion below sees the
        probe the transport actually issued."""

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.queries: list[str] = []

        def ExecQuery(self, wql: str) -> list:
            self.queries.append(wql)
            text = " ".join(wql.split())
            if "Msvm_Ps2Mouse" in text:
                return [SimpleNamespace(Name=GUID + "-ps2")]
            if "Msvm_SyntheticMouse" in text:
                return []
            return super().ExecQuery(wql)

    svc = Ps2OnlyService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    out = console.get_display_info(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["mouse_present"] is False, (
        "PRR-101: mouse_present is the synthetic-only answer and must stay "
        "false on a PS/2-only VM"
    )
    assert out["mouse_ps2_present"] is True, (
        "PRR-101: the WMI transport must probe Msvm_Ps2Mouse — a PS/2-only "
        "VM cannot read as 'no mouse at all' on the default in-process path"
    )
    ps2_queries = [
        q for q in svc.queries
        if "msvm_ps2mouse" in q.lower()
        and re.search(r"systemname\s*=\s*'" + re.escape(GUID) + r"'", q, re.I)
    ]
    assert ps2_queries, (
        "PRR-101: the PS/2 probe must be a SystemName-scoped Msvm_Ps2Mouse "
        f"query (queries seen: {svc.queries!r})"
    )
    assert stub.scripts == []


def test_failed_ps2_probe_surfaces_not_laundered(monkeypatch, unrestricted_cfg):
    """PRR-101 failure leg, mirroring the AC8 launder shape: the synthetic
    mouse discovery SUCCEEDS via super() and ONLY the Msvm_Ps2Mouse query
    raises — so the ConsoleError can only come from the PS/2 probe (a probe
    failure laundered to absent would report mouse_ps2_present=False
    instead of raising)."""

    class FailedPs2ProbeService(FakeWMIService):
        def ExecQuery(self, wql: str) -> list:
            text = " ".join(wql.split()).upper()
            if "MSVM_PS2MOUSE" in text:
                raise OSError("rpc unavailable")  # probe failure, NOT empty
            return super().ExecQuery(wql)

    svc = FailedPs2ProbeService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    with pytest.raises(ConsoleError, match="rpc unavailable"):
        console.get_display_info(unrestricted_cfg, "vm1")
    assert stub.scripts == [], "a failed PS/2 probe must not fall back to PowerShell"


class _BrokenEnumeration:
    """Stand-in for a live SWbemObjectSet whose enumeration fails mid-call
    (CUB2-1: a REAL result set is enumerated lazily, so a COM/RPC failure
    lands at iteration time, not at query time). Iterable-shaped — so the
    laundering _rows helper reaches its list(result) arm — but iterating
    raises like a live com_error would."""

    def __iter__(self):
        raise OSError("rpc unavailable during enumeration")


def test_failed_ps2_enumeration_never_answers_present(monkeypatch, unrestricted_cfg):
    """CUB2-1 fail-open pin, mirroring the PRR-101 launder shapes above: the
    Msvm_Ps2Mouse ExecQuery SUCCEEDS and only the returned row set FAILS to
    enumerate. _rows' except-Exception arm converted that failure into a
    truthy [result] row, so bool(rows) answered mouse_ps2_present=True — a
    failed probe reporting the mouse PRESENT. The probe must instead surface
    the failure as a ConsoleError; the mouse_ps2_present path may never
    answer True on a failed probe (the PS/2-present and PS/2-absent legs
    elsewhere in this file pin the genuine answers)."""

    class BrokenEnumerationPs2Service(FakeWMIService):
        def ExecQuery(self, wql: str) -> list:
            text = " ".join(wql.split()).upper()
            if "MSVM_PS2MOUSE" in text:
                return _BrokenEnumeration()  # query ok, enumeration fails
            return super().ExecQuery(wql)

    svc = BrokenEnumerationPs2Service(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    with pytest.raises(
        ConsoleError, match="rpc unavailable during enumeration"
    ):
        console.get_display_info(unrestricted_cfg, "vm1")
    assert stub.scripts == [], "a failed PS/2 probe must not fall back to PowerShell"
