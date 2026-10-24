"""Frozen acceptance checks for issue #45 (Phase 2.5): the optional
in-process WMI/COM console backend (src/hyperv_mcp/wmiconsole.py) with
per-VM GUID caching and automatic PowerShell fallback, the consolebench
engine, and the console.py integration selecting between them.

Token -> AC map (each -k token selects exactly one test):
  c1_ps_timings         AC1: PowerShell-path ops carry timings with
                             transport "powershell" and one spawn_ms float
                             per run_ps call (vmident.resolve included).
  c2_wmi_timings        AC2: WMI-path results/meta carry timings with
                             transport "wmi" and connect_ms/rebind_ms/
                             method_ms floats.
  c3_bench_selftest     AC3: consolebench exact nearest-rank percentiles,
                             bench()/render_comparison()/run_soak() shapes.
  c5_cache_invalidation AC5: EnabledState change re-resolves device paths
                             and never reuses a stale head; head change
                             refreshes; invalidate()/invalidate_all() drop.
  c6_fallback           AC6: COM off -> PowerShell; WMI method failure ->
                             ConsoleError with ZERO PowerShell retries;
                             BackendUnavailable -> PowerShell fallback.
  c8_zero_spawns        AC8: WMI path serves screenshot/click/type_text
                             with ZERO run_ps calls (identity resolved
                             in-process) and the per-VM lock still held.
  c9_remote_dcom        AC9: remote cfg reaches connect_service (host +
                             credentials derivation recorded); DCOM failure
                             -> BackendUnavailable -> WS-Man fallback.

Pinned contract the implementation MUST match:
  * ConsoleWMI public methods return (result, timings) TUPLES.
  * consolebench.pct is nearest-rank: rank = max(1, ceil(q * n)) over
    ascending-sorted values; pct(values, q) == sorted(values)[rank - 1].
    bench(fn, n, **kw) -> dict with n plus p50_ms/p95_ms/mean_ms;
    render_comparison(before_rows, after_rows) takes lists of dicts with a
    "label" key and returns a str containing both labels; run_soak(op_fns,
    agents, n) runs agents workers each executing the ops n times and
    returns a LIST of one dict per agent with p50_ms and p95_ms.
  * FakeWMIService pins the SWbem surface the backend uses: ExecQuery(WQL)
    for SELECT ... and ASSOCIATORS OF {...} WHERE ResultClass = X, Get(path)
    rebinds, Path_.Path strings, Methods_(name).InParameters.SpawnInstance_()
    parameters set via Properties_(name).Value or attribute assignment, and
    ExecMethod_(name, in_params) results exposing ReturnValue/ImageData.
  * console.py reaches the backend only through the wmiconsole module
    attributes (COM_AVAILABLE, backend, connect_service); backend(cfg)
    never imports pywin32 - COM flows only through connect_service.
  * ConsoleWMI.invalidate_all() also clears the module's live service
    binding so the next backend(cfg) reconsults connect_service (the test
    isolation hook); a WMI method failure (WMIError) surfaces as
    ConsoleError keeping the ReturnValue detail, never retried via PS.

CI has no pywin32 and the base tree has neither new module: wmiconsole and
consolebench are imported ONLY inside test functions so this file collects
(and c1 fails on the missing timings key) before the feature exists.
"""

import base64
import contextlib
import json
import re
import sys
import threading
from types import SimpleNamespace

import pytest

from hyperv_mcp import console, pswindows, vmlocks
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"

class PSStub:
    """Adaptive run_ps stub (test_console.py FakePS style), remote-safe:
    responses key off substrings surviving the WS-Man composition."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        self.scripts.append(script)
        # The bare $vmTarget EMIT (not resolver presence): issue #18's folded
        # scripts also mention $vmTarget and must not be served the GUID.
        if script.rstrip().endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "GetVirtualSystemThumbnailImage" in script:
            width = re.search(r"WidthPixels\s*=\s*(\d+)", script)
            height = re.search(r"HeightPixels\s*=\s*(\d+)", script)
            w = int(width.group(1)) if width else 640
            h = int(height.group(1)) if height else 480
            if "$sizes" in script:
                seed = re.search(r"\$sizes = @\([,(@]*(\d+),(\d+)\)", script)
                if seed:
                    w, h = int(seed.group(1)), int(seed.group(2))
            payload = b"\x00\x00\x00\x00" + b"\x5a\xa5" * (w * h)
            encoded = base64.b64encode(payload).decode("ascii")
            body = json.dumps({"returnValue": 0, "imageDataB64": encoded})
            if "$sizes" in script:
                # folded capture (issue #18): metadata ahead of the payload
                return pswindows.PSResult(
                    stdout="VMID=" + GUID + "\n" + "HEAD=320x240" + "\n"
                    + "SIZES=" + str(w) + "x" + str(h) + "\n"
                    + "USED=" + str(w) + "x" + str(h) + "\n" + body,
                    returncode=0,
                )
            return pswindows.PSResult(stdout=body, returncode=0)
        if "SetAbsolutePosition" in script:
            # folded positional mouse (issue #18): the script computes the
            # head-space position itself; the stub mirrors it with the same
            # 320x240 head the other branches advertise.
            x = y = fw = fh = 0
            for line in script.splitlines():
                ls = line.strip()
                for name in ("$x", "$y", "$fw", "$fh"):
                    if ls.startswith(name + " ="):
                        raw = ls.split("=", 1)[1].strip()
                        if raw.lstrip("-").isdigit():
                            val = int(raw)
                            if name == "$x":
                                x = val
                            elif name == "$y":
                                y = val
                            elif name == "$fw":
                                fw = val
                            else:
                                fh = val
            # (0,0) is a real coordinate (issue #25): a positional script
            # always reports its computed head position, never 'no position'.
            if fw or fh:
                hx = round(x * 320 / fw) if fw else x
                hy = round(y * 240 / fh) if fh else y
            else:
                hx, hy = x, y
            hx = max(0, min(hx, 319))
            hy = max(0, min(hy, 239))
            return pswindows.PSResult(
                stdout="HEADX=" + str(hx) + "\n" + "HEADY=" + str(hy)
                + "\n" + "RC=0",
                returncode=0,
            )
        if "Msvm_VideoHead" in script:
            return pswindows.PSResult(
                stdout='{"horizontal": 320, "vertical": 240}', returncode=0)
        if "Invoke-CimMethod" in script:
            return pswindows.PSResult(stdout="RC=0 CHUNK=1/1", returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)

class _Property:
    def __init__(self, store: dict, name: str) -> None:
        self._store, self._name = store, name

    @property
    def Value(self):
        return self._store.get(self._name)

    @Value.setter
    def Value(self, value) -> None:
        self._store[self._name] = value

class _InParameters:
    """SpawnInstance_ product; records Properties_('X').Value = v and
    inparams.X = v alike."""

    def __init__(self) -> None:
        object.__setattr__(self, "values", {})
    def SpawnInstance_(self):
        return _InParameters()
    def Properties_(self, name: str) -> _Property:
        return _Property(self.values, name)
    def __setattr__(self, name: str, value) -> None:
        self.values[name] = value

class FakeWmiObject:
    def __init__(self, service, path: str, props: dict) -> None:
        self._service = service
        self._props = dict(props)
        self._props["Path_"] = SimpleNamespace(
            Path=path, RelPath=path, DisplayName=path)
    def Methods_(self, name: str):
        return SimpleNamespace(InParameters=_InParameters())
    def ExecMethod_(self, name: str, in_params):
        return self._service.exec_method(self, name, in_params)
    def Associators_(self, result_class: str):
        return self._service.ExecQuery("ASSOCIATORS OF {"
            + self._props["Path_"].Path + "} WHERE ResultClass = " + result_class)
    def __getattr__(self, name):
        try:
            return self.__dict__["_props"][name]
        except KeyError:
            raise AttributeError(name) from None

_COUNT_KEYS = {"Msvm_VirtualSystemManagementService": "management_service",
               "Msvm_SyntheticMouse": "mouse", "Msvm_Keyboard": "keyboard",
               "Msvm_VideoHead": "video_head"}

class FakeWMIService:
    """SWbemServices-shaped fake for root\\virtualization\\v2. Device resolutions are
    counted per class so cache invalidation is observable; every
    ExecMethod_ is recorded as (path, method, in-param values)."""

    def __init__(self, guid=GUID, name="vm1", state=2, head=(1024, 768)):
        self.counts = {"computer_system": 0, "management_service": 0,
                       "keyboard": 0, "mouse": 0, "video_head": 0}
        self.methods: list = []
        self.captures: list = []
        self.method_rc = 0
        self._vm = FakeWmiObject(self, 'Msvm_ComputerSystem.Name="' + guid + '"',
                                 {"Name": guid, "ElementName": name,
                                  "EnabledState": state})
        self._head = FakeWmiObject(self, 'Msvm_VideoHead.Name="' + guid + '-head"',
                                   {"CurrentHorizontalResolution": head[0],
                                    "CurrentVerticalResolution": head[1]})
        self._keyboard = FakeWmiObject(self, 'Msvm_Keyboard.Name="' + guid + '-kb"', {})
        self._mouse = FakeWmiObject(self, 'Msvm_SyntheticMouse.Name="' + guid + '-mouse"', {})
        self._mgmt = FakeWmiObject(self,
            'Msvm_VirtualSystemManagementService.CreationClassName="svc"', {})
        self._by_path = {o._props["Path_"].Path: o for o in
                         (self._vm, self._head, self._keyboard,
                          self._mouse, self._mgmt)}
    def set_vm_state(self, state: int) -> None:
        self._vm._props["EnabledState"] = state
    def set_head(self, horizontal: int, vertical: int) -> None:
        self._head._props["CurrentHorizontalResolution"] = horizontal
        self._head._props["CurrentVerticalResolution"] = vertical
    def ExecQuery(self, wql: str) -> list:
        text = " ".join(wql.split())
        if "ASSOCIATORS OF" in text.upper():
            found = re.search(r'ResultClass\s*=\s*"?(\w+)"?', text)
            result_class = found.group(1) if found else ""
            if result_class == "Msvm_ComputerSystem":
                return [self._vm]  # device-owner association
            return self._by_class(result_class)
        if "Msvm_ComputerSystem" in text:
            self.counts["computer_system"] += 1
            return [self._vm]  # identity / state read
        for cls in _COUNT_KEYS:
            if cls in text:
                return self._by_class(cls)
        return []
    def Get(self, path: str) -> FakeWmiObject:
        return self._by_path[path]
    def exec_method(self, obj, name: str, in_params):
        self.methods.append((obj._props["Path_"].Path, name, dict(in_params.values)))
        if name == "GetVirtualSystemThumbnailImage":
            width = int(in_params.values["WidthPixels"])
            height = int(in_params.values["HeightPixels"])
            self.captures.append((width, height))
            payload = b"\x00\x00\x00\x00" + b"\x5a\xa5" * (width * height)
            return SimpleNamespace(ReturnValue=self.method_rc, ImageData=payload)
        return SimpleNamespace(ReturnValue=self.method_rc)
    def _by_class(self, cls: str) -> list:
        key = _COUNT_KEYS.get(cls)
        if key is None:
            return []
        self.counts[key] += 1
        return {"management_service": self._mgmt, "mouse": self._mouse,
                "keyboard": self._keyboard, "video_head": self._head}[key]

def _ps(monkeypatch) -> PSStub:
    """Install a recording run_ps stub and return it."""
    stub = PSStub()
    monkeypatch.setattr(pswindows, "run_ps", stub)
    return stub

def _maybe_force_powershell(monkeypatch) -> None:
    """Base-tree safe; post-implementation forces the PowerShell path so AC1
    is deterministic even where pywin32 happens to be installed."""
    module = sys.modules.get("hyperv_mcp.wmiconsole")
    if module is not None:
        monkeypatch.setattr(module, "COM_AVAILABLE", False, raising=False)

def _drop_backend(wmiconsole, cfg) -> None:
    """Isolation hook: invalidate_all() clears the module-level live service
    binding, so backend(cfg) reconsults connect_service."""
    try:
        wmiconsole.backend(cfg).invalidate_all()
    except wmiconsole.BackendUnavailable:
        pass

def _install_wmi(monkeypatch, cfg, connect):
    """connect_service -> `connect`, COM_AVAILABLE True, any earlier test's
    service binding dropped; no pywin32, no real COM."""
    from hyperv_mcp import wmiconsole
    monkeypatch.setattr(wmiconsole, "connect_service", connect)
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
    _drop_backend(wmiconsole, cfg)
    return wmiconsole

def _assert_ps_timings(timings, stub) -> None:
    """Transport timings carry one float per run_ps call the op made."""
    spawns = timings["spawn_ms"]
    assert isinstance(spawns, list) and bool(spawns)
    assert all(isinstance(v, float) for v in spawns)
    assert len(spawns) == len(stub.scripts)

def test_c1_ps_timings(monkeypatch, unrestricted_cfg):
    """AC1: PowerShell-path ops report timings: transport "powershell", one
    spawn_ms float per run_ps call (vmident.resolve included)."""
    _maybe_force_powershell(monkeypatch)
    stub = _ps(monkeypatch)
    _img, meta = console.screenshot(unrestricted_cfg, "vm1", width=320, height=240)
    assert meta["timings"]["transport"] == "powershell"
    _assert_ps_timings(meta["timings"], stub)

    stub = _ps(monkeypatch)
    out = console.type_text(unrestricted_cfg, "vm1", "ps timings")
    assert out["timings"]["transport"] == "powershell"
    _assert_ps_timings(out["timings"], stub)

    stub = _ps(monkeypatch)
    out = console.click(unrestricted_cfg, "vm1", 160, 120,
                        frame_width=320, frame_height=240)
    assert out["timings"]["transport"] == "powershell"
    _assert_ps_timings(out["timings"], stub)

def test_c2_wmi_timings(monkeypatch, unrestricted_cfg):
    """AC2: WMI-served ops carry timings: transport "wmi" plus
    connect_ms/rebind_ms/method_ms floats (connect_ms may be 0.0 cached)."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    def check(timings):
        assert timings["transport"] == "wmi"
        for key in ("connect_ms", "rebind_ms", "method_ms"):
            assert isinstance(timings[key], float), key

    _img, meta = console.screenshot(unrestricted_cfg, "vm1", width=320, height=240)
    check(meta["timings"])
    out = console.type_text(unrestricted_cfg, "vm1", "wmi timings")
    check(out["timings"])
    out = console.click(unrestricted_cfg, "vm1", 160, 120,
                        frame_width=320, frame_height=240)
    check(out["timings"])
    assert stub.scripts == []

def test_c3_bench_selftest():
    """AC3: consolebench nearest-rank pct (rank = max(1, ceil(q*n)) over
    ascending-sorted values) and bench()/render_comparison()/run_soak()."""
    from hyperv_mcp import consolebench

    assert consolebench.pct([10, 20, 30, 40], 0.5) == 20   # rank 2
    assert consolebench.pct([10, 20, 30, 40], 0.75) == 30  # rank 3
    assert consolebench.pct([10, 20, 30, 40], 0.0) == 10   # rank clamped to 1
    assert consolebench.pct([3, 1, 2], 0.5) == 2           # sorted internally

    calls: list[str] = []

    def op(tag):
        calls.append(tag)

    stats = consolebench.bench(op, 4, tag="synthetic")
    assert stats["n"] == 4
    assert calls == ["synthetic"] * 4
    for key in ("p50_ms", "p95_ms", "mean_ms"):
        assert isinstance(stats[key], (int, float)), key

    table = consolebench.render_comparison(
        [{"label": "before-screenshot", "p50_ms": 1200.0}],
        [{"label": "after-screenshot", "p50_ms": 40.0}],
    )
    assert isinstance(table, str)
    assert "before-screenshot" in table and "after-screenshot" in table

    lock = threading.Lock()
    counter = {"runs": 0}

    def soak_op():
        with lock:
            counter["runs"] += 1

    per_agent = consolebench.run_soak([soak_op], agents=3, n=2)
    assert counter["runs"] == 6  # 3 agents x n=2 x the one op
    assert len(per_agent) == 3
    for entry in per_agent:
        assert "p50_ms" in entry and "p95_ms" in entry
    assert callable(consolebench.main)

def test_c5_cache_invalidation(monkeypatch, unrestricted_cfg):
    """AC5: EnabledState change re-resolves cached device paths and never
    reuses a stale head; head change refreshes; invalidate() and
    invalidate_all() drop the cache."""
    svc = FakeWMIService(head=(1024, 768))
    wmiconsole = _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    backend = wmiconsole.backend(unrestricted_cfg)
    assert isinstance(backend, wmiconsole.ConsoleWMI)

    state, timings = backend.vm_state(GUID)
    assert state == 2 and isinstance(timings, dict)
    assert backend.head_resolution(GUID)[0] == (1024, 768)
    backend.type_text(GUID, "warm")
    backend.mouse_click(GUID, 1, 10, 10)
    keyboard_q, mouse_q = svc.counts["keyboard"], svc.counts["mouse"]
    # Cache hit: repeated ops resolve nothing new.
    backend.type_text(GUID, "again")
    backend.mouse_click(GUID, 1, 11, 11)
    assert svc.counts["keyboard"] == keyboard_q
    assert svc.counts["mouse"] == mouse_q
    # Head-resolution change refreshes the cached head.
    svc.set_head(800, 600)
    assert backend.head_resolution(GUID)[0] == (800, 600)
    # EnabledState change drops the cached device paths + head resolution.
    svc.set_vm_state(3)
    assert backend.vm_state(GUID)[0] == 3
    backend.type_text(GUID, "post-flip")
    backend.mouse_click(GUID, 1, 12, 12)
    assert svc.counts["keyboard"] > keyboard_q
    assert svc.counts["mouse"] > mouse_q
    svc.set_head(640, 480)
    assert backend.head_resolution(GUID)[0] == (640, 480)  # stale never reused
    # invalidate(guid) drops the cache for that VM.
    backend.type_text(GUID, "rewarm")
    keyboard_q = svc.counts["keyboard"]
    backend.invalidate(GUID)
    backend.type_text(GUID, "after-invalidate")
    assert svc.counts["keyboard"] > keyboard_q
    # invalidate_all() drops every cached entry.
    backend.type_text(GUID, "rewarm-all")
    keyboard_q = svc.counts["keyboard"]
    backend.invalidate_all()
    backend.type_text(GUID, "after-invalidate-all")
    assert svc.counts["keyboard"] > keyboard_q

    payload, _t = backend.capture(GUID, 320, 240)
    assert isinstance(payload, (bytes, bytearray))
    assert len(payload) == 4 + 320 * 240 * 2  # 4-byte prefix + RGB565

def test_c6_fallback(monkeypatch, unrestricted_cfg):
    """AC6: COM off uses PowerShell; a WMI method failure reaches the caller
    as ConsoleError with zero PowerShell retries (type_text must never
    double-send); BackendUnavailable falls back."""
    from hyperv_mcp import wmiconsole

    assert issubclass(wmiconsole.WMIError, RuntimeError)
    assert issubclass(wmiconsole.BackendUnavailable, RuntimeError)

    # (i) COM_AVAILABLE False -> the existing PowerShell path.
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    stub = _ps(monkeypatch)
    out = console.type_text(unrestricted_cfg, "vm1", "com off")
    assert out["ok"] and len(stub.scripts) >= 1
    assert out["timings"]["transport"] == "powershell"

    # (ii) WMI method failure (ReturnValue != 0) -> structured error, no
    # retry via PowerShell.
    svc = FakeWMIService(head=(320, 240))
    svc.method_rc = 5
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)
    with pytest.raises(ConsoleError, match="ReturnValue=5"):
        console.type_text(unrestricted_cfg, "vm1", "never doubled")
    assert stub.scripts == []

    # (iii) BackendUnavailable on connect -> PowerShell fallback.
    def refused(cfg):
        raise wmiconsole.BackendUnavailable("dcom connect failed")

    _install_wmi(monkeypatch, unrestricted_cfg, refused)
    stub = _ps(monkeypatch)
    img, meta = console.screenshot(unrestricted_cfg, "vm1", width=320, height=240)
    assert img.size == (320, 240) and len(stub.scripts) >= 1
    assert meta["timings"]["transport"] == "powershell"

def test_c8_zero_spawns(monkeypatch, unrestricted_cfg):
    """AC8: the WMI path serves screenshot (valid 4-byte prefix + w*h*2
    RGB565 payload), click and type_text with ZERO run_ps calls (identity
    resolved in-process) and the per-VM lock still held."""
    svc = FakeWMIService(head=(320, 240))
    _install_wmi(monkeypatch, unrestricted_cfg, lambda cfg: svc)
    stub = _ps(monkeypatch)

    locked: list[str] = []
    real_lock = vmlocks.vm_lock

    @contextlib.contextmanager
    def recording_lock(key, *args, **kwargs):
        # Issue #14: vm_lock gained mode=/wait_s=; record and pass through.
        locked.append(key)
        with real_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(vmlocks, "vm_lock", recording_lock)

    img, meta = console.screenshot(unrestricted_cfg, "vm1", width=320, height=240)
    assert img.size == (320, 240)
    raw = b"\x00\x00\x00\x00" + b"\x5a\xa5" * (320 * 240)
    assert meta["frame_hash"] == console._frame_hash(raw)
    assert meta["prefix_hex"] == raw[:4].hex()

    out = console.click(unrestricted_cfg, "vm1", 160, 120,
                        frame_width=320, frame_height=240)
    assert out["ok"] is True and out["head_x"] == 160 and out["head_y"] == 120
    assert console.type_text(unrestricted_cfg, "vm1", "hello console")["ok"] is True

    assert stub.scripts == []
    # Feedback PRR-020: _input_lock also records the (guid, "console")
    # tuple — normalize before comparing instead of relying on any()
    # short-circuiting past it.
    assert any(
        (k[0] if isinstance(k, tuple) else k).casefold() == GUID for k in locked
    )
    # the typed text and the move+click actually reached the WMI methods
    typed = [m for m in svc.methods if m[1] == "TypeText"]
    assert typed and typed[-1][2].get("AsciiText") == "hello console"
    names = [m[1] for m in svc.methods]
    assert "SetAbsolutePosition" in names and "ClickButton" in names
    assert svc.captures and svc.captures[0] == (320, 240)
    caps = [m for m in svc.methods if m[1] == "GetVirtualSystemThumbnailImage"]
    assert caps and all("TargetSystem" in m[2] for m in caps)

def test_c9_remote_dcom(monkeypatch):
    """AC9: a remote-host cfg reaches connect_service unchanged (the fake
    derives the DCOM target from pswindows.hyperv_host and consults
    credentials.resolve_host); a DCOM connect failure raises
    BackendUnavailable and console falls back to the WS-Man hop."""
    from hyperv_mcp import credentials, wmiconsole

    cfg = Config.from_dict({"hyperv": {"host": "nuc01"}, "unrestricted": True})
    cred = credentials.CredentialSet("hostuser", "hostpass-xyz")
    resolved: list = []

    def fake_resolve_host(environ=None):
        resolved.append(environ)
        return cred

    monkeypatch.setattr(credentials, "resolve_host", fake_resolve_host)

    svc = FakeWMIService(head=(320, 240))
    seen = {}

    def fake_connect(received_cfg):
        seen["cfg"] = received_cfg
        seen["host"] = pswindows.hyperv_host(received_cfg)
        seen["cred"] = credentials.resolve_host()
        return svc

    _install_wmi(monkeypatch, cfg, fake_connect)
    stub = _ps(monkeypatch)

    _img, meta = console.screenshot(cfg, "vm1", width=320, height=240)
    assert stub.scripts == []
    assert seen["cfg"] is cfg and seen["host"] == "nuc01"
    assert seen["cred"] is cred and resolved
    assert meta["timings"]["transport"] == "wmi"

    def refused(received_cfg):
        raise wmiconsole.BackendUnavailable("dcom connect failed")

    monkeypatch.setattr(wmiconsole, "connect_service", refused)
    _drop_backend(wmiconsole, cfg)
    stub = _ps(monkeypatch)
    img, meta = console.screenshot(cfg, "vm1", width=320, height=240)
    assert img.size == (320, 240)
    assert stub.scripts
    assert any("Invoke-Command" in s and "nuc01" in s for s in stub.scripts)
    assert meta["timings"]["transport"] == "powershell"


def test_click_at_origin_ps_positions_pointer(monkeypatch, unrestricted_cfg):
    """Issue #25 origin protocol: a positional click at (0,0) reports the
    computed head origin (HEADX=0/HEADY=0) instead of silently skipping
    positioning — the stub emits the computed position for every genuine
    positional script, value-independent."""
    _maybe_force_powershell(monkeypatch)
    stub = _ps(monkeypatch)
    out = console.click(unrestricted_cfg, "vm1", 0, 0,
                        frame_width=640, frame_height=480)
    assert out["head_x"] == 0 and out["head_y"] == 0
    assert "SetAbsolutePosition" in stub.scripts[-1]
