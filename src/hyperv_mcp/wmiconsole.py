"""In-process Hyper-V WMI console backend (issue #45, option 1).

Serves console capture/input operations directly against
``root\\virtualization\\v2`` over COM (pywin32) with NO powershell.exe spawn
per call, caching per-VM object PATHS and re-binding objects per operation.
Empirical facts baked into this module (live-host probes, issue #45 trace
02-reproduction.md):

  - Direct dynamic-dispatch method calls (``obj.TypeText(...)``) fail with
    SWbemObjectEx "Invalid method Parameter(s)"; every method invocation
    must go through ``Methods_(name).InParameters.SpawnInstance_()`` +
    ``ExecMethod_``, with object-typed parameters (``TargetSystem``) taking
    the object PATH string.
  - ``SWbemObject.Associators_`` rejects keyword arguments under dynamic
    dispatch; WQL ``ASSOCIATORS OF {path} WHERE ResultClass = X`` is the
    working equivalent of the production Get-CimAssociatedInstance legs.
  - One-time COM connect is 0-16 ms and a cached-path re-bind is ~0 ms, so
    the cold powershell.exe start (375-469 ms each) is the entire point of
    this backend.

pywin32 is OPTIONAL: the import guard keeps this module importable (and the
server fully functional on the PowerShell transport) wherever it is absent
— CI installs no pywin32. Selection happens in ``console.py``: this backend
first when ``COM_AVAILABLE`` and connectable, the existing ``run_ps`` path
otherwise. A WMI METHOD failure (``WMIError``) is a structured error and is
never retried through PowerShell (input must never double-send); only
connect-level unavailability (``BackendUnavailable`` — including "the WMI
plane cannot resolve this VM") falls back.

This module never spawns a process and never references ``run_ps`` (the
spawn-discipline census): the only spawn owner remains pswindows.
"""

from __future__ import annotations

import contextlib
import threading
import time
from typing import Any

from . import credentials, guestexec, policy, pswindows, vmident
from .config import Config

_WMI_NS = "root\\virtualization\\v2"
_PREFIX_LEN = 4
_MAX_NAME_LEN = 260

try:  # optional dependency: hyperv-mcp[wmi]
    import pythoncom  # type: ignore[import-untyped]
    import win32com.client  # type: ignore[import-untyped]

    _COM_IMPORT_OK = True
except Exception:  # pragma: no cover - exercised on CI (no pywin32)
    pythoncom = None  # type: ignore[assignment]
    win32com = None  # type: ignore[assignment]
    _COM_IMPORT_OK = False

# Selection flag read by console.py at CALL time via the module attribute
# (tests patch it). Mirrors the real import result until patched.
COM_AVAILABLE = _COM_IMPORT_OK


class WMIError(RuntimeError):
    """Structured WMI method failure (non-zero ReturnValue, bad payload)."""


class BackendUnavailable(RuntimeError):
    """The in-process WMI backend cannot serve this call (connect failure,
    unusable namespace, or the target VM not present in the WMI plane).
    console.py falls back to the PowerShell transport on exactly this."""


# ---------------------------------------------------------------------------
# COM apartment handling
# ---------------------------------------------------------------------------

_mta_lock = threading.Lock()
_mta_anchored = False


def _anchor_mta() -> None:
    """Hold one process-lifetime MTA reference from the first successful
    connect so the cached SWbem service can never outlive the apartment
    between the per-operation brackets below."""
    global _mta_anchored
    if not _COM_IMPORT_OK:
        return
    with _mta_lock:
        if _mta_anchored:
            return
        try:
            pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
            _mta_anchored = True
            # deliberately never uninitialized: the anchor owns the MTA
        except Exception:
            pass


@contextlib.contextmanager
def _com_thread():
    """COM apartment bracket for one backend operation on the calling
    thread. The calling thread joins the process MTA ONCE and never
    uninitializes: repeated CoUninitialize cycles around cached SWbem
    objects segfault at release (live-host verified — the anchor-only
    probe pattern is the stable one), and FastMCP worker threads live as
    long as the process, so per-thread references are bounded. RPC_E_CHANGED_MODE
    (thread already STA) is swallowed and the call proceeds."""
    _ensure_thread_com()
    yield


_tls = threading.local()


def _ensure_thread_com() -> None:
    if not _COM_IMPORT_OK:
        return
    if getattr(_tls, "initialized", False):
        return
    try:
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        _tls.initialized = True
    except Exception:
        pass


# ---------------------------------------------------------------------------
# connection seam
# ---------------------------------------------------------------------------

def _locator() -> Any:
    """The real SWbemLocator factory. Tests patch this seam to drive the
    REAL connect_service credential flow without pywin32 (issue #45 round-2
    plan-critic blocker: the gate wraps the COM primitives, the seam CALL
    itself stays unconditional)."""
    return win32com.client.Dispatch("WbemScripting.SWbemLocator")


def connect_service(cfg: Config) -> Any:
    """Connect to the Hyper-V WMI namespace for the CALLER's config.

    Local mode: SWbemLocator.ConnectServer('.', root\\virtualization\\v2).
    Remote mode (cfg.hyperv.host, issue #43): DCOM ConnectServer to the
    configured host, with credentials resolved per call from HYPERV_HOST_*
    (module-attribute access — tests monkeypatch credentials.resolve_host);
    a complete pair rides username/password, otherwise implicit auth.

    Every COM step is gated on the REAL import result (_COM_IMPORT_OK), so
    the credential/locator logic still runs against a faked _locator on a
    pywin32-less box. Any failure raises BackendUnavailable (redacted).
    """
    host = pswindows.hyperv_host(cfg)
    cred = credentials.resolve_host() if host else None
    try:
        if _COM_IMPORT_OK:
            _anchor_mta()
        loc = _locator()
        if host:
            if cred is not None:
                return loc.ConnectServer(host, _WMI_NS, cred.username, cred.password)
            return loc.ConnectServer(host, _WMI_NS)
        return loc.ConnectServer(".", _WMI_NS)
    except BackendUnavailable:
        raise
    except Exception as exc:
        raise BackendUnavailable(
            pswindows.redact(f"WMI connect to {host or 'localhost'} failed: {exc}")
        ) from None


# ---------------------------------------------------------------------------
# WQL helpers
# ---------------------------------------------------------------------------

def _wql_quote(value: str) -> str:
    """Single-quoted WQL literal (SQL-style quote doubling — VM names are
    caller input and must never break out of the literal)."""
    return "'" + value.replace("'", "''") + "'"


def _rows(result: Any) -> list:
    """Normalize an ExecQuery result to a list. Real SWbemObjectSet is
    iterable; fakes may return a bare object or a list; None means empty."""
    if result is None:
        return []
    if isinstance(result, list):
        return result
    if isinstance(result, (str, bytes, dict)):
        return [result]
    if hasattr(result, "__iter__"):
        try:
            return list(result)
        except Exception:
            return [result]
    return [result]


def _path_of(obj: Any) -> str:
    return str(obj.Path_.Path)


def _exec_method(service: Any, obj_path: str, method: str, **params: Any) -> Any:
    """The ONLY method-invocation shape that works on this stack (probe
    fact): spawned in-parameters + ExecMethod_. In-parameters are set via
    plain attribute assignment (works on both real SWbem and the fakes)."""
    obj = service.Get(obj_path)
    definition = obj.Methods_(method)
    inp = definition.InParameters.SpawnInstance_()
    for name, value in params.items():
        setattr(inp, name, value)
    return obj.ExecMethod_(method, inp)


def _check_rv(out: Any, method: str) -> None:
    try:
        rv = int(out.ReturnValue)
    except (TypeError, ValueError):
        raise WMIError(f"{method} returned no parsable ReturnValue") from None
    if rv != 0:
        raise WMIError(f"{method} failed with ReturnValue={rv}")


# ---------------------------------------------------------------------------
# per-VM cache
# ---------------------------------------------------------------------------

class _VMCache:
    """Cached object PATHS plus the last-seen VM state. Paths are strings
    (apartment-safe); objects are re-bound per operation via Get()."""

    __slots__ = ("cs_path", "kb_path", "mouse_path", "head_path", "state")

    def __init__(self, cs_path: str, state: int) -> None:
        self.cs_path = cs_path
        self.kb_path: str | None = None
        self.mouse_path: str | None = None
        self.head_path: str | None = None
        self.state = state

    def drop_devices(self) -> None:
        self.kb_path = None
        self.mouse_path = None
        self.head_path = None


class ConsoleWMI:
    """Backend bound to one WMI service (one host). Thread-safe: the
    per-VM cache is lock-guarded and console input ops additionally hold
    the per-VM vm_lock at the console layer."""

    def __init__(self, service: Any) -> None:
        self._service = service
        self._lock = threading.Lock()
        self._vms: dict[str, _VMCache] = {}
        self._names: dict[str, str] = {}
        self._vsms_path: str | None = None

    # -- internals ----------------------------------------------------------

    def _query_one(self, wql: str, ambiguous_value_error: bool = False) -> Any | None:
        rows = _rows(self._service.ExecQuery(wql))
        if not rows:
            return None
        if len(rows) > 1:
            if ambiguous_value_error:
                # caller-input identity ambiguity — same class vmident uses
                raise ValueError(
                    f"WMI query returned {len(rows)} rows where one was expected"
                )
            raise WMIError(f"WMI query returned {len(rows)} rows where one was expected")
        return rows[0]

    def _ensure_entry(self, guid: str) -> _VMCache:
        guid = guid.lower()
        with self._lock:
            entry = self._vms.get(guid)
        if entry is not None:
            return entry
        obj = self._query_one(
            "SELECT * FROM Msvm_ComputerSystem WHERE Name = " + _wql_quote(guid)
        )
        if obj is None:
            raise BackendUnavailable(f"VM {guid} is not present in the WMI plane")
        entry = _VMCache(_path_of(obj), int(getattr(obj, "EnabledState", 0) or 0))
        with self._lock:
            self._vms.setdefault(guid, entry)
            return self._vms[guid]

    def _rebind_cs(self, guid: str) -> tuple[_VMCache, Any]:
        """Re-bind the CS object from the cached path and refresh the cached
        state; a state change drops ALL cached device paths together (issue
        contract: keyboard/mouse/head are re-resolved on state flips)."""
        entry = self._ensure_entry(guid)
        try:
            obj = self._service.Get(entry.cs_path)
            state = int(getattr(obj, "EnabledState", entry.state) or 0)
        except WMIError:
            raise
        except Exception:
            # stale path (VMMS rebuild): re-resolve identity once
            obj = self._query_one(
                "SELECT * FROM Msvm_ComputerSystem WHERE Name = " + _wql_quote(guid.lower())
            )
            if obj is None:
                raise BackendUnavailable(
                    f"VM {guid} is not present in the WMI plane"
                ) from None
            entry.cs_path = _path_of(obj)
            state = int(getattr(obj, "EnabledState", entry.state) or 0)
        if state != entry.state:
            entry.drop_devices()
            entry.state = state
        return entry, obj

    def _vsms(self) -> str:
        if self._vsms_path is None:
            obj = self._query_one("SELECT * FROM Msvm_VirtualSystemManagementService")
            if obj is None:
                raise BackendUnavailable(
                    "Msvm_VirtualSystemManagementService not present in the WMI plane"
                )
            self._vsms_path = _path_of(obj)
        return self._vsms_path

    def _keyboard_path(self, guid: str, entry: _VMCache) -> str:
        if entry.kb_path is not None:
            return entry.kb_path
        rows = _rows(self._service.ExecQuery(
            "ASSOCIATORS OF {" + entry.cs_path + "} WHERE ResultClass = Msvm_Keyboard"
        ))
        if not rows:
            raise WMIError("no keyboard device associated with the VM")
        entry.kb_path = _path_of(rows[0])
        return entry.kb_path

    def _mouse_path(self, guid: str, entry: _VMCache) -> str:
        if entry.mouse_path is not None:
            return entry.mouse_path
        for mouse in _rows(self._service.ExecQuery("SELECT * FROM Msvm_SyntheticMouse")):
            try:
                owners = _rows(self._service.ExecQuery(
                    "ASSOCIATORS OF {" + _path_of(mouse)
                    + "} WHERE ResultClass = Msvm_ComputerSystem"
                ))
            except WMIError:
                raise
            except Exception:
                continue
            for owner in owners:
                if str(getattr(owner, "Name", "")).lower() == guid.lower():
                    entry.mouse_path = _path_of(mouse)
                    return entry.mouse_path
        raise WMIError("no synthetic mouse device associated with the VM")

    def _head_object(self, guid: str, entry: _VMCache) -> Any | None:
        """Head object via cached path (re-read per call so resolution
        changes are picked up), re-resolved on path failure."""
        obj: Any | None = None
        if entry.head_path is not None:
            try:
                obj = self._service.Get(entry.head_path)
            except WMIError:
                raise
            except Exception:
                entry.head_path = None
                obj = None
        if obj is None:
            rows = _rows(self._service.ExecQuery(
                "ASSOCIATORS OF {" + entry.cs_path + "} WHERE ResultClass = Msvm_VideoHead"
            ))
            if rows:
                obj = rows[0]
                entry.head_path = _path_of(obj)
        return obj

    # -- public operations (all return (result, timings)) -------------------

    def vm_state(self, guid: str) -> tuple[int, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            return entry.state, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms, "method_ms": 0.0,
            }

    def head_resolution(self, guid: str) -> tuple[tuple[int, int] | None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            obj = self._head_object(guid, entry)
            method_ms = (time.monotonic() - t0) * 1000.0
            head: tuple[int, int] | None = None
            if obj is not None:
                h = getattr(obj, "CurrentHorizontalResolution", None)
                v = getattr(obj, "CurrentVerticalResolution", None)
                try:
                    hi, vi = int(h or 0), int(v or 0)
                except (TypeError, ValueError):
                    hi = vi = 0
                if hi > 0 and vi > 0:
                    head = (hi, vi)
            return head, {
                "connect_ms": 0.0,
                "rebind_ms": 0.0,
                "method_ms": method_ms,
            }

    def capture(self, guid: str, width: int, height: int) -> tuple[bytes, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            vsms = self._vsms()
            out = _exec_method(
                self._service, vsms, "GetVirtualSystemThumbnailImage",
                TargetSystem=entry.cs_path, WidthPixels=width, HeightPixels=height,
            )
            _check_rv(out, "GetVirtualSystemThumbnailImage")
            try:
                data = bytes(out.ImageData)
            except (TypeError, ValueError):
                raise WMIError("GetVirtualSystemThumbnailImage returned no image data") from None
            expected = width * height * 2 + _PREFIX_LEN
            if len(data) != expected:
                raise WMIError(
                    f"thumbnail payload length mismatch: got {len(data)}, expected {expected}"
                )
            method_ms = (time.monotonic() - t0) * 1000.0
            return data, {
                "connect_ms": 0.0, "rebind_ms": 0.0, "method_ms": method_ms,
            }

    def type_text(self, guid: str, text: str) -> tuple[None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            kb = self._keyboard_path(guid, entry)
            out = _exec_method(self._service, kb, "TypeText", AsciiText=text)
            _check_rv(out, "TypeText")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def type_scancodes(self, guid: str, codes: list[int]) -> tuple[None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            kb = self._keyboard_path(guid, entry)
            out = _exec_method(
                self._service, kb, "TypeScancodes", ScanCodes=list(codes)
            )
            _check_rv(out, "TypeScancodes")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_move(self, guid: str, hx: int, hy: int) -> tuple[None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetAbsolutePosition",
                HorizontalPosition=int(hx), VerticalPosition=int(hy),
            )
            _check_rv(out, "SetAbsolutePosition")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_click(
        self, guid: str, button: int, hx: int | None = None, hy: int | None = None
    ) -> tuple[None, dict]:
        """Move-then-click when hx/hy given; hx/hy None (both) means click at
        the CURRENT position (the preserved click(0,0) contract)."""
        if (hx is None) != (hy is None):
            raise ValueError("mouse_click requires both hx and hy, or neither")
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            if hx is not None and hy is not None:
                out = _exec_method(
                    self._service, mouse, "SetAbsolutePosition",
                    HorizontalPosition=int(hx), VerticalPosition=int(hy),
                )
                _check_rv(out, "SetAbsolutePosition")
            out = _exec_method(
                self._service, mouse, "ClickButton", ButtonIndex=int(button)
            )
            _check_rv(out, "ClickButton")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_button(self, guid: str, button: int, is_down: bool) -> tuple[None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetButtonState",
                ButtonIndex=int(button), IsDown=bool(is_down),
            )
            _check_rv(out, "SetButtonState")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_scroll(self, guid: str, delta: int) -> tuple[None, dict]:
        with _com_thread():
            entry, _obj = self._rebind_cs(guid)
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetScrollPosition",
                ScrollPositionDelta=int(delta),
            )
            _check_rv(out, "SetScrollPosition")
            return None, {
                "connect_ms": 0.0, "rebind_ms": 0.0,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def display_info(self, guid: str) -> tuple[dict, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, cs = self._rebind_cs(guid)
            head_obj = self._head_object(guid, entry)
            try:
                kb_obj = self._service.Get(self._keyboard_path(guid, entry))
            except WMIError:
                # no keyboard associated — reported as absent, matching the
                # PS display-info contract ([bool]$kb), not an error
                kb_obj = None
            except Exception:
                kb_obj = None
            try:
                mouse_obj = self._service.Get(self._mouse_path(guid, entry))
            except WMIError:
                mouse_obj = None
            except Exception:
                mouse_obj = None
            method_ms = (time.monotonic() - t0) * 1000.0

            def _res(obj: Any) -> tuple[int | None, int | None]:
                h = getattr(obj, "CurrentHorizontalResolution", None)
                v = getattr(obj, "CurrentVerticalResolution", None)
                try:
                    return int(h or 0), int(v or 0)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return None, None

            hh, hv = _res(head_obj) if head_obj is not None else (None, None)
            info = {
                "enabled_state": entry.state,
                "head_horizontal": hh,
                "head_vertical": hv,
                "keyboard_present": kb_obj is not None,
                "keyboard_enabled": getattr(kb_obj, "EnabledState", None) if kb_obj else None,
                "mouse_present": mouse_obj is not None,
                "mouse_enabled": getattr(mouse_obj, "EnabledState", None) if mouse_obj else None,
            }
            return info, {
                "connect_ms": 0.0, "rebind_ms": 0.0, "method_ms": method_ms,
            }

    # -- identity + cache management ----------------------------------------

    def resolve_vm(self, cfg: Config, vm_name: str = "", vm_id: str = "") -> vmident.VMRef:
        """In-process identity resolution (zero PowerShell). Mirrors
        vmident.resolve's policy ordering AND its caller-input error class
        (ValueError — surfaces as error_class "invalid", never "transport"):
        caller-supplied name is policy-checked BEFORE any lookup; a by-id
        lookup policy-checks the RESOLVED name; ambiguous/empty/mismatched
        identity raises ValueError exactly like vmident. A VM MISSING from
        the WMI plane is BackendUnavailable (the caller falls back to the
        PowerShell transport). Resolved name->GUID pairs are cached but
        REVALIDATED on every hit (cheap Get on the cached CS path) so a
        deleted/recreated or renamed VM self-heals within one call instead
        of serving a stale identity (implementation-review F2)."""
        guid = vm_id.strip() if vm_id else ""
        if guid:
            if vm_name:
                _checked_caller_name(vm_name)
                policy.vm_allowed(cfg, vm_name)
            guestexec.validate_vm_guid(guid)
            entry = self._cs_by_guid(guid)
            if entry is None:
                raise BackendUnavailable(f"VM id {guid} is not present in the WMI plane")
            name = entry.element_name
            if not name:
                raise ValueError(f"VM id {guid} resolved to an empty name")
            if vm_name and name.casefold() != vm_name.casefold():
                raise ValueError("vm_name and vm_id refer to different VMs")
            if not vm_name:
                policy.vm_allowed(cfg, name)
            return vmident.VMRef(id=guid.lower(), name=name)
        _checked_caller_name(vm_name)
        policy.vm_allowed(cfg, vm_name)
        key = vm_name.casefold()
        with self._lock:
            cached_guid = self._names.get(key)
        if cached_guid is not None:
            entry = self._cs_by_guid(cached_guid, drop_name_key=key)
            if entry is not None and entry.element_name.casefold() == key:
                return vmident.VMRef(id=cached_guid, name=vm_name)
            # stale mapping (rename, or delete+recreate under a new GUID):
            # fall through and re-resolve by the current name
        entry = self._cs_by_name(vm_name)
        if entry is None:
            raise BackendUnavailable(f"VM '{vm_name}' is not present in the WMI plane")
        guid_str = entry.guid.lower()
        guestexec.validate_vm_guid(guid_str)
        with self._lock:
            self._names[key] = guid_str
        return vmident.VMRef(id=guid_str, name=vm_name)

    def _cs_by_guid(self, guid: str, drop_name_key: str = "") -> _ResolvedCS | None:
        """GUID -> (guid, ElementName) via the cache first, then one query.
        A cache entry whose object path no longer resolves pops the entry
        (and, via drop_name_key, the name mapping that led here) before the
        re-query, so callers never see a sticky stale identity."""
        lower = guid.lower()
        with self._lock:
            entry = self._vms.get(lower)
        if entry is not None:
            try:
                obj = self._service.Get(entry.cs_path)
                return _ResolvedCS(lower, str(getattr(obj, "ElementName", "") or ""))
            except WMIError:
                raise
            except Exception:
                with self._lock:
                    self._vms.pop(lower, None)
                    if drop_name_key:
                        self._names.pop(drop_name_key, None)
        obj = self._query_one(
            "SELECT * FROM Msvm_ComputerSystem WHERE Name = " + _wql_quote(lower),
            ambiguous_value_error=True,
        )
        if obj is None:
            if drop_name_key:
                with self._lock:
                    self._names.pop(drop_name_key, None)
            return None
        self._seed_cache(lower, obj)
        return _ResolvedCS(lower, str(getattr(obj, "ElementName", "") or ""))

    def _cs_by_name(self, vm_name: str) -> _ResolvedCS | None:
        obj = self._query_one(
            "SELECT * FROM Msvm_ComputerSystem WHERE ElementName = " + _wql_quote(vm_name),
            ambiguous_value_error=True,
        )
        if obj is None:
            return None
        guid = str(getattr(obj, "Name", "") or "")
        self._seed_cache(guid.lower(), obj)
        return _ResolvedCS(guid, str(getattr(obj, "ElementName", "") or ""))

    def _seed_cache(self, guid: str, obj: Any) -> None:
        """Seed the per-VM cache WITHOUT wiping an existing entry's cached
        device paths (resolve_vm runs per operation; overwriting the entry
        would re-resolve the keyboard/mouse/head every call)."""
        guid = guid.lower()
        with self._lock:
            if guid not in self._vms:
                self._vms[guid] = _VMCache(
                    _path_of(obj), int(getattr(obj, "EnabledState", 0) or 0)
                )

    def invalidate(self, guid: str) -> None:
        guid = guid.lower()
        with self._lock:
            self._vms.pop(guid, None)
            self._names = {k: v for k, v in self._names.items() if v != guid}

    def invalidate_all(self) -> None:
        """Drop every cached entry AND the module-level backend binding so
        the next backend(cfg) reconsults connect_service (the test isolation
        hook). The calling instance stays functional for its current op."""
        with self._lock:
            self._vms.clear()
            self._names.clear()
        with _backend_lock:
            for key in [k for k, be in _backends.items() if be is self]:
                _backends.pop(key, None)


class _ResolvedCS:
    """Identity-resolution result: stable GUID plus the display name."""

    __slots__ = ("guid", "element_name")

    def __init__(self, guid: str, element_name: str) -> None:
        self.guid = guid
        self.element_name = element_name


def _checked_caller_name(vm_name: str) -> str:
    if not vm_name or not vm_name.strip():
        raise ValueError("vm_name or vm_id is required")
    if len(vm_name) > _MAX_NAME_LEN:
        raise ValueError(f"vm_name exceeds {_MAX_NAME_LEN} characters")
    return vm_name


# ---------------------------------------------------------------------------
# backend cache
# ---------------------------------------------------------------------------

_backends: dict[str, ConsoleWMI] = {}
_backend_lock = threading.Lock()


def _host_key(cfg: Config) -> str:
    return pswindows.hyperv_host(cfg) or "."


def backend(cfg: Config) -> ConsoleWMI:
    """Cached ConsoleWMI per host-key; raises BackendUnavailable when the
    service cannot be obtained. Never imports pywin32 itself."""
    key = _host_key(cfg)
    with _backend_lock:
        be = _backends.get(key)
        if be is not None:
            return be
    service = connect_service(cfg)
    be = ConsoleWMI(service)
    with _backend_lock:
        _backends.setdefault(key, be)
        return _backends[key]


def shutdown() -> None:
    """Drop every cached service/object reference so no COM object is
    released after the apartment is gone. Long-running servers never need
    this (caches live as long as the process); short-lived CLIs call it
    before exit to avoid release-at-teardown noise (live-host verified)."""
    with _backend_lock:
        backends = list(_backends.values())
        _backends.clear()
    for be in backends:
        with be._lock:  # noqa: SLF001 - same-module teardown
            be._vms.clear()
            be._vsms_path = None
            be._service = None
