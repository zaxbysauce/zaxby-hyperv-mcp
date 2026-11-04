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
  - A thread that has never joined an apartment HARD-FAILS its first COM
    call (CO_E_NOTINITIALIZED — probe-verified), so every COM-touching
    entry point (connect + resolve + operations) joins the process MTA via
    ``_ensure_thread_com`` before touching COM. pywin32 auto-initializes
    only the importing main thread.

pywin32 is OPTIONAL: the import guard keeps this module importable (and the
server fully functional on the PowerShell transport) wherever it is absent
— CI installs no pywin32. Selection happens in ``console.py``: this backend
first when ``COM_AVAILABLE`` and connectable, the existing ``run_ps`` path
otherwise. Error classes (PRR-002/005 taxonomy):

  - ``WMIError`` — a WMI METHOD/transport failure after selection
    (non-zero ReturnValue, bad payload, raw COM call failure). Structured
    error to the caller, NEVER retried through PowerShell (input must
    never double-send).
  - ``BackendUnavailable`` — the backend cannot serve this call AT ALL
    (connect failure, unusable namespace, target VM not in the WMI plane).
    Falls back to PowerShell at SELECTION time only; raised mid-operation
    it surfaces as a ConsoleError like any method failure (falling back
    mid-op could double-send input).

In-process COM calls carry no per-call timeout (a hung WMI provider blocks
that VM's operations until the provider returns; the PowerShell transport
keeps its process-kill bounds — documented in README).

This module never spawns a process and never references ``run_ps`` (the
spawn-discipline census): the only spawn owner remains pswindows.
"""

from __future__ import annotations

import contextlib
import threading
import time
from typing import Any, Literal, overload

from . import credentials, guestexec, policy, pswindows, vmident
from .config import Config

_WMI_NS = "root\\virtualization\\v2"
_PREFIX_LEN = 4
_MAX_NAME_LEN = 260
_CONNECT_FAILURE_TTL_S = 30.0

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
    """Structured WMI method/transport failure AFTER selection (non-zero
    ReturnValue, bad payload, raw COM call failure). Never retried through
    PowerShell — console input must never double-send."""


class BackendUnavailable(RuntimeError):
    """The in-process WMI backend cannot serve this call (connect failure,
    unusable namespace, or the target VM not present in the WMI plane).
    console.py falls back to the PowerShell transport on this at SELECTION
    time; raised mid-operation it surfaces as a ConsoleError (no mid-op
    transport switch — input must never double-send)."""


# ---------------------------------------------------------------------------
# COM apartment handling
# ---------------------------------------------------------------------------

_mta_lock = threading.Lock()
_mta_anchored = False


def _anchor_mta() -> None:
    """Hold one process-lifetime MTA reference from the first successful
    connect so the cached SWbem service can never outlive the apartment
    between operations. Per-thread joining is _ensure_thread_com's job."""
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
        except OSError:
            # RPC_E_CHANGED_MODE: the calling thread already joined an STA
            # (pywin32 auto-initializes the importing main thread as STA).
            # The anchor reference is best-effort; per-thread init below
            # still runs. Anything else propagates to connect_service.
            pass


@contextlib.contextmanager
def _com_thread():
    """COM apartment bracket for one backend operation on the calling
    thread. The calling thread joins the process MTA ONCE and never
    uninitializes: repeated CoUninitialize cycles around cached SWbem
    objects segfault at release (live-host verified — the anchor-only
    probe pattern is the stable one), and SDK worker threads live as
    long as the process, so per-thread references are bounded."""
    _ensure_thread_com()
    yield


_tls = threading.local()


def _ensure_thread_com() -> None:
    """Join the process MTA on the calling thread (once per thread). A
    thread that never joins hard-fails its first COM call with
    CO_E_NOTINITIALIZED (probe-verified), so every COM-touching entry
    point calls this first. A thread already in an STA (pywin32
    auto-initializes the importing main thread) stays there: SWbem works
    from either apartment, only cross-apartment consistency matters."""
    if not _COM_IMPORT_OK:
        return
    if getattr(_tls, "initialized", False):
        return
    try:
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        _tls.initialized = True
    except OSError:
        # RPC_E_CHANGED_MODE: thread already joined an STA. SWbem calls
        # work from the existing apartment; nothing to recover.
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
    configured host, with credentials resolved per connect from
    HYPERV_HOST_* (module-attribute access — tests monkeypatch
    credentials.resolve_host); a complete pair rides username/password,
    otherwise implicit auth. The backend cache means one connect per host
    per process (see backend()).

    The calling thread joins the process MTA first (fresh worker threads
    hard-fail COM otherwise). Every failure — including an incomplete
    HYPERV_HOST_* pair — raises BackendUnavailable so the caller falls
    back to the PowerShell transport (which re-raises the credential
    error itself, after its policy gates). Message text is redacted.
    """
    host = pswindows.hyperv_host(cfg)
    try:
        _ensure_thread_com()
        if _COM_IMPORT_OK:
            _anchor_mta()
        cred = credentials.resolve_host() if host else None
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_state(obj: Any, default: int) -> int:
    """Read EnabledState through _com: a property read on a dead WMI object
    raises com_error just like a method call does."""
    return _safe_int(_com("read EnabledState", lambda: getattr(obj, "EnabledState", default)))


def _com(operation: str, fn, *args: Any, **kwargs: Any) -> Any:
    """Run one raw COM call, translating every transport failure into
    WMIError (PRR-005): a pywintypes.com_error is neither WMIError nor
    BackendUnavailable and would otherwise bypass every structured-error
    handler in console.py. Our own control-flow exceptions pass through.
    The message carries the serving worker's identity (issue #95
    supplement AC4: spawn/refusal history is attributable from the log
    alone — worker turnover is exactly the failure mode this backend
    guards against)."""
    try:
        return fn(*args, **kwargs)
    except (WMIError, BackendUnavailable, ValueError):
        raise
    except Exception as exc:
        # The worker identity must be DISTINGUISHABLE: under mcp 2.x every
        # dispatched tool body runs on an anyio worker whose thread NAME is
        # the constant "AnyIO worker thread", so the name alone cannot say
        # which worker (or which creator's session) served the call. The
        # thread ident is stable per worker and shows the turnover the fix
        # is about (implementation-review).
        worker = threading.current_thread()
        identity = f"{worker.name}#{threading.get_ident()}"
        raise WMIError(
            pswindows.redact(f"WMI {operation} failed (worker {identity}): {exc}")
        ) from None


def _boot_epoch_from_cs(cs: Any) -> int | None:
    """Whole seconds since the Unix epoch of (now - OnTimeInMilliseconds), or
    None when the CS reports nothing usable (issue #28's credential-free
    host-side boot boundary; pausing the VM shifts it and callers fail
    closed on a mismatch)."""
    raw = getattr(cs, "OnTimeInMilliseconds", None)
    if raw is None:
        return None
    try:
        boot_ms = int(raw)
    except (TypeError, ValueError):
        return None
    if boot_ms <= 0:
        return None
    return int(time.time() - boot_ms / 1000.0)


def _rows(result: Any) -> list:
    """Normalize an ExecQuery result to a list. Real SWbemObjectSet is
    iterable (live-probed via CDispatch); fakes may return a bare object
    or a list; None means empty."""
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
    return _com("path read", lambda: str(obj.Path_.Path))


def _exec_method(service: Any, obj_path: str, method: str, **params: Any) -> Any:
    """The ONLY method-invocation shape that works on this stack (probe
    fact): spawned in-parameters + ExecMethod_. In-parameters are set via
    plain attribute assignment (works on both real SWbem and the fakes).
    Operation tokens carry the method name (issue #95 supplement AC4: a
    surfaced input-method failure must name the concrete operation)."""
    obj = _com(f"bind {obj_path}", lambda: service.Get(obj_path))
    definition = _com(f"method lookup {method}", lambda: obj.Methods_(method))
    inp = _com(f"spawn in-parameters {method}", lambda: definition.InParameters.SpawnInstance_())
    for name, value in params.items():
        _com(f"set parameter {method}", lambda n=name, v=value: setattr(inp, n, v))
    return _com(f"ExecMethod_ {method}", lambda: obj.ExecMethod_(method, inp))


def _check_rv(out: Any, method: str) -> None:
    try:
        rv = int(out.ReturnValue)
    except (AttributeError, TypeError, ValueError):
        raise WMIError(f"{method} returned no parsable ReturnValue") from None
    if rv != 0:
        raise WMIError(f"{method} failed with ReturnValue={rv}")


# ---------------------------------------------------------------------------
# per-VM cache
# ---------------------------------------------------------------------------

class _VMCache:
    """Cached object PATHS plus the last-seen VM state. Paths are strings
    (apartment-safe); objects are re-bound per operation via Get(). Field
    writes are made under the owning ConsoleWMI's lock."""

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
    """Backend bound to one WMI service (one host). Thread-safe: shared
    cache state is mutated under ``_lock`` and console input ops
    additionally hold the per-VM vm_lock at the console layer.

    ``creator`` records the thread whose COM apartment produced the cached
    service (issue #95): pywin32 SWbem services die with their creating
    worker, so the cache is only valid while that thread lives."""

    def __init__(self, service: Any, creator: threading.Thread | None = None) -> None:
        self._service = service
        self._lock = threading.Lock()
        self._vms: dict[str, _VMCache] = {}
        self._names: dict[str, str] = {}
        self._vsms_path: str | None = None
        self.creator = creator or threading.current_thread()

    @property
    def creator_thread(self) -> threading.Thread:
        """The thread that created the cached service (query provenance;
        supplement AC3)."""
        return self.creator

    # -- internals ----------------------------------------------------------

    def _query_one(self, wql: str, ambiguous_value_error: bool = False) -> Any | None:
        rows = _rows(_com("ExecQuery", lambda: self._service.ExecQuery(wql)))
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
        entry = _VMCache(_path_of(obj), _read_state(obj, 0))
        with self._lock:
            self._vms.setdefault(guid, entry)
            return self._vms[guid]

    def _rebind_cs(self, guid: str) -> tuple[_VMCache, Any]:
        """Re-bind the CS object from the cached path and refresh the cached
        state. A state change drops ALL cached device paths together; a
        stale-path recovery (VMMS rebuild) drops them too — the rebuilt
        namespace's device paths are suspect even when EnabledState matches
        (a checkpoint apply replaces devices without changing state)."""
        entry = self._ensure_entry(guid)
        recovered = False
        try:
            obj = _com("bind CS", lambda: self._service.Get(entry.cs_path))
            state = _read_state(obj, entry.state)
        except WMIError:
            # stale path (VMMS rebuild): re-resolve identity once
            obj = self._query_one(
                "SELECT * FROM Msvm_ComputerSystem WHERE Name = " + _wql_quote(guid.lower())
            )
            if obj is None:
                raise BackendUnavailable(
                    f"VM {guid} is not present in the WMI plane"
                ) from None
            recovered = True
            state = _read_state(obj, entry.state)
        with self._lock:
            if recovered:
                entry.cs_path = _path_of(obj)
                entry.drop_devices()
            elif state != entry.state:
                entry.drop_devices()
            entry.state = state
        return entry, obj

    def _vsms(self) -> str:
        with self._lock:
            cached = self._vsms_path
        if cached is not None:
            return cached
        obj = self._query_one("SELECT * FROM Msvm_VirtualSystemManagementService")
        if obj is None:
            raise BackendUnavailable(
                "Msvm_VirtualSystemManagementService not present in the WMI plane"
            )
        path = _path_of(obj)
        with self._lock:
            self._vsms_path = path
        return path

    def _keyboard_path(self, guid: str, entry: _VMCache) -> str:
        """Cached keyboard path, re-resolved through the counted ASSOCIATORS
        channel when uncached; a VM with no keyboard is WMIError."""
        if entry.kb_path is not None:
            return entry.kb_path
        rows = _rows(_com("ExecQuery keyboard", lambda: self._service.ExecQuery(
            "ASSOCIATORS OF {" + entry.cs_path + "} WHERE ResultClass = Msvm_Keyboard"
        )))
        if not rows:
            raise WMIError("no keyboard device associated with the VM")
        with self._lock:
            entry.kb_path = _path_of(rows[0])
        return entry.kb_path

    @overload
    def _mouse_path(
        self, guid: str, entry: _VMCache, absent_ok: Literal[True]
    ) -> str | None: ...

    @overload
    def _mouse_path(
        self, guid: str, entry: _VMCache, absent_ok: Literal[False] = ...
    ) -> str: ...

    def _mouse_path(
        self, guid: str, entry: _VMCache, absent_ok: bool = False
    ) -> str | None:
        """Cached synthetic-mouse path via ONE SystemName-scoped query —
        the same key-filter discovery console.py's _MOUSE_SYNTHETIC uses
        (FND-16 scoping parity; the namespace serves several mice per
        host, so the WQL filter itself binds the row to THIS VM — no
        client-side SystemName re-filter, which objects that do not
        expose the attribute would defeat). Absence (zero rows) returns
        None with absent_ok / raises WMIError otherwise; a TRANSPORT
        failure propagates as WMIError (CUB-478: _com() folds the
        underlying OSError/com_error, so nothing else escapes) — never
        laundered to absent."""
        if entry.mouse_path is not None:
            return entry.mouse_path
        rows = _rows(_com("ExecQuery mouse", lambda: self._service.ExecQuery(
            "SELECT * FROM Msvm_SyntheticMouse WHERE SystemName = "
            + _wql_quote(guid.lower())
        )))
        if not rows:
            if absent_ok:
                return None
            raise WMIError("no synthetic mouse device associated with the VM")
        with self._lock:
            entry.mouse_path = _path_of(rows[0])
        return entry.mouse_path

    def _ps2_mouse_present(self, guid: str) -> bool:
        """Per-call PS/2 mouse presence probe (issue #83 Design b,
        PRR-101): the same SystemName-scoped key filter _mouse_path uses,
        against Msvm_Ps2Mouse — the WMI transport's mirror of the folded
        script's _MOUSE_PS2 query, so display_info's mouse_ps2_present
        agrees across transports. Empty rows -> not present; a TRANSPORT
        failure propagates as WMIError (same absent_ok semantics as
        _mouse_path's probe — never laundered to absent). Uncached on
        purpose: display_info is the only consumer, a per-call probe
        needs no cache entry to invalidate."""
        rows = _rows(_com("ExecQuery ps2 mouse", lambda: self._service.ExecQuery(
            "SELECT * FROM Msvm_Ps2Mouse WHERE SystemName = "
            + _wql_quote(guid.lower())
        )))
        return bool(rows)

    def _head_object(self, guid: str, entry: _VMCache) -> Any | None:
        """Head object via cached path (re-read per call so resolution
        changes are picked up), re-resolved on path failure."""
        obj: Any | None = None
        if entry.head_path is not None:
            try:
                obj = _com("bind head", lambda: self._service.Get(entry.head_path))
            except WMIError:
                with self._lock:
                    entry.head_path = None
                obj = None
        if obj is None:
            rows = _rows(_com("ExecQuery video head", lambda: self._service.ExecQuery(
                "ASSOCIATORS OF {" + entry.cs_path + "} WHERE ResultClass = Msvm_VideoHead"
            )))
            if rows:
                obj = rows[0]
                with self._lock:
                    entry.head_path = _path_of(obj)
        return obj

    # -- public operations (all return (result, timings)) -------------------
    # connect_ms is the measured backend lookup (near-zero on a warm cache);
    # rebind_ms is the cached-CS re-bind + state check; method_ms is the
    # operation's WMI work. Chunked/poll ops (type_text, type_scancodes,
    # wait_frame_change, capture_sequence) SUM these phases across their
    # iterations (documented in README).

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
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            obj = self._head_object(guid, entry)
            method_ms = (time.monotonic() - t0) * 1000.0
            head: tuple[int, int] | None = None
            if obj is not None:
                h = getattr(obj, "CurrentHorizontalResolution", None)
                v = getattr(obj, "CurrentVerticalResolution", None)
                try:
                    hi, vi = int(h), int(v)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    hi = vi = 0
                if hi > 0 and vi > 0:
                    head = (hi, vi)
            return head, {
                "connect_ms": 0.0,
                "rebind_ms": rebind_ms,
                "method_ms": method_ms,
            }

    def capture(self, guid: str, width: int, height: int) -> tuple[bytes, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            vsms = self._vsms()
            out = _exec_method(
                self._service, vsms, "GetVirtualSystemThumbnailImage",
                TargetSystem=entry.cs_path, WidthPixels=width, HeightPixels=height,
            )
            _check_rv(out, "GetVirtualSystemThumbnailImage")
            try:
                data = bytes(out.ImageData)
            except (AttributeError, TypeError, ValueError):
                raise WMIError("GetVirtualSystemThumbnailImage returned no image data") from None
            expected = width * height * 2 + _PREFIX_LEN
            if len(data) != expected:
                raise WMIError(
                    f"thumbnail payload length mismatch: got {len(data)}, expected {expected}"
                )
            method_ms = (time.monotonic() - t0) * 1000.0
            return data, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms, "method_ms": method_ms,
            }

    def type_text(self, guid: str, text: str) -> tuple[None, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            kb = self._keyboard_path(guid, entry)
            out = _exec_method(self._service, kb, "TypeText", AsciiText=text)
            _check_rv(out, "TypeText")
            return None, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def type_scancodes(self, guid: str, codes: list[int]) -> tuple[None, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            kb = self._keyboard_path(guid, entry)
            out = _exec_method(
                self._service, kb, "TypeScancodes", ScanCodes=list(codes)
            )
            _check_rv(out, "TypeScancodes")
            return None, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_move(self, guid: str, hx: int, hy: int) -> tuple[None, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetAbsolutePosition",
                HorizontalPosition=int(hx), VerticalPosition=int(hy),
            )
            _check_rv(out, "SetAbsolutePosition")
            return None, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_click(
        self, guid: str, button: int, hx: int | None = None, hy: int | None = None
    ) -> tuple[None, dict]:
        """Move-then-click when hx/hy given (including (0,0), a real
        coordinate); hx/hy None (both) means click at the CURRENT position
        (the click-without-coordinates contract)."""
        if (hx is None) != (hy is None):
            raise ValueError("mouse_click requires both hx and hy, or neither")
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
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
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_button(self, guid: str, button: int, is_down: bool) -> tuple[None, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetButtonState",
                ButtonIndex=int(button), IsDown=bool(is_down),
            )
            _check_rv(out, "SetButtonState")
            return None, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def mouse_scroll(self, guid: str, delta: int) -> tuple[None, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, _obj = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            mouse = self._mouse_path(guid, entry)
            out = _exec_method(
                self._service, mouse, "SetScrollPosition",
                ScrollPositionDelta=int(delta),
            )
            _check_rv(out, "SetScrollPosition")
            return None, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms,
                "method_ms": (time.monotonic() - t0) * 1000.0,
            }

    def display_info(self, guid: str) -> tuple[dict, dict]:
        with _com_thread():
            t0 = time.monotonic()
            entry, cs = self._rebind_cs(guid)
            rebind_ms = (time.monotonic() - t0) * 1000.0
            t0 = time.monotonic()
            head_obj = self._head_object(guid, entry)
            # Device presence mirrors the PS [bool]$kb contract: EMPTY
            # association rows mean absent; a FAILED probe is an error, never
            # silently "absent" (except-Exception laundering removed, PRR-013).
            kb_rows = _rows(_com("ExecQuery keyboard", lambda: self._service.ExecQuery(
                "ASSOCIATORS OF {" + entry.cs_path + "} WHERE ResultClass = Msvm_Keyboard"
            )))
            kb_obj = kb_rows[0] if kb_rows else None
            # Mouse discovery is the SystemName-scoped query every mouse op
            # uses (see _mouse_path; FND-16 scoping parity with console.py).
            # Absent (zero rows) -> present False; a FAILED probe
            # (bind/transport) raises — never laundered to absent (PRR-013).
            mouse_path = self._mouse_path(guid, entry, absent_ok=True)
            mouse_obj = _com("bind mouse", lambda: self._service.Get(mouse_path)) if mouse_path else None
            # PRR-101: the PS/2 probe is the WMI mirror of the folded
            # script's _MOUSE_PS2 query (issue #83 Design b) — mouse_present
            # above stays the synthetic-only answer the input ops act on;
            # this key reports the fallback device's presence. Empty rows ->
            # False; a failed probe raises WMIError (never laundered).
            ps2_present = self._ps2_mouse_present(guid)
            method_ms = (time.monotonic() - t0) * 1000.0

            def _res(obj: Any) -> tuple[int | None, int | None]:
                h = getattr(obj, "CurrentHorizontalResolution", None)
                v = getattr(obj, "CurrentVerticalResolution", None)
                try:
                    hi, vi = int(h), int(v)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return None, None
                if hi <= 0 or vi <= 0:
                    return None, None
                return hi, vi

            hh, hv = _res(head_obj) if head_obj is not None else (None, None)
            info = {
                "enabled_state": entry.state,
                "head_horizontal": hh,
                "head_vertical": hv,
                "keyboard_present": kb_obj is not None,
                "keyboard_enabled": getattr(kb_obj, "EnabledState", None) if kb_obj else None,
                "mouse_present": mouse_obj is not None,
                "mouse_enabled": getattr(mouse_obj, "EnabledState", None) if mouse_obj else None,
                "mouse_ps2_present": ps2_present,
                "boot_epoch": _boot_epoch_from_cs(cs),
            }
            return info, {
                "connect_ms": 0.0, "rebind_ms": rebind_ms, "method_ms": method_ms,
            }

    def boot_epoch(self, guid: str) -> int | None:
        """The host-side boot boundary (issue #28): whole seconds since the
        Unix epoch of (now - Msvm_ComputerSystem.OnTimeInMilliseconds).
        Credential-free host WMI, so it is meaningful in firmware and WinPE;
        None when the provider reports nothing usable."""
        with _com_thread():
            _entry, cs = self._rebind_cs(guid)
            return _boot_epoch_from_cs(cs)

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
        with _com_thread():
            return self._resolve_vm_locked(cfg, vm_name=vm_name, vm_id=vm_id)

    def _resolve_vm_locked(
        self, cfg: Config, vm_name: str = "", vm_id: str = ""
    ) -> vmident.VMRef:
        # vmident parity: the RAW vm_id gates the by-id branch, so a
        # whitespace-only vm_id is rejected, not silently by-name resolved.
        if vm_id:
            guid = vm_id.strip()
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
                obj = _com("bind CS", lambda: self._service.Get(entry.cs_path))
                return _ResolvedCS(lower, str(getattr(obj, "ElementName", "") or ""))
            except WMIError:
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
        """Resolve by ElementName, accepting only GUID-shaped Name rows: the
        namespace also contains the HOST computer system (ElementName can
        equal its non-GUID Name — the exact hijack guestexec's PS resolver
        filters, live-observed as ElementName='VSAN', Name='VSAN'). A host
        row is skipped, never cached; only genuine ambiguity between valid
        VM rows raises ValueError."""
        rows = _rows(_com("ExecQuery CS by name", lambda: self._service.ExecQuery(
            "SELECT * FROM Msvm_ComputerSystem WHERE ElementName = " + _wql_quote(vm_name)
        )))
        matches: list[Any] = []
        for obj in rows:
            guid = str(getattr(obj, "Name", "") or "")
            try:
                guestexec.validate_vm_guid(guid)
            except ValueError:
                continue
            matches.append(obj)
        if not matches:
            return None
        if len(matches) > 1:
            raise ValueError(
                f"WMI query returned {len(matches)} rows where one was expected"
            )
        obj = matches[0]
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
                    _path_of(obj), _read_state(obj, 0)
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

_backends: dict[tuple[str, int], ConsoleWMI] = {}
_backend_lock = threading.Lock()
# Per-host connect locks: the CONNECT itself must not run under the
# process-global cache lock, or a slow DCOM connect for one host stalls
# backend acquisition for every other host (implementation-review).
_connect_locks: dict[str, threading.Lock] = {}
# Negative memo: a failed connect is re-attempted at most once per TTL, so
# a downed DCOM endpoint costs one connect timeout per TTL instead of one
# per console call (PRR-012). Cleared by shutdown() and on success.
_connect_failures: dict[str, tuple[float, BackendUnavailable]] = {}


def _host_key(cfg: Config) -> str:
    # "local" keeps a remote cfg with hyperv.host="." from sharing the
    # local-mode cache entry (different credential intents).
    return pswindows.hyperv_host(cfg) or "local"


def _cache_key(cfg: Config) -> tuple[str, int]:
    """The cache key of a backend: (host, creating thread).

    A pywin32 SWbem service dies with the thread that created it, so a
    service must never be handed to a DIFFERENT thread: another worker
    would then use a service whose creator has exited (the exact #95
    symptom), and no liveness check on the acquiring side can close that
    window. Keying the cache per thread keeps every service with its own
    creator; a worker thread's service stays valid for that worker's
    lifetime, and a thread whose service died reconnects on its next call.
    """
    return (_host_key(cfg), threading.get_ident())


def backend(cfg: Config) -> ConsoleWMI:
    """Cached ConsoleWMI per (host, thread); raises BackendUnavailable when
    the service cannot be obtained (memoized for
    _CONNECT_FAILURE_TTL_S so an unreachable endpoint costs one connect
    per TTL, not one per call). Never imports pywin32 itself.

    Issue #95: a cached service is only valid while its CREATING thread
    lives (pywin32 SWbem services die with their creator worker — the
    executed replacement-worker probe shows exactly the
    1-pass/3-fail signature). A cache hit whose creator has exited is
    dropped and the connection is re-established on the REQUESTING
    thread; the negative memo keeps its TTL, is re-read under the
    per-host connect lock (single-flight) and is cleared by a
    successful connect."""
    key = _cache_key(cfg)
    host_key = _host_key(cfg)
    with _backend_lock:
        be = _backends.get(key)
        if be is not None:
            creator = be.creator
            if creator is not None and creator.is_alive():
                return be
            # Creator exited: the cached service is dead (disconnected
            # SWbem). Drop it and reconnect below on the live requester.
            _backends.pop(key, None)
        memo = _connect_failures.get(host_key)
        if memo is not None:
            failed_at, err = memo
            if time.monotonic() - failed_at < _CONNECT_FAILURE_TTL_S:
                raise err
            _connect_failures.pop(host_key, None)
    # The CONNECT runs OUTSIDE the process-global cache lock, under a
    # per-host connect lock: a slow credentialed DCOM connect for one host
    # must not stall backend acquisition for every other host
    # (implementation-review). The per-host lock keeps ONE connect in
    # flight per host: a caller that arrives while another is connecting
    # WAITS here. On the healthy path it then connects for ITSELF (a
    # service is never handed to a worker other than its creator, so the
    # cache is keyed per thread); on the FAILURE path it finds the
    # negative memo, which is re-read under this lock, and shares the
    # first caller's failure instead of opening its own connect.
    with _connect_lock(host_key):
        with _backend_lock:
            be = _backends.get(key)
            if be is not None:
                creator = be.creator
                if creator is not None and creator.is_alive():
                    return be
            # The memo is RE-READ under the connect lock: a caller that
            # passed the outer check while another thread was failing the
            # connect must see the failure instead of opening a second
            # connect (the single-flight property the old all-under-one-
            # lock shape had).
            memo = _connect_failures.get(host_key)
            if memo is not None:
                failed_at, err = memo
                if time.monotonic() - failed_at < _CONNECT_FAILURE_TTL_S:
                    raise err
                _connect_failures.pop(host_key, None)
        try:
            service = connect_service(cfg)
        except BackendUnavailable as exc:
            with _backend_lock:
                _connect_failures[host_key] = (time.monotonic(), exc)
            raise
        be = ConsoleWMI(service)
        with _backend_lock:
            _backends[key] = be
            # A successful connect clears the host's negative memo: the
            # host is reachable, so a stale failure must not keep
            # refusing the NEXT worker for the rest of the TTL.
            _connect_failures.pop(host_key, None)
        return be


def _connect_lock(host_key: str) -> threading.Lock:
    """The per-host connect lock (see backend())."""
    with _backend_lock:
        lock = _connect_locks.get(host_key)
        if lock is None:
            lock = threading.Lock()
            _connect_locks[host_key] = lock
        return lock


def shutdown() -> None:
    """Drop every cached service/object reference so no COM object is
    released after the apartment is gone. Long-running servers never need
    this (caches live as long as the process); short-lived CLIs call it
    before exit to avoid release-at-teardown noise (live-host verified).
    Clearing the caches (not nulling live instances) keeps any straggler
    op working rather than raising AttributeError on a nulled service."""
    with _backend_lock:
        backends = list(_backends.values())
        _backends.clear()
        _connect_failures.clear()
        _connect_locks.clear()
    for be in backends:
        with be._lock:  # noqa: SLF001 - same-module teardown
            be._vms.clear()
            be._names.clear()
            be._vsms_path = None
