"""Operation-time capture of the loopback-socket WinError 10038 failure.

Issue #167 AC3. A CI-only cascade (`OSError: [WinError 10038] An operation
was attempted on something that is not a socket`) took 35 tests down at
once and left no evidence: the socket family CATCHES the socket exception
before any pytest reporting hook can see it, so the error class, the
failing operation and the handle's origin were all gone by the time the
failure was reported.

This module therefore observes the failure WHERE IT HAPPENS - at the
socket operation that raises - and writes a diagnosis artifact before the
family's own handler can swallow it. The artifact names:

* the failing socket operation (`accept`, `recv`, `sendall`, `connect`, ...);
* the owning fixture leg, taken from the failing frame's function name;
* the handle origin: whether the invalid handle came from the
  hvsock-monkeypatch side or from the real listener.

The origin is a genuine provenance signal, not an inference from "the test
uses a monkeypatch": at socket CREATION time the capture records whether
the function currently installed at `hvsock.connect` was executing on the
creation stack - that function is the one that handed the socket out. A
socket accepted by a real listener was not created by it.

Contract:
* the original exception is ALWAYS re-raised: the capture observes, it
  never swallows or masks;
* a failure that is not winerror 10038 is not captured at all;
* the artifact writer's own failure never masks the test failure;
* artifacts are uniquely named for the lifetime of the process - across
  concurrent writers AND across capture activations - so neither a cascade
  nor a re-activation can overwrite an earlier artifact;
* nothing but the operation name, the leg name, the origin classification
  and non-identifying metadata is recorded - no payload, no credentials,
  no guest content, no absolute guest path.
"""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

DIAG_DIR_ENV = "HYPERV_MCP_10038_DIAG_DIR"
_WINERROR_10038 = 10038
_CAPTURED_OPERATIONS = ("recv", "accept", "sendall", "connect")


def _diagnosis_dir() -> Path:
    """Where artifacts are written: the configured directory, else a temp one."""
    configured = os.environ.get(DIAG_DIR_ENV)
    if configured:
        return Path(configured)
    import tempfile

    return Path(tempfile.gettempdir()) / "hyperv-mcp-socket-10038"


def _installed_hvsock_connect():
    """The function currently installed at `hvsock.connect`, if any."""
    try:
        from hyperv_mcp import hvsock
    except Exception:  # noqa: BLE001 - the module may not import in isolation
        return None
    return getattr(hvsock, "connect", None)


def _on_creation_stack(target) -> bool:
    """True when `target` is executing on the current call stack.

    Identity, not name: the frame's code object and globals must be the
    function's own, so an unrelated function with the same name does not
    match.
    """
    if target is None:
        return False
    code = getattr(target, "__code__", None)
    globals_ = getattr(target, "__globals__", None)
    if code is None or globals_ is None:
        return False
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code is code and frame.f_globals is globals_:
            return True
        frame = frame.f_back
    return False


# The pytest leg currently running, published by the conftest so a capture
# that happens on a BACKGROUND thread can name the test that owns it. A
# background thread's own stack shows only the thread's frames (its target
# function, generically named "worker"), which cannot identify one test
# among a 35-test cascade - so the owning leg comes from the pytest context
# there, and from the live stack on the main thread, where the fixture or
# test frame IS on the stack.
_CURRENT_LEG: str | None = None
_CURRENT_LEG_LOCK = threading.Lock()


def set_current_leg(name: str | None) -> None:
    """Publish (or clear) the pytest leg currently running."""
    global _CURRENT_LEG
    with _CURRENT_LEG_LOCK:
        _CURRENT_LEG = name


def current_leg() -> str | None:
    """The pytest leg currently running, if one was published."""
    with _CURRENT_LEG_LOCK:
        return _CURRENT_LEG


def _owning_leg() -> str:
    """The fixture leg (or test) that was running when the failure raised.

    The live call stack is read rather than the exception's traceback: an
    exception raised in C and caught immediately carries ONLY the catching
    frame in its traceback - the caller's frames exist only as it
    propagates - so the leg is invisible from the traceback at exactly the
    moment the capture needs it.

    The leg is the frame inside a TEST module: a fixture-raised failure
    (the shape the socket family produces) names the fixture there, and a
    failure raised by the family's own helper code still attributes to the
    test that drove it. The capture's own frames are skipped.

    On a BACKGROUND THREAD the stack carries only that thread's own frames,
    so the frame it offers is the thread's target ("worker"), not the test
    that owns the failure. There the published pytest leg is used instead.
    """
    frame = sys._getframe(1)
    candidates: list[tuple[str, str]] = []
    while frame is not None:
        # Identity, not filename: this module's own frames are skipped, but
        # a TEST module whose name merely shares the suffix (for example
        # test_socket_10038_diagnosis.py) is not.
        if frame.f_globals.get("__name__") != __name__:
            candidates.append((os.path.basename(frame.f_code.co_filename),
                               frame.f_code.co_name))
        frame = frame.f_back
    on_main_thread = threading.current_thread() is threading.main_thread()
    for base, name in candidates:
        if "test" in base and name and not name.startswith("<"):
            if on_main_thread:
                return name
            # A background thread's stack names the thread's target, not the
            # owning test; fall through to the published pytest leg.
            break
    published = current_leg()
    if published:
        return published
    for _base, name in reversed(candidates):
        if name and not name.startswith("<"):
            return name
    return "unknown"


class SocketDiagnosis:
    """Installs the operation-time capture for the socket test family."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._origins: dict[int, str] = {}
        self._saved: dict[str, object] = {}

    # ---- lifecycle ----

    def install(self) -> None:
        with self._lock:
            if self._saved:
                return
            saved_init = socket.socket.__init__
            self._saved["__init__"] = saved_init
            for name in _CAPTURED_OPERATIONS:
                self._saved[name] = getattr(socket.socket, name)
            socket.socket.__init__ = self._init_factory(saved_init)  # type: ignore[method-assign]
            for name in _CAPTURED_OPERATIONS:
                setattr(socket.socket, name, self._wrap(name))

    def uninstall(self) -> None:
        with self._lock:
            if not self._saved:
                return
            socket.socket.__init__ = self._saved["__init__"]  # type: ignore[method-assign]
            for name in _CAPTURED_OPERATIONS:
                setattr(socket.socket, name, self._saved[name])
            self._saved.clear()
            self._origins.clear()

    # ---- the socket seams ----

    def _init_factory(self, saved_init):
        """A plain function (not a bound method): as a class attribute it
        receives the SOCKET as its first argument."""

        def _init(sock, *args, **kwargs) -> None:
            origin = "real-listener"
            if _on_creation_stack(_installed_hvsock_connect()):
                origin = "hvsock-monkeypatch-side"
            saved_init(sock, *args, **kwargs)
            with self._lock:
                self._origins[id(sock)] = origin

        _init.__name__ = "__init__"
        return _init

    def _wrap(self, operation: str):
        original = self._saved[operation]

        def _operation(sock, *args, **kwargs):
            try:
                return original(sock, *args, **kwargs)
            except OSError as exc:
                if getattr(exc, "winerror", None) == _WINERROR_10038:
                    self._record(operation, exc, sock)
                raise

        _operation.__name__ = operation
        return _operation

    # ---- the artifact ----

    def _record(self, operation: str, exc: BaseException, sock) -> None:
        """Write the diagnosis. Never raises: the test failure must win."""
        try:
            with self._lock:
                self._counter += 1
                counter = self._counter
                origin = self._origins.get(id(sock), "unknown")
            leg = _owning_leg()
            directory = _diagnosis_dir()
            directory.mkdir(parents=True, exist_ok=True)
            # Name components: leg, pid, the process-wide sequence (the
            # uniqueness guarantee - never reset by a re-activation, never
            # shared by concurrent writers), then the per-activation counter
            # (how many failures THIS activation has recorded). The sequence
            # alone makes the name unique for the process lifetime; the
            # counter is kept for readability only.
            name = "socket-10038-{}-{}-{}-{}.json".format(
                leg.replace("/", "_"), os.getpid(), _next_process_sequence(), counter
            )
            artifact = {
                "winerror": _WINERROR_10038,
                "error": str(exc),
                "operation": operation,
                "owning_leg": leg,
                "handle_origin": origin,
                "pid": os.getpid(),
                "recorded_at": time.time(),
                "python": sys.version.split()[0],
            }
            target = directory / name
            tmp = target.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(artifact, indent=2, sort_keys=True),
                           encoding="utf-8")
            tmp.replace(target)
        except Exception:  # noqa: BLE001 - a writer failure must not mask the test
            return


# The uniqueness component of artifact names (issue #167 review follow-up).
# An INSTANCE counter is not enough: the per-test conftest fixture
# deactivates the capture after each test and activate() then builds a NEW
# SocketDiagnosis, so an instance counter restarts at 0 - two tests in the
# same process failing with the same owning leg would build the SAME
# filename and tmp.replace(target) would destroy the earlier artifact. This
# sequence is module-level (a re-activation never resets it) and incremented
# under its own lock, so concurrent writers get distinct values too.
_SEQ_LOCK = threading.Lock()
_PROCESS_SEQ = 0


def _next_process_sequence() -> int:
    """A sequence value unique for the process lifetime, thread-safe."""
    global _PROCESS_SEQ
    with _SEQ_LOCK:
        _PROCESS_SEQ += 1
        return _PROCESS_SEQ


_ACTIVE: SocketDiagnosis | None = None


def activate() -> SocketDiagnosis:
    """Install the capture (idempotent) and return the active instance."""
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = SocketDiagnosis()
    _ACTIVE.install()
    return _ACTIVE


def deactivate() -> None:
    """Remove the capture."""
    global _ACTIVE
    if _ACTIVE is not None:
        _ACTIVE.uninstall()
        _ACTIVE = None
