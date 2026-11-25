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
* installing while ANOTHER instance is installed is REFUSED: the socket
  methods and `Thread.start` are process-global, so two overlapping
  instances could uninstall each other's patches. A re-activation of the
  SAME instance is fine (it never wraps a wrapper);
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
import weakref
from pathlib import Path

DIAG_DIR_ENV = "HYPERV_MCP_10038_DIAG_DIR"
_WINERROR_10038 = 10038
# `shutdown` is included because the family calls it on a closed socket and swallows the resulting WinError 10038 - without it, a real failure of that shape produced no artifact at all.
# Every socket operation that touches the handle can raise the same
# WinError 10038 (WSAENOTSOCK) on a closed socket, and the family calls
# several of them inside exception-swallowing cleanup paths - so a real
# failure of any of those shapes must leave an artifact. The census is
# every handle-touching operation of `socket.socket`; `close` and `detach`
# `close` IS captured: on Windows a close on a handle another thread has
# invalidated raises the same WinError 10038, and the family closes
# handles it does not exclusively own.
_CAPTURED_OPERATIONS = (
    "accept", "bind", "close", "connect", "dup", "getpeername",
    "getsockname", "getsockopt", "listen", "recv", "recv_into", "recvfrom",
    "recvfrom_into", "send", "sendall", "sendto", "setblocking", "settimeout",
    "setsockopt", "shutdown",
)


# The operations that put a socket on the LISTENER's own creation path. A
# socket that is bound AND listened on is positively the listener's - the
# capture observes that rather than inferring it from "the connector did
# not make it".
_LISTENER_OPERATIONS = ("bind", "listen")

# The PRISTINE socket methods, captured once at import. Every wrapper calls
# these and every uninstall restores these, so activating the capture twice
# (or overlapping two instances) can never leave a wrapper calling another
# wrapper, and can never leave a stale wrapper installed.
_ORIGINAL_SOCKET_INIT = socket.socket.__init__
_ORIGINAL_SOCKET_METHODS = {
    name: getattr(socket.socket, name)
    for name in _CAPTURED_OPERATIONS + _LISTENER_OPERATIONS
}

def _diagnosis_dir() -> Path:
    """Where artifacts are written: the configured directory, else a temp one."""
    configured = os.environ.get(DIAG_DIR_ENV)
    if configured:
        return Path(configured)
    import tempfile

    return Path(tempfile.gettempdir()) / "hyperv-mcp-socket-10038"


def _original_hvsock_connect():
    """The connector the repository ships, captured at IMPORT time.

    It is the reference for the origin label: a socket created while the
    INSTALLED connector is on the creation stack is the monkeypatch side
    only when the installed connector is NOT the original one - the
    original connector is the production path, and labelling it as a
    monkeypatch would present an OBSERVED substitution as something it
    is not (the round-22 plan gate's finding).

    The capture happens at IMPORT, before any test can monkeypatch the
    connector: a lazy capture would read the FAKE as the original.
    """
    global _ORIGINAL_CONNECT
    if _ORIGINAL_CONNECT is not _UNSET:
        return _ORIGINAL_CONNECT
    try:
        from hyperv_mcp import hvsock
    except Exception:  # noqa: BLE001 - the module may not import in isolation
        _ORIGINAL_CONNECT = None
        return None
    _ORIGINAL_CONNECT = getattr(hvsock, "connect", None)
    return _ORIGINAL_CONNECT


def _installed_hvsock_connect():
    """The function currently installed at `hvsock.connect`, if any.

    It is the MONKEYPATCH side only when it differs from the original
    connector the repository ships.
    """
    try:
        from hyperv_mcp import hvsock
    except Exception:  # noqa: BLE001 - the module may not import in isolation
        return None
    installed = getattr(hvsock, "connect", None)
    if installed is None:
        return None
    if installed is _original_hvsock_connect():
        # The ORIGINAL connector: the production path, not a substitution.
        return None
    return installed


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


# The original connector, captured at IMPORT time (see
# `_original_hvsock_connect`): a lazy capture would read a test's FAKE as
# the original.
_UNSET = object()
_ORIGINAL_CONNECT: object = _UNSET

# The leg of the FIXTURE (or test) that was executing when a thread was
# started, keyed by the thread object. A thread's own stack cannot show it:
# the frames of the code that STARTED the thread are not on the thread's
# stack. Filled at Thread.start time while the capture is installed.
#
# The entry carries the THREAD ITSELF, not just its id: an id can be
# reused after a thread is collected, and a reused id would hand a new
# thread another thread's leg - an attribution presented as an
# observation (the round-15 implementation reviewer's finding).
_THREAD_LEGS: dict[int, tuple["weakref.ref[object]", str]] = {}


def _current_stack_leg() -> str | None:
    """The OUTERMOST test-module frame that is executing right now.

    The outermost one is the owner: a fixture that called a helper which
    started the thread must be recorded as the FIXTURE, not the helper, and
    a test body that called a helper must be recorded as the TEST.
    """
    frame = sys._getframe(1)
    found: str | None = None
    while frame is not None:
        if frame.f_globals.get("__name__") != __name__:
            base = os.path.basename(frame.f_code.co_filename)
            name = frame.f_code.co_name
            if "test" in base and name and not name.startswith("<"):
                found = name
        frame = frame.f_back
    return found


def _thread_leg() -> str | None:
    """The leg recorded for the CURRENT thread, if any.

    The recorded entry names the thread it was recorded FOR: an id that
    has since been reused by a different thread does not carry over.
    """
    thread = threading.current_thread()
    entry = _THREAD_LEGS.get(id(thread))
    if entry is None:
        return None
    owner, leg = entry
    return leg if owner() is thread else None


def _install_thread_leg_recorder(saved: dict) -> None:
    """Record the starting leg of every thread started while installed."""
    original_start = threading.Thread.start

    def start_with_leg(self, *args, **kwargs):
        # The REGISTERED owner of the current thread takes PRECEDENCE over
        # an incidental frame on the current stack: a worker defined in a
        # test file supplies its own test-module frame, and that worker's
        # function name is no more identifying than "worker" - the
        # registered owner is the fixture or test that started the chain.
        leg = _thread_leg() or _current_stack_leg()
        if leg:
            _THREAD_LEGS[id(self)] = (weakref.ref(self), leg)
        return original_start(self, *args, **kwargs)

    saved["Thread.start"] = original_start
    threading.Thread.start = start_with_leg


def _remove_thread_leg_recorder(saved: dict) -> None:
    original_start = saved.pop("Thread.start", None)
    if original_start is not None:
        threading.Thread.start = original_start

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

    On the MAIN THREAD the leg is the OUTERMOST test-module frame, so a
    failure inside a nested helper names the fixture or test that owns it
    rather than the helper (the real family's shape is
    `fake_connect -> socket.create_connection -> connect`). A direct
    fixture raise - the shape the frozen oracle produces - has exactly one
    test-module frame, so it is unaffected.

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
    test_frames = [
        name
        for base, name in candidates
        if "test" in base and name and not name.startswith("<")
    ]
    if on_main_thread:
        # The owning leg is the pytest TEST that was running when one is on
        # the stack, and otherwise the FIXTURE that owns the call.
        #
        # A test body runs AFTER its fixtures, so a fixture's frame is on
        # the stack only while the fixture itself is executing - in which
        # case no test function is on the stack either, and the outermost
        # test-module frame (the fixture) owns the failure. That is the
        # shape the frozen oracle produces, and the shape the socket
        # family's fixture-installed `fake_connect` produces. When a test
        # body is on the stack, every frame inside it is a helper the test
        # called, and the TEST owns the failure - naming the helper would
        # not identify which of a 35-test cascade failed.
        # The published pytest leg names the ACTUAL test node. When that
        # node is on the stack, every test-module frame inside it is a
        # helper the test called - the test owns the failure, and a helper
        # whose name happens to start with "test_" must not be named
        # instead. When the published leg is NOT on the stack, the test
        # body has not started: this is a FIXTURE's setup, and the
        # outermost test-module frame is the fixture that owns it (the
        # frozen oracle's `synthetic_hvsock_leg`).
        published = current_leg()
        if published and published in test_frames:
            return published
        if test_frames:
            return test_frames[-1]
    else:
        # A background thread's stack names the thread's target, not the
        # owning test; the published pytest leg is used instead.
        # A thread's own stack carries only its frames, so the leg of the
        # FIXTURE that STARTED the thread is recovered from the registry the
        # capture fills at Thread.start time. When the thread was not
        # started under the capture (or nothing was recorded), the running
        # pytest item is the best available identifier, and the artifact
        # says which kind of attribution it is.
        started_by = _thread_leg()
        if started_by:
            return started_by
        published = current_leg()
        if published:
            return published
    for _base, name in reversed(candidates):
        if name and not name.startswith("<"):
            return name
    return "unknown"


# The observed origins and the listener steps, keyed by the socket's id.
#
# They are MODULE-level so they survive the public activation
# lifecycle: `deactivate()` drops the active instance and the next
# `activate()` builds a new one, so an instance-level registry would
# lose a still-live socket's observed provenance at every boundary (the
# round-21 implementation reviewer's finding). The entries hold WEAK
# references, so a collected socket's entry dies with it and a
# recycled id can never inherit it.
_ORIGINS: dict[int, tuple["weakref.ref[object]", str]] = {}
_LISTENER_STEPS: dict[int, tuple["weakref.ref[object]", set[str]]] = {}


class SocketDiagnosis:
    """Installs the operation-time capture for the socket test family."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        # The origin and listener-step registries are MODULE-level, so
        # they survive the public activation lifecycle: `deactivate()`
        # drops the active instance and the next `activate()` builds a
        # new one, so an instance-level registry would lose a live
        # socket's observed provenance at every boundary (the round-21
        # implementation reviewer's finding). The entries carry the
        # SOCKET ITSELF, not just its id: an id can be reused after a
        # socket is collected, and a reused id would let a new socket
        # inherit another socket's observed bind/listen steps - an
        # attribution presented as an observation (the round-15 finding).
        self._saved: dict[str, object] = {}

    # ---- lifecycle ----

    def install(self) -> None:
        global _INSTALLED_BY
        with self._lock:
            if self._saved:
                return
            if _INSTALLED_BY is not None and _INSTALLED_BY is not self:
                # The socket methods and `Thread.start` are PROCESS-GLOBAL,
                # so two overlapping instances would uninstall each
                # other's patches. The non-overlap is enforced here
                # rather than left to the caller (the round-22
                # implementation reviewer's finding).
                raise RuntimeError(
                    "the socket diagnosis capture is already installed by "
                    "another instance; overlapping instances cannot "
                    "coordinate the process-global patches"
                )
            # The ownership is claimed HERE, so a DIRECT installation
            # takes it too - claiming it only in `activate()` left a
            # direct installation invisible to the guard above (the
            # round-22 implementation reviewer's finding).
            _INSTALLED_BY = self
            self._saved["__init__"] = _ORIGINAL_SOCKET_INIT
            for name, original in _ORIGINAL_SOCKET_METHODS.items():
                self._saved[name] = original
            socket.socket.__init__ = self._init_factory(_ORIGINAL_SOCKET_INIT)  # type: ignore[method-assign]
            for name in _CAPTURED_OPERATIONS:
                setattr(socket.socket, name, self._wrap(name))
            _install_thread_leg_recorder(self._saved)

    def uninstall(self) -> None:
        global _INSTALLED_BY
        with self._lock:
            if not self._saved:
                return
            if _INSTALLED_BY is self:
                _INSTALLED_BY = None
            socket.socket.__init__ = _ORIGINAL_SOCKET_INIT  # type: ignore[method-assign]
            for name, original in _ORIGINAL_SOCKET_METHODS.items():
                setattr(socket.socket, name, original)
            _remove_thread_leg_recorder(self._saved)
            self._saved.clear()
            # The origin and listener-step registries are MODULE-level
            # (see `_ORIGINS`), so they are NOT cleared here: a socket
            # whose identity has not changed keeps the provenance it was
            # observed with across an activation boundary.
            # The THREAD registry is NOT cleared: a thread started under
            # one activation and released after another keeps the
            # STARTER's leg, which is the truth. Clearing it would make
            # the fallback name the CURRENT test - an attribution
            # presented as an observation (the plan gate's cross-
            # activation probe). The entries are weak references, so a
            # dead thread's entry dies with it.

    # ---- the socket seams ----

    def _inherit_origin(self, source, accepted) -> None:
        """Carry an observed origin across the accept seam."""
        with self._lock:
            entry = _ORIGINS.get(id(source))
            if entry is None:
                return
            owner, origin = entry
            if owner() is not source or not origin or origin == "unknown":
                return
            _ORIGINS[id(accepted)] = (weakref.ref(accepted), origin)

    def _note_listener_step(self, sock, operation: str) -> None:
        """Record that a socket reached one half of the listener's own
        creation path.

        The promotion to "real-listener" needs BOTH a successful bind and
        a successful listen: one half alone does not establish that the
        socket is the listener's.
        """
        with self._lock:
            entry = _LISTENER_STEPS.get(id(sock))
            if entry is None or entry[0]() is not sock:
                # A different socket that happens to carry the same id:
                # its steps start empty, never the previous one's.
                steps: set[str] = set()
            else:
                steps = entry[1]
            steps.add(operation)
            _LISTENER_STEPS[id(sock)] = (weakref.ref(sock), steps)
            if "bind" in steps and "listen" in steps:
                _ORIGINS[id(sock)] = (weakref.ref(sock), "real-listener")

    def _init_factory(self, saved_init):
        """A plain function (not a bound method): as a class attribute it
        receives the SOCKET as its first argument."""

        def _init(sock, *args, **kwargs) -> None:
            # The provenance is recorded as what was OBSERVED, not as a
            # guess about the family's intent:
            #   * created while the INSTALLED connector was on the stack ->
            #     "hvsock-monkeypatch-side";
            #   * otherwise the socket starts as UNKNOWN, and it is
            #     PROMOTED to "real-listener" if the capture later sees it
            #     BOUND and LISTENED on - which is the listener's own
            #     creation path, and is observable rather than inferred.
            # A socket that is neither stays "unknown": a negative
            # observation (the connector did not make it) does not
            # establish that the listener did.
            if _on_creation_stack(_installed_hvsock_connect()):
                origin = "hvsock-monkeypatch-side"
            else:
                origin = "unknown"
            # The origin is recorded BEFORE the constructor runs: a
            # constructor that FAILS is recorded against the origin its
            # creation stack already showed, not against "unknown".
            with self._lock:
                _ORIGINS[id(sock)] = (weakref.ref(sock), origin)
            try:
                saved_init(sock, *args, **kwargs)
            except OSError as exc:
                # `socket.socket(fileno=...)` with an invalid handle raises
                # the SAME WinError 10038, and the family uses exactly
                # that seam - so the constructor's failure is observed
                # here, not swallowed by the wrapper.
                if getattr(exc, "winerror", None) == _WINERROR_10038:
                    self._record("__init__", exc, sock)
                raise

        _init.__name__ = "__init__"
        return _init

    def _wrap(self, operation: str):
        original = _ORIGINAL_SOCKET_METHODS[operation]

        def _operation(sock, *args, **kwargs):
            try:
                result = original(sock, *args, **kwargs)
            except OSError as exc:
                if getattr(exc, "winerror", None) == _WINERROR_10038:
                    self._record(operation, exc, sock)
                raise
            if operation in ("bind", "listen"):
                self._note_listener_step(sock, operation)
            if operation == "dup" and isinstance(result, socket.socket):
                # `dup` hands the SAME handle to a NEW socket object, so
                # the duplicate carries the origin it was duplicated from
                # - the same handoff the accept seam performs.
                self._inherit_origin(sock, result)
            if operation == "accept" and isinstance(result, tuple):
                # `accept` returns a (connection, address) PAIR, so the
                # accepted socket is the pair's first element. The ACCEPTED
                # socket is on the listener's side of the connection, but it
                # performs no bind and listen of its own, so it inherits the
                # listener's observed provenance instead of being recorded
                # as unknown.
                accepted = result[0] if result else None
                if isinstance(accepted, socket.socket):
                    self._inherit_origin(sock, accepted)
            return result

        _operation.__name__ = operation
        return _operation

    # ---- the artifact ----

    def _record(self, operation: str, exc: BaseException, sock) -> None:
        """Write the diagnosis. Never raises: the test failure must win."""
        try:
            with self._lock:
                self._counter += 1
                counter = self._counter
                entry = _ORIGINS.get(id(sock))
                origin = "unknown"
                if entry is not None and entry[0]() is sock:
                    origin = entry[1]
            leg = _owning_leg()
            directory = _diagnosis_dir()
            directory.mkdir(parents=True, exist_ok=True)
            # Name components: leg, pid, the process-wide sequence (the
            # uniqueness guarantee - never reset by a re-activation, never
            # shared by concurrent writers), then the per-activation counter
            # (how many failures THIS activation has recorded). The sequence
            # alone makes the name unique for the process lifetime; the
            # counter is kept for readability only.
            name = f"socket-10038-{_safe_component(leg)}-{os.getpid()}-{_next_process_sequence()}-{counter}.json"
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


# The maximum length of the artifact's leg component. The full name is
# bounded because a file system's component limit is: a long
# PARAMETERIZED node name would otherwise produce a name over the limit,
# the write would fail, and the writer's failure is swallowed - the
# diagnosis would be LOST exactly when it was needed. Uniqueness does
# not come from this component (the pid, the process sequence and the
# per-activation counter carry it), so truncating it loses nothing.
_MAX_LEG_COMPONENT = 48


def _safe_component(text: str) -> str:
    """A WINDOWS-SAFE, BOUNDED file name component.

    The leg name is a pytest node name, and a PARAMETERIZED node name can
    contain characters Windows forbids in a file name (`<`, `>`, `:`, `"`,
    `|`, `?`, `*`). Only `/` was sanitized before, so the artifact write
    could fail - and the writer's failure is swallowed, so the diagnosis
    was LOST exactly when it was needed. Every character outside the
    safe set becomes `_`, and the component is truncated to
    `_MAX_LEG_COMPONENT`; the ORIGINAL leg stays in the artifact's
    content, so the attribution is not degraded by the file name.
    """
    safe = "".join(
        character if (character.isalnum() or character in "._-") else "_"
        for character in text
    )
    return safe[:_MAX_LEG_COMPONENT]


def _next_process_sequence() -> int:
    """A sequence value unique for the process lifetime, thread-safe."""
    global _PROCESS_SEQ
    with _SEQ_LOCK:
        _PROCESS_SEQ += 1
        return _PROCESS_SEQ


# Capture the shipped connector NOW, before a test can substitute it.
_original_hvsock_connect()

# The instance that currently owns the process-global patches.
_INSTALLED_BY: "SocketDiagnosis | None" = None

_ACTIVE: SocketDiagnosis | None = None


def activate() -> SocketDiagnosis:
    """Install the capture (idempotent) and return the active instance."""
    global _ACTIVE, _INSTALLED_BY
    if _ACTIVE is None:
        _ACTIVE = SocketDiagnosis()
    _ACTIVE.install()
    _INSTALLED_BY = _ACTIVE
    return _ACTIVE


def deactivate() -> None:
    """Remove the capture."""
    global _ACTIVE
    if _ACTIVE is not None:
        _ACTIVE.uninstall()
        _ACTIVE = None
