"""Frozen acceptance checks for issue #95's plan supplement (AC3/AC4): the
in-process WMI console backend must stay usable across replacement worker
threads, and a selected WMI input-method failure after worker replacement
must surface with worker/operation context instead of being replayed
through the PowerShell transport.

Token -> AC map:
  test_fresh_and_replacement_workers_use_live_com_services
      AC3: a fresh worker and then a replacement worker complete read-only
      console queries with the module's existing MTA-anchor state left at
      its natural value (the anchor is a retained regression control, not
      something these checks disable); a third query after the second
      worker also exits still succeeds, and the backend cache MUST record
      a creator surface naming the worker that served EACH query
      (plan-critic round-1 blocker 5: the surface is required, not a
      tolerant probe).
  test_replacement_worker_failure_does_not_replay_input
      AC4: an input-method failure after worker replacement surfaces as
      WMIError/ConsoleError carrying the serving worker's identity AND the
      concrete operation (method) context, with ZERO PowerShell transport
      calls (console input must never double-send).

The fakes model the SWbem lifetime observed in the incident: a service
object raises "Object is not connected to server" once its creator thread
has terminated, using Thread object identity so OS thread-ID reuse cannot
make the checks pass accidentally. Worker replacement is sequential
(start a thread, join it, then the next caller runs) so nothing races.
No VM mutation or live COM dependency is involved.
"""

import threading

from hyperv_mcp import console, pswindows, wmiconsole
from hyperv_mcp.config import Config
from hyperv_mcp.console import ConsoleError

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class _Path:
    def __init__(self, path: str) -> None:
        self.Path = path


class _Spawned:
    """InParameters.SpawnInstance_() product; parameters set by plain
    attribute assignment (the shape _exec_method uses)."""


class _InParameters:
    def SpawnInstance_(self) -> _Spawned:
        return _Spawned()


class _MethodDef:
    def __init__(self) -> None:
        self.InParameters = _InParameters()


class _Out:
    def __init__(self, return_value: int = 0) -> None:
        self.ReturnValue = return_value


class _Obj:
    """SWbemObject-shaped fake: Path_.Path, property getattr fallback, and
    Methods_/ExecMethod_ routed back to the owning service so the
    input-method path observes the same creator lifetime."""

    def __init__(self, service: "Service", path: str, **props) -> None:
        self._service = service
        self.Path_ = _Path(path)
        self._props = props

    def __getattr__(self, name: str):
        try:
            return self.__dict__["_props"][name]
        except KeyError:
            raise AttributeError(name) from None

    def Methods_(self, name: str):
        self._service.note_input_method(name)
        return _MethodDef()

    def ExecMethod_(self, name: str, in_params):
        self._service.note_input_method(name)
        return _Out()


class Service:
    """SWbemServices fake pinned to its creator thread's lifetime.

    ExecQuery/Get raise "Object is not connected to server" once the
    creator has terminated (the incident's failure mode). With
    fail_input_methods set, the input-method invocation path (Methods_ /
    ExecMethod_ of TypeText) raises the same error even on a LIVE service,
    so AC4's failure is forced deterministically after the fix reconnects
    for the replacement worker.
    """

    fail_input_methods = False

    def __init__(self) -> None:
        self.owner = threading.current_thread()
        self._vm = _Obj(
            self,
            'Msvm_ComputerSystem.Name="' + GUID + '"',
            Name=GUID,
            ElementName="vm1",
            EnabledState=2,
        )
        self._keyboard = _Obj(self, 'Msvm_Keyboard.Name="' + GUID + '-kb"')
        self._by_path = {
            self._vm.Path_.Path: self._vm,
            self._keyboard.Path_.Path: self._keyboard,
        }

    def _check(self) -> None:
        if (
            self.owner is not threading.current_thread()
            and not self.owner.is_alive()
        ):
            raise RuntimeError("Object is not connected to server")

    def note_input_method(self, method: str) -> None:
        self._check()
        if type(self).fail_input_methods and method == "TypeText":
            raise RuntimeError("Object is not connected to server")

    def ExecQuery(self, wql: str) -> list:
        self._check()
        text = " ".join(wql.split())
        # Keyboard first: the ASSOCIATORS lookup embeds the CS object path,
        # which itself contains the substring "Msvm_ComputerSystem".
        if "Msvm_Keyboard" in text:
            return [self._keyboard]
        if "Msvm_ComputerSystem" in text:
            return [self._vm]
        return []

    def Get(self, path: str) -> _Obj:
        self._check()
        return self._by_path[path]


class Locator:
    def ConnectServer(self, *args) -> Service:
        return Service()


def _install_fake_service(monkeypatch) -> None:
    """Fresh module caches plus the creator-lifetime fake at the _locator
    seam; the MTA-anchor state keeps its natural value (AC3's control)."""
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})
    monkeypatch.setattr(wmiconsole, "_locator", Locator)


def test_fresh_and_replacement_workers_use_live_com_services(monkeypatch):
    cfg = Config()
    _install_fake_service(monkeypatch)

    results: list = []
    errors: list = []
    served_by: list = []

    def query(worker_name: str) -> None:
        try:
            be = wmiconsole.backend(cfg)
            results.append(be._query_one("SELECT * FROM Msvm_ComputerSystem"))
            served_by.append(_required_creator(be, worker_name))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    def _required_creator(be, worker_name: str):
        # Plan-critic round-1 blocker 5: the creator surface is REQUIRED —
        # the cache must record which worker owns the backend it returned,
        # per query, not merely expose a tolerant probe.
        for attr in ("creator", "_creator", "creator_thread", "_creator_thread"):
            try:
                candidate = getattr(be, attr)
            except AttributeError:
                continue
            if isinstance(candidate, threading.Thread):
                return candidate
            raise AssertionError(
                f"creator surface {attr!r} is not a Thread: {candidate!r}"
            )
        raise AssertionError(
            "cached backend exposes no creator surface; the query provenance "
            "required by the supplement (which worker served each query) is "
            "not recorded"
        )

    # Fresh worker, then its replacement: each must complete the query, and
    # the backend it was served by must record THAT worker as creator.
    for name in ("wmi-worker-A", "wmi-worker-B"):
        worker = threading.Thread(target=query, args=(name,), name=name)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive(), "WORKER_QUERY_TIMED_OUT"
        assert not errors, "DISCONNECTED_CACHED_SERVICE: " + repr(errors)

    # Third query after worker B exited too (THIS thread is the next
    # replacement worker): the behavioral floor is three consecutive
    # replacement workers all succeeding.
    query(threading.current_thread().name)
    assert not errors, "DISCONNECTED_CACHED_SERVICE: " + repr(errors)
    assert len(results) == 3
    assert len(served_by) == 3
    # Per-query worker identity: leg 1 was served by a creator on worker A,
    # leg 2 on worker B (the replacement worker forced a reconnect on its
    # own thread), leg 3 by this thread.
    assert served_by[0].name == "wmi-worker-A", served_by[0].name
    assert served_by[1].name == "wmi-worker-B", served_by[1].name
    assert served_by[2] is threading.current_thread()


def test_replacement_worker_failure_does_not_replay_input(monkeypatch):
    cfg = Config(unrestricted=True)
    _install_fake_service(monkeypatch)
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", True)
    monkeypatch.setattr(Service, "fail_input_methods", True)

    # The PowerShell fallback seam every console transport call goes
    # through (console._run -> pswindows.run_ps, and vmident's resolver):
    # a sentinel that fails the test loudly if input is ever replayed.
    ps_calls: list = []

    def _no_ps_fallback(*args, **kwargs):
        ps_calls.append(args)
        raise AssertionError("PS FALLBACK NOT ALLOWED")

    monkeypatch.setattr(pswindows, "run_ps", _no_ps_fallback)

    # Worker A connects the backend (becoming its service's creator), then
    # exits — sequential, no racing threads.
    def connect_worker() -> None:
        wmiconsole.backend(cfg)

    worker_a = threading.Thread(target=connect_worker, name="wmi-connect-A")
    worker_a.start()
    worker_a.join(timeout=5)
    assert not worker_a.is_alive(), "CONNECT_WORKER_TIMED_OUT"

    # Replacement worker B drives a console input operation through the
    # console layer (selection included). After the fix reconnects the
    # service for B, the fake's input method fails; that failure must
    # SURFACE with worker AND operation context and must never reach
    # PowerShell.
    surfaced: list = []

    def input_worker() -> None:
        try:
            console.type_text(cfg, "vm1", "must-not-double-send")
        except Exception as exc:
            surfaced.append(exc)

    worker_b = threading.Thread(target=input_worker, name="wmi-input-B")
    worker_b.start()
    worker_b.join(timeout=15)
    assert not worker_b.is_alive(), "INPUT_WORKER_TIMED_OUT"

    assert len(surfaced) == 1, repr(surfaced)
    exc = surfaced[0]
    assert isinstance(exc, (wmiconsole.WMIError, ConsoleError)), type(exc)
    message = str(exc)
    assert "wmi-input-B" in message, (
        "input-method failure carries no worker identity: " + message
    )
    assert "TypeText" in message, (
        "input-method failure carries no operation context: " + message
    )
    assert ps_calls == [], (
        "console input was replayed through the PowerShell transport"
    )
