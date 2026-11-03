"""Frozen deterministic model of disconnected SWbem after creator-thread exit.

Adapted from issue #95's supplied driver to the current source symbols (the
issue anchor predates the mcp 2.x migration). The fake raises only when a
service's creator has terminated, and uses Thread object identity so OS
thread-ID reuse cannot make it pass accidentally. No VM mutation or live COM
dependency is involved.
"""
import threading

from hyperv_mcp import wmiconsole
from hyperv_mcp.config import Config


def test_replacement_worker_can_query(monkeypatch):
    cfg = Config()
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})
    monkeypatch.setattr(wmiconsole, "_COM_IMPORT_OK", False)
    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)

    class Service:
        def __init__(self):
            self.owner = threading.current_thread()

        def ExecQuery(self, query):
            if self.owner is not threading.current_thread() and not self.owner.is_alive():
                raise RuntimeError("Object is not connected to server")
            return [{"name": "mock-vm"}]

    class Locator:
        def ConnectServer(self, *args):
            return Service()

    monkeypatch.setattr(wmiconsole, "_locator", Locator)

    results, errors = [], []

    def query():
        try:
            be = wmiconsole.backend(cfg)
            row = be._query_one("SELECT * FROM Msvm_ComputerSystem")
            # A REAL row, not a None (an empty query) that a count-only
            # assertion would accept (implementation-review).
            assert row is not None, "console query returned no row"
            results.append(row)
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    for _ in range(4):
        thread = threading.Thread(target=query)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive(), "WORKER_QUERY_TIMED_OUT"

    assert not errors, "DISCONNECTED_CACHED_SERVICE: " + repr(errors)
    assert len(results) == 4
