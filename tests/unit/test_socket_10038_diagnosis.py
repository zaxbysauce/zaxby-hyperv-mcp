"""Tests for the operation-time WinError 10038 capture (issue #167 AC3).

The capture's whole purpose is to survive the socket family's habit of
swallowing the exception: these checks therefore drive the capture
directly, through a socket operation that really raises
`OSError: [WinError 10038]` on this platform, and assert both what the
artifact says and what the test still observes.
"""

import json
import os
import socket
import threading

import pytest
from _socket_10038_diagnosis import DIAG_DIR_ENV, activate, deactivate

from hyperv_mcp import hvsock

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="WinError 10038 is Windows-only"
)


@pytest.fixture()
def capture(tmp_path, monkeypatch):
    """Activate the capture with its artifact directory pointed at a scratch path."""
    monkeypatch.setenv(DIAG_DIR_ENV, str(tmp_path / "diag"))
    activate()
    try:
        yield tmp_path / "diag"
    finally:
        deactivate()


def _closed_socket() -> socket.socket:
    """A socket whose handle is no longer a socket (recv raises 10038)."""
    sock = socket.socket()
    sock.close()
    return sock


def _artifacts(directory) -> list[dict]:
    if not directory.exists():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        out.append(json.loads(path.read_text(encoding="utf-8")))
    return out


def test_capture_records_the_hvsock_monkeypatch_origin(capture, monkeypatch):
    """A socket handed out by the function installed at hvsock.connect is
    classified as the monkeypatch side."""
    created: list[socket.socket] = []

    def fake_connect(*args, **kwargs):
        sock = socket.socket()
        created.append(sock)
        return sock

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    sock = hvsock.connect("vm", 1)
    sock.close()
    with pytest.raises(OSError) as excinfo:
        sock.recv(64)
    assert getattr(excinfo.value, "winerror", None) == 10038

    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["handle_origin"] == "hvsock-monkeypatch-side"


def test_capture_records_the_real_listener_origin(capture):
    """A socket created outside the hvsock.connect path is classified as
    the real-listener side."""
    sock = _closed_socket()
    with pytest.raises(OSError):
        sock.recv(64)
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["handle_origin"] == "real-listener"


def test_capture_names_the_operation_and_the_owning_leg(capture):
    """The artifact names the failing operation and the leg that was running."""
    sock = _closed_socket()
    with pytest.raises(OSError):
        sock.recv(64)
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["operation"] == "recv"
    assert artifacts[0]["owning_leg"] == (
        "test_capture_names_the_operation_and_the_owning_leg"
    )
    assert artifacts[0]["winerror"] == 10038


def test_capture_survives_an_exception_swallowed_by_a_background_thread(capture):
    """The evidence exists even when the failing thread swallows the error -
    the case the socket family actually hits."""
    sock = _closed_socket()
    seen: list[BaseException] = []

    def worker():
        try:
            sock.recv(64)
        except OSError as exc:  # the family's own swallow
            seen.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert seen and getattr(seen[0], "winerror", None) == 10038
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["operation"] == "recv"


def test_capture_ignores_a_non_10038_oserror(capture):
    """A different OSError is not captured, and it is not masked."""
    sock = socket.socket()
    try:
        with pytest.raises(OSError) as excinfo:
            sock.settimeout(0.01)
            sock.connect(("192.0.2.1", 9))
        assert getattr(excinfo.value, "winerror", None) != 10038
    finally:
        sock.close()
    assert _artifacts(capture) == [], "a non-10038 error must not be captured"


def test_capture_never_masks_the_original_failure(capture):
    """The original error still reaches the caller."""
    sock = _closed_socket()
    with pytest.raises(OSError) as excinfo:
        sock.recv(64)
    assert getattr(excinfo.value, "winerror", None) == 10038
    assert isinstance(excinfo.value, OSError)


def test_a_failing_writer_does_not_mask_the_test_failure(capture, monkeypatch, tmp_path):
    """When the artifact cannot be written, the original failure still surfaces."""
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv(DIAG_DIR_ENV, str(blocked / "diag"))
    sock = _closed_socket()
    with pytest.raises(OSError) as excinfo:
        sock.recv(64)
    assert getattr(excinfo.value, "winerror", None) == 10038


def test_concurrent_failures_do_not_overwrite_each_other(capture):
    """Two legs failing at once produce two artifacts, not one."""
    sockets = [_closed_socket() for _ in range(2)]
    errors: list[BaseException] = []

    def worker(sock):
        try:
            sock.recv(64)
        except OSError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(s,)) for s in sockets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert len(errors) == 2, f"expected two swallowed errors, got {errors}"
    artifacts = _artifacts(capture)
    assert len(artifacts) == 2, f"expected two artifacts, got {artifacts}"
    names = {path.name for path in capture.glob("*.json")}
    assert len(names) == 2, f"artifact names must be unique: {names}"
