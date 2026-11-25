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
    the side the installed connector did NOT produce. The capture records
    only what it can establish - whether the socket was created while the
    installed connector was on the stack - so it does not claim a family
    role it cannot prove."""
    sock = _closed_socket()
    with pytest.raises(OSError):
        sock.recv(64)
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["handle_origin"] == "not-the-installed-connector"


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
    # The owning leg must name the TEST, not the thread's target: a
    # background thread's own stack carries only its frames, so a stack-only
    # attribution says "worker" and cannot identify one test among a
    # 35-test cascade.
    assert artifacts[0]["owning_leg"] == (
        "test_capture_survives_an_exception_swallowed_by_a_background_thread"
    ), f"expected the owning test, got {artifacts[0]['owning_leg']!r}"


def test_capture_attributes_a_nested_helper_to_the_running_test(capture):
    """A failure inside a helper the TEST called names the TEST.

    A helper is an implementation detail of the test that called it, so
    naming the helper would not identify which of a 35-test cascade
    failed. (A failure raised while a FIXTURE runs is a different shape:
    no test function is on the stack then, and the fixture owns it - the
    frozen oracle pins that case.)
    """
    def nested_helper():
        sock = _closed_socket()
        sock.recv(64)

    with pytest.raises(OSError):
        nested_helper()
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["owning_leg"] == (
        "test_capture_attributes_a_nested_helper_to_the_running_test"
    ), f"expected the running test, got {artifacts[0]['owning_leg']!r}"


@pytest.fixture()
def owning_fixture():
    """A fixture whose nested helper fails - the family's fixture shape.

    A fixture executes during SETUP, before the test body, so no test
    function is on the stack when the failure is captured. The error is
    swallowed here so the test body can still assert on the artifact (a
    fixture that raised would make the test ERROR before its body ran).
    """
    def nested_helper():
        sock = _closed_socket()
        sock.recv(64)

    try:
        nested_helper()
    except OSError:
        pass


def test_capture_attributes_a_fixture_failure_to_the_fixture(capture, owning_fixture):
    """A failure raised while a FIXTURE runs names the fixture.

    The outermost test-module frame is the fixture that owns the failure.
    The frozen synthetic oracle pins this shape too (`synthetic_hvsock_leg`).
    """
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["owning_leg"] == "owning_fixture", (
        f"expected the owning fixture, got {artifacts[0]['owning_leg']!r}"
    )


@pytest.fixture()
def thread_starting_fixture():
    """A FIXTURE that starts a thread whose socket operation fails.

    This is the family's shape: the fixture owns the work, and the failure
    happens on the thread - whose own stack cannot show the fixture that
    started it.
    """
    errors: list[BaseException] = []

    def worker():
        sock = _closed_socket()
        sock.recv(64)

    def guarded():
        try:
            worker()
        except OSError as exc:  # the family's own swallow
            errors.append(exc)

    thread = threading.Thread(target=guarded)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert errors and getattr(errors[0], "winerror", None) == 10038
    return errors


def test_capture_attributes_a_fixture_started_thread_to_the_fixture(
    capture, thread_starting_fixture
):
    """A thread started by a FIXTURE names that fixture, not the test."""
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["owning_leg"] == "thread_starting_fixture", (
        f"expected the starting fixture, got {artifacts[0]['owning_leg']!r}"
    )
    assert artifacts[0]["operation"] == "recv"


def test_capture_records_a_10038_raised_by_shutdown(capture):
    """`shutdown` on a closed socket raises the same 10038 the family sees.

    The family calls shutdown and swallows the error, so without the
    capture on that operation a real failure of that shape would leave no
    evidence at all.
    """
    sock = _closed_socket()
    with pytest.raises(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["operation"] == "shutdown"
    assert artifacts[0]["winerror"] == 10038


@pytest.fixture()
def helper_started_thread_fixture():
    """A FIXTURE that calls a HELPER which starts the thread.

    The thread's own stack carries only its frames, and the helper sits
    between the fixture and the start call - so the owning leg is the
    fixture, not the helper.
    """
    errors: list[BaseException] = []

    def helper_starts_thread():
        def worker():
            sock = _closed_socket()
            sock.recv(64)

        def guarded():
            try:
                worker()
            except OSError as exc:  # the family's own swallow
                errors.append(exc)

        thread = threading.Thread(target=guarded)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()

    helper_starts_thread()
    assert errors and getattr(errors[0], "winerror", None) == 10038


def test_capture_attributes_a_helper_started_thread_to_its_fixture(
    capture, helper_started_thread_fixture
):
    """A thread started by a helper a FIXTURE called names the FIXTURE."""
    artifacts = _artifacts(capture)
    assert len(artifacts) == 1, f"expected one artifact, got {artifacts}"
    assert artifacts[0]["owning_leg"] == "helper_started_thread_fixture", (
        f"expected the owning fixture, got {artifacts[0]['owning_leg']!r}"
    )


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


def test_reactivation_does_not_overwrite_an_earlier_artifact(tmp_path, monkeypatch):
    """Two activate/deactivate cycles with the SAME owning leg leave two
    artifacts, and both survive on disk.

    The per-test conftest fixture deactivates the capture after every test,
    so whatever keeps artifact names unique must outlive ONE activation: a
    counter that resets with each new activation makes the second failure
    reuse the first artifact's filename, and tmp.replace(target) silently
    destroys the earlier evidence."""
    diag = tmp_path / "diag"
    monkeypatch.setenv(DIAG_DIR_ENV, str(diag))

    def failing_leg():
        activate()
        try:
            sock = _closed_socket()
            with pytest.raises(OSError) as excinfo:
                sock.recv(64)
            assert getattr(excinfo.value, "winerror", None) == 10038
        finally:
            deactivate()

    failing_leg()
    failing_leg()

    names = {path.name for path in diag.glob("*.json")}
    assert len(names) == 2, (
        f"two activations with the same leg must leave two distinct "
        f"artifacts, got {sorted(names)}"
    )
    artifacts = _artifacts(diag)
    assert len(artifacts) == 2, f"both artifacts must survive on disk: {artifacts}"
    # Both failures attribute to the SAME leg - distinct filenames, not a
    # distinct leg, are what keeps the two artifacts apart. The leg is the
    # test that was running (the helper is an implementation detail of it).
    assert {a["owning_leg"] for a in artifacts} == {
        "test_reactivation_does_not_overwrite_an_earlier_artifact"
    }
    assert all(a["winerror"] == 10038 for a in artifacts)
