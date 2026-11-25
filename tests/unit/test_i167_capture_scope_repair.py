"""The capture's removal must be the LAST word on the socket class.

A test's ``monkeypatch`` saves the value it FINDS, and while the capture is
installed that value is the CAPTURE'S WRAPPER. pytest finalizes the
``monkeypatch`` fixture AFTER the capture's own teardown, so the undo puts
the wrapper back after the capture removed it. The socket class then keeps a
capture wrapper for the rest of the session, and the rest of the suite sees
a patched socket class that records nothing - the promise the conftest
states ("the rest of the unit suite must never see a patched socket class")
is broken (issue #167 AC3; the round-23 plan gate's executed probe).

The two tests below are ONE scenario in two halves, and the order matters:
the first creates the late restore, the second observes the state the next
test starts from. pytest runs the tests of a file in definition order.
"""

import socket
import threading

from _socket_10038_diagnosis import _ORIGINAL_SOCKET_METHODS

# The pristine values, captured when this module is imported (collection
# time, before any test runs). The capture module's own record is the
# authoritative one for the socket methods: it is captured at ITS import,
# before any test can substitute a value.
_PRISTINE_SETSOCKOPT = _ORIGINAL_SOCKET_METHODS["setsockopt"]
_PRISTINE_THREAD_START = threading.Thread.start


def test_a_a_late_restore_puts_the_capture_wrapper_back(monkeypatch):
    """Reproduce the ordering: the capture installs, the test's monkeypatch
    saves the capture's wrapper, the capture is removed, and the monkeypatch
    undo puts the wrapper back."""
    from _socket_10038_diagnosis import activate, deactivate

    def spy(self, *args, **kwargs):
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    activate()
    try:
        assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT, (
            "the capture must have installed its wrapper before the test "
            "substitutes the method")
        # The substitution SAVES what it finds - the capture's wrapper.
        monkeypatch.setattr(socket.socket, "setsockopt", spy)
    finally:
        deactivate()

    assert socket.socket.setsockopt is _PRISTINE_SETSOCKOPT, (
        "the capture's own removal must restore the pristine method")
    monkeypatch.undo()
    assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT, (
        "the late restore must put the capture's wrapper back - that is the "
        "condition the repair has to survive")


def test_b_the_socket_class_is_pristine_after_the_late_restore():
    """The state the NEXT test starts from: no capture outside its scope."""
    assert socket.socket.setsockopt is _PRISTINE_SETSOCKOPT, (
        "a capture wrapper survived the test that installed it: the rest of "
        "the suite would see a patched socket class")
    assert threading.Thread.start is _PRISTINE_THREAD_START, (
        "the capture's thread-leg recorder survived the test that installed "
        "it")


def test_c_a_patch_that_is_not_the_capture_survives_the_repair():
    """The repair restores the CAPTURE's wrappers, not other patches.

    A fixture that outlives a single test may legitimately patch a socket
    method or `Thread.start`; the repair runs after EVERY test's teardown,
    so a repair that restored every non-pristine attribute would stomp
    that patch before the next test could use it. The repair therefore
    restores only the wrappers this capture installed.
    """
    from _socket_10038_diagnosis import restore_pristine_socket_methods

    def sentinel(self, *args, **kwargs):
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    socket.socket.setsockopt = sentinel
    try:
        assert restore_pristine_socket_methods() == 0, (
            "the repair must not touch a patch that is not the capture's")
        assert socket.socket.setsockopt is sentinel, (
            "the repair replaced a patch that is not the capture's")
    finally:
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT
