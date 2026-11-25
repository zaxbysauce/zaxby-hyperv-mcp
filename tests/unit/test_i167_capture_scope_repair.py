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

    # The capture's removal leaves the TEST's own patch in place: the
    # capture restores only what still holds its own wrapper.
    assert socket.socket.setsockopt is spy, (
        "the capture's removal replaced a patch it did not make")
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


def test_d_a_longer_lived_patch_survives_the_capture_lifecycle():
    """A patch the capture did not make survives its WHOLE lifecycle.

    A fixture that outlives a single test may own a patch of its own. The
    capture must neither BYPASS it (its wrapper delegates to the method
    that was in place when it installed) nor DESTROY it (its removal
    restores that method, not the import-time one) - and the teardown
    repair must not touch it either.
    """
    from _socket_10038_diagnosis import activate, deactivate, restore_pristine_socket_methods

    calls: list[str] = []

    def sentinel(self, *args, **kwargs):
        calls.append("sentinel")
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    socket.socket.setsockopt = sentinel
    try:
        activate()
        try:
            assert socket.socket.setsockopt is not sentinel, (
                "the capture installed its own wrapper")
            sock = socket.socket()
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            finally:
                sock.close()
            assert calls, (
                "the capture's wrapper bypassed the patch that was in place "
                "before it installed")
        finally:
            deactivate()
        assert socket.socket.setsockopt is sentinel, (
            "the capture's removal destroyed a patch it did not make")
        assert restore_pristine_socket_methods() == 0, (
            "the repair must not touch a patch the capture did not make")
        assert socket.socket.setsockopt is sentinel, (
            "the repair replaced a patch the capture did not make")
    finally:
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT


def test_e_a_patch_installed_while_the_capture_is_active_survives_it():
    """A patch that appears DURING the capture's life is not the capture's.

    The capture restores only what still holds its own wrapper, so a patch
    another party installs while the capture is active survives the
    capture's removal - the capture did not make it and must not destroy
    it.
    """
    from _socket_10038_diagnosis import activate, deactivate

    def late(self, *args, **kwargs):
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    activate()
    try:
        socket.socket.setsockopt = late
    finally:
        deactivate()
    try:
        assert socket.socket.setsockopt is late, (
            "the capture's removal replaced a patch that was installed while "
            "it was active")
    finally:
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT


def test_f_a_wrapper_around_the_capture_wrapper_is_not_the_capture_s():
    """Ownership is decided by IDENTITY, not by a copyable marker.

    `functools.wraps` copies a function's attributes, so a wrapper built
    around the capture's wrapper would carry any marker the capture set on
    it. Such a wrapper belongs to the other party, and neither the
    capture's removal nor the repair may replace it.
    """
    import functools

    from _socket_10038_diagnosis import activate, deactivate, restore_pristine_socket_methods

    activate()
    try:
        capture_wrapper = socket.socket.setsockopt

        @functools.wraps(capture_wrapper)
        def around(*args, **kwargs):
            return capture_wrapper(*args, **kwargs)

        socket.socket.setsockopt = around
    finally:
        deactivate()
    try:
        assert socket.socket.setsockopt is around, (
            "the capture's removal replaced a wrapper that is not its own")
        assert restore_pristine_socket_methods() == 0, (
            "the repair counted a wrapper it does not own")
        assert socket.socket.setsockopt is around, (
            "the repair replaced a wrapper it does not own")
    finally:
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT


def test_g_a_late_restore_from_an_earlier_activation_is_still_repaired(monkeypatch):
    """A wrapper saved by an EARLIER activation is still the capture's own.

    The capture can be deactivated and activated again while a test's
    `monkeypatch` still holds the first activation's wrapper. The late
    restore then puts THAT wrapper back, and the repair has to recognise
    it - a registry that remembers only the latest wrapper per name would
    leave it installed for the rest of the session.
    """
    from _socket_10038_diagnosis import activate, deactivate, restore_pristine_socket_methods

    def spy(self, *args, **kwargs):
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    activate()
    try:
        # the substitution SAVES the first activation's wrapper
        monkeypatch.setattr(socket.socket, "setsockopt", spy)
    finally:
        deactivate()
    activate()
    try:
        pass
    finally:
        deactivate()
    monkeypatch.undo()
    assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT, (
        "the late restore must put the first activation's wrapper back")
    assert restore_pristine_socket_methods() == 1, (
        "the repair must recognise the earlier activation's wrapper")
    assert socket.socket.setsockopt is _PRISTINE_SETSOCKOPT, (
        "the repair did not restore the value the earlier activation "
        "displaced")


def test_h_a_nested_displacement_is_unwound(monkeypatch):
    """A wrapper that displaced an EARLIER capture wrapper is unwound.

    A later activation can install over a wrapper that a late restore put
    back, so the later wrapper's displaced value is itself a capture
    wrapper. Restoring one step would leave the earlier wrapper installed,
    so the repair walks the chain down to the first value the capture does
    NOT own.
    """
    from _socket_10038_diagnosis import activate, deactivate, restore_pristine_socket_methods

    def spy(self, *args, **kwargs):
        return _PRISTINE_SETSOCKOPT(self, *args, **kwargs)

    # activation A installs, the test saves A's wrapper, A is removed, and
    # the late restore puts A's wrapper back
    activate()
    try:
        monkeypatch.setattr(socket.socket, "setsockopt", spy)
    finally:
        deactivate()
    monkeypatch.undo()

    # activation B installs OVER A's wrapper, so B displaced A's wrapper
    activate()
    try:
        assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT
        monkeypatch.setattr(socket.socket, "setsockopt", spy)
    finally:
        deactivate()
    monkeypatch.undo()

    assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT, (
        "the late restore must put the newer wrapper back")
    assert restore_pristine_socket_methods() == 1, (
        "the repair must unwind the nested displacement")
    assert socket.socket.setsockopt is _PRISTINE_SETSOCKOPT, (
        "the repair left an EARLIER capture wrapper installed")


def test_i_a_nested_thread_displacement_is_unwound(monkeypatch):
    """The same unwinding applies to `Thread.start`.

    The capture's thread-leg recorder patches `Thread.start` too, so a
    nested displacement there would leave a capture wrapper installed for
    the rest of the session - and a wrapper that still records legs.
    """
    from _socket_10038_diagnosis import activate, deactivate

    def spy(self, *args, **kwargs):
        return _PRISTINE_THREAD_START(self, *args, **kwargs)

    activate()
    try:
        # the substitution SAVES the first activation's thread wrapper
        monkeypatch.setattr(threading.Thread, "start", spy)
    finally:
        deactivate()
    monkeypatch.undo()

    activate()
    try:
        assert threading.Thread.start is not _PRISTINE_THREAD_START
    finally:
        deactivate()
    assert threading.Thread.start is _PRISTINE_THREAD_START, (
        "the capture's removal left an earlier capture wrapper installed on "
        "Thread.start")


def test_j_the_repair_runs_even_when_a_finalizer_raises():
    """The repair must run on the ERROR path too.

    When a finalizer raises, the exception is thrown at the hook's yield
    point - so a repair placed after the yield would be skipped, exactly
    where a leaked wrapper matters most. The hook is driven directly here:
    it is driven with a raised exception, and the repair must still have
    run.
    """
    import importlib.util
    import pathlib

    from _socket_10038_diagnosis import activate, deactivate

    activate()
    try:
        wrapper = socket.socket.setsockopt
    finally:
        deactivate()
    # the late restore: the capture's wrapper is back
    socket.socket.setsockopt = wrapper
    assert socket.socket.setsockopt is not _PRISTINE_SETSOCKOPT

    conftest_path = pathlib.Path(__file__).with_name("conftest.py")
    spec = importlib.util.spec_from_file_location("i167_scope_conftest",
                                                  conftest_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    generator = module.pytest_runtest_teardown(None, None)
    next(generator)
    try:
        generator.throw(RuntimeError("the teardown failed"))
    except RuntimeError:
        pass
    repaired = socket.socket.setsockopt is _PRISTINE_SETSOCKOPT
    socket.socket.setsockopt = _PRISTINE_SETSOCKOPT
    assert repaired, (
        "the repair must run even when a finalizer raises: the wrapper the "
        "failing finalizer restored would otherwise stay installed")
