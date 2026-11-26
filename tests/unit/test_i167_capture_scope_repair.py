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


def test_k_a_retained_foreign_wrapper_cannot_record_after_deactivation(tmp_path,
                                                                      monkeypatch):
    """A wrapper a foreign patch kept must be INERT after the activation.

    Preserving the foreign patch also preserves its reference to the
    capture's wrapper, and that reference stayed operational: a later call
    through it still recorded a diagnosis artifact (the round-9
    implementation reviewer's finding). The capture's wrappers now delegate
    WITHOUT recording once their activation is over.
    """
    import functools

    import pytest
    from _socket_10038_diagnosis import activate, deactivate

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))
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
        sock = socket.socket()
        try:
            sock.close()
            with pytest.raises(OSError) as excinfo:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            assert getattr(excinfo.value, "winerror", None) == 10038, (
                "the probe must raise the WinError 10038 the capture observes")
        finally:
            try:
                sock.close()
            except OSError:
                pass
        assert not list(tmp_path.iterdir()), (
            "the retained capture wrapper still recorded a diagnosis after "
            f"its activation ended: {list(tmp_path.iterdir())}")
    finally:
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT


def test_l_a_reinstalled_instance_does_not_reactivate_an_earlier_wrapper(tmp_path,
                                                                          monkeypatch):
    """Reusing the SAME instance must not revive an earlier installation.

    The capture's contract allows a direct `install()`/`uninstall()` reuse
    of one instance. With a per-INSTANCE active flag, the second
    installation reactivated the wrappers of the FIRST one - so a wrapper a
    foreign patch had retained could record again, and could record twice
    when the call reached both wrappers. The activity is bound to the
    individual INSTALLATION instead.
    """
    import functools

    import pytest
    from _socket_10038_diagnosis import SocketDiagnosis

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))
    diagnosis = SocketDiagnosis()
    diagnosis.install()
    try:
        first_wrapper = socket.socket.setsockopt

        @functools.wraps(first_wrapper)
        def around(*args, **kwargs):
            return first_wrapper(*args, **kwargs)

        socket.socket.setsockopt = around
    finally:
        diagnosis.uninstall()
    try:
        diagnosis.install()
        sock = socket.socket()
        try:
            sock.close()
            # the RETAINED wrapper belongs to the FIRST installation and
            # must be inert, even though the instance is installed again
            with pytest.raises(OSError):
                around(sock, socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        assert not list(tmp_path.iterdir()), (
            "the earlier installation's wrapper recorded again after the "
            f"instance was reinstalled: {list(tmp_path.iterdir())}")
    finally:
        diagnosis.uninstall()
        socket.socket.setsockopt = _PRISTINE_SETSOCKOPT


def test_m_a_call_in_flight_when_the_capture_ends_records_nothing(tmp_path,
                                                                  monkeypatch):
    """A call that was ALREADY IN FLIGHT when the capture ended records nothing.

    The wrapper checks its installation BEFORE the call, so a call that
    blocks inside the socket method and raises the WinError 10038 after the
    capture was deactivated used to write a diagnosis - outside the
    activation it belonged to. The recording is bound to the installation
    that COMMITS it.
    """
    import threading

    from _socket_10038_diagnosis import activate, deactivate

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))
    entered = threading.Event()
    release = threading.Event()

    def blocking(self, *args, **kwargs):
        entered.set()
        release.wait(30)
        error = OSError("the socket was invalidated")
        error.winerror = 10038
        raise error

    monkeypatch.setattr(socket.socket, "recv", blocking)
    activate()
    thread = threading.Thread(target=lambda: _recv_once())
    try:
        thread.start()
        assert entered.wait(30), "the operation did not start"
    finally:
        deactivate()
        release.set()
        thread.join(30)
    assert not list(tmp_path.iterdir()), (
        "an operation that was in flight when the capture ended still recorded "
        f"a diagnosis: {list(tmp_path.iterdir())}")


def _recv_once():
    """One recv on a fresh socket; the error is expected."""
    sock = socket.socket()
    try:
        sock.recv(1)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_n_a_constructor_in_flight_when_the_capture_ends_records_nothing(tmp_path,
                                                                        monkeypatch):
    """A CONSTRUCTOR that was already in flight when the capture ended records
    nothing.

    The operation wrapper got that rule; the constructor had the same
    check-before-call shape, so a constructor that blocked and raised the
    WinError 10038 after the deactivation still wrote a diagnosis.
    """
    import threading

    from _socket_10038_diagnosis import activate, deactivate

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))
    entered = threading.Event()
    release = threading.Event()

    def blocking(self, *args, **kwargs):
        entered.set()
        release.wait(30)
        error = OSError("the socket was invalidated")
        error.winerror = 10038
        raise error

    monkeypatch.setattr(socket.socket, "__init__", blocking)
    activate()
    thread = threading.Thread(target=_construct_once)
    try:
        thread.start()
        assert entered.wait(30), "the constructor did not start"
    finally:
        deactivate()
        release.set()
        thread.join(30)
    assert not list(tmp_path.iterdir()), (
        "a constructor that was in flight when the capture ended still "
        f"recorded a diagnosis: {list(tmp_path.iterdir())}")


def _construct_once():
    """One construction on a fresh socket; the error is expected."""
    try:
        socket.socket(fileno=1)
    except OSError:
        pass


def _pause_between_check_and_commit(monkeypatch):
    """Make the capture's recording WAIT after the wrapper's token check.

    Returns (reached, release): the wrapper has passed its own activation
    check and called _record when `reached` is set; _record proceeds when
    `release` is set. That is exactly the window between the check and the
    commit.
    """
    import threading

    import _socket_10038_diagnosis as capture

    reached = threading.Event()
    release = threading.Event()
    instance = capture._ACTIVE
    original = instance._record

    def paused(*args, **kwargs):
        reached.set()
        release.wait(30)
        return original(*args, **kwargs)

    monkeypatch.setattr(instance, "_record", paused)
    return reached, release


def test_o_a_call_paused_between_the_check_and_the_commit_records_nothing(
        tmp_path, monkeypatch):
    """The activation check and the commit are ONE step.

    A call that passed the wrapper's token check and then paused before the
    recording must not write after the deactivation completed - the check
    that counts is the one made under the lock that ends the activation.
    """
    import threading

    from _socket_10038_diagnosis import activate, deactivate

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))

    def failing(self, *args, **kwargs):
        error = OSError("the socket was invalidated")
        error.winerror = 10038
        raise error

    monkeypatch.setattr(socket.socket, "recv", failing)
    activate()
    reached, release = _pause_between_check_and_commit(monkeypatch)
    thread = threading.Thread(target=_recv_once)
    try:
        thread.start()
        assert reached.wait(30), "the wrapper never reached the recording"
    finally:
        deactivate()
        release.set()
        thread.join(30)
    assert not list(tmp_path.iterdir()), (
        "a call that paused between the check and the commit still recorded "
        f"a diagnosis: {list(tmp_path.iterdir())}")


def test_p_a_constructor_paused_between_the_check_and_the_commit_records_nothing(
        tmp_path, monkeypatch):
    """The same single-step rule for the CONSTRUCTOR's recording."""
    import threading

    from _socket_10038_diagnosis import activate, deactivate

    monkeypatch.setenv("HYPERV_MCP_10038_DIAG_DIR", str(tmp_path))

    def failing(self, *args, **kwargs):
        error = OSError("the socket was invalidated")
        error.winerror = 10038
        raise error

    monkeypatch.setattr(socket.socket, "__init__", failing)
    activate()
    reached, release = _pause_between_check_and_commit(monkeypatch)
    thread = threading.Thread(target=_construct_once)
    try:
        thread.start()
        assert reached.wait(30), "the constructor never reached the recording"
    finally:
        deactivate()
        release.set()
        thread.join(30)
    assert not list(tmp_path.iterdir()), (
        "a constructor that paused between the check and the commit still "
        f"recorded a diagnosis: {list(tmp_path.iterdir())}")


def _pause_at(monkeypatch, owner, attribute):
    """Make `owner.attribute` WAIT before running, once the wrapper reaches it.

    Returns (reached, release): `reached` is set when the wrapper has passed
    its own activation check and called the commit function; the commit
    proceeds when `release` is set - the window between check and commit.
    """
    import threading

    reached = threading.Event()
    release = threading.Event()
    original = getattr(owner, attribute)

    def paused(*args, **kwargs):
        reached.set()
        release.wait(30)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, attribute, paused)
    return reached, release


def _run_paused(action, reached, release):
    """Run `action` on a thread; deactivate once it reaches the commit."""
    import threading

    from _socket_10038_diagnosis import deactivate

    thread = threading.Thread(target=action)
    try:
        thread.start()
        assert reached.wait(30), "the wrapper never reached the commit"
    finally:
        deactivate()
        release.set()
        thread.join(30)


def test_q_a_listener_step_paused_before_its_commit_records_nothing(monkeypatch):
    """The listener-step provenance commit is bound to its installation under
    the lock the deactivation takes."""
    import _socket_10038_diagnosis as capture
    from _socket_10038_diagnosis import activate

    activate()
    reached, release = _pause_at(monkeypatch, capture._ACTIVE,
                                 "_note_listener_step")
    sock = socket.socket()
    try:
        _run_paused(lambda: sock.bind(("127.0.0.1", 0)), reached, release)
        entry = capture._LISTENER_STEPS.get(id(sock))
        assert entry is None or entry[0]() is not sock, (
            "a bind that paused between the check and the commit recorded a "
            "listener step after the capture ended")
    finally:
        sock.close()


def test_r_an_inherited_origin_paused_before_its_commit_records_nothing(
        monkeypatch):
    """The inherited-origin provenance commit is bound the same way."""
    import weakref

    import _socket_10038_diagnosis as capture
    from _socket_10038_diagnosis import activate

    activate()
    source = socket.socket()
    capture._ORIGINS[id(source)] = (weakref.ref(source),
                                    "hvsock-monkeypatch-side")
    reached, release = _pause_at(monkeypatch, capture._ACTIVE,
                                 "_inherit_origin")
    duplicated = []
    try:
        _run_paused(lambda: duplicated.append(source.dup()), reached, release)
        for other in duplicated:
            entry = capture._ORIGINS.get(id(other))
            assert entry is None or entry[0]() is not other or (
                entry[1] != "hvsock-monkeypatch-side"), (
                "a dup that paused between the check and the commit inherited "
                "an origin after the capture ended")
    finally:
        for other in duplicated:
            other.close()
        source.close()


def test_s_a_constructor_origin_paused_before_its_commit_records_nothing(
        monkeypatch):
    """The constructor's origin commit is bound the same way."""
    import _socket_10038_diagnosis as capture
    from _socket_10038_diagnosis import activate

    activate()
    reached, release = _pause_at(monkeypatch, capture, "_on_creation_stack")
    built = []
    try:
        _run_paused(lambda: built.append(socket.socket()), reached, release)
        for sock in built:
            entry = capture._ORIGINS.get(id(sock))
            assert entry is None or entry[0]() is not sock, (
                "a constructor that paused between the check and the commit "
                "recorded an origin after the capture ended")
    finally:
        for sock in built:
            sock.close()


def _leg_registered(capture, thread):
    entry = capture._THREAD_LEGS.get(id(thread))
    return entry is not None and entry[0]() is thread


def test_t_a_thread_leg_commit_is_final_when_the_capture_ends(monkeypatch):
    """A thread-leg registration paused between its check and its commit is
    final by the time the deactivation completes.

    The deactivation runs on a RAW thread (the capture's own Thread.start
    wrapper must not be involved) while the registering thread is paused
    inside the commit. If the deactivation can COMPLETE while the commit is
    still pending, the registry changes after the capture ended: the state
    seen right after the deactivation must then equal the final state.
    """
    import _thread
    import threading
    import weakref as real_weakref

    import _socket_10038_diagnosis as capture
    from _socket_10038_diagnosis import activate

    activate()
    go = threading.Event()
    reached = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    inner = threading.Thread(target=lambda: None)

    class PausedWeakref:
        """The module's `weakref`, pausing when the thread-leg entry is made."""

        def __getattr__(self, name):
            return getattr(real_weakref, name)

        def ref(self, *args, **kwargs):
            if args and args[0] is inner:
                reached.set()
                release.wait(30)
            return real_weakref.ref(*args, **kwargs)

    def worker():
        go.wait(30)
        inner.start()

    outer = threading.Thread(target=worker)
    outer.start()  # before the proxy exists: this start must not pause
    monkeypatch.setattr(capture, "weakref", PausedWeakref())

    def deactivator():
        capture.deactivate()
        finished.set()

    completed = False
    during = None
    try:
        go.set()
        assert reached.wait(30), "the thread-leg commit was never reached"
        _thread.start_new_thread(deactivator, ())
        completed = finished.wait(1.0)
        during = _leg_registered(capture, inner)
    finally:
        release.set()
        outer.join(30)
        finished.wait(30)
        if inner.ident is not None:
            inner.join(30)
    after = _leg_registered(capture, inner)
    assert after, "the thread leg was never recorded: the test is vacuous"
    if completed:
        assert during == after, (
            "the deactivation completed while a thread-leg commit was "
            "pending, and the registry changed after it")


def test_u_installation_ownership_is_serialized_across_instances(monkeypatch):
    """Two instances installing from two threads cannot both pass the
    ownership check: the check, the claim and the release share ONE lock.

    The first install is held INSIDE the shared lock; the second must not get
    past it until the first releases, and then it must be refused.
    """
    import threading

    import _socket_10038_diagnosis as capture

    capture.deactivate()  # the family fixture's own installation
    real = capture._OWNERSHIP_LOCK
    inside = threading.Event()
    proceed = threading.Event()

    class Gate:
        def __init__(self):
            self.entered = 0

        def __enter__(self):
            real.acquire()
            self.entered += 1
            if self.entered == 1:
                inside.set()
                proceed.wait(30)
            return self

        def __exit__(self, *args):
            real.release()

    gate = Gate()
    monkeypatch.setattr(capture, "_OWNERSHIP_LOCK", gate)
    first, second = capture.SocketDiagnosis(), capture.SocketDiagnosis()
    outcomes = {}
    done_second = threading.Event()

    def run(name, instance, done=None):
        try:
            instance.install()
            outcomes[name] = "installed"
        except RuntimeError:
            outcomes[name] = "refused"
        if done is not None:
            done.set()

    t_first = threading.Thread(target=run, args=("first", first))
    t_second = threading.Thread(target=run, args=("second", second, done_second))
    try:
        t_first.start()
        assert inside.wait(30), "the first install never entered the lock"
        t_second.start()
        assert not done_second.wait(0.5), (
            "the second install got past the ownership lock while the first "
            "was still inside it")
    finally:
        proceed.set()
        t_first.join(30)
        t_second.join(30)
        first.uninstall()
        second.uninstall()
    assert outcomes == {"first": "installed", "second": "refused"}, outcomes
    # install x2 and the first's uninstall (+ the second's no-op uninstall)
    assert gate.entered >= 3, (
        "uninstall did not take the shared ownership lock "
        f"(entered {gate.entered} times)")


def test_v_competing_public_activations_cannot_orphan_the_installed_capture(
        monkeypatch):
    """Two threads calling the PUBLIC activate() cannot leave a patched socket
    class that deactivate() no longer reaches.

    The first activation is paused while it CONSTRUCTS its instance, before it
    publishes it. Without a lock around the public selection, the second
    activation sees no active instance, builds and installs its own, and the
    first then overwrites the published instance with one whose install is
    refused - so deactivate() removes the refused instance and the installed
    one keeps its process-global patches.
    """
    import threading

    import _socket_10038_diagnosis as capture

    capture.deactivate()  # the family fixture's own installation
    real_class = capture.SocketDiagnosis
    inside = threading.Event()
    proceed = threading.Event()
    state = {"first": True}

    class PausingInstance(real_class):
        def __init__(self):
            if state["first"]:
                state["first"] = False
                inside.set()
                proceed.wait(30)
            super().__init__()

    monkeypatch.setattr(capture, "SocketDiagnosis", PausingInstance)
    finished = threading.Event()

    def activate_quietly(done=None):
        try:
            capture.activate()
        except RuntimeError:
            pass  # a refused competing installation
        if done is not None:
            done.set()

    first = threading.Thread(target=activate_quietly)
    second = threading.Thread(target=activate_quietly, args=(finished,))
    try:
        first.start()
        assert inside.wait(30), "the first activation never reached its instance"
        second.start()
        finished.wait(0.5)  # with the lock the second must still be waiting
    finally:
        proceed.set()
        first.join(30)
        second.join(30)
        capture.deactivate()
    leftovers = [name for name, original in capture._ORIGINAL_SOCKET_METHODS.items()
                 if getattr(socket.socket, name, None) is not original]
    assert not leftovers, (
        "deactivate() left capture wrappers on the socket class after two "
        f"competing public activations: {leftovers}")
