"""Named-secret typing, lock-state detection and one-attempt unlock
(issue #130).

secret_ref (env:NAME / allowlisted file:PATH) resolves host-side: the value
is typed or set but never returned, logged or echoed — responses carry only
its length. file: paths must pass the host_read_roots policy gate (an
arbitrary host file typed into the guest is an exfiltration channel).
hyperv_console_lock_state reports locked/unlocked/unknown from the guest's
process table (LogonUI.exe), replacing the retired screenshot-byte-size
guess. hyperv_console_unlock refuses when not locked (no input), makes at
most ONE attempt per call, and verifies through lock state AND a frame
change before claiming success.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from hyperv_mcp import console, guestexec, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialError
from hyperv_mcp.policy import PolicyDenied

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"


class FakePS:
    """Minimal recorder stub shaped like test_console's: resolver legs get
    the GUID, every other leg returns a clean success."""

    def __init__(self, responses=()):
        self.scripts = []
        self.kwargs = []
        self.responses = list(responses)

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        if self.responses:
            item = self.responses.pop(0)
        elif "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget"):
            item = pswindows.PSResult(stdout=GUID, returncode=0)
        elif "EnabledState" in script:
            body = json.dumps({
                "enabled_state": 2, "head_horizontal": 1024, "head_vertical": 768,
                "keyboard_present": True, "keyboard_enabled": 2,
                "mouse_present": True, "mouse_enabled": 2,
            })
            item = pswindows.PSResult(stdout="VMID=" + GUID + "\n" + body, returncode=0)
        else:
            item = pswindows.PSResult(stdout="", returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(console.time, "sleep", lambda s: None)


def test_secret_ref_typed_and_never_echoed(monkeypatch, unrestricted_cfg):
    """AC1: the resolved value is typed; the response reports its length and
    never the value."""
    monkeypatch.setenv("APP_TEST_SECRET", "S3cr3t-Typed-P4ss!")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    out = console.type_text(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert out["ok"] is True
    assert out["chars"] == len("S3cr3t-Typed-P4ss!")
    assert out["secret_typed"] is True
    stdin_payloads = [kw["stdin_b64"] for kw in fake.kwargs if "stdin_b64" in kw]
    typed = base64.b64decode("".join(
        line for payload in stdin_payloads for line in payload.split("\n") if line
    )).decode("utf-8")
    assert typed == "S3cr3t-Typed-P4ss!"
    # the value never appears in any script body the recorder captured
    assert all("S3cr3t-Typed-P4ss!" not in s for s in fake.scripts)


def test_secret_ref_outside_allowlist_refused(monkeypatch):
    """AC2: a file: source outside the host read policy refuses and types
    nothing; bare paths refuse the same way. Console input is ENABLED here
    so the observed refusal is the file-leg policy gate, not the category."""
    cfg = Config()
    cfg.destructive.console_input = True  # the category gate passes ...
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(PolicyDenied):
        console.type_text(cfg, "vm1", secret_ref="file:E:/outside/secret.txt")
    with pytest.raises(CredentialError, match="env:NAME or file:PATH"):
        console.type_text(cfg, "vm1", secret_ref="E:/bare/path.txt")
    assert fake.scripts == []  # nothing typed


def test_unlock_refused_when_not_locked(monkeypatch, unrestricted_cfg):
    """AC3: unlock on an unlocked (or unknown-state) console refuses with
    not_locked and sends no input."""
    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    monkeypatch.setattr(console, "lock_state",
                        lambda cfg, vm_name="", vm_id="": {
                            "ok": True, "state": "unlocked",
                            "evidence": "LogonUI.exe absent"})
    calls: list[str] = []
    monkeypatch.setattr(console, "press_key",
                        lambda *a, **k: calls.append("press_key"))
    monkeypatch.setattr(console, "type_text",
                        lambda *a, **k: calls.append("type_text"))
    monkeypatch.setattr(console, "screenshot",
                        lambda *a, **k: calls.append("screenshot"))
    with pytest.raises(Exception, match="not_locked"):
        console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert calls == []


def test_lock_state_reports_locked_from_logonui(monkeypatch, unrestricted_cfg):
    """AC4: a running LogonUI.exe in the guest's process table reports
    locked, with the evidence recorded."""
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")
    seen: dict[str, str] = {}

    def fake_guest_run_ps(cfg, vm_name="", script="", **kwargs):
        seen["script"] = script
        seen["vm_name"] = vm_name
        return {"ok": True, "exit_code": 0, "stdout": "LOCKED\n",
                "stderr": "", "vm_name": vm_name}

    monkeypatch.setattr(guestexec, "guest_run_ps", fake_guest_run_ps)
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    out = console.lock_state(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["state"] == "locked"
    assert "LogonUI" in out["evidence"]
    assert "LogonUI" in seen["script"]


def test_failed_unlock_does_not_retry(monkeypatch, unrestricted_cfg):
    """AC5: one failed attempt stops there and reports unlock_failed — the
    secret is typed exactly once, and the guest account is never locked out
    by repetition."""
    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    monkeypatch.setattr(console, "lock_state", lambda cfg, vm_name="", vm_id="": {
        "ok": True,
        "state": "locked" if not getattr(console.lock_state, "_final", False) else "locked",
        "evidence": "LogonUI.exe present",
    })
    typed: list[str] = []
    pressed: list[str] = []
    monkeypatch.setattr(console, "screenshot",
                        lambda cfg, vm_name="", **k: (
                            None, {"frame_hash": "pre" if not typed else "post"}))
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    monkeypatch.setattr(console, "press_key",
                        lambda cfg, vm_name="", key="", **k: pressed.append(key))

    def fake_type_text(cfg, vm_name="", text="", secret_ref="", **k):
        typed.append(text)  # R13: record the VALUE typed, not the ref

    monkeypatch.setattr(console, "type_text", fake_type_text)
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    with pytest.raises(Exception, match="unlock_failed"):
        console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert typed == ["pw"]  # exactly one attempt, the RESOLVED secret typed
    assert pressed == ["escape", "enter"]


def test_unlocked_token_is_not_misparsed_as_locked(monkeypatch, unrestricted_cfg):
    """R2 pin: the guest reporting UNLOCKED must read as unlocked — the
    substring containment 'LOCKED' in 'UNLOCKED' inverted every unlocked
    verdict (reviewer blocker 2)."""
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    monkeypatch.setattr(guestexec, "guest_run_ps", lambda cfg, vm_name="", script="", **k: {
        "ok": True, "exit_code": 0, "stdout": "UNLOCKED\n", "stderr": ""})
    out = console.lock_state(unrestricted_cfg, "vm1")
    assert out["state"] == "unlocked"


def test_unlock_success_path_real_lock_state(monkeypatch, unrestricted_cfg):
    """R2/R7: the success path through the REAL lock_state parser — wake,
    type the resolved secret once, submit, and the guest transitions to
    UNLOCKED with a frame change."""
    monkeypatch.setenv("APP_TEST_SECRET", "good-pw")
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    submitted = {"done": False}

    def fake_guest_run_ps(cfg, vm_name="", script="", **k):
        token = "UNLOCKED\n" if submitted["done"] else "LOCKED\n"
        return {"ok": True, "exit_code": 0, "stdout": token, "stderr": ""}

    monkeypatch.setattr(guestexec, "guest_run_ps", fake_guest_run_ps)

    def fake_press_key(cfg, vm_name="", key="", **k):
        if key == "enter":
            submitted["done"] = True

    typed_ok: list[str] = []

    def fake_type_text(cfg, vm_name="", text="", secret_ref="", **k):
        typed_ok.append(text)

    monkeypatch.setattr(console, "press_key", fake_press_key)
    monkeypatch.setattr(console, "type_text", fake_type_text)
    hashes = iter(["h1", "h2"])

    def fake_screenshot(cfg, vm_name="", **k):
        return None, {"frame_hash": next(hashes)}

    monkeypatch.setattr(console, "screenshot", fake_screenshot)
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    out = console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert out["ok"] is True and out["state"] == "unlocked" and out["attempts"] == 1
    assert typed_ok == ["good-pw"]
    assert "frame changed" in out["evidence"]


def test_restricted_config_lock_and_unlock_usable(monkeypatch):
    """R1/R7 black-box pin with a NON-unrestricted config: lock_state
    (read-only, no category) and unlock (console_input enabled) must be
    usable without unrestricted=True."""
    cfg = Config()
    cfg.destructive.console_input = True  # NOT unrestricted
    cfg.secret_env_names = ["APP_TEST_*"]
    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    monkeypatch.setattr(guestexec, "guest_run_ps", lambda cfg, vm_name="", script="", **k: {
        "ok": True, "exit_code": 0, "stdout": "UNLOCKED\n", "stderr": ""})
    out = console.lock_state(cfg, "vm1")  # R1: no PolicyDenied on 'read'
    assert out["state"] == "unlocked"
    with pytest.raises(Exception, match="not_locked"):
        console.unlock(cfg, "vm1", secret_ref="env:APP_TEST_SECRET")


def test_literal_text_unchanged(monkeypatch, unrestricted_cfg):
    """AC6: typing literal text behaves exactly as before — no secret_ref
    resolution, no secret_typed key, same chunks/chars response."""
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.type_text(unrestricted_cfg, "vm1", "plain text")
    assert out["ok"] is True
    assert out["chunks"] == 1 and out["chars"] == len("plain text")
    assert "secret_typed" not in out
    stdin_payloads = [kw["stdin_b64"] for kw in fake.kwargs if "stdin_b64" in kw]
    typed = base64.b64decode("".join(
        line for payload in stdin_payloads for line in payload.split("\n") if line
    )).decode("utf-8")
    assert typed == "plain text"


def test_lock_state_unknown_when_the_leg_fails(monkeypatch, unrestricted_cfg):
    """The lock verdict is honest when the process-table leg fails: unknown
    with the failure named in evidence, never a guessed locked/unlocked."""
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")

    def failing_guest_run_ps(cfg, vm_name="", script="", **kwargs):
        return {"ok": False, "exit_code": 1, "stdout": "", "stderr": "boom",
                "vm_name": vm_name}

    monkeypatch.setattr(guestexec, "guest_run_ps", failing_guest_run_ps)
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    out = console.lock_state(unrestricted_cfg, "vm1")
    assert out["ok"] is True
    assert out["state"] == "unknown"
    assert "boom" in out["evidence"]


def test_set_value_secret_ref_resolved_host_side(monkeypatch):
    """secret_ref on hyperv_ui_set_value resolves through the same contract:
    the resolved value rides the payload, the response carries only the
    length, and a file: source outside the policy refuses before the leg."""
    import hyperv_mcp.uia as uia

    monkeypatch.setenv("APP_TEST_SECRET", "uia-secret")
    captured: dict[str, object] = {}

    class _Cred:
        pass

    def fake_verb_request(cfg, ref, cred, verb, args, **kwargs):
        captured["verb"] = verb
        captured["args"] = args
        return {"ok": True, "length_set": len(args["value"])}

    monkeypatch.setattr(uia, "_verb_request", fake_verb_request)
    monkeypatch.setattr(uia.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    cfg = Config()
    cfg.destructive.ui_input = True
    cfg.secret_env_names = ["APP_TEST_*"]
    # R3: the registered tool always supplies value="" (its default) — the
    # exact wrapper-kwarg shape that used to be refused before resolving.
    out = uia.set_value(cfg, "vm1", cred=_Cred(), selector={"name": "box"},
                        value="", secret_ref="env:APP_TEST_SECRET")
    assert out["ok"] is True
    assert out["length_set"] == len("uia-secret")
    assert captured["args"]["value"] == "uia-secret"
    with pytest.raises(ValueError, match="mutually exclusive"):
        uia.set_value(cfg, "vm1", cred=_Cred(), selector={"name": "box"},
                      value="x", secret_ref="env:APP_TEST_SECRET")


def test_env_secret_denied_by_default(monkeypatch):
    """Final-critic Critical 1: the env: path is DENY-ALL by default — a
    config that never lists secret_env_names cannot read any variable, so
    the server's own credential variables are not typeable into a guest."""
    cfg = Config()
    cfg.destructive.console_input = True  # NOT unrestricted, no allowlist
    monkeypatch.setenv("SOME_RANDOM_VAR", "value")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(CredentialError, match="secret_env_names allowlist"):
        console.type_text(cfg, "vm1", secret_ref="env:SOME_RANDOM_VAR")
    assert fake.scripts == []


def test_server_credential_vars_always_refused(monkeypatch):
    """Final-critic Critical 1: HYPERV_GUEST_PASSWORD / HYPERV_HOST_PASSWORD
    / HYPERV_MCP_HTTP_TOKEN are refused EVEN WHEN the allowlist matches
    them (the hard-deny set outranks the allowlist)."""
    from hyperv_mcp.credentials import resolve_secret_ref

    allow_all = ["*"]
    for name in ("HYPERV_GUEST_PASSWORD", "HYPERV_HOST_PASSWORD",
                 "HYPERV_MCP_HTTP_TOKEN", "hyperv_guest_password"):
        monkeypatch.setenv(name.upper(), "x")
        with pytest.raises(CredentialError, match="always refused"):
            resolve_secret_ref(f"env:{name}", environ=dict(os.environ),
                               allowed_env=allow_all)


def test_agent_token_env_refused(monkeypatch):
    """The configured http.token_env / per-agent token variables ride the
    hard-deny set through the callers."""
    cfg = Config()
    cfg.destructive.console_input = True
    cfg.secret_env_names = ["*"]
    cfg.http.token_env = "MY_CUSTOM_TOKEN_VAR"
    monkeypatch.setenv("MY_CUSTOM_TOKEN_VAR", "tok")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    with pytest.raises(CredentialError, match="always refused"):
        console.type_text(cfg, "vm1", secret_ref="env:MY_CUSTOM_TOKEN_VAR")
    assert fake.scripts == []


def test_allowlisted_env_secret_is_usable(monkeypatch, unrestricted_cfg):
    """The allowlist admits ordinary app-test variables (glob, case-
    insensitive)."""
    unrestricted_cfg.secret_env_names = ["app_test_*"]
    monkeypatch.setenv("app_test_case_insensitive", "ok")
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.type_text(unrestricted_cfg, "vm1",
                            secret_ref="env:APP_TEST_CASE_INSENSITIVE")
    assert out["ok"] is True and out["chars"] == 2


def test_docstrings_disclose_the_focus_limitation():
    """M9 kill pin: the unlock docstrings (module layer + both server
    registrations) carry the password-field focus limitation — a silent
    disclosure decay would fail here (final-critic finding 3)."""
    import inspect
    from pathlib import Path

    import hyperv_mcp.server as server_module

    module_doc = " ".join((inspect.getdoc(console.unlock) or "").split())
    assert "not explicitly focused" in module_doc
    server_src = " ".join(
        Path(server_module.__file__).read_text(encoding="utf-8").split())
    assert "not explicitly focused" in server_src, (
        "the hyperv_console_unlock registration must disclose the focus "
        "limitation"
    )
    # and the module docstring's limitation text names the UIA follow-ups
    assert "UIA helper" in module_doc


def test_secret_env_names_loads_from_a_config_file():
    """Final-critic round-2 finding: the allowlist is settable through the
    real config loader (Config.from_dict), not just by attribute — an
    operator following the README gets a working env: leg, not a startup
    ConfigError."""
    from hyperv_mcp.config import Config

    cfg = Config.from_dict({"secret_env_names": ["APP_TEST_*"]})
    assert cfg.secret_env_names == ["APP_TEST_*"]


def test_unlock_plan_is_one_atomic_lock_acquisition(monkeypatch, unrestricted_cfg):
    """CONC-01/BASE-01 kill pin: the whole wake/type/submit plan runs under
    ONE console-input-lock acquisition (the callees run with assume_lock),
    so a concurrent console op can never interleave keystrokes into the
    typed secret. A counting wrapper around console._input_lock asserts the
    acquisition count for the three-leg plan is exactly 1."""
    import itertools

    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    acquisitions = itertools.count()
    real_lock = console._input_lock

    def counting_lock(ref):
        acquisitions.__next__()
        return real_lock(ref)

    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    monkeypatch.setattr(console, "_input_lock", counting_lock)
    submitted = {"n": 0}

    def fake_press(cfg, vm_name="", key="", **k):
        if key == "enter":
            submitted["n"] += 1

    monkeypatch.setattr(console, "lock_state", lambda cfg, vm_name="", vm_id="": {
        "ok": True,
        "state": "unlocked" if submitted["n"] else "locked",
        "evidence": "LogonUI.exe present"})
    monkeypatch.setattr(console, "screenshot",
                        lambda cfg, vm_name="", **k: (
                            None, {"frame_hash": "before" if not submitted["n"] else "after"}))
    monkeypatch.setattr(console, "press_key", fake_press)
    monkeypatch.setattr(console, "type_text",
                        lambda cfg, vm_name="", text="", **k: {"ok": True})
    out = console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert out["ok"] is True
    # exactly ONE acquisition for the plan scope (lock_state/screenshot run
    # outside the input lock and are stubbed here): the counter issued one
    # number, so the next unused value is 1.
    assert next(acquisitions) == 1


def test_lock_state_is_console_session_scoped(monkeypatch, unrestricted_cfg):
    """SEC-01 kill pin: the guest script scopes LogonUI to the explorer
    session (the active console), never machine-wide — a LogonUI left in a
    disconnected RDP session must not read as locked."""
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "tester")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    captured: dict[str, str] = {}

    def fake_guest_run_ps(cfg, vm_name="", script="", **k):
        captured["script"] = script
        return {"ok": True, "exit_code": 0, "stdout": "UNLOCKED\n", "stderr": ""}

    monkeypatch.setattr(guestexec, "guest_run_ps", fake_guest_run_ps)
    out = console.lock_state(unrestricted_cfg, "vm1")
    assert out["state"] == "unlocked"
    assert "explorer" in captured["script"]
    assert "SessionId -eq $expl.SessionId" in captured["script"]


def test_unlock_verifies_with_a_bounded_poll(monkeypatch, unrestricted_cfg):
    """BASE-03 kill pin: the post-submit verification polls the lock state
    (up to the deadline) instead of one fixed-sleep sample, so a slow logon
    that unlocks at the first poll tick still succeeds."""
    samples = {"n": 0}
    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]

    monkeypatch.setattr(console, "lock_state", lambda cfg, vm_name="", vm_id="": {
        "ok": True,
        "state": "unlocked" if samples["n"] >= 1 else "locked",
        "evidence": "polled"})

    def fake_press(cfg, vm_name="", key="", **k):
        if key == "enter":
            samples["n"] += 1  # the guest unlocks after the first poll tick

    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())
    monkeypatch.setattr(console, "type_text", lambda cfg, vm_name="", text="", **k: None)
    monkeypatch.setattr(console, "press_key", fake_press)
    monkeypatch.setattr(console, "screenshot",
                        lambda cfg, vm_name="", **k: (
                            None, {"frame_hash": "before" if samples["n"] == 0 else "after"}))
    ticks = iter(range(100))

    import types as _types

    class FakeClock:
        def __init__(self):
            self.t = 0.0

        def monotonic(self):
            return self.t

        def sleep(self, s):
            self.t += s
            next(ticks, None)

    clock = FakeClock()
    monkeypatch.setattr(console, "time", _types.SimpleNamespace(
        monotonic=clock.monotonic, sleep=clock.sleep))
    out = console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")
    assert out["ok"] is True and out["state"] == "unlocked"
    assert clock.t > 0  # at least one poll tick elapsed (a poll, not a sample)


def test_positive_file_secret_typed(tmp_path, monkeypatch, unrestricted_cfg):
    """BASE-04 kill pin: the positive file: leg — an allowlisted secret
    file resolves and is typed verbatim (single line, BOM-free)."""
    secret_file = tmp_path / "pw.txt"
    secret_file.write_bytes(b"file-pw-123\n")
    unrestricted_cfg.host_read_roots = [str(tmp_path)]
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = console.type_text(unrestricted_cfg, "vm1",
                            secret_ref=f"file:{secret_file}")
    assert out["ok"] is True and out["chars"] == len("file-pw-123")
    assert out["secret_typed"] is True


def test_type_text_secret_ref_and_text_are_mutually_exclusive(unrestricted_cfg):
    """BASE-04 kill pin: type_text refuses secret_ref + text together."""
    with pytest.raises(ValueError, match="mutually exclusive"):
        console.type_text(unrestricted_cfg, "vm1", text="x",
                          secret_ref="env:ANY")


def test_unlock_requires_frame_change(monkeypatch, unrestricted_cfg):
    """BASE-04 kill pin: lock state flipping to unlocked with an UNCHANGED
    frame still fails (the AND clause is load-bearing — deleting it used to
    leave the suite green)."""
    monkeypatch.setenv("APP_TEST_SECRET", "pw")
    unrestricted_cfg.secret_env_names = ["APP_TEST_*"]
    submitted = {"n": 0}
    monkeypatch.setattr(console, "lock_state", lambda cfg, vm_name="", vm_id="": {
        "ok": True,
        "state": "unlocked" if submitted["n"] else "locked",
        "evidence": "flaky same-frame"})
    monkeypatch.setattr(console.vmident, "resolve",
                        lambda cfg, vm_name="", vm_id="": type(
                            "R", (), {"name": "vm1", "id": "guid"})())

    def fake_press(cfg, vm_name="", key="", **k):
        if key == "enter":
            submitted["n"] += 1

    monkeypatch.setattr(console, "press_key", fake_press)
    monkeypatch.setattr(console, "type_text", lambda cfg, vm_name="", text="", **k: None)
    monkeypatch.setattr(console, "screenshot",
                        lambda cfg, vm_name="", **k: (None, {"frame_hash": "same"}))
    with pytest.raises(Exception, match="unlock_failed"):
        console.unlock(unrestricted_cfg, "vm1", secret_ref="env:APP_TEST_SECRET")


def test_agent_and_operations_and_profile_env_names_denied(monkeypatch):
    """BASE-04 + SEC-03 kill pins: the cfg.http.agents, operations.key_env,
    and credential-profile password_env legs of the hard-deny set — each
    used to be deletable with the suite green."""
    cfg = Config()
    cfg.destructive.console_input = True
    cfg.secret_env_names = ["*"]
    cfg.http.agents = {"agent-a": "AGENT_A_TOKEN"}
    cfg.operations.key_env = "HMAC_KEY_VAR"
    profile = type("P", (), {"name": "vm1", "password_env": "VM1_PW_ENV",
                             "victim_password_env": "VM1_VPW_ENV"})
    cfg.credential_profiles = (profile,)
    for var in ("AGENT_A_TOKEN", "HMAC_KEY_VAR", "VM1_PW_ENV", "VM1_VPW_ENV"):
        monkeypatch.setenv(var, "v")
        fake = FakePS()
        monkeypatch.setattr(pswindows, "run_ps", fake)
        with pytest.raises(CredentialError, match="always refused"):
            console.type_text(cfg, "vm1", secret_ref=f"env:{var}")
        assert fake.scripts == []
