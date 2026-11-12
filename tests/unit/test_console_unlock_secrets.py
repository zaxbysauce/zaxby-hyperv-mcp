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
