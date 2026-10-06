"""Evidence tests: bundle contract, credential gate on the UI tree leg,
screenshot-without-credentials path, best-effort UIA error shape."""

import pytest

from hyperv_mcp import evidence, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialError, CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


class FakePS:
    def __init__(self, responses):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if not self.responses:
            raise AssertionError("unexpected extra run_ps call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeImage:
    """Stand-in for the PIL image; the module passes it through untouched."""


def _base_meta():
    return {
        "vm_name": "test-vm",
        "vm_id": "e953c649-abcd",
        "width": 1024, "height": 768,
        "frame_hash": "a" * 64,
        "captured_at": "2026-09-29T12:00:00.000+00:00",
        "capture_method": "GetVirtualSystemThumbnailImage",
    }


VM_GUID = "e953c649-1234-5678-9abc-def012345678"


@pytest.fixture()
def fake_screenshot(monkeypatch):
    captured = {}

    def _capture(cfg, vm_name, width=1024, height=768, save_path="", vm_id=""):
        captured["vm_name"] = vm_name
        captured["vm_id"] = vm_id
        return FakeImage(), _base_meta()

    monkeypatch.setattr(evidence.console, "screenshot", _capture)
    # capture_evidence resolves the target first (vmident by-name leg) —
    # serve it so no real PowerShell spawns in tests.
    monkeypatch.setattr(
        pswindows, "run_ps",
        lambda script, **kw: pswindows.PSResult(stdout=VM_GUID, returncode=0),
    )
    _capture.captured = captured
    return _capture


def test_policy_denied_before_any_work(monkeypatch):
    cfg = Config()
    called = FakePS([])
    monkeypatch.setattr(pswindows, "run_ps", called)
    with pytest.raises(PolicyDenied):
        evidence.capture_evidence(cfg, "test-vm", cred=CRED)


def test_screenshot_only_path_needs_no_credentials(fake_screenshot):
    cfg = Config(unrestricted=True)
    out = evidence.capture_evidence(cfg, "test-vm")
    assert out["ok"] is True
    assert isinstance(out["image"], FakeImage)
    meta = out["meta"]
    assert meta["captured_at"].endswith("+00:00")
    assert meta["vm_id"].startswith("e953c649")
    assert meta["width"] == 1024 and meta["height"] == 768
    assert len(meta["frame_hash"]) == 64
    assert meta["ui_tree"] == {"requested": False}
    # issue #8: the screenshot leg receives the SAME resolved GUID the UIA
    # leg would use — one identity for the whole bundle.
    assert fake_screenshot.captured["vm_id"] == VM_GUID
    assert fake_screenshot.captured["vm_name"] == "test-vm"


def test_ui_tree_without_credentials_raises(fake_screenshot):
    cfg = Config(unrestricted=True)
    with pytest.raises(CredentialError, match="UI element tree"):
        evidence.capture_evidence(cfg, "test-vm", ui_tree=True, cred=None)


def test_ui_tree_with_credentials_merges_tree(fake_screenshot, monkeypatch):
    cfg = Config(unrestricted=True)
    captured = {}

    def fake_run(cfg_, vm, inner, cred_, timeout_ms=60000):
        captured["script"] = inner
        return {"elements": 7, "truncated": False,
                "tree": {"name": "Desktop", "control_type": "Pane", "children": []}}

    monkeypatch.setattr(evidence, "run_guest_inner", fake_run)
    out = evidence.capture_evidence(cfg, "test-vm", ui_tree=True, cred=CRED)
    ui = out["meta"]["ui_tree"]
    assert ui == {
        "requested": True, "ok": True, "elements": 7, "truncated": False,
        "tree": {"name": "Desktop", "control_type": "Pane", "children": []},
    }
    # The UIA leg is bounded and parseable: markers for the bounded walker.
    assert "UIAutomationClient" in captured["script"]
    assert "$script:cap = 200" in captured["script"]
    assert "Walk $root 3" in captured["script"]


def test_ui_tree_failure_is_best_effort(fake_screenshot, monkeypatch):
    cfg = Config(unrestricted=True)

    def boom(*a, **k):
        raise RuntimeError("no interactive desktop")

    monkeypatch.setattr(evidence, "run_guest_inner", boom)
    out = evidence.capture_evidence(cfg, "test-vm", ui_tree=True, cred=CRED)
    # The screenshot still ships.
    assert out["ok"] is True
    assert isinstance(out["image"], FakeImage)
    ui = out["meta"]["ui_tree"]
    assert ui["ok"] is False
    assert "no interactive desktop" in ui["error"]
    assert "interactive desktop" in ui["note"]


def test_bounds_and_depth_clamped(fake_screenshot, monkeypatch):
    cfg = Config(unrestricted=True)
    captured = {}

    def fake_run(cfg_, vm, inner, cred_, timeout_ms=60000):
        captured["script"] = inner
        return {"elements": 1, "truncated": True, "tree": {}}

    monkeypatch.setattr(evidence, "run_guest_inner", fake_run)
    out = evidence.capture_evidence(
        cfg, "test-vm", ui_tree=True, ui_tree_depth=99, ui_tree_max_elements=99999, cred=CRED,
    )
    # Depth clamped to 6, element cap to 500.
    assert "$script:cap = 500" in captured["script"]
    assert "Walk $root 6" in captured["script"]
    # PRR-C2: the truncated pass-through is pinned in BOTH directions — a
    # capped tree must not be reported as complete.
    assert out["meta"]["ui_tree"]["truncated"] is True
