"""Shared unit-test fixtures. No real Hyper-V is touched."""

import time

import pytest

from hyperv_mcp.config import Config


@pytest.fixture(autouse=True)
def _ps_transport_default(monkeypatch):
    """Unit tests default to the PowerShell console transport: no real
    Hyper-V through EITHER transport (the suite stubs run_ps; the
    in-process WMI backend is likewise never real here — on boxes with
    pywin32 AND a live namespace it would otherwise serve silently).
    Tests that exercise the WMI path install their own fake backend
    explicitly and re-enable it via wmiconsole.COM_AVAILABLE (issue #45).
    The backend/negative-cache state is reset per test so no test inherits
    another test's fake service (review F3-C/P24)."""
    from hyperv_mcp import wmiconsole

    monkeypatch.setattr(wmiconsole, "COM_AVAILABLE", False)
    monkeypatch.setattr(wmiconsole, "_backends", {})
    monkeypatch.setattr(wmiconsole, "_connect_failures", {})


@pytest.fixture()
def png_encode_counter(monkeypatch):
    """Count PNG encodes (issue #17, PRR-016).

    The single oracle the "one PNG encode per returned image" invariant rests
    on. It lives here rather than being copied into each test file so there is
    one implementation to maintain. `Image.init()` runs first: without it the
    SAVE registry does not exist yet and a patch made earlier is overwritten by
    plugin registration, which would make the counter read zero and every
    encode-count assertion vacuous.

    `tests/unit/test_d01_screenshot_decode.py` keeps its own byte-locked copy
    because that file is frozen by the issue-tracer red checkpoint.
    """
    from PIL import Image

    Image.init()
    original = Image.SAVE["PNG"]
    box = {"encodes": 0}

    def counting_encode(fp, *args, **kwargs):
        box["encodes"] += 1
        return original(fp, *args, **kwargs)

    monkeypatch.setitem(Image.SAVE, "PNG", counting_encode)
    return box


@pytest.fixture()
def deny_all_cfg() -> Config:
    return Config()


@pytest.fixture()
def unrestricted_cfg() -> Config:
    return Config(unrestricted=True)


@pytest.fixture()
def lab_cfg(tmp_path) -> Config:
    """A realistic restrictive lab config: one VM pattern, tmp roots."""
    return Config(
        allowed_vm_patterns=["test-vm-*"],
        host_read_roots=[str(tmp_path / "host-read")],
        host_write_roots=[str(tmp_path / "host-write")],
        guest_read_roots=["C:\\guest-read"],
        guest_write_roots=["C:\\guest-write"],
    )


def content_blocks(result):
    """Content blocks from any mcp call_tool return shape.

    Handles the historical tuple form, the converted list form, and the
    CallToolResult object that in-process call_tool returns when a tool
    returns one (issue #9 envelope delivery)."""
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    return content if isinstance(content, list) else [content]


def envelope_from_result(result, label: str) -> dict:
    """Parse the first text block of a failure result into the envelope."""
    import json

    blocks = content_blocks(result)
    texts = [c for c in blocks if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)

@pytest.fixture(scope="session", autouse=True)
def _reap_stray_controllers():
    """Session-end safety net (PRR-012): any controller that outlived its
    test — e.g. AC8's failure path, whose frozen-file reap sits after its
    assertion (the test file is checkpoint-anchored and cannot be edited) —
    is terminated here. Controllers created before the session started (an
    operator's own hyperv-mcp-http) are never touched."""
    started = time.time()
    yield
    try:
        import psutil
    except ImportError:  # dev extra absent: warn, never mask test results
        return

    victims = []
    for proc in psutil.process_iter(["pid", "cmdline", "create_time"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or [])
            created = proc.info.get("create_time") or 0
        except psutil.Error:
            continue
        if "hyperv_mcp.http_entry" in cmd or "hyperv-mcp-http" in cmd:
            if created >= started:
                victims.append(proc)
    for proc in victims:
        try:
            proc.terminate()
        except psutil.Error:
            pass
    if victims:
        psutil.wait_procs(victims, timeout=5.0)
        for proc in victims:
            try:
                proc.kill()
            except psutil.Error:
                pass


@pytest.fixture(autouse=True)
def _restore_bootstrap_module_globals():
    """Per-test isolation (PRR-014): bootstrap() writes _config into
    credentials/pswindows/auditlog AND server._bootstrapped/CFG — a server
    reload alone cannot undo it (the b01 guard's scope, generalized).
    AC5 in test_b03_stdio_proxy reaches bootstrap() through the launcher
    with no teardown of its own, so this fixture is the boundary that keeps
    one test's config out of the next test."""
    from hyperv_mcp import auditlog as _a
    from hyperv_mcp import credentials as _c
    from hyperv_mcp import pswindows as _pw
    from hyperv_mcp import server as _srv
    from hyperv_mcp import vmlocks as _vl

    saved = {
        ("auditlog", "_config"): getattr(_a, "_config", None),
        ("credentials", "_config"): getattr(_c, "_config", None),
        ("pswindows", "_config"): getattr(_pw, "_config", None),
        ("pswindows", "_redact"): getattr(_pw, "_redact", None),
        ("server", "_bootstrapped"): getattr(_srv, "_bootstrapped", False),
        ("server", "CFG"): getattr(_srv, "CFG", None),
        # bootstrap() also wires vmlocks' default bounded wait; without this
        # a test reaching bootstrap leaks its vm_lock_wait_s into the rest of
        # the session (review CLEAN-note on PR #58).
        ("vmlocks", "_DEFAULT_WAIT_S"): getattr(_vl, "_DEFAULT_WAIT_S", 30.0),
    }
    yield
    _a._config = saved[("auditlog", "_config")]
    _c._config = saved[("credentials", "_config")]
    _pw._config = saved[("pswindows", "_config")]
    _pw._redact = saved[("pswindows", "_redact")]
    _srv._bootstrapped = saved[("server", "_bootstrapped")]
    _srv.CFG = saved[("server", "CFG")]
    _vl._DEFAULT_WAIT_S = saved[("vmlocks", "_DEFAULT_WAIT_S")]

