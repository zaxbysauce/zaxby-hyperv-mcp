"""Frozen acceptance checks for issue #18 (Workstream D PR 2, D-02).

Every console call must start exactly ONE PowerShell process on the PowerShell
transport: the VM resolution, the display-head lookup, the device lookup and
the operation itself run inside one script; chunked keyboard input keeps every
chunk and its pacing inside that one process with chunks riding stdin as base64
lines; the screenshot fallback chain loops the de-duplicated size list in the
script and never attempts a size twice; the mouse lookup is scoped to the VM
with a SystemName WQL filter with no per-device association scan; and the parse
lane captures the full WMI template of every console op.

RED at base 4c1ecd4d6d3b44abbeb52ed62e5ec7edc538f69c, GREEN after the fix.

The SpawnCounter stub below replaces pswindows.run_ps. It serves the per-leg
protocol the base implementation speaks (a bare GUID for the by-name resolver,
a head JSON, a capture JSON, ...) and the folded single-script protocol the fix
speaks (VMID=/HEAD=/SIZES=/USED=/ATTEMPTED= metadata lines with the payload as
the final stdout line). The discriminator is the presence of $vmTarget in the
script: base templates bake the pre-resolved GUID into a Name= filter and never
mention $vmTarget; every folded script carries the resolver prelude
($vmTarget = $null ...) or the by-id preamble ($vmTarget = '<guid>').
"""

from __future__ import annotations

import base64
import json
import re

import pytest

from hyperv_mcp import console, pswindows
from hyperv_mcp.config import Config

# The real transport, captured before any test patches it: the executed-chunk
# check runs the generated script through real PowerShell 5.1.
_REAL_RUN_PS = pswindows.run_ps

GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
WMI_NS_BACKSLASH = "root\\virtualization\\v2"
HEAD = (1024, 768)


def _payload_json(w: int, h: int) -> str:
    """A size-correct GetVirtualSystemThumbnailImage JSON payload."""
    raw = b"\x00" * (w * h * 2 + 4)
    return json.dumps({"returnValue": 0, "imageDataB64": base64.b64encode(raw).decode()})


def _int_literal(value: str) -> int | None:
    value = value.strip().rstrip(";").strip()
    return int(value) if value.isdigit() else None


def _fmt(sizes: list[tuple[int, int]]) -> str:
    return ",".join(f"{w}x{h}" for w, h in sizes)


def _dedup(sizes: list[tuple[int, int]]) -> list[tuple[int, int]]:
    seen: list[tuple[int, int]] = []
    for size in sizes:
        if size not in seen:
            seen.append(size)
    return seen


class SpawnCounter:
    """pswindows.run_ps replacement: counts calls, records scripts, and serves
    the response the leg's script shape implies."""

    def __init__(self, *, capture_ok: bool = True):
        self.count = 0
        self.scripts: list[str] = []
        self.kwargs: list[dict] = []
        self.served: list[pswindows.PSResult] = []
        self.capture_ok = capture_ok

    def __call__(self, script: str, timeout_s: float | None = None, stdin_b64: str | None = None):
        self.count += 1
        self.scripts.append(script)
        self.kwargs.append({"timeout_s": timeout_s, "stdin_b64": stdin_b64})
        result = self._serve(script, stdin_b64)
        self.served.append(result)
        return result

    # -- response synthesis ------------------------------------------------

    def _serve(self, script: str, stdin_b64: str | None) -> pswindows.PSResult:
        s = script.strip()
        folded = "$vmTarget" in s
        if s.endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        if "Get-VM -Id $vmTarget" in s and s.endswith("$vm.Name"):
            return pswindows.PSResult(stdout="vm1", returncode=0)
        if "EnabledState" in s:
            body = json.dumps(
                {
                    "enabled_state": 2,
                    "head_horizontal": HEAD[0],
                    "head_vertical": HEAD[1],
                    "keyboard_present": True,
                    "keyboard_enabled": 2,
                    "mouse_present": True,
                    "mouse_enabled": 2,
                }
            )
            if folded:
                return pswindows.PSResult(stdout="VMID=" + GUID + "\n" + body, returncode=0)
            return pswindows.PSResult(stdout=body, returncode=0)
        if "$baseline" in s:
            return pswindows.PSResult(stdout="STOP=deadline POLLS=1 HASH=" + "ab" * 32, returncode=0)
        if "GetVirtualSystemThumbnailImage" in s:
            if folded and "$sizes" in s:
                return self._serve_folded_screenshot(s)
            w, h = _size_from_script(s)
            if not self.capture_ok:
                return pswindows.PSResult(stdout="", stderr="capture boom", returncode=1)
            return pswindows.PSResult(stdout=_payload_json(w, h), returncode=0)
        if (
            "SetAbsolutePosition" in s
            or "ClickButton" in s
            or "SetButtonState" in s
            or "SetScrollPosition" in s
        ):
            lines: list[str] = []
            pos = _position_from_script(s)
            if pos is not None:
                lines.append("HEADX=" + str(pos[0]))
                lines.append("HEADY=" + str(pos[1]))
            lines.append("RC=0")
            return pswindows.PSResult(stdout="\n".join(lines), returncode=0)
        if "Msvm_VideoHead" in s:
            return pswindows.PSResult(
                stdout=json.dumps({"horizontal": HEAD[0], "vertical": HEAD[1]}), returncode=0
            )
        if "TypeText" in s or "TypeScancodes" in s:
            n = _stdin_lines(stdin_b64)
            lines = ["RC=0 CHUNK=" + str(i + 1) + "/" + str(max(n, 1)) for i in range(max(n, 1))]
            return pswindows.PSResult(stdout="\n".join(lines), returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)

    def _serve_folded_screenshot(self, script: str) -> pswindows.PSResult:
        """The folded screenshot loop: de-duplicated chain requested -> head ->
        640x480 -> 320x240, one payload for the first success or ATTEMPTED for
        the all-fail case."""
        w, h = _size_from_script(script)
        chain = _dedup([(w, h), HEAD, (640, 480), (320, 240)])
        if self.capture_ok:
            uw, uh = chain[0]
            return pswindows.PSResult(
                stdout="VMID="
                + GUID
                + "\nHEAD=1024x768\nSIZES="
                + _fmt(chain)
                + "\nUSED="
                + _fmt([chain[0]])
                + "\n"
                + _payload_json(uw, uh),
                returncode=0,
            )
        return pswindows.PSResult(
            stdout="VMID=" + GUID + "\nATTEMPTED=" + _fmt(chain),
            stderr="capture boom",
            returncode=1,
        )


def _size_from_script(script: str) -> tuple[int, int]:
    w = h = 0
    for line in script.splitlines():
        ls = line.strip()
        if ls.startswith("WidthPixels"):
            w = _int_literal(ls.split("=", 1)[1]) or 0
        elif ls.startswith("HeightPixels"):
            h = _int_literal(ls.split("=", 1)[1]) or 0
    if not (w and h):
        # The folded screenshot seeds its in-script chain with the requested
        # size ($sizes = @(@(W,H))) and drives the loop from variables.
        m = re.search(r"\$sizes = @\([,(@]*(\d+),(\d+)\)", script)
        if m:
            w, h = int(m.group(1)), int(m.group(2))
    return w, h


def _position_from_script(script: str) -> tuple[int, int] | None:
    """The head-space position a mouse script acts on. The legacy per-leg script
    bakes the host-computed literals (HorizontalPosition = 10); the folded
    script declares its raw inputs ($x = 10 / $y = 10 / $fw = 0 / $fh = 0) and
    scales in-script, so the stub replicates _scale_to_head here."""
    hx = hy = None
    for line in script.splitlines():
        ls = line.strip()
        if ls.startswith("HorizontalPosition"):
            hx = _int_literal(ls.split("=", 1)[1])
        elif ls.startswith("VerticalPosition"):
            hy = _int_literal(ls.split("=", 1)[1])
    if hx is not None and hy is not None:
        return hx, hy
    x = y = fw = fh = 0
    for line in script.splitlines():
        ls = line.strip()
        for name, cur in (("$x", "x"), ("$y", "y"), ("$fw", "fw"), ("$fh", "fh")):
            if ls.startswith(name + " ="):
                val = _int_literal(ls.split("=", 1)[1])
                if cur == "x":
                    x = val or 0
                elif cur == "y":
                    y = val or 0
                elif cur == "fw":
                    fw = val or 0
                else:
                    fh = val or 0
    if not any((x, y, fw, fh)) and "$x =" not in script:
        return None
    # (0,0) is a real coordinate (issue #25): a script with a folded $x/$y
    # positional leg always reports its computed head position.
    if fw or fh:
        hx = round(x * HEAD[0] / fw) if fw else x
        hy = round(y * HEAD[1] / fh) if fh else y
    else:
        hx, hy = x, y
    return (
        max(0, min(hx, HEAD[0] - 1)),
        max(0, min(hy, HEAD[1] - 1)),
    )


def _stdin_lines(stdin_b64: str | None) -> int:
    if not stdin_b64:
        return 0
    return len([ln for ln in stdin_b64.split("\n") if ln.strip()])


def _sizes_from_scripts(scripts: list[str]) -> list[str]:
    """Per-leg capture scripts carry literal WidthPixels/HeightPixels; the folded
    loop drives them from variables, so this is empty for a folded script."""
    sizes = []
    for script in scripts:
        if "GetVirtualSystemThumbnailImage" not in script:
            continue
        w, h = _size_from_script(script)
        if w and h:
            sizes.append(f"{w}x{h}")
    return sizes


def _attempted_from_response(result: pswindows.PSResult | None) -> list[str]:
    if result is None:
        return []
    for line in result.stdout.splitlines():
        if line.startswith("ATTEMPTED="):
            return line[len("ATTEMPTED=") :].split(",")
    return []


def _install(monkeypatch, stub: SpawnCounter) -> SpawnCounter:
    monkeypatch.setattr(pswindows, "run_ps", stub)
    return stub


# ---------------------------------------------------------------------------
# AC1-AC8: spawn counts
# ---------------------------------------------------------------------------


def test_click_spawns_one_process(monkeypatch, unrestricted_cfg):
    """AC1: click(cfg, vm1, 10, 10) starts exactly 1 PowerShell process."""
    stub = _install(monkeypatch, SpawnCounter())
    out = console.click(unrestricted_cfg, "vm1", 10, 10)
    assert stub.count == 1, f"AC1: click started {stub.count} PowerShell processes"
    assert out["vm_name"] == "vm1" and out["head_x"] == 10 and out["head_y"] == 10


def test_mouse_move_spawns_one_process(monkeypatch, unrestricted_cfg):
    """AC2: mouse_move(cfg, vm1, 10, 10) starts exactly 1 PowerShell process."""
    stub = _install(monkeypatch, SpawnCounter())
    out = console.mouse_move(unrestricted_cfg, "vm1", 10, 10)
    assert stub.count == 1, f"AC2: mouse_move started {stub.count} PowerShell processes"
    assert out["vm_name"] == "vm1" and out["head_x"] == 10 and out["head_y"] == 10


def test_mouse_button_and_scroll_spawn_one_process_each(monkeypatch, unrestricted_cfg):
    """AC3: mouse_button and scroll together start exactly 2 processes."""
    stub1 = _install(monkeypatch, SpawnCounter())
    console.mouse_button(unrestricted_cfg, "vm1", 1, True)
    n1 = stub1.count
    stub2 = _install(monkeypatch, SpawnCounter())
    console.scroll(unrestricted_cfg, "vm1", 1)
    total = n1 + stub2.count
    assert total == 2, f"AC3: mouse_button and scroll started {total} PowerShell processes"


def test_keyboard_ops_spawn_one_process_each(monkeypatch, unrestricted_cfg):
    """AC4: press_key, key_combo, type_scancodes (2 codes) and type_text (5 chars)
    together start exactly 4 processes."""
    total = 0
    for op in (
        lambda: console.press_key(unrestricted_cfg, "vm1", "enter"),
        lambda: console.key_combo(unrestricted_cfg, "vm1", ["ctrl", "a"]),
        lambda: console.type_scancodes(unrestricted_cfg, "vm1", [0x1C, 0x9C]),
        lambda: console.type_text(unrestricted_cfg, "vm1", "hello"),
    ):
        stub = _install(monkeypatch, SpawnCounter())
        op()
        total += stub.count
    assert total == 4, f"AC4: four keyboard ops started {total} PowerShell processes"


def test_chunked_input_spawns_one_process(monkeypatch, unrestricted_cfg):
    """AC5: type_text (1200 chars, 3 chunks) and type_scancodes (192 codes, 3
    chunks) together start exactly 2 processes; chunking and pacing stay inside
    the one process and the text rides stdin as base64 lines."""
    text = "a" * 512 + "b" * 512 + "c" * 176
    stub_text = _install(monkeypatch, SpawnCounter())
    out_text = console.type_text(unrestricted_cfg, "vm1", text)
    stub_codes = _install(monkeypatch, SpawnCounter())
    out_codes = console.type_scancodes(unrestricted_cfg, "vm1", list(range(192)))
    total = stub_text.count + stub_codes.count
    assert total == 2, f"AC5: chunked input started {total} PowerShell processes"
    assert out_text["chunks"] == 3 and out_text["chars"] == 1200
    assert out_codes["chunks"] == 3 and out_codes["scancodes_sent"] == 192
    lines = [ln for ln in (stub_text.kwargs[-1]["stdin_b64"] or "").split("\n") if ln.strip()]
    assert len(lines) == 3, "AC5: one folded type_text process must carry 3 stdin lines"
    assert base64.b64decode(lines[0]).decode() == "a" * 512
    assert base64.b64decode(lines[2]).decode() == "c" * 176
    assert text not in stub_text.scripts[-1], "AC5: typed text must never appear in the script"
    assert "[Console]::In.ReadLine()" in stub_text.scripts[-1]
    assert "Start-Sleep -Milliseconds 50" in stub_text.scripts[-1]
    assert "Start-Sleep -Milliseconds 20" in stub_codes.scripts[-1]


def test_screenshot_spawns_one_process(monkeypatch, unrestricted_cfg):
    """AC6: a first-size screenshot success starts exactly 1 process."""
    stub = _install(monkeypatch, SpawnCounter())
    _frame, meta = console.screenshot(unrestricted_cfg, "vm1")
    assert stub.count == 1, f"AC6: screenshot started {stub.count} PowerShell processes"
    assert meta["vm_id"] == GUID
    assert meta["width"] == 1024 and meta["height"] == 768
    assert meta["fallback_used"] == ""
    assert meta["head_resolution"] == {"horizontal": 1024, "vertical": 768}


def test_screenshot_fallback_chain_spawns_one_process_and_never_retries_a_size(monkeypatch, unrestricted_cfg):
    """AC7: a 640x480 request whose every capture fails starts exactly 1 process,
    never attempts a size twice, and still raises ConsoleError."""
    stub = _install(monkeypatch, SpawnCounter(capture_ok=False))
    with pytest.raises(console.ConsoleError):
        console.screenshot(unrestricted_cfg, "vm1", 640, 480)
    sizes = _sizes_from_scripts(stub.scripts) or _attempted_from_response(stub.served[-1])
    no_duplicate_sizes = len(sizes) == len(set(sizes))
    assert (stub.count, no_duplicate_sizes) == (1, True), (
        f"AC7: screenshot fallback chain started {stub.count} processes and attempted {sizes}"
    )
    # Structural pin: the chain is built and de-duplicated INSIDE the script, so
    # a folded script that loops sizes but retries one cannot pass on the stub's
    # synthesized ATTEMPTED line alone.
    script = stub.scripts[-1]
    assert "$sizes" in script, "AC7: the folded screenshot does not build its size chain in-script"
    assert "$seen" in script, "AC7: the folded screenshot has no in-script de-duplication guard"


def test_positional_mouse_script_guards_missing_head(monkeypatch, unrestricted_cfg):
    """AC18: WHEN a positional mouse op runs and the display head resolution is
    unavailable, THE SYSTEM SHALL raise the structured error naming it and never
    click blind. The folded script must carry the head-absence guard ahead of any
    positioning call (a null head would otherwise scale to 0 and click the origin)."""
    stub = _install(monkeypatch, SpawnCounter())
    console.mouse_move(unrestricted_cfg, "vm1", 10, 10)
    script = stub.scripts[-1]
    guard = "display head resolution unavailable"
    assert guard in script, (
        "AC18: positional mouse script has no head-absence guard"
    )
    assert script.index(guard) < script.index("SetAbsolutePosition"), (
        "AC18: the head-absence guard must precede any positioning call"
    )


def test_display_info_wait_and_sequence_spawn_minimum(monkeypatch, unrestricted_cfg):
    """AC8: get_display_info + wait_frame_change + capture_sequence(count=3)
    start at most 5 processes in total."""
    total = 0
    stub = _install(monkeypatch, SpawnCounter())
    info = console.get_display_info(unrestricted_cfg, "vm1")
    total += stub.count
    assert info["enabled_state"] == 2 and info["vm_id"] == GUID

    stub = _install(monkeypatch, SpawnCounter())
    wait = console.wait_frame_change(unrestricted_cfg, "vm1")
    total += stub.count
    assert wait["stop_reason"] == "deadline" and wait["vm_name"] == "vm1"

    stub = _install(monkeypatch, SpawnCounter())
    seq = console.capture_sequence(unrestricted_cfg, "vm1", count=3, interval_s=1)
    total += stub.count
    assert [f["changed_bytes_vs_previous"] for f in seq["frames"]] == [0, 0, 0]
    assert total <= 5, (
        f"AC8: display_info, wait_frame_change and capture_sequence started {total} PowerShell processes"
    )


# ---------------------------------------------------------------------------
# AC9-AC11: SystemName-scoped mouse lookup
# ---------------------------------------------------------------------------


def _mouse_scripts(monkeypatch, unrestricted_cfg) -> list[str]:
    """Generate mouse scripts through both addressing paths. The by-name path
    resolves the GUID inside the script ($vmTarget); the by-id path binds the
    literal GUID via the preamble, which is what proves the filter is scoped to
    THIS VM rather than to an unbound variable."""
    stub = _install(monkeypatch, SpawnCounter())
    console.mouse_move(unrestricted_cfg, "vm1", 10, 10)
    console.scroll(unrestricted_cfg, "vm1", 1)
    console.mouse_move(unrestricted_cfg, vm_id=GUID, x=10, y=10)
    console.scroll(unrestricted_cfg, vm_id=GUID, delta=1)
    return stub.scripts


def _is_mouse_script(script: str) -> bool:
    return any(
        m in script for m in ("SetAbsolutePosition", "SetButtonState", "SetScrollPosition", "ClickButton")
    )


def test_mouse_lookup_filters_by_system_name(monkeypatch, unrestricted_cfg):
    """AC9: the generated mouse scripts select the mouse with a SystemName WQL
    filter bound to the VM target."""
    scripts = _mouse_scripts(monkeypatch, unrestricted_cfg)
    mouse = [s for s in scripts if _is_mouse_script(s)]
    assert mouse, "AC9: no mouse script was generated"
    for script in mouse:
        assert "SystemName='$vmTarget'" in script, "AC9: mouse script has no SystemName filter"
    by_id = [s for s in mouse if "$vmTarget = '" + GUID + "'" in s]
    assert by_id, "AC9: no by-id mouse script binds the VM GUID to $vmTarget"


def test_mouse_lookup_has_no_per_device_association_scan(monkeypatch, unrestricted_cfg):
    """AC10: no generated mouse script contains the per-device association scan."""
    scripts = _mouse_scripts(monkeypatch, unrestricted_cfg)
    hits = sum(s.count("Get-CimAssociatedInstance -InputObject $m") for s in scripts)
    assert hits == 0, "AC10: per-device association scan still present"


def test_display_info_mouse_lookup_filters_by_system_name(monkeypatch, unrestricted_cfg):
    """AC11: the display-info script uses the SystemName filter and drops the
    foreach mouse scan."""
    stub = _install(monkeypatch, SpawnCounter())
    console.get_display_info(unrestricted_cfg, "vm1")
    script = stub.scripts[-1]
    filter_present = "SystemName='$vmTarget'" in script
    loop_present = "foreach ($m in $mice)" in script
    assert (filter_present, loop_present) == (True, False), (
        "AC11: display-info mouse lookup is not SystemName-scoped"
    )


# ---------------------------------------------------------------------------
# AC12: the parse lane captures every op's WMI template (Linux-runnable)
# ---------------------------------------------------------------------------


class _Recorder:
    """The parse lane's stub (tests/unit/test_script_parse.py): every non-leg
    script gets empty stdout, so an op that needs its intermediate values before
    generating its WMI script never generates one."""

    def __init__(self):
        self.scripts: list[str] = []

    def __call__(self, script: str, timeout_s: float | None = None, stdin_b64: str | None = None):
        self.scripts.append(script)
        s = script.strip()
        if "Msvm_ComputerSystem" in s and s.endswith("$vmTarget"):
            return pswindows.PSResult(stdout=GUID, returncode=0)
        return pswindows.PSResult(stdout="", returncode=0)


# One marker per op: a string that appears ONLY in that op's own WMI template.
# The head-resolution script also carries the root\\virtualization\\v2 namespace
# but none of these markers, so the namespace alone cannot satisfy a row.
_OP_MARKERS = (
    ("mouse_move", lambda cfg: console.mouse_move(cfg, "vm1", 100, 50), "SetAbsolutePosition"),
    ("click with coordinates", lambda cfg: console.click(cfg, "vm1", 100, 50), "SetAbsolutePosition"),
    ("mouse_button", lambda cfg: console.mouse_button(cfg, "vm1", 1, True), "SetButtonState"),
    ("scroll", lambda cfg: console.scroll(cfg, "vm1", 1), "SetScrollPosition"),
    ("press_key", lambda cfg: console.press_key(cfg, "vm1", "enter"), "TypeScancodes"),
    ("type_text", lambda cfg: console.type_text(cfg, "vm1", "hi"), "TypeText"),
    ("get_display_info", lambda cfg: console.get_display_info(cfg, "vm1"), "EnabledState"),
    (
        "wait_frame_change",
        lambda cfg: console.wait_frame_change(cfg, "vm1"),
        "GetVirtualSystemThumbnailImage",
    ),
    ("screenshot", lambda cfg: console.screenshot(cfg, "vm1"), "GetVirtualSystemThumbnailImage"),
)


def test_parse_lane_recorder_captures_wmi_template_for_every_console_op(monkeypatch, unrestricted_cfg):
    """AC12: driving every console op against the parse lane's Recorder hands it a
    script carrying that op's own root\\virtualization\\v2 WMI template."""
    rec = _Recorder()
    monkeypatch.setattr(pswindows, "run_ps", rec)
    missing = []
    for name, op, marker in _OP_MARKERS:
        before = len(rec.scripts)
        try:
            op(unrestricted_cfg)
        except Exception:  # noqa: BLE001 - the lane swallows op failures by design
            pass
        produced = [s for s in rec.scripts[before:] if marker in s and WMI_NS_BACKSLASH in s]
        if not produced:
            missing.append(name)
    assert missing == [], f"AC12: ops that never generated their WMI template: {missing}"


# ---------------------------------------------------------------------------
# AC14 substitute evidence: the PS/2 fallback's script structure
# ---------------------------------------------------------------------------


def test_ps2_fallback_branch_present(monkeypatch, unrestricted_cfg):
    """AC14 substitute evidence (no Gen1 VM exists on the available host): the
    generated mouse scripts carry the Msvm_Ps2Mouse fallback under the same
    SystemName filter for non-positional ops, and positional ops report the
    structured error naming the missing synthetic mouse instead of acting."""
    stub = _install(monkeypatch, SpawnCounter())
    console.mouse_button(unrestricted_cfg, "vm1", 1, True)
    console.scroll(unrestricted_cfg, "vm1", 1)
    console.click(unrestricted_cfg, "vm1")
    scripts = stub.scripts[-3:]
    assert len(scripts) == 3, "AC14: expected one script per non-positional mouse op"
    for script, method in zip(scripts, ("SetButtonState", "SetScrollPosition", "ClickButton"), strict=True):
        assert "Msvm_Ps2Mouse" in script, (
            "AC14: no PS/2 fallback branch in the non-positional mouse script"
        )
        assert "SystemName='$vmTarget'" in script
        assert method in script, f"AC14: PS/2 path lost {method}"

    stub = _install(monkeypatch, SpawnCounter())
    console.mouse_move(unrestricted_cfg, "vm1", 10, 10)
    move_script = stub.scripts[-1]
    assert "no synthetic mouse device associated with the VM" in move_script, (
        "AC14: positional ops must name the missing synthetic mouse"
    )
    assert "absolute positioning" in move_script or "SetAbsolutePosition" in move_script


# ---------------------------------------------------------------------------
# AC19: the scancode chunk expression delivers every code (executed in real
# PowerShell 5.1). Phase 4.5 reviewer finding: PS 5.1 flattens @(@(a,b)) for a
# single chunk, so a nested array-of-arrays sent one byte and no stubbed check
# could see it. The structural marker (always evaluated) is the discriminator;
# the execution half runs where PowerShell exists.
# ---------------------------------------------------------------------------

_CHUNK_MARKER = (
    "$r = Invoke-CimMethod -InputObject $kb -MethodName TypeScancodes "
    "-ErrorAction Stop -Arguments @{ ScanCodes = [byte[]]$chunks[$lo..$hi] }"
)


def _executed_chunk_bytes(script: str) -> list[list[int]]:
    """Execute the generated scancode script's chunk slicing in real PowerShell
    5.1 and return the bytes each chunk would deliver.

    The VM-resolution prelude and the CIM calls need a live VM and are
    irrelevant to the slicing, so the harness re-runs exactly the emitted
    `$chunks` literal, `$n`, and the loop's slice arithmetic — verbatim strings
    from the generated script, which is whose PS 5.1 semantics the reviewer's
    Critical finding was about."""
    import os
    import re

    if not os.path.exists(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
        pytest.skip("no PowerShell on this host")
    pswindows.init(Config(unrestricted=True))  # the transport gate, as tests do
    seed = re.search(r"^\$chunks = @\(.*\)$", script, re.M)
    n_line = re.search(r"^\$n = \d+$", script, re.M)
    lo = re.search(r"\$lo = \$i \* 64", script)
    hi = re.search(r"\$hi = \[math\]::Min\(\$lo \+ 63, \$chunks\.Count - 1\)", script)
    sl = re.search(r"\[byte\[\]\]\$chunks\[\$lo\.\.\$hi\]", script)
    assert seed and n_line and lo and hi and sl, "AC19: chunk arithmetic not found in the script"
    body = (
        seed.group(0) + "\n"
        + n_line.group(0) + "\n"
        + "for ($i = 0; $i -lt $n; $i++) {\n"
        + "    " + lo.group(0) + "\n"
        + "    " + hi.group(0) + "\n"
        + "    Write-Output ('SLICE=' + ((" + sl.group(0) + ") -join ','))\n"
        + "}\n"
    )
    result = _REAL_RUN_PS(body, timeout_s=60)
    assert result.returncode == 0, f"AC19: chunk script failed: {result.stderr[:200]}"
    chunks: list[list[int]] = []
    for line in result.stdout.splitlines():
        if line.startswith("SLICE="):
            payload = line[len("SLICE="):]
            chunks.append([int(b) for b in payload.split(",") if b != ""])
    return chunks

def test_scancode_chunk_expression_delivers_all_codes(monkeypatch, unrestricted_cfg):
    """AC19: every code of every chunk reaches TypeScancodes when the generated
    script runs under real PowerShell 5.1 — single-chunk and multi-chunk."""
    stub = _install(monkeypatch, SpawnCounter())
    console.type_scancodes(unrestricted_cfg, "vm1", [0x1C, 0x9C])
    single = stub.scripts[-1]
    assert _CHUNK_MARKER in single, (
        "AC19: the scancode script does not slice its in-script code array"
    )

    stub = _install(monkeypatch, SpawnCounter())
    console.type_scancodes(unrestricted_cfg, "vm1", list(range(192)))
    multi = stub.scripts[-1]
    assert _CHUNK_MARKER in multi

    # press_key/key_combo are single-chunk paths too
    stub = _install(monkeypatch, SpawnCounter())
    console.press_key(unrestricted_cfg, "vm1", "escape")
    key = stub.scripts[-1]
    assert _CHUNK_MARKER in key

    assert _executed_chunk_bytes(single) == [[0x1C, 0x9C]]
    assert _executed_chunk_bytes(key) == [[0x01, 0x81]]
    assert _executed_chunk_bytes(multi) == [
        list(range(64)), list(range(64, 128)), list(range(128, 192)),
    ]


def test_position_from_script_origin_is_real(monkeypatch, unrestricted_cfg):
    """Issue #25 origin protocol: a folded positional script at (0,0)
    resolves to head (0,0), not None — _position_from_script discriminates
    on the positional leg, never on the coordinate values."""
    stub = _install(monkeypatch, SpawnCounter())
    console.click(unrestricted_cfg, "vm1", 0, 0,
                  frame_width=640, frame_height=480)
    assert _position_from_script(stub.scripts[-1]) == (0, 0)
