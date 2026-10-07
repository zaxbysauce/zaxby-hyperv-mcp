"""Evidence capture: screenshot paired with capture metadata and an optional
bounded guest UI element tree (AC13).

The screenshot core is reused from console.screenshot unchanged (fallback
chain, frame hash, host_write gate for save_path), so this module's new
surface is the SINGLE-CALL bundle: [ImageContent, TextContent] where the
text metadata pairs the image with captured_at (UTC ISO-8601), vm_id,
capture dimensions, frame hash, and — when requested — a UIAutomation
element tree gathered via PowerShell Direct.

The UIA leg is best-effort with explicit error reporting: a PS Direct
session may not see an interactive desktop, in which case ui_tree carries
{ok: False, error: ...} while the screenshot still ships. Credentials are
required ONLY for the UI tree leg.
"""

from __future__ import annotations

from typing import Any

from . import console, vmident
from .config import Config
from .credentials import CredentialError, CredentialSet
from .diagnostics import run_guest_inner

_UIA_MAX_DEPTH = 6
_UIA_MAX_ELEMENTS = 500


def _uia_script(depth: int, max_elements: int) -> str:
    depth = max(1, min(int(depth), _UIA_MAX_DEPTH))
    cap = max(1, min(int(max_elements), _UIA_MAX_ELEMENTS))
    return f"""
Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop
$script:seen = 0
$script:cap = {cap}
function Walk($el, $depth) {{
    if ($script:seen -ge $script:cap -or $depth -lt 0) {{ return $null }}
    $script:seen++
    $rect = ''
    try {{
        $r = $el.Current.BoundingRectangle
        $rect = "{{{0}}},{{{1}}},{{{2}}},{{{3}}}" -f [int]$r.X, [int]$r.Y, [int]$r.Width, [int]$r.Height
    }} catch {{ $rect = '' }}
    $node = @{{
        name = ''
        control_type = ''
        automation_id = ''
        class_name = ''
        rect = $rect
        children = @()
    }}
    try {{ $node.name = [string]$el.Current.Name }} catch {{ }}
    try {{ $node.control_type = [string]$el.Current.ControlType.ProgrammaticName -replace '^ControlType\\.', '' }} catch {{ }}
    try {{ $node.automation_id = [string]$el.Current.AutomationId }} catch {{ }}
    try {{ $node.class_name = [string]$el.Current.ClassName }} catch {{ }}
    if ($depth -gt 0) {{
        $kids = $el.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($k in $kids) {{
            if ($script:seen -ge $script:cap) {{ break }}
            $child = Walk $k ($depth - 1)
            if ($null -ne $child) {{ $node.children += $child }}
        }}
    }}
    return $node
}}
$root = [System.Windows.Automation.AutomationElement]::RootElement
$tree = Walk $root {depth}
[PSCustomObject]@{{ elements = $script:seen; truncated = ($script:seen -ge $script:cap); tree = $tree }} |
    ConvertTo-Json -Compress -Depth {_UIA_MAX_DEPTH + 2}
""".strip()


def capture_evidence(
    cfg: Config,
    vm_name: str = "",
    width: int = 1024,
    height: int = 768,
    save_path: str = "",
    *,
    ui_tree: bool = False,
    ui_tree_depth: int = 3,
    ui_tree_max_elements: int = 200,
    cred: CredentialSet | None = None,
    vm_id: str = "",
) -> dict:
    """Screenshot + evidence metadata, optionally with a guest UIA tree.

    Resolves the target once (name or GUID) — the ONLY resolve in this
    module — and the UIA leg addresses the guest by that resolved GUID via
    run_guest_inner. console.screenshot receives ONLY the GUID (no name):
    it re-resolves the fresh name itself by GUID, so a rename between this
    module's resolve and the screenshot can never fork the bundle's
    identity (PRR-006), and the whole bundle acts on one identity.

    Returns {ok, image: <PIL.Image>, meta: <screenshot meta extended with
    ui_tree>} mirroring console.screenshot's (image, meta) tuple contract;
    the server layer converts to [ImageContent, TextContent].
    """
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    tree_cred: CredentialSet | None = None
    if ui_tree:
        if cred is None:
            raise CredentialError(
                "guest credentials are required for the UI element tree "
                "(set HYPERV_GUEST_USERNAME/HYPERV_GUEST_PASSWORD or pass username/password)"
            )
        tree_cred = cred

    image, meta = console.screenshot(
        cfg, width=width, height=height, save_path=save_path, vm_id=ref.id
    )
    ui: dict[str, Any] = {"requested": ui_tree}
    if tree_cred is not None:
        try:
            outcome = run_guest_inner(
                cfg, ref.id,
                _uia_script(ui_tree_depth, ui_tree_max_elements), tree_cred,
                timeout_ms=60000,
            )
            ui = {
                "requested": True,
                "ok": True,
                "elements": outcome.get("elements"),
                "truncated": bool(outcome.get("truncated")),
                "tree": outcome.get("tree"),
            }
        except Exception as exc:
            ui = {
                "requested": True, "ok": False,
                "error": str(exc),
                "note": "a PowerShell Direct session may not see an interactive desktop",
            }
    meta = dict(meta)
    meta["ui_tree"] = ui
    return {"ok": True, "image": image, "meta": meta}
