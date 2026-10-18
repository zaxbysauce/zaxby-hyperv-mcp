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
    fmt: str = "",
    quality=None,
    scale=None,
    crop=None,
    if_changed_from: str = "",
) -> dict:
    """Screenshot + evidence metadata, optionally with a guest UIA tree.

    Resolves the target once (name or GUID) — the ONLY resolve in this
    module — and the UIA leg addresses the guest by that resolved GUID via
    run_guest_inner. console.screenshot receives ONLY the GUID (no name):
    it re-resolves the fresh name itself by GUID, so a rename between this
    module's resolve and the screenshot can never fork the bundle's
    identity (PRR-006), and the whole bundle acts on one identity.

    Returns {ok, image: <console.Frame>, meta: <screenshot meta extended with
    ui_tree>} mirroring console.screenshot's (image, meta) tuple contract; the
    image is a console.Frame — a PIL.Image.Image subclass carrying the decoded
    pixels and the single encoding made for them, which the server layer
    reuses rather than encoding again. The server layer converts to
    [ImageContent, TextContent].

    `image` is None when `if_changed_from` matches the current capture: the
    frame is unchanged, so nothing is decoded, encoded or written, and `meta`
    carries `unchanged: true`. The UI-tree leg is skipped in that case too —
    it is a credentialed 60 s PowerShell Direct session whose entire purpose is
    to describe the frame that was just captured, and shipping its content
    beside `unchanged: true` both spends the cost and discloses fresh guest
    content for a frame the caller already has. `meta["ui_tree"]` then reports
    `{requested: true, skipped: true, reason}` so the omission is visible
    rather than silent; a caller who passed `ui_tree=false` still gets exactly
    `{requested: false}`, because the frame's change state is not its business.
    The output options (`fmt`, `quality`, `scale`, `crop`) are
    the same ones console.screenshot validates, so an unsupported value is
    refused here too rather than silently ignored.
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
        cfg, width=width, height=height, save_path=save_path, vm_id=ref.id,
        fmt=fmt, quality=quality, scale=scale, crop=crop,
        if_changed_from=if_changed_from,
    )
    ui: dict[str, Any] = {"requested": ui_tree}
    if meta.get("unchanged") and ui_tree:
        # The frame is unchanged, so the tree would describe a frame the
        # caller already has a tree for. Skip the credentialed session and
        # say so, rather than paying for it and merging its content in.
        # Gated on the REQUEST: a caller who asked for no tree must keep
        # getting exactly {"requested": False} whatever the frame did, or
        # the unchanged path changes a key set the caller never varied.
        ui = {
            "requested": True,
            "skipped": True,
            "reason": (
                "unchanged: the UI tree describes the frame this call captured, "
                "and an unchanged frame produces no new output image — so there "
                "is nothing new for the tree to describe"
            ),
        }
    elif tree_cred is not None:
        try:
            outcome = run_guest_inner(
                cfg, ref.id,
                _uia_script(ui_tree_depth, ui_tree_max_elements), tree_cred,
                timeout_ms=60000, mode="read",
            )
            ui = {
                "requested": True,
                "ok": True,
                "elements": outcome.get("elements"),
                "truncated": bool(outcome.get("truncated")),
                "tree": outcome.get("tree"),
            }
        except Exception as exc:
            from . import errors  # late import: errors pulls the policy tree
            ui = {
                "requested": True, "ok": False,
                "error": str(exc),
                # Feedback PRR-004: classify the swallowed failure (a lock
                # expiry becomes "busy" here instead of an anonymous string).
                "error_class": errors.classify(exc),
                "note": "a PowerShell Direct session may not see an interactive desktop",
            }
    meta = dict(meta)
    meta["ui_tree"] = ui
    return {"ok": True, "image": image, "meta": meta}
