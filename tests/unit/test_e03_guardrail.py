"""Issue #24 Phase-4.2 guardrail (NOT part of the frozen checkpoint set —
this file is additive hardening authored after the red checkpoint, per the
amendment-avoidance rule for frozen files).

The defect class the frozen checks close is "coordination state that lives
only in the request lifecycle": a long-running tool whose result/progress
dies with one blocking call, and coordination arguments that never reach the
mechanism that must honour them. The single guardrail for the class: every
tool registered in `operations.DETACHABLE_TOOLS` must DECLARE both
`detach` and `idempotency_key` on its schema — a future tool added to the
detachable set without the parameters would silently re-create the original
defect (the coordination argument refused as unknown) while every other test
stays green.
"""

import asyncio
import importlib
import json

import hyperv_mcp.server as server_module
from hyperv_mcp import operations


def test_every_detachable_tool_declares_the_coordination_params(tmp_path):
    """Schema-level guardrail for the issue-#24 defect class: each member of
    operations.DETACHABLE_TOOLS carries detach AND idempotency_key in its
    input schema. RED on the pre-fix base (the schema check ran against a
    server whose detachable tools declared neither), GREEN after the fix —
    and GREEN means zero drift between the detachable set and the declared
    parameters forever after."""
    p = tmp_path / "e03-guardrail-config.json"
    p.write_text(json.dumps({"allowed_vm_patterns": ["test-*"], "unrestricted": True}),
                 encoding="utf-8")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(p)})
    tools = {t.name: t for t in asyncio.run(mod.get_mcp().list_tools())}

    assert len(operations.DETACHABLE_TOOLS) == 13
    missing = []
    for name in sorted(operations.DETACHABLE_TOOLS):
        props = (getattr(tools[name], "input_schema", None) or {}).get("properties", {})
        for param in ("detach", "idempotency_key"):
            if param not in props:
                missing.append(f"{name}.{param}")
    assert not missing, (
        "defect-class guardrail: every detachable tool must declare both "
        f"coordination parameters; missing {missing}"
    )
