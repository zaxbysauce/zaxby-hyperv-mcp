#!/usr/bin/env python3
"""Opt-in multi-agent soak benchmark for hyperv-mcp (issue #20, ENH-04).

Runs 1, 4 and 8 concurrent agents against the real tool layer and reports
p50/p95/p99 plus busy and incorrect rates per agent count. The audit's FND-01,
FND-02 and FND-15 latency numbers are not reproducible from the repo without
something like this.

Two modes:

  --fake   drives the REAL tool layer with a stubbed ``pswindows.run_ps``, so
           the harness itself is CI-tested without Hyper-V. The stub serves the
           same leg shapes the frozen acceptance checks use.
  (live)   drives a real host. Refuses to start unless HYPERV_MCP_INTEGRATION=1,
           HYPERV_MCP_SOAK=1 and HYPERV_MCP_TEST_VM are all set and guest
           credentials resolve — the same disposable-VM discipline as
           tests/integration/conftest.py.

Both modes use only read-only and console-input tools. No lifecycle or
destructive call is ever made.

Percentiles reuse ``hyperv_mcp.consolebench.pct`` (nearest-rank) rather than
reimplementing them, so the two cannot drift. No new runtime dependency.

Usage::

    python scripts/soak_bench.py --fake --agents 1,4,8 --iterations 3 --json
    HYPERV_MCP_INTEGRATION=1 HYPERV_MCP_SOAK=1 HYPERV_MCP_TEST_VM=<disposable> \\
        python scripts/soak_bench.py --agents 1,4,8 --iterations 20 --json
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import importlib
import json
import os
import sys
import tempfile
import threading
import time
from contextvars import ContextVar
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from hyperv_mcp import consolebench, pswindows  # noqa: E402

#: A stable stand-in GUID for the fake transport's resolution legs.
FAKE_GUID = "e953c649-dcab-438d-9a54-3af74a82b624"
FAKE_VM = "test-vm-soak"
DEFAULT_AGENTS = "1,4,8"
TOOLS = ("hyperv_console_screenshot", "hyperv_guest_run_ps", "hyperv_console_scroll")


# ---------------------------------------------------------------------------
# the fake transport
# ---------------------------------------------------------------------------


def _capture_payload(w: int, h: int) -> str:
    """A size-correct GetVirtualSystemThumbnailImage JSON payload: a 4-byte
    opaque prefix followed by w*h*2 bytes of RGB565."""
    raw = b"\x00" * (w * h * 2 + 4)
    return json.dumps({"returnValue": 0, "imageDataB64": base64.b64encode(raw).decode()})


def _classify(script: str) -> str:
    s = script.strip()
    if "Get-VM -Id $vmTarget" in s and s.endswith("$vm.Name"):
        return "resolve_id"
    if "Msvm_ComputerSystem" in s and s.endswith("$vmTarget"):
        return "resolve_name"
    if "Invoke-Command -VMId" in s:
        return "guest"
    if "GetVirtualSystemThumbnailImage" in s:
        return "capture"
    if any(
        marker in s
        for marker in (
            "SetScrollPosition", "SetButtonState", "SetAbsolutePosition",
            "ClickButton", "TypeText", "TypeScancodes",
        )
    ):
        return "input"
    return "list"


class SoakStub:
    """``pswindows.run_ps`` stand-in for --fake mode.

    Serves the leg shapes the real tool layer expects (the same ones the frozen
    acceptance checks use) and echoes the calling agent's token on the guest
    leg, so an ``incorrect`` sample means the token really did not come back
    rather than the stub having nothing to say.

    The token rides a ContextVar rather than a thread-id map: mcp 2.x dispatches
    every sync tool body through ``anyio.to_thread.run_sync``, which copies the
    caller's context into the worker thread, so a value set in the agent thread
    before its call is visible to the stub inside the worker. A thread-id map
    would see the worker's ident instead of the agent's and silently echo "".
    """

    def __init__(self, durations: dict[str, int] | None = None) -> None:
        self.durations = dict(durations or {})
        self.default_ms = 25
        self._mu = threading.Lock()
        self.calls = 0

    def adopt(self, token: str) -> None:
        _token_var.set(token)

    def _token(self) -> str:
        return _token_var.get()

    def __call__(self, script: str, **kwargs) -> pswindows.PSResult:
        leg = _classify(script)
        duration = int(self.durations.get(leg, self.default_ms))
        with self._mu:
            self.calls += 1
        return pswindows.PSResult(
            stdout=self._serve(leg), returncode=0, duration_ms=duration
        )

    def _serve(self, leg: str) -> str:
        if leg == "resolve_id":
            return FAKE_VM
        if leg == "resolve_name":
            return FAKE_GUID
        if leg == "guest":
            return json.dumps(
                {"exit_code": 0, "stdout": self._token(), "stderr": ""}
            )
        if leg == "capture":
            return (
                f"VMID={FAKE_GUID}\nSIZES=160x160,640x480,320x240\nUSED=160x160\n"
                + _capture_payload(160, 160)
            )
        if leg == "input":
            return "RC=0"
        return ""


#: The calling agent's token, copied into the worker thread by the dispatch.
_token_var: ContextVar[str] = ContextVar("hyperv_mcp_soak_token", default="")


# ---------------------------------------------------------------------------
# sampling
# ---------------------------------------------------------------------------


def summarize(samples: list[dict]) -> dict:
    """Aggregate soak samples into one report row.

    Percentiles are nearest-rank over the ``ok`` samples only (a fail-fast
    error must never read as a fast sample). ``busy_rate`` and
    ``incorrect_rate`` are counted over ALL samples, so a harness that rejects
    everything reports its own rejection rate instead of hiding it.

    An empty ok-pool yields null percentiles with the rates still computed,
    rather than raising — ``summarize`` cannot know which mode called it, so the
    behaviour is the same in both.
    """
    total = len(samples)
    ok_ms = [float(s["ms"]) for s in samples if s.get("ok")]
    busy = sum(1 for s in samples if s.get("busy"))
    incorrect = sum(1 for s in samples if s.get("incorrect"))
    out: dict = {
        "n": total,
        "ok": len(ok_ms),
        "busy": busy,
        "incorrect": incorrect,
        "busy_rate": (busy / total) if total else 0.0,
        "incorrect_rate": (incorrect / total) if total else 0.0,
    }
    if ok_ms:
        out["p50_ms"] = consolebench.pct(ok_ms, 0.50)
        out["p95_ms"] = consolebench.pct(ok_ms, 0.95)
        out["p99_ms"] = consolebench.pct(ok_ms, 0.99)
    else:
        out["p50_ms"] = None
        out["p95_ms"] = None
        out["p99_ms"] = None
    return out


def _blocks(result):
    blocks = result[0] if isinstance(result, tuple) else result
    if not isinstance(blocks, list) and hasattr(blocks, "content"):
        blocks = blocks.content
    return blocks if isinstance(blocks, list) else [blocks]


def _sample(tool: str, result, elapsed_ms: float, token: str) -> dict:
    """Turn one tool call into one sample.

    Success is read from the CallToolResult's ``is_error`` rather than from an
    ``ok`` field in the payload, because the image tools return a metadata
    sidecar that carries no ``ok`` key at all -- only the envelope tools do.
    """
    blocks = _blocks(result)
    is_error = bool(getattr(result, "is_error", False))
    envelope: dict = {}
    for block in blocks:
        if getattr(block, "type", "") == "text":
            try:
                envelope = json.loads(block.text)
            except ValueError:
                envelope = {}
            break
    ok = (not is_error) and envelope.get("ok", True) is not False
    if ok and tool == "hyperv_console_screenshot":
        # The screenshot tool returns [ImageContent, metadata]; no image block
        # means the capture did not happen.
        ok = any(getattr(b, "type", "") == "image" for b in blocks)
    sample = {
        "tool": tool,
        "ok": ok,
        "ms": elapsed_ms,
        "busy": envelope.get("error_class") == "busy",
        "incorrect": False,
    }
    if not ok:
        return sample
    if tool == "hyperv_guest_run_ps":
        # The guest leg echoes the agent's own token; anything else is wrong.
        sample["incorrect"] = envelope.get("stdout") != token
    elif tool == "hyperv_console_screenshot":
        # A requested-size mismatch only sets fallback_used metadata; the
        # returned dimensions are what the caller asked for unless the capture
        # genuinely fell back, which is worth seeing in the rate.
        sample["incorrect"] = bool(envelope.get("fallback_used"))
    return sample


# ---------------------------------------------------------------------------
# modes
# ---------------------------------------------------------------------------


def _fake_server(tmp: Path):
    """Bootstrap a real server whose PowerShell transport is the stub.

    The config allows ``test-*`` VMs and the console_input destructive
    category, and points the audit sink at a tmp file; guest credentials are
    monkeypatched into the environment. Without all three, every sample would
    be a policy or credential rejection and the run would measure nothing.
    """
    import hyperv_mcp.server as server_module

    log = tmp / "soak-audit.jsonl"
    cfg = tmp / "soak-config.json"
    cfg.write_text(
        json.dumps(
            {
                "allowed_vm_patterns": ["test-*"],
                "audit_log_path": str(log),
                "destructive": {"console_input": True},
            }
        ),
        encoding="utf-8",
    )
    os.environ["HYPERV_MCP_CONFIG"] = str(cfg)
    os.environ["HYPERV_GUEST_USERNAME"] = "soak-agent"
    os.environ["HYPERV_GUEST_PASSWORD"] = "soak-agent-pass"
    mod = importlib.reload(server_module)
    # The config path must ride the environ handed to bootstrap, exactly as the
    # frozen acceptance checks do — bootstrap(environ) forwards it to
    # Config.load(environ), and an empty dict silently falls back to defaults,
    # which deny every console_input call and make the whole run measure its own
    # rejections.
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg)})
    return mod


def _agent_loop(mcp, stub, token: str, iterations: int, samples: list, lock: threading.Lock) -> None:
    stub.adopt(token)
    for _ in range(iterations):
        for tool in TOOLS:
            args: dict = {"vm_name": FAKE_VM}
            if tool == "hyperv_console_screenshot":
                args = {"vm_name": FAKE_VM, "width": 160, "height": 160}
            elif tool == "hyperv_guest_run_ps":
                args = {"vm_name": FAKE_VM, "script": f"Write-Output {token}"}
            elif tool == "hyperv_console_scroll":
                args = {"vm_name": FAKE_VM, "delta": 1}
            t0 = time.monotonic()
            try:
                result = asyncio.run(mcp.call_tool(tool, args))
            except Exception as exc:  # a crash is a sample too, not a hang
                elapsed = (time.monotonic() - t0) * 1000.0
                sample = {
                    "tool": tool, "ok": False, "ms": elapsed,
                    "busy": False, "incorrect": False, "error": type(exc).__name__,
                }
            else:
                sample = _sample(tool, result, (time.monotonic() - t0) * 1000.0, token)
            with lock:
                samples.append(sample)


#: Environment the fake mode sets and MUST restore, so running the harness
#: inside a test process cannot leak a deleted config path or a fake guest
#: credential into whichever test runs next.
_FAKE_ENV = (
    "HYPERV_MCP_CONFIG",
    "HYPERV_GUEST_USERNAME",
    "HYPERV_GUEST_PASSWORD",
    "HYPERV_MCP_UNRESTRICTED",
)


def _run_fake(agents: int, iterations: int) -> dict:
    from hyperv_mcp import wmiconsole

    stub = SoakStub()
    saved_run_ps = pswindows.run_ps
    saved_com_available = wmiconsole.COM_AVAILABLE
    saved_env = {name: os.environ.get(name) for name in _FAKE_ENV}
    pswindows.run_ps = stub
    # Force the PowerShell transport, the same way consolebench's
    # --transport powershell does. On a host where the in-process WMI backend
    # connects, console tools would otherwise serve through it and fail to
    # resolve the fake VM, turning every console sample into a transport error
    # instead of a measurement.
    wmiconsole.COM_AVAILABLE = False
    samples: list[dict] = []
    lock = threading.Lock()
    try:
        with tempfile.TemporaryDirectory(prefix="hyperv-mcp-soak-") as tmpdir:
            mod = _fake_server(Path(tmpdir))
            mcp = mod.get_mcp()
            threads = [
                threading.Thread(
                    target=_agent_loop,
                    args=(mcp, stub, f"soak-token-{i}", iterations, samples, lock),
                    name=f"soak-agent-{i}",
                )
                for i in range(agents)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=300)
            alive = [t.name for t in threads if t.is_alive()]
    finally:
        pswindows.run_ps = saved_run_ps
        wmiconsole.COM_AVAILABLE = saved_com_available
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        import hyperv_mcp.server as server_module

        importlib.reload(server_module)
    row = summarize(samples)
    row["agents"] = agents
    row["iterations"] = iterations
    row["mode"] = "fake"
    if alive:
        row["hung_agents"] = alive
    return row


def _live_env_ready() -> tuple[bool, str]:
    """The live mode's precondition, as (ready, reason).

    Mirrors tests/integration/conftest.py: the three soak variables plus guest
    credentials, all read from THIS process's environment.
    """
    if os.environ.get("HYPERV_MCP_INTEGRATION", "") != "1":
        return False, "HYPERV_MCP_INTEGRATION is not set to 1 (real Hyper-V tests stay skipped)"
    if os.environ.get("HYPERV_MCP_SOAK", "") != "1":
        return False, "HYPERV_MCP_SOAK is not set to 1"
    vm = (os.environ.get("HYPERV_MCP_TEST_VM") or "").strip()
    if not vm:
        return False, "HYPERV_MCP_TEST_VM is not set (name a disposable test VM)"
    have_creds = os.environ.get("HYPERV_GUEST_USERNAME", "") and (
        os.environ.get("HYPERV_GUEST_PASSWORD", "")
        or os.environ.get("HYPERV_GUEST_PASSWORD_FILE", "")
    )
    if not have_creds:
        return False, "guest credentials missing (HYPERV_GUEST_USERNAME + PASSWORD/FILE)"
    return True, vm


def _run_live(agents: int, iterations: int) -> dict:
    ready, detail = _live_env_ready()
    if not ready:
        raise SystemExit(f"soak_bench: live mode refused: {detail}")
    vm = detail
    import hyperv_mcp.credentials as credentials
    import hyperv_mcp.pswindows as pswindows_mod
    from hyperv_mcp.config import Config

    credentials.init(Config(unrestricted=True))
    pswindows_mod.init(Config(unrestricted=True), credentials.redact)
    import hyperv_mcp.auditlog as auditlog

    auditlog.init(Config(unrestricted=True))

    from hyperv_mcp import console, guestexec

    samples: list[dict] = []
    lock = threading.Lock()
    tokens = {i: f"live-token-{i}" for i in range(agents)}

    def agent(index: int) -> None:
        token = tokens[index]
        for _ in range(iterations):
            for tool in TOOLS:
                t0 = time.monotonic()
                try:
                    if tool == "hyperv_console_screenshot":
                        console.screenshot(cfg_unrestricted(), vm, 160, 160)
                        ok, extra = True, {}
                    elif tool == "hyperv_guest_run_ps":
                        out = guestexec.guest_run_ps(
                            cfg_unrestricted(), vm, f"Write-Output {token}"
                        )
                        ok = bool(out.get("ok"))
                        extra = {"stdout": out.get("stdout", "")}
                    else:
                        out = console.scroll(cfg_unrestricted(), vm, 1)
                        ok = bool(out.get("ok"))
                        extra = {}
                except Exception as exc:
                    elapsed = (time.monotonic() - t0) * 1000.0
                    sample = {
                        "tool": tool, "ok": False, "ms": elapsed,
                        "busy": False, "incorrect": False, "error": type(exc).__name__,
                    }
                else:
                    elapsed = (time.monotonic() - t0) * 1000.0
                    sample = {
                        "tool": tool, "ok": ok, "ms": elapsed,
                        "busy": False, "incorrect": False,
                    }
                    if ok and tool == "hyperv_guest_run_ps":
                        sample["incorrect"] = extra.get("stdout") != token
                    if ok and tool == "hyperv_console_screenshot":
                        sample["incorrect"] = bool(extra.get("fallback_used"))
                with lock:
                    samples.append(sample)

    threads = [
        threading.Thread(target=agent, args=(i,), name=f"live-agent-{i}")
        for i in range(agents)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=600)
    alive = [t.name for t in threads if t.is_alive()]
    row = summarize(samples)
    row["agents"] = agents
    row["iterations"] = iterations
    row["mode"] = "live"
    row["vm"] = vm
    if alive:
        row["hung_agents"] = alive
    return row


def cfg_unrestricted():
    from hyperv_mcp.config import Config

    return Config(unrestricted=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_agents(text: str) -> list[int]:
    counts = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        if value < 1:
            raise ValueError(f"agent count must be >= 1, got {value}")
        counts.append(value)
    if not counts:
        raise ValueError("no agent counts given")
    return counts


def _render(row: dict) -> str:
    def num(key: str) -> str:
        value = row.get(key)
        return f"{value:9.1f}" if isinstance(value, (int, float)) else "      null"

    return (
        f"agents={row['agents']:<3} n={row['n']:<5} ok={row['ok']:<5} "
        f"busy={row['busy']:<3} incorrect={row['incorrect']:<3} "
        f"p50={num('p50_ms')} p95={num('p95_ms')} p99={num('p99_ms')} "
        f"busy_rate={row['busy_rate']:.4f} incorrect_rate={row['incorrect_rate']:.4f}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="soak_bench",
        description="Opt-in multi-agent soak benchmark for hyperv-mcp.",
    )
    parser.add_argument("--fake", action="store_true", help="stub run_ps; no Hyper-V needed")
    parser.add_argument("--agents", default=DEFAULT_AGENTS, help="comma-separated agent counts")
    parser.add_argument("--iterations", type=int, default=3, help="loops per agent")
    parser.add_argument("--json", action="store_true", help="one JSON row per agent count")
    parser.add_argument("--vm", default="", help="live mode only: the disposable test VM")
    args = parser.parse_args(argv)

    if args.iterations < 1:
        print("soak_bench: --iterations must be >= 1", file=sys.stderr)
        return 2
    try:
        counts = _parse_agents(args.agents)
    except ValueError as exc:
        print(f"soak_bench: {exc}", file=sys.stderr)
        return 2

    runner = _run_fake if args.fake else _run_live
    for count in counts:
        row = runner(count, args.iterations)
        if args.json:
            print(json.dumps(row, sort_keys=True))
        else:
            print(_render(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
