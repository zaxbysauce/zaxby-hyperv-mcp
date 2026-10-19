"""Console latency benchmark engine (issue #45, AC2/AC3).

Committed, offline-testable machinery behind the real-host benchmark:

  - ``pct``: nearest-rank percentile, ``rank = max(1, ceil(q * n))`` over
    ascending-sorted values (exact integers on integer vectors — the frozen
    selftest pins three of them).
  - ``bench``: run one operation n times and report n/p50_ms/p95_ms/mean_ms
    (plus ``last_result`` so callers can verify which transport served).
  - ``render_comparison``: before/after report (call it with two DIFFERENT
    measurements; a single run prints its rows as JSON only).
  - ``run_soak``: concurrent-agent soak — each agent thread runs every op
    n times; FAILED ops are counted and EXCLUDED from the percentiles
    (a fail-fast error must never read as a fast sample), and each entry
    reports its error count plus per-op latency vectors.

CLI (real-host evidence generator, AC4)::

    python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --n 15
    python -m hyperv_mcp.consolebench --vm NAME --n 15 --agents 4
    python -m hyperv_mcp.consolebench --vm NAME --transport powershell
    python -m hyperv_mcp.consolebench --vm NAME --transport powershell \
        --baseline before.json
    python -m hyperv_mcp.consolebench --selftest

Scope and policy note: the CLI runs with an UNRESTRICTED in-process config
(it is an operator tool driving the host directly, not the policy-gated
MCP server) — ``--vm`` is NOT subject to allowed_vm_patterns and input ops
are NOT gated by the console_input category. Only point it at disposable
VMs. ``--transport powershell`` forces the fallback transport in-process
by setting ``wmiconsole.COM_AVAILABLE = False`` (benchmark-only forcing —
the product has no config knob); ``--transport wmi`` sets the flag the
other way and the run VERIFIES that served ops actually reported the wmi
transport, failing honestly when the plane is unreachable instead of
labeling PowerShell numbers as WMI. ``--baseline`` renders a
render_comparison table against a previous run's saved JSON rows.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any

from . import config as config_mod


def pct(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile: rank = max(1, ceil(q * n)) over the
    ascending-sorted values; pct(values, q) == sorted(values)[rank - 1].

    `Sequence` rather than `list` because `list` is invariant: a
    `list[int]` — which is what a millisecond counter naturally holds —
    is not a `list[float]`, so a `list` annotation here forces every
    caller to convert. `sorted()` works on any Sequence, so widening
    costs nothing and `int` is promotable to `float`.
    """
    if not values:
        raise ValueError("pct of an empty list")
    if not (0.0 <= q <= 1.0):
        raise ValueError("q must be within 0.0..1.0")
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


def bench(fn: Callable[..., Any], n: int, **kw: Any) -> dict:
    """Time n executions of fn(**kw); returns n/p50_ms/p95_ms/mean_ms plus
    ``last_result`` (fn's final return, for transport verification)."""
    if n < 1:
        raise ValueError("n must be >= 1")
    times_ms: list[float] = []
    last: Any = None
    for _ in range(n):
        t0 = time.monotonic()
        last = fn(**kw)
        times_ms.append((time.monotonic() - t0) * 1000.0)
    return {
        "n": n,
        "p50_ms": pct(times_ms, 0.50),
        "p95_ms": pct(times_ms, 0.95),
        "mean_ms": sum(times_ms) / len(times_ms),
        "last_result": last,
    }


def render_comparison(before_rows: list[dict], after_rows: list[dict]) -> str:
    """Side-by-side report; rows are dicts with at least a 'label' key.
    Both sections list their own rows verbatim, so before/after labels do
    not need to match one-to-one."""
    def _section(title: str, rows: list[dict]) -> list[str]:
        lines = [f"== {title} ==", "label                                  p50_ms      p95_ms"]

        def _num(row: dict, key: str) -> str:
            value = row.get(key)
            return f"{value:10.1f}" if isinstance(value, (int, float)) else "         -"

        for row in rows:
            label = str(row.get("label"))
            lines.append(
                f"{label[:39]:<40}{_num(row, 'p50_ms')}{_num(row, 'p95_ms')}"
            )
        return lines

    return "\n".join(_section("before", before_rows) + [""] + _section("after", after_rows))


def run_soak(op_fns: list[Callable[[], Any]], agents: int, n: int) -> list[dict]:
    """Each of ``agents`` threads runs every op ``n`` times; returns one
    stats dict per agent. FAILED ops are counted (``errors``) and excluded
    from the percentiles, so a fail-fast error never reads as a fast
    sample; ``per_op_ms`` carries per-op latency vectors for per-op p50."""
    if agents < 1 or n < 1:
        raise ValueError("agents and n must be >= 1")
    results: list[dict] = [{} for _ in range(agents)]

    def _agent(index: int) -> None:
        times_ms: list[float] = []
        per_op_ms: list[list[float]] = [[] for _ in op_fns]
        errors = 0
        last_error = ""
        for _ in range(n):
            for op_index, op in enumerate(op_fns):
                t0 = time.monotonic()
                try:
                    op()
                except Exception as exc:  # noqa: BLE001 - soak counts failures
                    errors += 1
                    last_error = f"{type(exc).__name__}: {exc}"
                    continue  # failed ops never enter the latency pool
                times_ms.append((time.monotonic() - t0) * 1000.0)
                per_op_ms[op_index].append(times_ms[-1])
        entry: dict[str, Any] = {
            "p50_ms": pct(times_ms, 0.50) if times_ms else None,
            "p95_ms": pct(times_ms, 0.95) if times_ms else None,
            "mean_ms": sum(times_ms) / len(times_ms) if times_ms else None,
            "n": len(times_ms),
            "errors": errors,
        }
        if last_error:
            entry["last_error"] = last_error
        if op_fns:
            entry["per_op_ms"] = per_op_ms
        results[index] = entry

    threads = [threading.Thread(target=_agent, args=(i,)) for i in range(agents)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _selftest() -> int:
    failures: list[str] = []

    def _check(ok: bool, what: str) -> None:
        if not ok:
            failures.append(what)

    _check(pct([10, 20, 30, 40], 0.5) == 20, "pct rank 2")
    _check(pct([10, 20, 30, 40], 0.75) == 30, "pct rank 3")
    _check(pct([10, 20, 30, 40], 0.0) == 10, "pct rank clamp")
    _check(pct([3, 1, 2], 0.5) == 2, "pct sorts internally")

    calls: list[str] = []

    def op(tag: str) -> None:
        calls.append(tag)

    stats = bench(op, 4, tag="synthetic")
    _check(stats["n"] == 4 and calls == ["synthetic"] * 4, "bench calls fn n times")
    _check(all(isinstance(stats[k], (int, float))
               for k in ("p50_ms", "p95_ms", "mean_ms")), "bench keys")

    table = render_comparison(
        [{"label": "before-screenshot", "p50_ms": 1200.0}],
        [{"label": "after-screenshot", "p50_ms": 40.0}],
    )
    _check("before-screenshot" in table and "after-screenshot" in table,
           "render_comparison labels")

    lock = threading.Lock()
    counter = {"runs": 0}

    def soak_op() -> None:
        with lock:
            counter["runs"] += 1

    per_agent = run_soak([soak_op], agents=3, n=2)
    _check(counter["runs"] == 6, "soak run count")
    _check(len(per_agent) == 3
           and all("p50_ms" in e and "p95_ms" in e for e in per_agent),
           "soak per-agent stats")

    def bad_op() -> None:
        raise RuntimeError("synthetic failure")

    mixed = run_soak([bad_op, soak_op], agents=1, n=1)[0]
    _check(mixed["errors"] == 1 and mixed["n"] == 1,
           "soak excludes failed ops from the latency pool")
    _check(mixed["per_op_ms"][0] == [] and len(mixed["per_op_ms"][1]) == 1,
           "soak per-op vectors split success from failure")
    assert callable(main)

    if failures:
        print("SELFTEST FAILURES: " + "; ".join(failures))
        return 1
    print("SELFTEST OK")
    return 0


def _load_rows(text: str) -> list[dict]:
    """Accept either a JSON array of rows or JSONL (the CLI's own stdout
    format: one JSON object per line, status text lines ignored)."""
    text = text.strip()
    if text.startswith("["):
        return json.loads(text)
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    return rows


def _transport_of(result: Any) -> str | None:
    """Read the timings.transport a served op actually reported."""
    candidate: Any = result
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        candidate = result[1]
    if isinstance(candidate, dict):
        timings = candidate.get("timings")
        if isinstance(timings, dict):
            transport = timings.get("transport")
            return str(transport) if transport is not None else None
    return None


def _live_ops(cfg: Any, vm: str) -> dict[str, Callable[[], Any]]:
    from . import console

    return {
        "screenshot": lambda: console.screenshot(cfg, vm_name=vm, width=1024, height=768),
        "click": lambda: console.click(cfg, vm_name=vm, x=10, y=10,
                                       frame_width=1024, frame_height=768),
        "type_text": lambda: console.type_text(cfg, vm_name=vm, text="bench"),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    from . import credentials, pswindows

    parser = argparse.ArgumentParser(description="Console latency benchmark (issue #45)")
    parser.add_argument("--vm", default="", help="disposable target VM name")
    parser.add_argument("--n", type=int, default=15, help="iterations per op")
    parser.add_argument("--warmup", type=int, default=1,
                        help="discarded warmup iterations per op before timing")
    parser.add_argument("--agents", type=int, default=1,
                        help="concurrent soak agents (1 = single-agent)")
    parser.add_argument("--transport", choices=["auto", "wmi", "powershell"], default="auto",
                        help="benchmark-only forcing; product selection stays automatic")
    parser.add_argument("--baseline", default="",
                        help="path to a previous run's JSON rows; renders a before/after table")
    parser.add_argument("--selftest", action="store_true",
                        help="offline selftest (no Hyper-V, no real transport)")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
    if args.n < 1:
        parser.error("--n must be >= 1")
    if args.agents < 1:
        parser.error("--agents must be >= 1")
    if args.warmup < 0:
        parser.error("--warmup must be >= 0")
    if not args.vm:
        parser.error("--vm is required unless --selftest")

    from . import wmiconsole

    forced = None
    if args.transport == "powershell":
        wmiconsole.COM_AVAILABLE = False
        forced = "powershell"
    elif args.transport == "wmi":
        wmiconsole.COM_AVAILABLE = True
        forced = "wmi"

    cfg = config_mod.Config(unrestricted=True)
    pswindows.init(cfg, credentials.redact)
    ops = _live_ops(cfg, args.vm)

    rows: list[dict] = []
    had_error = False
    transport_mismatch = ""
    try:
        if args.agents == 1:
            for label, fn in ops.items():
                for _ in range(args.warmup):
                    try:
                        fn()
                    except Exception:  # noqa: BLE001 - warmup is discarded
                        pass
                stats = bench(fn, args.n)
                served = _transport_of(stats.pop("last_result"))
                if forced and served is not None and served != forced:
                    transport_mismatch = (
                        f"--transport {forced} requested but ops were served by '{served}'"
                    )
                elif forced and served is None:
                    transport_mismatch = (
                        f"--transport {forced} requested but the op reported no timings"
                    )
                rows.append({"label": label, "transport": served, **stats})
                print(json.dumps(rows[-1]), flush=True)
        else:
            fns = list(ops.values())
            labels = list(ops.keys())
            for fn in fns:
                for _ in range(args.warmup):
                    try:
                        fn()
                    except Exception:  # noqa: BLE001 - warmup is discarded
                        pass
            if forced:
                served_probe = _transport_of(fns[0]())
                if served_probe != forced:
                    print(
                        f"# TRANSPORT MISMATCH: --transport {forced} requested "
                        f"but ops are served by '{served_probe}'", flush=True)
                    return 2  # finally below still runs shutdown()
            per_agent = run_soak(fns, agents=args.agents, n=args.n)
            for i, agent in enumerate(per_agent):
                row = {"label": f"agent-{i}", **agent}
                per_op = row.pop("per_op_ms", None)
                if per_op:
                    row["per_op"] = {
                        labels[j]: {
                            "n": len(v),
                            "p50_ms": pct(v, 0.50) if v else None,
                            "p95_ms": pct(v, 0.95) if v else None,
                        }
                        for j, v in enumerate(per_op)
                    }
                rows.append(row)
                print(json.dumps(row), flush=True)
                if agent.get("errors"):
                    had_error = True
    finally:
        wmiconsole.shutdown()  # drop COM references before interpreter teardown

    if transport_mismatch:
        print(f"# TRANSPORT MISMATCH: {transport_mismatch}", flush=True)
        return 2
    if had_error:
        print("# soak reported failed ops (excluded from percentiles)", flush=True)
        return 1
    if forced:
        print(f"# transport forced: {forced}", flush=True)
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as fh:
            baseline_text = fh.read()
        baseline_rows = _load_rows(baseline_text)
        print(render_comparison(baseline_rows, [
            {k: v for k, v in row.items() if k in ("label", "p50_ms", "p95_ms")}
            for row in rows
        ]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
