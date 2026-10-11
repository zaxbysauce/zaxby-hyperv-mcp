"""Console latency benchmark engine (issue #45, AC2/AC3).

Committed, offline-testable machinery behind the real-host benchmark:

  - ``pct``: nearest-rank percentile, ``rank = max(1, ceil(q * n))`` over
    ascending-sorted values (exact integers on integer vectors — the frozen
    selftest pins three of them).
  - ``bench``: run one operation n times and report n/p50_ms/p95_ms/mean_ms.
  - ``render_comparison``: before/after table.
  - ``run_soak``: concurrent-agent soak — each agent thread runs every op
    n times; per-agent percentiles come back (the multi-agent half of AC2;
    the console-scoped slice of issue #20's soak).

CLI (real-host evidence generator, AC4)::

    python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --n 15
    python -m hyperv_mcp.consolebench --vm NAME --n 15 --agents 4
    python -m hyperv_mcp.consolebench --vm NAME --transport powershell
    python -m hyperv_mcp.consolebench --selftest

``--transport powershell`` forces the fallback transport in-process by
setting ``wmiconsole.COM_AVAILABLE = False`` (benchmark-only forcing — the
product has no config knob; selection stays automatic). Live mode drives
the production ``console`` ops and prints JSON rows suitable for
``render_comparison``.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable
from typing import Any

from . import config as config_mod


def pct(values: list[float], q: float) -> float:
    """Nearest-rank percentile: rank = max(1, ceil(q * n)) over the
    ascending-sorted values; pct(values, q) == sorted(values)[rank - 1]."""
    if not values:
        raise ValueError("pct of an empty list")
    if not (0.0 <= q <= 1.0):
        raise ValueError("q must be within 0.0..1.0")
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


def bench(fn: Callable[..., Any], n: int, **kw: Any) -> dict:
    """Time n executions of fn(**kw); returns n/p50_ms/p95_ms/mean_ms."""
    if n < 1:
        raise ValueError("n must be >= 1")
    times_ms: list[float] = []
    for _ in range(n):
        t0 = time.monotonic()
        fn(**kw)
        times_ms.append((time.monotonic() - t0) * 1000.0)
    return {
        "n": n,
        "p50_ms": pct(times_ms, 0.50),
        "p95_ms": pct(times_ms, 0.95),
        "mean_ms": sum(times_ms) / len(times_ms),
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
    stats dict per agent (p50/p95 over that agent's op executions)."""
    if agents < 1 or n < 1:
        raise ValueError("agents and n must be >= 1")
    results: list[dict] = [{} for _ in range(agents)]

    def _agent(index: int) -> None:
        times_ms: list[float] = []
        error = ""
        for _ in range(n):
            for op in op_fns:
                t0 = time.monotonic()
                try:
                    op()
                except Exception as exc:  # noqa: BLE001 - soak reports failures
                    error = f"{type(exc).__name__}: {exc}"
                times_ms.append((time.monotonic() - t0) * 1000.0)
        results[index] = {
            "p50_ms": pct(times_ms, 0.50),
            "p95_ms": pct(times_ms, 0.95),
            "mean_ms": sum(times_ms) / len(times_ms),
            "n": len(times_ms),
            "error": error,
        }

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

    if failures:
        print("SELFTEST FAILURES: " + "; ".join(failures))
        return 1
    print("SELFTEST OK")
    return 0


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

    from . import pswindows

    parser = argparse.ArgumentParser(description="Console latency benchmark (issue #45)")
    parser.add_argument("--vm", default="", help="disposable target VM name")
    parser.add_argument("--n", type=int, default=15, help="iterations per op")
    parser.add_argument("--agents", type=int, default=1,
                        help="concurrent soak agents (1 = single-agent)")
    parser.add_argument("--transport", choices=["auto", "wmi", "powershell"], default="auto",
                        help="benchmark-only forcing; product selection stays automatic")
    parser.add_argument("--selftest", action="store_true",
                        help="offline selftest (no Hyper-V, no real transport)")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

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
    pswindows.init(cfg)
    ops = _live_ops(cfg, args.vm)

    rows: list[dict] = []
    if args.agents <= 1:
        for label, fn in ops.items():
            stats = bench(fn, args.n)
            rows.append({"label": label, **stats})
            print(json.dumps(rows[-1]), flush=True)
    else:
        fns = list(ops.values())
        per_agent = run_soak(fns, agents=args.agents, n=args.n)
        for i, agent in enumerate(per_agent):
            row = {"label": f"agent-{i}", **agent}
            rows.append(row)
            print(json.dumps(row), flush=True)
    if forced:
        print(f"# transport forced: {forced}", flush=True)
    if rows:
        print(render_comparison(rows, rows), flush=True)
    from . import wmiconsole as _wm
    _wm.shutdown()  # drop COM references before interpreter teardown
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
