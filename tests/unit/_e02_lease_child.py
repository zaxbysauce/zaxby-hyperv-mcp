"""Child-process driver for the AC1 cross-process lock check (issue #23,
class E-02). Spawned BY PATH from test_e02_leases.py:

    python _e02_lease_child.py <vm_id> <ready_file>

The child bootstraps a full server wiring against the environment it was
handed (the parent points HYPERV_MCP_STATE_DB at the shared database and
HYPERV_MCP_UNRESTRICTED at 1), takes the per-VM lock on <vm_id>, writes
<ready_file> to signal "lock held", and then blocks forever — it NEVER exits
on its own; the parent kills it in its finally block. If taking the lock
fails the child exits 3 without writing the ready file, so the parent's
readiness poll reports the death with this process's stderr.

RED at base / GREEN after the fix: this driver itself behaves identically in
both worlds (at base the lock it takes is process-local, so only the PARENT's
concurrent acquire stays green — which is exactly the RED signature AC1
pins). Nothing here touches real Hyper-V: no PowerShell is run by this
process, it only bootstraps and holds a lock.
"""

from __future__ import annotations

import os
import sys
import time

from hyperv_mcp import server as server_module
from hyperv_mcp import vmlocks


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <vm_id> <ready_file>", file=sys.stderr
        )
        return 2
    vm_id = sys.argv[1]
    ready_file = sys.argv[2]

    # Wire this process exactly as a server process would be wired against
    # the shared state DB named by the environment the parent handed over.
    server_module.bootstrap(dict(os.environ))

    try:
        with vmlocks.vm_lock(vm_id, wait_s=0):
            with open(ready_file, "w", encoding="utf-8") as fh:
                fh.write(f"{os.getpid()}\n")
            # Block until the parent kills this process; the lock stays held.
            while True:
                time.sleep(0.5)
    except vmlocks.VMBusy as exc:
        print(f"child could not acquire the VM lock: {exc}", file=sys.stderr)
        return 3
    return 0  # unreachable: the loop above only ends when the parent kills us


if __name__ == "__main__":
    raise SystemExit(main())
