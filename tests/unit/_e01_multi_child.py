"""Child-process driver for the two-processes-share-store check (C8).

Spawned twice in parallel by the parent, each instance starts N guest jobs
(argv[2]) against the shared state DB named by argv[1] (also exported as
HYPERV_MCP_STATE_DB before Config.load, so the store the children share is
the one the parent named), with a fake pswindows.run_ps installed so no
real PowerShell or guest is touched. It prints the started job ids as ONE
JSON list on stdout and exits 0. Two instances overlapping on one WAL
database is exactly the concurrency the store's busy_timeout must absorb.
"""

from __future__ import annotations

import json
import os
import sys
import uuid

from hyperv_mcp import credentials, guestjobs, pswindows
from hyperv_mcp.config import Config

_GUID = str(uuid.uuid5(uuid.NAMESPACE_OID, "test-vm"))


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def main() -> int:
    os.environ["HYPERV_MCP_STATE_DB"] = sys.argv[1]
    count = int(sys.argv[2])
    started = {"legs": 0}

    def fake_run_ps(script, **kwargs):
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_GUID, returncode=0)
        # The start leg: a distinct pid per leg keeps the registry entries
        # distinguishable; the job ids (not the pids) are the identity the
        # parent asserts on.
        started["legs"] += 1
        return pswindows.PSResult(stdout=json.dumps({
            "pid": 1000 + started["legs"], "job_dir": "d", "start_time_ticks": 1,
        }), returncode=0)

    pswindows.run_ps = fake_run_ps
    cfg = Config.load()
    credentials.init(cfg)
    cred = credentials.resolve_guest()
    ids = []
    for _ in range(count):
        out = guestjobs.job_start(cfg, "test-vm", "x.exe", cred=cred)
        ids.append(out["job_id"])
    sys.stdout.write(json.dumps(ids) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
