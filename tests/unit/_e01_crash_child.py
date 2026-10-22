"""Child-process driver for the crash-during-start acceptance check (C3).

The parent spawns this module with sys.executable. It starts ONE guest job
against the state DB named by HYPERV_MCP_STATE_DB (inherited env) with a
fake pswindows.run_ps installed, and hard-exits with os._exit(1) INSIDE the
guest start leg — after the reservation exists but before any success
payload could be parsed or any cleanup could run, which is exactly the
crash window the durable store must survive.

The job id is recovered for the parent by decoding the start leg's base64
`$enc` payload and writing the `$id = '<32 hex>'` value it embeds to the
record path given as argv[1] BEFORE the hard exit, so the parent can prove
the row it addresses afterwards is the very job that was starting.
"""

from __future__ import annotations

import base64
import os
import re
import sys
import uuid

from hyperv_mcp import credentials, guestjobs, pswindows
from hyperv_mcp.config import Config

_GUID = str(uuid.uuid5(uuid.NAMESPACE_OID, "test-vm"))
_ENC_RE = re.compile(r"\$enc = '([A-Za-z0-9+/=]+)'")
_JOB_ID_RE = re.compile(r"\$id = '([0-9a-f]{32})'")


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _fake_run_ps(script, **kwargs):
    if _is_resolution_leg(script):
        return pswindows.PSResult(stdout=_GUID, returncode=0)
    # The start action: the outer wrapper carries the start script as a b64
    # $enc payload, and the decoded text embeds the reserved job id as
    # $id = '<32 hex>'. Record it, then die without returning a payload —
    # no exception unwinds, so no release/cleanup path can possibly run.
    match = _ENC_RE.search(script)
    inner = base64.b64decode(match.group(1)).decode("utf-8") if match else ""
    id_match = _JOB_ID_RE.search(inner)
    if id_match:
        with open(sys.argv[1], "w", encoding="utf-8") as fh:
            fh.write(id_match.group(1))
        os._exit(1)
    raise AssertionError("unexpected run_ps leg after the identity leg")


def main() -> int:
    record_path = sys.argv[1]
    pswindows.run_ps = _fake_run_ps
    cfg = Config.load()
    credentials.init(cfg)
    guestjobs.job_start(cfg, "test-vm", "x.exe", cred=credentials.resolve_guest())
    # Unreachable when the crash window fires: the fake start leg never
    # returns. Reaching this line means the leg completed and no crash was
    # simulated, which voids the condition the parent checks.
    sys.stderr.write(f"crash window missed; no record written to {record_path}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
