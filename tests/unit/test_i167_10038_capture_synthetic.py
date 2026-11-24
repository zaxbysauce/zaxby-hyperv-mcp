"""Issue #167 AC3 — synthetic WinError 10038 instance for the capture clause.

RED at base, GREEN after the fix: at the base commit no capture mechanism
exists anywhere in the tree, so the synthetic failure below produces no
diagnosis artifact and ``repro/check-C3.sh`` fails its artifact clause with
the AC3 marker; once the socket family's capture mechanism exists, the same
failure produces an artifact under ``$HYPERV_MCP_10038_DIAG_DIR`` naming
the three things AC3 requires.

This file only constructs the DETERMINISTIC synthetic instance of the
CI-only race (the real cascade never reproduces locally); the artifact
assertions live in the check script. The instance reproduces the family's
fixture-leg shape: ``hvsock.connect`` monkeypatched to a loopback connector,
a real listener standing in for the guest end, and the invalid handle
produced on the MONKEYPATCH side — the connector's own socket is closed and
then ``recv`` runs on it (OSError winerror 10038, WSAENOTSOCK). Therefore:

- the exact failing socket operation is ``recv``;
- the owning fixture leg is ``synthetic_hvsock_leg``;
- the invalid handle was produced by the hvsock monkeypatch, not by the
  real listener.

Mutation that must kill this check: the capture hook removed from the
socket family (or its env-var-controlled artifact path dropped) — the
script then finds no artifact and fails with the AC3 marker.
"""

import os
import socket

import pytest


@pytest.fixture()
def synthetic_hvsock_leg(monkeypatch):
    """The family's leg shape; raises OSError winerror 10038 deterministically."""
    from hyperv_mcp import hvsock

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        port = listener.getsockname()[1]

        def fake_connect(*args, **kwargs):
            # The hvsock monkeypatch side: THIS connector's handle is the one
            # that goes invalid below (not the real listener's).
            return socket.create_connection(("127.0.0.1", port), timeout=5)

        monkeypatch.setattr(hvsock, "connect", fake_connect)
        print("fixture-leg: synthetic_hvsock_leg (hvsock monkeypatch side)")
        handle = hvsock.connect("synthetic-vm-guid", 1)
        handle.close()  # the handle is now invalid (no longer a socket)
        # The exact failing socket operation, inside the fixture leg:
        handle.recv(64)  # OSError: [WinError 10038]
        yield handle
    finally:
        listener.close()


@pytest.mark.skipif(os.name != "nt", reason="WinError 10038 is Windows-only")
def test_synthetic_leg_raises_10038(synthetic_hvsock_leg):
    """Unreachable by design: the leg must raise during fixture setup."""
    pytest.fail("the synthetic leg must raise during setup, not reach the test")
