"""Issue #135 acceptance checks (trace 135-127-138-gui-electron-drivability):
the tcp relay kind — a bidirectional byte stream from a host loopback port
to a guest loopback port over a Hyper-V socket, with no PowerShell process
in the data path.

ACs carried:
  AC1  test_bytes_round_trip_unmodified             NEW-SURFACE
  AC2  test_header_line_precedes_client_bytes       NEW-SURFACE
  AC3  test_refused_header_closes_client            NEW-SURFACE
  AC4  test_large_binary_payload_intact             NEW-SURFACE
  AC5  test_concurrent_connections_are_independent  NEW-SURFACE
  AC6  test_non_loopback_bind_refused               NEW-SURFACE
  AC7  test_refused_without_relay_policy            NEW-SURFACE
  AC8  test_remote_host_mode_refused                NEW-SURFACE
  AC9  test_missing_stream_capability_refused       NEW-SURFACE
  AC10 test_stop_closes_listener_and_connections    NEW-SURFACE
  AC11 test_foreign_agent_sees_unknown_relay        NEW-SURFACE
  AC12 test_sockaddr_hv_layout                      NEW-SURFACE
  AC13 test_ctypes_path_selected_without_af_hyperv  NEW-SURFACE
  AC14 test_register_service_script_contract        NEW-SURFACE
  AC15 test_parse_uia_helper_and_client             PRESERVING (green at base;
       lives here, not in a new test_script_parse_new.py, per intake
       finding 1 — the repo carries no such file and a preserving check
       cannot have a file-absence base leg)
  AC16 test_http_relay_regression_floor             PRESERVING (green at base;
       self-contained re-declaration of the existing tests/unit/test_relay.py
       floor so this file pins it on its own)

RED at base 6c34438 for AC1-AC14: the hvsock module and the kind="tcp"
surface do not exist (ImportError naming hvsock / TypeError naming kind /
a refused flag). AC15 and AC16 pass against the current code and must stay
green.

Seams these checks freeze (the implementation must provide them, issue
#135 Design 1/4/6):
  - hyperv_mcp.hvsock.connect(vm_guid, service_guid, timeout_s=...) -> socket
    (the single transport seam; monkeypatched to dial a local fake)
  - hyperv_mcp.hvsock.pack_sockaddr_hv(vm_guid, service_guid) -> 36 bytes
  - hyperv_mcp.hvsock.SERVICE_GUID — the project's fixed service GUID
  - hyperv_mcp.hvsock._load_ws2_32() -> the Ws2_32 ctypes binding (so the
    pre-3.12 path can be driven with a recording winsock)
  - uia.helper_capabilities(...) -> set[str] — what the VM's installed
    helper advertises; relay_start(kind="tcp") consults it

What is faked: every host PowerShell leg (pswindows.run_ps answers by-name
resolution legs with a stable per-name GUID); the guest side of the
Hyper-V socket is a local threaded TCP server. No real Hyper-V, no real
hvsocket transport, nothing executed in a guest.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import importlib.resources
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid

import pytest

from hyperv_mcp import pswindows, relay
from hyperv_mcp.config import Config, DestructivePolicy
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")


_GUID = "e953c649-1234-5678-9abc-def012345678"


def _relay_cfg_required():
    """A config whose lease axis is required, for the lease-gate checks."""
    return Config.from_dict({
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"relay": True},
        "leases": {"required": True},
    })

VM_GUID_HEX = "e953c649-1234-5678-9abc-def012345678"
SVC_GUID_HEX = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

_PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_REAL_RUN_PS = pswindows.run_ps  # saved before any monkeypatching

_ENC_RE = re.compile(r"\$enc = '([A-Za-z0-9+/=]+)'")
_NAME_RE = re.compile(r"ElementName -eq '([^']*)'")


def _is_resolution_leg(script: str) -> bool:
    """A standalone by-name resolution leg emits $vmTarget as its last line."""
    return "Msvm_ComputerSystem" in script and script.rstrip().endswith("$vmTarget")


def _is_by_id_leg(script: str) -> bool:
    """The by-id counterpart: `Get-VM -Id $vmTarget` emitting the VM name.

    `relay_start(kind="tcp")` consults the capability seam with the resolved
    id alone, and that seam re-resolves by id — so the by-id leg must be
    served too, or every tcp start dies on "resolved to an empty name".
    """
    return "Get-VM -Id $vmTarget" in script and script.rstrip().endswith(
        "$vm.Name")


def _resolved_guid(script: str) -> str:
    """Stable per-name GUID: distinct names are distinct VMs (test_relay idiom)."""
    m = _NAME_RE.search(script)
    return str(uuid.uuid5(uuid.NAMESPACE_OID, m.group(1) if m else ""))


class FakePS:
    """pswindows.run_ps stand-in: serves by-name resolution legs with a
    stable per-name GUID; every other leg is recorded and answered
    benignly (the tcp start path may run capability legs; only the
    per-connection path must stay PowerShell-free, which AC5 pins)."""

    def __init__(self, responses=None):
        self.scripts: list[str] = []
        self._r = list(responses or [])

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        if _is_resolution_leg(script):
            return pswindows.PSResult(stdout=_resolved_guid(script), returncode=0)
        if _is_by_id_leg(script):
            return pswindows.PSResult(stdout="test-vm", returncode=0)
        if self._r:
            item = self._r.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return pswindows.PSResult(stdout="", returncode=0)


def _relay_cfg(enabled: bool = True) -> Config:
    return Config(
        allowed_vm_patterns=["test-*"],
        destructive=DestructivePolicy(relay=enabled),
    )


@pytest.fixture(autouse=True)
def _clean_relays():
    relay.clear_registry_for_tests()
    yield
    relay.clear_registry_for_tests()


# ---------------------------------------------------------------------------
# the guest side of the Hyper-V socket: a local threaded fake
# ---------------------------------------------------------------------------


class GuestStreamFake:
    """Threaded local TCP server standing in for the guest end of the Hyper-V
    socket. Per connection it consumes the relay's one-line header, answers
    per ``mode``, then behaves as the guest forwarder would:

    - "echo":   answer {"ok":true}, then echo every byte back (the wire
                protocol of #135 Design 3 with the pump short-circuited)
    - "refuse": answer {"ok":false,"error_class":...} and close
    - "silent": close without answering
    """

    def __init__(self, mode: str = "echo"):
        assert mode in ("echo", "refuse", "silent")
        self.mode = mode
        self.headers: list[bytes] = []
        self.header_ok: list[bool] = []
        self.connections = 0
        self.refusal = b'{"ok":false,"error_class":"no_forwarder"}\n'
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_one, args=(conn,), daemon=True).start()

    def _read_header(self, conn) -> bytes:
        buf = b""
        deadline = time.monotonic() + 10.0
        conn.settimeout(0.5)
        while time.monotonic() < deadline and b"\n" not in buf:
            try:
                chunk = conn.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        line, _, rest = buf.partition(b"\n")
        self.headers.append(line)
        ok = False
        try:
            parsed = json.loads(line.decode("utf-8"))
            ok = (isinstance(parsed, dict) and parsed.get("v") == 1
                  and "port" in parsed)
        except Exception:
            ok = False
        self.header_ok.append(ok)
        return rest

    def _serve_one(self, conn) -> None:
        self.connections += 1
        try:
            rest = self._read_header(conn)
            if self.mode == "refuse":
                conn.sendall(self.refusal)
                return
            if self.mode == "silent":
                return
            conn.sendall(b'{"ok":true}\n')
            if rest:
                conn.sendall(bytes(rest))
            conn.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                conn.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _patch_caps(monkeypatch, caps) -> None:
    """Freeze what the VM's helper advertises (uia.helper_capabilities)."""
    from hyperv_mcp import uia

    monkeypatch.setattr(
        uia, "helper_capabilities", lambda *a, **k: set(caps), raising=False)


def _start_tcp_relay(monkeypatch, *, guest_port=9222, mode="echo",
                     caps=("uia", "msaa", "stream"), owner=None,
                     cfg=None, bind=None):
    """Wire every seam and start one tcp relay against the local fake.

    Returns (out, fake, connect_calls, ps). RED at base: hvsock absent.
    """
    from hyperv_mcp import hvsock  # RED at base: cannot import name 'hvsock'

    fake = GuestStreamFake(mode=mode)
    connect_calls: list[tuple[tuple, dict]] = []

    def fake_connect(*args, **kwargs):
        connect_calls.append((args, kwargs))
        return socket.create_connection(("127.0.0.1", fake.port), timeout=15)

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    _patch_caps(monkeypatch, caps)
    ps = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    kwargs = {"kind": "tcp", "cred": CRED, "owner": owner}
    if bind is not None:
        kwargs["bind"] = bind
    try:
        out = relay.relay_start(cfg or _relay_cfg(), "test-vm", guest_port, **kwargs)
    finally:
        pass
    return out, fake, connect_calls, ps


def _read_exact(sock, n: int, timeout: float = 20.0) -> bytes:
    """Read exactly n bytes or until the deadline (short read -> short return)."""
    buf = b""
    deadline = time.monotonic() + timeout
    sock.settimeout(0.5)
    while len(buf) < n and time.monotonic() < deadline:
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except TimeoutError:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _read_until_eof(sock, timeout: float = 15.0) -> tuple[bytes, bool]:
    """Read until the peer closes. Returns (data, closed)."""
    buf = b""
    deadline = time.monotonic() + timeout
    sock.settimeout(0.5)
    closed = False
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            continue
        except OSError:
            break
        if not chunk:
            closed = True
            break
        buf += chunk
    return buf, closed


# ---------------------------------------------------------------------------
# AC1 — bytes round-trip unmodified
# ---------------------------------------------------------------------------


def test_bytes_round_trip_unmodified(monkeypatch):
    """AC1: a client's bytes reach the guest stream unmodified and the guest
    stream's bytes come back unmodified, over a real loopback listener with
    an injected echoing guest stream."""
    out, fake, _calls, _ps = _start_tcp_relay(monkeypatch, mode="echo")
    try:
        assert out.get("ok") is True, f"AC1: relay_start failed: {out}"
        assert out.get("kind") == "tcp", (
            f"AC1: the result must name its kind; got {out.get('kind')!r}")
        assert str(out.get("url", "")).startswith("http://127.0.0.1:"), (
            f"AC1: the tcp relay's url is the loopback listener: {out.get('url')!r}")
        payload = b"ac1-round-trip:" + bytes(range(256))
        with socket.create_connection(
                ("127.0.0.1", out["host_port"]), timeout=15) as sock:
            sock.sendall(payload)
            got = _read_exact(sock, len(payload), timeout=20)
        assert len(got) == len(payload), (  # count before content
            f"AC1: delivered {len(got)} of {len(payload)} bytes back")
        assert got == payload, "AC1: the bytes were modified in transit"
        assert fake.headers and fake.header_ok[0], (
            "AC1: the guest stream never saw a valid header line — the "
            "injected stream was not driven")
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC2 — the header line precedes any client byte
# ---------------------------------------------------------------------------


def test_header_line_precedes_client_bytes(monkeypatch):
    """AC2: the first bytes on the guest stream are the one-line header
    naming the relay's guest port; client bytes only follow after."""
    out, fake, _calls, _ps = _start_tcp_relay(
        monkeypatch, guest_port=9333, mode="echo")
    try:
        assert out.get("ok") is True, f"AC2: relay_start failed: {out}"
        payload = b"ac2-client-bytes"
        with socket.create_connection(
                ("127.0.0.1", out["host_port"]), timeout=15) as sock:
            sock.sendall(payload)
            got = _read_exact(sock, len(payload), timeout=20)
        assert len(fake.headers) == 1, (  # count before detail
            f"AC2: expected exactly one guest stream; saw {len(fake.headers)}")
        assert fake.header_ok[0], (
            "AC2: the guest stream's first line was not the header — client "
            f"bytes preceded it (first line: {fake.headers[0][:60]!r})")
        header = json.loads(fake.headers[0].decode("utf-8"))
        assert header.get("v") == 1 and header.get("port") == 9333, (
            f"AC2: the header must name the relay's guest port; got {header!r}")
        assert got == payload, "AC2: the echo round-trip broke"
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC3 — a refused (or unanswered) header closes the client
# ---------------------------------------------------------------------------


def test_refused_header_closes_client(monkeypatch):
    """AC3: when the guest forwarder answers the header with a refusal or
    closes without answering, the client connection is closed with no
    client byte forwarded back."""
    for mode in ("refuse", "silent"):
        out, fake, _calls, _ps = _start_tcp_relay(monkeypatch, mode=mode)
        try:
            assert out.get("ok") is True, f"AC3 ({mode}): relay_start failed"
            with socket.create_connection(
                    ("127.0.0.1", out["host_port"]), timeout=15) as sock:
                sock.sendall(b"ac3-payload")
                data, closed = _read_until_eof(sock, timeout=15)
            assert closed, (
                f"AC3 ({mode}): the client connection was not closed after "
                "the guest forwarder refused the header")
            assert data == b"", (
                f"AC3 ({mode}): the client received {data[:40]!r} — a "
                "half-open bridge must not answer")
        finally:
            # AMENDED (issue #147 follow-up discipline, CHECK_WRONG): the
            # first draft never stopped the relay, so the loop's second
            # iteration collided with the duplicate-target rule (#11) and the
            # check could not run against a correct implementation. Stopping
            # it changes nothing the check asserts.
            try:
                relay.relay_stop(_relay_cfg(), out["relay_id"])
            except Exception:
                pass
            fake.close()


# ---------------------------------------------------------------------------
# AC4 — a 4 MiB all-byte-values payload survives intact
# ---------------------------------------------------------------------------


def test_large_binary_payload_intact(monkeypatch):
    """AC4: a 4 MiB payload containing every byte value is delivered intact
    — the tcp kind carries no size cap (the http kind caps bodies at 1 MiB)."""
    payload = bytes(range(256)) * 16384  # exactly 4 MiB
    assert len(payload) == 4 * 1024 * 1024  # count before content
    out, fake, _calls, _ps = _start_tcp_relay(monkeypatch, mode="echo")
    try:
        assert out.get("ok") is True, f"AC4: relay_start failed: {out}"
        with socket.create_connection(
                ("127.0.0.1", out["host_port"]), timeout=30) as sock:
            sock.sendall(payload)
            got = _read_exact(sock, len(payload), timeout=60)
        assert len(got) == len(payload), (
            f"AC4: delivered {len(got)} of {len(payload)} bytes — the payload "
            "was capped or truncated in transit")
        assert got == payload, "AC4: the large payload was modified in transit"
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC5 — concurrent clients, one guest stream each, no PowerShell per connection
# ---------------------------------------------------------------------------


def test_concurrent_connections_are_independent(monkeypatch):
    """AC5: two connected clients are each carried on their OWN guest stream
    concurrently, and accepting a client connection spawns no PowerShell."""
    out, fake, calls, ps = _start_tcp_relay(monkeypatch, mode="echo")
    try:
        assert out.get("ok") is True, f"AC5: relay_start failed: {out}"
        scripts_before = len(ps.scripts)
        p1, p2 = b"ac5-client-one-payload", b"ac5-client-two-payload"
        c1 = socket.create_connection(("127.0.0.1", out["host_port"]), timeout=15)
        c2 = socket.create_connection(("127.0.0.1", out["host_port"]), timeout=15)
        try:
            c1.sendall(p1)
            c2.sendall(p2)
            got1 = _read_exact(c1, len(p1), timeout=20)
            got2 = _read_exact(c2, len(p2), timeout=20)
        finally:
            c1.close()
            c2.close()
        assert len(calls) == 2, (  # count before detail
            f"AC5: {len(calls)} guest streams were opened for 2 clients — "
            "each client must ride its own stream")
        assert fake.connections == 2
        vms = {
            (a[0] if a else kw.get("vm_guid")) for a, kw in calls
        }
        assert vms == {_resolved_guid(ps.scripts[0])}, (
            "AC5: every guest stream must dial the relay's resolved VM")
        assert got1 == p1 and got2 == p2, (
            "AC5: the two clients' streams crossed or were corrupted")
        assert len(ps.scripts) == scripts_before, (
            "AC5: a client connection spawned a host PowerShell process — "
            "the data path must be the Hyper-V socket only")
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC6 — a non-loopback bind is refused, no listener opens
# ---------------------------------------------------------------------------


def test_non_loopback_bind_refused(monkeypatch):
    """AC6: a tcp relay asked to bind a non-loopback address is refused and
    opens no listener (the loopback bind is the kind's whole boundary)."""
    from hyperv_mcp import hvsock  # RED at base

    opened: list[int] = []

    def fake_connect(*args, **kwargs):
        opened.append(1)
        raise AssertionError("AC6: a guest stream must not open on a refused bind")

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    _patch_caps(monkeypatch, ("uia", "msaa", "stream"))
    ps = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    with pytest.raises(ValueError, match="loopback-only"):
        relay.relay_start(_relay_cfg(), "test-vm", 9222, kind="tcp",
                          bind="0.0.0.0", cred=CRED)
    assert relay._relays == {}, "AC6: a refused start must leave no registry entry"
    assert opened == [], "AC6: no guest stream may open for a refused bind"


# ---------------------------------------------------------------------------
# AC7 — the relay policy category gates the new kind
# ---------------------------------------------------------------------------


def test_refused_without_relay_policy(monkeypatch):
    """AC7: with the relay category disabled the tcp start is refused before
    any listener or guest stream opens."""
    from hyperv_mcp import hvsock  # RED at base

    opened: list[int] = []

    def fake_connect(*args, **kwargs):
        opened.append(1)
        raise AssertionError("AC7: a guest stream opened under a denied policy")

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    _patch_caps(monkeypatch, ("uia", "msaa", "stream"))
    ps = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    cfg = Config(allowed_vm_patterns=["test-*"])  # relay defaults False
    with pytest.raises(PolicyDenied, match="relay"):
        relay.relay_start(cfg, "test-vm", 9222, kind="tcp", cred=CRED)
    assert relay._relays == {}, "AC7: no registry entry under a denied policy"
    assert ps.scripts == [], "AC7: the denial must fire before any PowerShell"
    assert opened == [], "AC7: no guest stream under a denied policy"


# ---------------------------------------------------------------------------
# AC8 — remote Hyper-V host mode is refused, naming local mode
# ---------------------------------------------------------------------------


def test_remote_host_mode_refused(monkeypatch):
    """AC8: a tcp relay under a configured remote Hyper-V host is refused
    with a structured error naming local mode — a Hyper-V socket is local
    to the host."""
    from hyperv_mcp import hvsock  # RED at base

    opened: list[int] = []

    def fake_connect(*args, **kwargs):
        opened.append(1)
        raise AssertionError("AC8: a guest stream opened in remote-host mode")

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    _patch_caps(monkeypatch, ("uia", "msaa", "stream"))
    ps = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    cfg = Config.from_dict({
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"relay": True},
        "hyperv": {"host": "remote-hyperv.example"},
    })
    assert pswindows.hyperv_host(cfg) == "remote-hyperv.example"
    with pytest.raises(ValueError, match="(?i)local"):
        relay.relay_start(cfg, "test-vm", 9222, kind="tcp", cred=CRED)
    assert relay._relays == {}, "AC8: no registry entry in remote-host mode"
    assert opened == [], "AC8: no guest stream in remote-host mode"


# ---------------------------------------------------------------------------
# AC9 — a helper without the stream capability is refused
# ---------------------------------------------------------------------------


def test_missing_stream_capability_refused(monkeypatch):
    """AC9: when the VM's helper does not advertise the stream capability the
    tcp start is refused as stream_unavailable and names
    hyperv_ui_helper_provision — before any guest stream opens."""
    from hyperv_mcp import hvsock  # RED at base

    opened: list[int] = []

    def fake_connect(*args, **kwargs):
        opened.append(1)
        raise AssertionError("AC9: a guest stream opened without the stream cap")

    monkeypatch.setattr(hvsock, "connect", fake_connect)
    _patch_caps(monkeypatch, ("uia", "msaa"))  # no "stream"
    ps = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", ps)
    with pytest.raises(ValueError, match="stream_unavailable") as excinfo:
        relay.relay_start(_relay_cfg(), "test-vm", 9222, kind="tcp", cred=CRED)
    assert "hyperv_ui_helper_provision" in str(excinfo.value), (
        "AC9: the refusal must name the remedy tool hyperv_ui_helper_provision; "
        f"got {str(excinfo.value)[:200]!r}")
    assert relay._relays == {}, "AC9: no registry entry on a capability refusal"
    assert opened == [], "AC9: no guest stream on a capability refusal"


# ---------------------------------------------------------------------------
# AC10 — stop closes the listener and every bridged connection
# ---------------------------------------------------------------------------


def test_stop_closes_listener_and_connections(monkeypatch):
    """AC10: relay_stop closes the tcp relay's listener AND every bridged
    client connection — nothing keeps serving, no client hangs."""
    out, fake, _calls, _ps = _start_tcp_relay(monkeypatch, mode="echo")
    try:
        assert out.get("ok") is True, f"AC10: relay_start failed: {out}"
        client = socket.create_connection(
            ("127.0.0.1", out["host_port"]), timeout=15)
        try:
            client.sendall(b"ac10-ping")
            assert _read_exact(client, len(b"ac10-ping"), timeout=20) == b"ac10-ping", (
                "AC10: the bridge must carry before stop proves it closes")
            stopped = relay.relay_stop(_relay_cfg(), out["relay_id"])
            assert stopped.get("stopped") is True, f"AC10: stop failed: {stopped}"
            data, closed = _read_until_eof(client, timeout=15)
            assert closed, "AC10: a bridged client connection survived the stop"
            assert data == b""
        finally:
            client.close()
        refused = False
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                s = socket.create_connection(
                    ("127.0.0.1", out["host_port"]), timeout=1)
                s.close()
                time.sleep(0.1)
            except OSError:
                refused = True
                break
        assert refused, "AC10: the listener still accepts connections after stop"
        row = relay.relay_status(_relay_cfg(), out["relay_id"])["relays"][0]
        assert row["stopped"] is True, "AC10: status must report the relay stopped"
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC11 — the ownership rule covers the new kind
# ---------------------------------------------------------------------------


def test_foreign_agent_sees_unknown_relay(monkeypatch):
    """AC11: an agent other than the one that started a tcp relay gets the
    same `unknown relay_id` answer for status and stop — the #11 ownership
    rule covers the new kind; the owner is unaffected."""
    out, fake, _calls, _ps = _start_tcp_relay(monkeypatch, mode="echo", owner="agent-a")
    try:
        assert out.get("ok") is True, f"AC11: relay_start failed: {out}"
        with pytest.raises(ValueError, match="unknown relay_id"):
            relay.relay_status(_relay_cfg(), out["relay_id"], owner="agent-b")
        with pytest.raises(ValueError, match="unknown relay_id"):
            relay.relay_stop(_relay_cfg(), out["relay_id"], owner="agent-b")
        assert out["relay_id"] in relay._relays, (
            "AC11: the foreign attempts must not disturb the owner's relay")
        rows = relay.relay_status(_relay_cfg(), out["relay_id"], owner="agent-a")
        assert len(rows["relays"]) == 1  # count before detail
        assert rows["relays"][0]["relay_id"] == out["relay_id"]
        stopped = relay.relay_stop(_relay_cfg(), out["relay_id"], owner="agent-a")
        assert stopped.get("stopped") is True
    finally:
        fake.close()


# ---------------------------------------------------------------------------
# AC12 — the sockaddr_hv byte layout (pure computation)
# ---------------------------------------------------------------------------


def test_sockaddr_hv_layout():
    """AC12: packing the Hyper-V socket address for a VM GUID and a service
    GUID yields exactly 36 bytes: family 34 little-endian, two zero bytes,
    then each GUID in bytes_le order. Pure computation — right on every
    supported Python."""
    from hyperv_mcp import hvsock  # RED at base

    pairs = [
        (VM_GUID_HEX, SVC_GUID_HEX),
        ("00112233-4455-6677-8899-aabbccddeeff",
         "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"),
    ]
    for vm_hex, svc_hex in pairs:
        buf = hvsock.pack_sockaddr_hv(vm_hex, svc_hex)
        assert isinstance(buf, (bytes, bytearray)), (
            f"AC12: pack_sockaddr_hv must return raw bytes; got {type(buf)!r}")
        b = bytes(buf)
        assert len(b) == 36, (  # count before content
            f"AC12: sockaddr_hv must be 36 bytes; got {len(b)}")
        assert b[0:2] == b"\x22\x00", (
            f"AC12: family must be 34 little-endian; got {b[0:2]!r}")
        assert b[2:4] == b"\x00\x00", (
            f"AC12: the two reserved bytes must be zero; got {b[2:4]!r}")
        assert b[4:20] == uuid.UUID(vm_hex).bytes_le, (
            "AC12: bytes 4..20 must be the VM GUID in bytes_le order")
        assert b[20:36] == uuid.UUID(svc_hex).bytes_le, (
            "AC12: bytes 20..36 must be the service GUID in bytes_le order")


# ---------------------------------------------------------------------------
# AC13 — the ctypes winsock path when socket.AF_HYPERV is absent
# ---------------------------------------------------------------------------


class RecordingWinsock:
    """Stand-in for the Ws2_32 ctypes binding: records every call. `socket`
    hands out REAL socket fds (a socketpair end, detached) so the natural
    wrap-then-settimeout flow works on the handle; `connect`/`WSAConnect`
    succeed with 0 without touching the network."""

    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []
        self.handles: list[int] = []
        self._peers: list[socket.socket] = []

    def close(self) -> None:
        for peer in self._peers:
            try:
                peer.close()
            except Exception:
                pass

    def _named(self, name):
        def method(*args):
            self.calls.append((name, args))
            return 0
        return method

    def socket(self, *args):
        self.calls.append(("socket", args))
        pair = socket.socketpair()
        self._peers.append(pair[1])
        handle = pair[0].detach()
        self.handles.append(handle)
        return handle

    def connect(self, *args):
        self.calls.append(("connect", args))
        return 0

    def WSAConnect(self, *args):
        self.calls.append(("WSAConnect", args))
        return 0

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._named(name)


def _winsock_buffer_bytes(value):
    """Extract the sockaddr bytes from whatever ctypes form was passed."""
    if isinstance(value, int):
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raw = getattr(value, "raw", None)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    try:
        return bytes(value)
    except Exception:
        return None


def test_ctypes_path_selected_without_af_hyperv(monkeypatch):
    """AC13: with socket.AF_HYPERV removed, the guest stream opens through
    the ctypes path — socket() for family 34, connect() with the 36-byte
    sockaddr, then the handle wrapped as a Python socket."""
    from hyperv_mcp import hvsock  # RED at base

    monkeypatch.delattr(socket, "AF_HYPERV", raising=False)
    ws = RecordingWinsock()
    monkeypatch.setattr(hvsock, "_load_ws2_32", lambda: ws, raising=False)
    sock = None
    try:
        sock = hvsock.connect(VM_GUID_HEX, SVC_GUID_HEX, timeout_s=5)
        socket_calls = [c for c in ws.calls if c[0] == "socket"]
        assert len(socket_calls) == 1, (  # count before detail
            f"AC13: expected exactly one winsock socket() call; saw "
            f"{[c[0] for c in ws.calls]}")
        af = socket_calls[0][1][0]
        assert af == 34, (
            f"AC13: the ctypes path must create the socket for family 34; "
            f"got {af!r}")
        conn_calls = [c for c in ws.calls if c[0] in ("connect", "WSAConnect")]
        assert len(conn_calls) == 1, (
            f"AC13: expected exactly one connect call; saw {conn_calls}")
        sockaddr = None
        for arg in conn_calls[0][1]:
            candidate = _winsock_buffer_bytes(arg)
            if candidate is not None:
                sockaddr = candidate
                break
        assert sockaddr is not None, (
            "AC13: the connect call carried no recognizable sockaddr buffer")
        assert len(sockaddr) == 36, (
            f"AC13: the connect sockaddr must be 36 bytes; got {len(sockaddr)}")
        expected = (b"\x22\x00\x00\x00"
                    + uuid.UUID(VM_GUID_HEX).bytes_le
                    + uuid.UUID(SVC_GUID_HEX).bytes_le)
        assert sockaddr == expected, (
            "AC13: the connect sockaddr does not match the sockaddr_hv layout")
        assert isinstance(sock, socket.socket), (
            f"AC13: connect must return a wrapped socket; got {type(sock)!r}")
        assert sock.fileno() == ws.handles[0], (
            "AC13: the returned socket must wrap the winsock handle")
    finally:
        if isinstance(sock, socket.socket):
            try:
                fd = sock.detach()
                socket.socket(fileno=fd).close()  # a real fd: close it for real
            except Exception:
                pass
        ws.close()


# ---------------------------------------------------------------------------
# AC14 — the service registration command's generated script
# ---------------------------------------------------------------------------


def test_register_service_script_contract(monkeypatch, capsys):
    """AC14: `hyperv-mcp-http --register-hvsocket-service` generates a
    PowerShell script that creates the GuestCommunicationServices key for
    the project's service GUID with an ElementName value (the logon-task
    command's recorder idiom, test_b03_stdio_proxy AC5)."""
    from hyperv_mcp import http_entry, hvsock, pswindows  # RED at base

    sink: list[str] = []

    def _recorder(script, **kwargs):
        sink.append(script)
        return pswindows.PSResult(stdout="REGISTERED", returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", _recorder)
    monkeypatch.setattr(http_entry, "run_ps", _recorder, raising=False)
    monkeypatch.delenv("HYPERV_MCP_CONFIG", raising=False)

    rc = http_entry.main(["--register-hvsocket-service"])
    capsys.readouterr()
    assert rc == 0, f"AC14: the command must succeed through the recorder; rc={rc}"
    assert sink, "AC14: the command generated no PowerShell script"  # count first
    lowered = "\n".join(sink).lower()
    assert "guestcommunicationservices" in lowered, (
        "AC14: the script must create the GuestCommunicationServices registry key")
    service_guid = str(hvsock.SERVICE_GUID).lower().strip("{}")
    assert service_guid in lowered, (
        "AC14: the script must create the key for the project's fixed "
        f"service GUID ({service_guid})")
    assert "elementname" in lowered, (
        "AC14: the key must carry an ElementName value")


# ---------------------------------------------------------------------------
# AC15 — PRESERVING: the helper and client scripts parse under PS 5.1
# ---------------------------------------------------------------------------


@pytest.fixture()
def _ps_available():
    if not os.path.isfile(_PS_EXE):
        pytest.skip("Windows PowerShell not available")


def _parse_errors(script: str) -> list[str]:
    """Parse-only validation via the real PS 5.1 parser (never executes)."""
    b64 = pswindows.utf8_b64(script)
    parser = (
        "$text = [System.Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String([Console]::In.ReadLine()))\n"
        "$errs = $null\n"
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "$text, [ref]$null, [ref]$errs) | Out-Null\n"
        "if ($errs.Count -gt 0) {\n"
        "    $errs | ForEach-Object { Write-Output ($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }\n"
        "    exit 1\n"
        "} else { Write-Output 'PARSE-OK' }\n"
    )
    result = _REAL_RUN_PS(parser, timeout_s=60, stdin_b64=b64)
    if result.stdout.strip() == "PARSE-OK":
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_parse_uia_helper_and_client(_ps_available):
    """AC15 (preserving): the packaged helper script and every client-side
    PowerShell script the host generates stay free of Windows PowerShell
    5.1 parse errors. Green at the anchor; the stream forwarder is added to
    the script this check parses, so the guarantee carries into the PR."""
    from hyperv_mcp import uia

    pswindows.init(Config(unrestricted=True))
    helper_text = (
        importlib.resources.files("hyperv_mcp")
        .joinpath("guest")
        .joinpath("uia_helper.ps1")
        .read_text(encoding="utf-8")
    )
    scripts = {
        "guest/uia_helper.ps1": helper_text,
        "uia.CLIENT_LEG_SCRIPT": uia.CLIENT_LEG_SCRIPT,
        "uia._RESET_INNER": uia._RESET_INNER,
        "uia._INSTALL_INNER": uia._INSTALL_INNER,
        "uia._AUTOLOGON_INNER": uia._AUTOLOGON_INNER,
        "uia._TASK_INNER": uia._TASK_INNER,
        "uia._TEARDOWN_WINLOGON_INNER": uia._TEARDOWN_WINLOGON_INNER,
    }
    assert len(scripts) == 7  # every member below is parse-checked
    for name, script in scripts.items():
        assert script and script.strip(), f"AC15: {name} is empty"
        assert _parse_errors(script) == [], (
            f"AC15: {name} does not parse under Windows PowerShell 5.1")


# ---------------------------------------------------------------------------
# AC16 — PRESERVING: the http kind still forwards plain HTTP
# ---------------------------------------------------------------------------


def test_http_relay_regression_floor(monkeypatch):
    """AC16 (preserving): a start with no kind argument still relays plain
    HTTP requests through one PS Direct guest leg exactly as before — the
    regression floor test_relay.py pins, re-declared here so this file is
    self-contained. Passes against the current code."""
    cfg = _relay_cfg()
    body = json.dumps({"Browser": "Chrome/126"}).encode()
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({
            "status": 200, "content_type": "application/json",
            "body_b64": base64.b64encode(body).decode()}),
        returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = relay.relay_start(cfg, "test-vm", 9222, cred=CRED)  # no kind kwarg
    assert out.get("ok") is True, f"AC16: relay_start failed: {out}"
    with urllib.request.urlopen(out["url"] + "/json/version", timeout=10) as resp:
        assert resp.status == 200
        assert json.loads(resp.read().decode())["Browser"] == "Chrome/126"
        assert resp.headers.get("X-Hyperv-Relay") == out["relay_id"]
    counters = relay.relay_status(cfg, out["relay_id"])["relays"][0]["counters"]
    assert counters["requests"] == 1 and counters["ok"] == 1  # count first
    assert counters["bytes_out"] == len(body)


# ---------------------------------------------------------------------------
# AC36 — the native path passes the GUID tuple, not the packed sockaddr
# ---------------------------------------------------------------------------


def test_native_path_passes_the_guid_tuple(monkeypatch):
    """AC36: on an interpreter that exposes `socket.AF_HYPERV` the connect
    address is the `(vm_id, service_id)` tuple of UUID strings the stdlib
    documents — never the packed 36-byte sockaddr, which `getsockaddrarg`
    rejects for this family with "AF_HYPERV address must be tuple, not bytes".
    """
    from hyperv_mcp import hvsock  # RED at base

    sent: dict = {}

    class RecordingSock:
        def settimeout(self, _t):
            pass

        def connect(self, addr):
            sent["addr"] = addr

        def close(self):
            pass

    monkeypatch.setattr(hvsock, "has_af_hyperv", lambda: True)
    monkeypatch.setattr(hvsock.socket, "socket", lambda *a, **k: RecordingSock())
    guid = "e953c649-1234-5678-9abc-def012345678"
    hvsock.connect(guid)
    assert sent.get("addr") == (guid, hvsock.SERVICE_GUID), (
        f"AC36: the native path must pass the GUID tuple; got "
        f"{sent.get('addr')!r}")
    assert not isinstance(sent.get("addr"), (bytes, bytearray)), (
        "AC36: the native path must not pass the packed sockaddr")


# ---------------------------------------------------------------------------
# AC39 — stream_unavailable survives as the tool envelope's error_class
# ---------------------------------------------------------------------------


def test_stream_unavailable_is_the_tool_error_class(monkeypatch, tmp_path):
    """AC39: the TOOL envelope carries `error_class "stream_unavailable"`, not
    the generic "invalid" a bare ValueError would classify to — the caller
    must be able to branch on it without string-matching the message."""
    import importlib

    import hyperv_mcp.server as server_module

    cfg_path = tmp_path / "relay.json"
    cfg_path.write_text(json.dumps({
        "allowed_vm_patterns": ["test-*"],
        "destructive": {"relay": True},
    }), encoding="utf-8")
    monkeypatch.setenv("HYPERV_GUEST_USERNAME", "Administrator")
    monkeypatch.setenv("HYPERV_GUEST_PASSWORD", "unit-test-pass")
    mod = importlib.reload(server_module)
    mod.bootstrap({"HYPERV_MCP_CONFIG": str(cfg_path)})
    try:
        _patch_caps(monkeypatch, ("uia", "msaa"))  # no "stream"
        monkeypatch.setattr(pswindows, "run_ps", FakePS())
        result = asyncio.run(mod.get_mcp().call_tool(
            "hyperv_relay_start",
            {"vm_name": "test-vm", "guest_port": 9222, "kind": "tcp"}))
        env = _tool_envelope(result, "hyperv_relay_start")
        assert env.get("ok") is False, f"AC39: {json.dumps(env)[:300]}"
        assert env.get("error_class") == "stream_unavailable", (
            f"AC39: the envelope must carry its own class; got "
            f"{env.get('error_class')!r} ({json.dumps(env)[:200]})")
    finally:
        importlib.reload(server_module)


def _tool_envelope(result, label: str) -> dict:
    content = result[0] if isinstance(result, tuple) else result
    if not isinstance(content, list) and hasattr(content, "content"):
        content = content.content
    texts = [c for c in content if getattr(c, "type", "") == "text"]
    assert texts, f"expected a text envelope block for {label}"
    return json.loads(texts[0].text)


# ---------------------------------------------------------------------------
# AC40 — a guest that accepts and never answers is torn down at the deadline
# ---------------------------------------------------------------------------


def test_silent_guest_stream_is_torn_down(monkeypatch):
    """AC40: a guest that accepts the socket and then never answers the header
    is torn down at the ack deadline instead of pinning the bridge thread
    forever -- the client sees a clean EOF, not a hang."""
    from hyperv_mcp import hvsock, relay  # RED at base

    monkeypatch.setattr(relay, "_STREAM_ACK_TIMEOUT_S", 0.4)

    class Silent:
        """Accepts the connection and then says nothing, ever."""

        def settimeout(self, _t):
            pass

        def sendall(self, _b):
            pass

        def recv(self, _n):
            raise TimeoutError("timed out")

        def close(self):
            pass

    monkeypatch.setattr(hvsock, "connect", lambda *a, **k: Silent())
    _patch_caps(monkeypatch, ("uia", "msaa", "stream"))
    monkeypatch.setattr(pswindows, "run_ps", FakePS())
    out = relay.relay_start(_relay_cfg(), "test-vm", 9222, kind="tcp", cred=CRED)
    try:
        with socket.create_connection(("127.0.0.1", out["host_port"]),
                                      timeout=15) as client:
            client.settimeout(15)
            started = time.monotonic()
            data = client.recv(4096)
            elapsed = time.monotonic() - started
        assert data == b"", (
            f"AC40: the client must see a clean EOF; got {data!r}")
        assert elapsed < 10.0, (
            f"AC40: the bridge must be torn down at the ack deadline, not "
            f"left hanging; took {elapsed:.1f}s")
    finally:
        relay.relay_stop(_relay_cfg(), out["relay_id"])


# ---------------------------------------------------------------------------
# AC41 — a bridge that pumped and saw EOF is a completion, not an error
# ---------------------------------------------------------------------------


def test_completed_bridge_is_not_an_error(monkeypatch):
    """AC41: a bridge that pumped bytes and then saw EOF is a COMPLETED
    connection. Counting it as an error made every ordinary short request (a
    /json listing) look like a failure in relay_status."""
    from hyperv_mcp import hvsock, relay  # RED at base

    class EchoGuest:
        """A REAL guest stand-in: answers the header, then echoes."""

        def __init__(self):
            self._sock = socket.socket()
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", 0))
            self._sock.listen(4)
            self.port = self._sock.getsockname()[1]
            self._stop = threading.Event()
            self._conns: list = []
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

        def close(self):
            self._stop.set()
            try:
                self._sock.close()
            except Exception:
                pass
            for conn in self._conns:
                try:
                    conn.close()
                except Exception:
                    pass

        def _serve(self):
            self._sock.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                self._conns.append(conn)
                threading.Thread(target=self._one, args=(conn,),
                                 daemon=True).start()

        def _one(self, conn):
            try:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(1)
                    if not chunk:
                        return
                    buf += chunk
                conn.sendall(b'{"ok":true}\n')
                while not self._stop.is_set():
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(chunk)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    guest = EchoGuest()
    try:
        monkeypatch.setattr(
            hvsock, "connect",
            lambda *a, **k: socket.create_connection(
                ("127.0.0.1", guest.port), timeout=15))
        _patch_caps(monkeypatch, ("uia", "msaa", "stream"))
        monkeypatch.setattr(pswindows, "run_ps", FakePS())
        out = relay.relay_start(_relay_cfg(), "test-vm", 9222, kind="tcp",
                                cred=CRED)
        try:
            with socket.create_connection(("127.0.0.1", out["host_port"]),
                                          timeout=15) as client:
                client.settimeout(15)
                client.sendall(b"ping")
                assert client.recv(4096) == b"ping", "AC41: the echo must arrive"
            # The bridge sees EOF once the client closes. Poll briefly so the
            # counters are read after the pump has settled.
            deadline = time.monotonic() + 10
            counters: dict = {}
            while time.monotonic() < deadline:
                status = relay.relay_status(_relay_cfg(), out["relay_id"])
                counters = ((status.get("relays") or [{}])[0]
                            .get("counters") or {})
                if counters.get("bytes_out"):
                    break
                time.sleep(0.05)
            time.sleep(0.3)
            status = relay.relay_status(_relay_cfg(), out["relay_id"])
            counters = ((status.get("relays") or [{}])[0].get("counters") or {})
            assert (counters.get("errors") or 0) == 0, (
                f"AC41: a completed bridge must not count an error; got "
                f"{counters}")
            assert (counters.get("bytes_out") or 0) >= 4, (
                f"AC41: the echo must have been counted; got {counters}")
        finally:
            relay.relay_stop(_relay_cfg(), out["relay_id"])
    finally:
        guest.close()


# ---------------------------------------------------------------------------
# AC44 — a tcp start reaches the capability seam with ONE identity
# ---------------------------------------------------------------------------


def test_tcp_start_reaches_the_capability_seam_with_one_identity(monkeypatch):
    """AC44 (review round): `relay_start(kind="tcp")` must consult the
    capability seam with an identity `uia.helper_capabilities` accepts.

    The shipped bug this pins: the start forwarded BOTH the resolved name and
    the resolved id, and `helper_capabilities` refuses a call carrying both —
    so every production tcp start died on that guard while every unit check
    stayed green, because each of them monkeypatches the seam itself. The
    probe therefore patches the DISCOVERY leg (`uia._install_facts`), not the
    capability function, and lets the real path run.
    """
    from hyperv_mcp import hvsock, relay, uia  # RED at base

    seen: dict = {}

    def fake_facts(cfg, ref, cred):
        seen["vm_name"] = ref.name
        seen["vm_id"] = ref.id
        return {"dir": "C:\\ProgramData\\hyperv-mcp\\uia-helper-x",
                "uuid": "", "nonce": "", "version": "1",
                "capabilities": ["uia", "msaa", "stream"]}

    monkeypatch.setattr(uia, "_install_facts", fake_facts)
    monkeypatch.setattr(hvsock, "connect",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("AC44: a guest stream opened")))
    monkeypatch.setattr(pswindows, "run_ps", FakePS())
    out = relay.relay_start(_relay_cfg(), "test-vm", 9222, kind="tcp",
                            cred=CRED)
    try:
        assert out.get("ok") is True, (
            f"AC44: the tcp start must reach the listener with a resolvable "
            f"identity; got {out}")
        assert seen.get("vm_id"), "AC44: the discovery leg never ran"
    finally:
        relay.relay_stop(_relay_cfg(), out["relay_id"])


# ---------------------------------------------------------------------------
# AC45 — the discovery leg's capability record reaches the host
# ---------------------------------------------------------------------------


def test_discovery_carries_capabilities_to_the_host(monkeypatch):
    """AC45 (review round): the capability set the guest records reaches
    `helper_capabilities`, and a record WITHOUT capabilities reads as the
    baseline — which is why a pre-#135 helper must still be refused a tcp
    relay. Probes the real function (only `_install_facts` is faked), so the
    plumbing the mocked seam hid is exercised."""
    from hyperv_mcp import relay, uia  # RED at base

    def with_caps(caps):
        def fake_facts(cfg, ref, cred):
            return {"dir": "C:\\ProgramData\\hyperv-mcp\\uia-helper-x",
                    "uuid": "", "nonce": "", "version": "1",
                    "capabilities": caps}
        return fake_facts

    monkeypatch.setattr(pswindows, "run_ps", FakePS())
    monkeypatch.setattr(uia, "_install_facts",
                        with_caps(["uia", "msaa", "stream"]))
    caps = uia.helper_capabilities(_relay_cfg(), cred=CRED, vm_id=_GUID)
    assert "stream" in caps, (
        f"AC45: the guest's recorded capability must reach the host; got "
        f"{sorted(caps)}")
    assert caps <= (uia.BASE_CAPABILITIES | {uia.ELECTRON_CAPABILITY,
                                             uia.STREAM_CAPABILITY}), (
        f"AC45: the host must intersect with its closed capability set; got "
        f"{sorted(caps)}")

    # a helper with no capabilities.txt (provisioned before #135) reads as the
    # baseline, so the tcp start is refused rather than attempted
    monkeypatch.setattr(uia, "_install_facts", with_caps([]))
    baseline = uia.helper_capabilities(_relay_cfg(), cred=CRED, vm_id=_GUID)
    assert "stream" not in baseline, (
        f"AC45: a helper with no recorded capabilities must not advertise "
        f"stream; got {sorted(baseline)}")
    with pytest.raises(ValueError, match="stream_unavailable"):
        relay.relay_start(_relay_cfg(), "test-vm", 9223, kind="tcp", cred=CRED)
