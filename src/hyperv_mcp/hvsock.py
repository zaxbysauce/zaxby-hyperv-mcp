"""Hyper-V socket transport (issue #135).

A Hyper-V socket (`AF_HYPERV`, family 34) connects a host process to a service
inside a guest VM by GUID pair, without using the guest's network adapters. It
is the same primitive PowerShell Direct is built on
(`PowerShell/PowerShell` `src/System.Management.Automation/engine/remoting/common/RemoteSessionHyperVSocket.cs`,
`AF_HYPERV = (System.Net.Sockets.AddressFamily)34`).

Two paths, one seam:

* **CPython 3.12+** exposes `socket.AF_HYPERV` and its address form is a
  `(vm_id, service_id)` tuple of UUID strings (`Doc/library/socket.rst`,
  `versionadded:: 3.12`). The stdlib packs the 36-byte sockaddr itself, so this
  path passes the pair straight through.
* **CPython 3.10/3.11** lack the constant (and the address form), so the socket
  is created and connected through `ctypes` against `Ws2_32.dll` and the
  resulting handle is wrapped with `socket.socket(fileno=...)` — the pattern
  recorded in CPython issue gh-92658.

`pack_sockaddr_hv` stays the pure packer the acceptance checks pin (C12): it is
what the ctypes `connect` consumes, and it documents the wire layout.

Wire layout of the 36-byte address: family (34) little-endian, two reserved
zero bytes, then the VM GUID and the service GUID, each as
`uuid.UUID(...).bytes_le` — the Windows in-memory GUID order, which is also
what .NET's `Guid.ToByteArray()` produces (the guest-side listener packs it
that way).
"""

from __future__ import annotations

import ctypes
import select
import socket
import time
import uuid

# Address family for Hyper-V sockets. Present as `socket.AF_HYPERV` from
# CPython 3.12; the constant is the same on every version, so it is defined
# here rather than read from the socket module.
AF_HYPERV = 34

# SOCK_STREAM and the protocol value the Hyper-V socket transport uses. The
# PowerShell engine's own HyperVSocketEndPoint passes `(ProtocolType)1`.
_SOCK_STREAM = 1
_HV_SOCKET_PROTOCOL = 1

# The reserved two bytes between the family and the first GUID.
_RESERVED = b"\x00\x00"

# `SERVICE_GUID` is the fixed, project-wide service identifier the guest
# forwarder listens on and the host dials. Generated once; published in the
# README and written to the host registry by
# `hyperv-mcp-http --register-hvsocket-service`.
SERVICE_GUID = "0b48efab-5086-42b0-94f6-7ddb08383dd6"

_DEFAULT_TIMEOUT_S = 30.0

# --- Winsock constants the ctypes path needs ---------------------------------
_INVALID_SOCKET = ctypes.c_void_p(-1).value
_FIONBIO = 0x8004667E          # set a socket to non-blocking mode
_SOL_SOCKET = 0xFFFF           # SOL_SOCKET on Windows
_SO_ERROR = 0x1007             # getsockopt option: the pending error
_WSAEWOULDBLOCK = 10035
_WSAEISCONN = 10056
def _guid_bytes(value: str) -> bytes:
    """`bytes_le` for a GUID string, rejecting anything that is not a GUID."""
    try:
        return uuid.UUID(str(value)).bytes_le
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"not a GUID: {value!r}") from exc


def pack_sockaddr_hv(vm_guid: str, service_guid: str) -> bytes:
    """Pack the 36-byte Hyper-V socket address for a VM/service GUID pair.

    `family` is little-endian, then two reserved zero bytes, then the VM GUID
    and the service GUID, each as `uuid.UUID(...).bytes_le`.
    """
    return (
        AF_HYPERV.to_bytes(2, "little")
        + _RESERVED
        + _guid_bytes(vm_guid)
        + _guid_bytes(service_guid)
    )


def has_af_hyperv() -> bool:
    """True when this interpreter exposes `socket.AF_HYPERV` (CPython 3.12+)."""
    return hasattr(socket, "AF_HYPERV")


def _connect_native(vm_guid: str, service_guid: str,
                    timeout_s: float) -> socket.socket:
    """Connect through `socket.AF_HYPERV` (CPython 3.12+).

    The address form is the `(vm_id, service_id)` tuple of UUID strings the
    stdlib documents — NOT the packed sockaddr, which `getsockaddrarg` rejects
    for this family with "AF_HYPERV address must be tuple, not bytes".
    """
    family = getattr(socket, "AF_HYPERV", AF_HYPERV)
    sock = socket.socket(family, _SOCK_STREAM, _HV_SOCKET_PROTOCOL)
    try:
        sock.settimeout(timeout_s)
        sock.connect((str(vm_guid), str(service_guid)))
    except BaseException:
        sock.close()
        raise
    return sock


def _load_ws2_32():
    """Return the `Ws2_32.dll` ctypes binding with its prototypes declared.

    The prototypes are not optional decoration: a Winsock `SOCKET` is
    pointer-sized, and ctypes' default `restype` is a 32-bit `int`, so a
    64-bit handle is silently truncated to its low word — the socket is then
    created on one handle and every later call addresses another. Isolated in
    its own function so the unit checks can drive this path with a recording
    winsock instead of the real DLL.
    """
    ws2_32 = ctypes.windll.ws2_32  # type: ignore[attr-defined]
    sock_p = ctypes.c_void_p
    ws2_32.socket.restype = sock_p
    ws2_32.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    ws2_32.connect.restype = ctypes.c_int
    ws2_32.connect.argtypes = [sock_p, ctypes.c_char_p, ctypes.c_int]
    ws2_32.closesocket.restype = ctypes.c_int
    ws2_32.closesocket.argtypes = [sock_p]
    ws2_32.getsockopt.restype = ctypes.c_int
    ws2_32.getsockopt.argtypes = [sock_p, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    ws2_32.ioctlsocket.restype = ctypes.c_int
    ws2_32.ioctlsocket.argtypes = [sock_p, ctypes.c_long,
                                   ctypes.POINTER(ctypes.c_ulong)]
    ws2_32.WSAGetLastError.restype = ctypes.c_int
    ws2_32.WSAGetLastError.argtypes = []
    return ws2_32


def _set_non_blocking(ws2_32, handle: int) -> None:
    mode = ctypes.c_ulong(1)
    if ws2_32.ioctlsocket(handle, _FIONBIO, ctypes.byref(mode)) != 0:
        raise OSError(
            f"Ws2_32.ioctlsocket(FIONBIO) failed: winsock error "
            f"{ws2_32.WSAGetLastError()}")


def _connect_error(ws2_32, handle: int) -> int:
    """The pending connect error, or 0 while it is still in flight."""
    buf = ctypes.c_int(0)
    size = ctypes.c_int(ctypes.sizeof(buf))
    if ws2_32.getsockopt(handle, _SOL_SOCKET, _SO_ERROR, ctypes.byref(buf),
                         ctypes.byref(size)) != 0:
        return ws2_32.WSAGetLastError()
    return int(buf.value)


def _await_connect(ws2_32, handle: int, timeout_s: float) -> None:
    """Wait (bounded) for a non-blocking connect to settle.

    A non-blocking `connect` returns `WSAEWOULDBLOCK` while the Hyper-V socket
    is still being established. The completion is observed through
    `SO_ERROR`, which stays 0 until the attempt either fails (non-zero) or
    succeeds (0 and the peer is now reachable) — so a 0 is confirmed with
    `select` reporting the socket writable rather than assumed.

    The deadline is a MONOTONIC INSTANT, not a `waited` accumulator: each
    `select` may block for the whole remaining budget, so an accumulator that
    advances by a fixed poll step per iteration under-counts the real elapsed
    time by roughly timeout^2 / (2 * step) — about 6 hours at the 30 s default,
    which is precisely the hang this wait exists to prevent.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        err = _connect_error(ws2_32, handle)
        if err == _WSAEISCONN:
            return
        if err not in (0, _WSAEWOULDBLOCK):
            raise OSError(f"Ws2_32.connect failed: winsock error {err}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"the Hyper-V socket to the guest did not connect within "
                f"{timeout_s:g}s")
        proxy = _HandleProxy(handle)
        try:
            _readable, writable, _errored = select.select(
                [], [proxy], [], remaining)
        except OSError:
            # A handle `select` cannot watch (already closed) is a failure,
            # not a reason to spin until the deadline.
            raise
        if writable:
            err = _connect_error(ws2_32, handle)
            if err in (0, _WSAEISCONN):
                return
            raise OSError(f"Ws2_32.connect failed: winsock error {err}")


class _HandleProxy:
    """A bare Winsock handle dressed as a `select`-able object.

    `select.select` on Windows asks only for `fileno()`; the handle is a plain
    descriptor number, so no socket object is needed to wait on it.
    """

    def __init__(self, handle: int) -> None:
        self._handle = int(handle)

    def fileno(self) -> int:
        return self._handle


def _connect_ctypes(vm_guid: str, service_guid: str,
                    timeout_s: float) -> socket.socket:
    """Connect through `Ws2_32.dll` and wrap the handle (CPython < 3.12).

    gh-92658: create the socket with `Ws2_32.socket`, connect it with
    `Ws2_32.connect`, then hand the handle to `socket.socket(fileno=...)`.
    The connect is issued non-blocking and awaited with a bounded deadline, so
    a guest that never answers cannot pin a bridge thread forever.
    """
    ws2_32 = _load_ws2_32()
    handle = ws2_32.socket(AF_HYPERV, _SOCK_STREAM, _HV_SOCKET_PROTOCOL)
    if handle == _INVALID_SOCKET or not handle:
        raise OSError(
            f"Ws2_32.socket(AF_HYPERV) failed: winsock error "
            f"{ws2_32.WSAGetLastError()}")
    handle = int(handle)
    try:
        sockaddr = pack_sockaddr_hv(vm_guid, service_guid)
        # An explicit size keeps the buffer at exactly 36 bytes: the default
        # `create_string_buffer(bytes)` appends a NUL terminator, and the
        # connect length must name the sockaddr, not the terminator.
        buf = ctypes.create_string_buffer(sockaddr, len(sockaddr))
        _set_non_blocking(ws2_32, handle)
        rc = ws2_32.connect(handle, buf, len(sockaddr))
        if rc != 0:
            err = ws2_32.WSAGetLastError()
            if err not in (_WSAEWOULDBLOCK, _WSAEISCONN):
                raise OSError(f"Ws2_32.connect failed: winsock error {err}")
            _await_connect(ws2_32, handle, timeout_s)
        # The handle is a SOCKET; on Windows Python's socket module accepts it
        # as `fileno`. `detach` is deliberately NOT called — the wrapper owns
        # the handle from here and closes it. Only send/recv/settimeout/close
        # are used on the wrapper, so the family it detects for itself is
        # irrelevant to the caller.
        sock = socket.socket(fileno=handle)
    except BaseException:
        ws2_32.closesocket(handle)
        raise
    sock.settimeout(timeout_s)
    return sock


def _connect_socket(vm_guid: str, service_guid: str,
                    timeout_s: float) -> socket.socket:
    """The single connect seam: `socket.AF_HYPERV` where present, else ctypes."""
    if has_af_hyperv():
        return _connect_native(vm_guid, service_guid, timeout_s)
    return _connect_ctypes(vm_guid, service_guid, timeout_s)


# Backwards-compatible alias: the packing helper was first named `sockaddr_hv`
# during implementation; the acceptance checks freeze `pack_sockaddr_hv`.
sockaddr_hv = pack_sockaddr_hv


def connect(
    vm_guid: str,
    service_guid: str = SERVICE_GUID,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> socket.socket:
    """Open a connected stream socket to `service_guid` inside `vm_guid`.

    The caller owns the returned socket and must close it. There is no
    fallback transport: when the guest stream cannot be opened this raises,
    and the caller closes the client connection rather than retrying over
    PowerShell Direct (issue #135 design note 7).
    """
    return _connect_socket(vm_guid, service_guid, timeout_s)
