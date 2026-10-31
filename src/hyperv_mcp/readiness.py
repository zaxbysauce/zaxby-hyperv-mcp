"""Credential-free deployment readiness from host-side Hyper-V signals.

Issue #32 (ENH-14): during an OS deployment an agent must decide when the
guest has moved from firmware/WinPE into a running Windows, and which build
and IPs it came up with — without guest credentials, which a mid-deployment
guest may not even have. Hyper-V publishes two host-side signals that need
no credentials:

  * the Heartbeat integration service (booted OS responding: OK / No Contact
    / Lost Communication), and
  * ``Msvm_KvpExchangeComponent.GuestIntrinsicExchangeItems`` — guest-pushed
    key/value pairs such as OSName, OSBuildNumber, NetworkAddressIPv4.

Both are read through vmident's GUID resolver (never by VM name), combined
with VM state into one ``hyperv_deployment_status`` phase answer, and the
``hyperv_wait_vm_state`` heartbeat field replaces the old constant
``guest_channel: "ps_direct_unverified"``.

KVP values are written by the guest: they are parsed in Python (never
interpolated into PowerShell), size-capped per item and in total, and
returned as display data only. A heartbeat that is not OK invalidates KVP
(the guest's KVP service may be down while stale pairs linger — issue #32
AC11), so ``kvp.available`` reflects the heartbeat-gated view.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from . import guestexec, pswindows, vmident
from .config import Config

#: Per-item and total caps for the guest-controlled KVP payload.
_KVP_ITEM_MAX = 64 * 1024
_KVP_TOTAL_MAX = 1024 * 1024


def parse_kvp_items(items: list[str] | None) -> dict[str, str]:
    """Parse ``GuestIntrinsicExchangeItems`` strings into ``{Name: Data}``.

    Each well-formed item is a CIM-XML ``<INSTANCE
    CLASSNAME="Msvm_KvpExchangeDataItem">`` element whose ``PROPERTY``
    children carry ``NAME`` ("Name"/"Data") and a ``VALUE`` text. Malformed
    entries are skipped without raising — the payload is guest-controlled
    and a bad row must never break the status call. Inputs over the caps are
    dropped and an over-budget batch stops absorbing items.
    """
    out: dict[str, str] = {}
    total = 0
    for raw in items or []:
        if not isinstance(raw, str) or not raw or len(raw) > _KVP_ITEM_MAX:
            continue
        total += len(raw)
        if total > _KVP_TOTAL_MAX:
            break
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue
        props: dict[str, str] = {}
        for prop in root.iter("PROPERTY"):
            name = prop.get("NAME")
            value_el = prop.find("VALUE")
            if name is None or value_el is None or value_el.text is None:
                continue
            props[name] = value_el.text
        if "Name" in props and "Data" in props:
            out[props["Name"]] = props["Data"]
    return out


def classify_phase(state: str, heartbeat: str | None, kvp_available: bool) -> str:
    """Map (VM state, heartbeat, KVP) to the deployment phase.

    ``off`` — the VM is Off; readiness questions do not arise.
    ``os_ready`` — Running, heartbeat OK and KVP published: an OS booted and
    is responding; PowerShell Direct may still need credentials.
    ``degraded`` — Running with heartbeat OK but no KVP (integration
    services late, absent, or the guest is not Windows).
    ``no_guest_signal`` — anything else: firmware, WinPE, booting, paused...
    """
    if state == "Off":
        return "off"
    if state == "Running" and heartbeat == "OK":
        return "os_ready" if kvp_available else "degraded"
    return "no_guest_signal"


def heartbeat_script(guid: str) -> str:
    """Standalone heartbeat leg: emit the Heartbeat status description."""
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        "$hb = Get-VMIntegrationService -VM $vm -Name Heartbeat -ErrorAction SilentlyContinue",
        "if ($hb) { [string]$hb.PrimaryStatusDescription } else { '' }",
    ])


def _action_script(guid: str) -> str:
    """The ONE action script: VM state + uptime + heartbeat + KVP, GUID-keyed."""
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        "$hb = Get-VMIntegrationService -VM $vm -Name Heartbeat -ErrorAction SilentlyContinue",
        "$kvp = Get-CimInstance -Namespace root/virtualization/v2"
        " -ClassName Msvm_KvpExchangeComponent"
        " -Filter \"SystemName='$vmTarget'\" -ErrorAction SilentlyContinue",
        "[PSCustomObject]@{",
        "  state = [string]$vm.State",
        "  uptime_s = [int]$vm.Uptime.TotalSeconds",
        "  heartbeat = if ($hb) { [string]$hb.PrimaryStatusDescription } else { '' }",
        "  kvp_items = @($kvp.GuestIntrinsicExchangeItems)",
        "} | ConvertTo-Json -Compress",
    ])


def _run(cfg: Config, script: str, timeout_s: int = 60) -> pswindows.PSResult:
    script, stdin = pswindows.compose_remote(cfg, script.strip())
    if stdin is None:
        result = pswindows.run_ps(script, timeout_s=timeout_s)
    else:
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    return pswindows.check_result(result)


def heartbeat_status(cfg: Config, ref: vmident.VMRef) -> str:
    """One PowerShell process: the heartbeat status description ("" if the
    integration service is absent). Used by hyperv_wait_vm_state's Running
    final leg — no KVP, no credentials."""
    return _run(cfg, heartbeat_script(ref.id)).stdout.strip()


def deployment_status(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    """Credential-free readiness: state + heartbeat + KVP in one phase.

    Exactly ONE action PowerShell process after vmident resolution; guest
    credentials are never resolved on any path of this function.
    """
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    rows = json.loads(_run(cfg, _action_script(ref.id)).stdout.strip() or "{}")
    if not isinstance(rows, dict):
        rows = {}
    state = str(rows.get("state") or "")
    heartbeat = str(rows.get("heartbeat") or "")
    # A heartbeat that is not OK invalidates KVP: the guest's KVP service may
    # be down while stale pairs from the previous OS linger (issue #32 AC11).
    kvp_all = parse_kvp_items(rows.get("kvp_items") or [])
    kvp = kvp_all if heartbeat == "OK" else {}
    ipv4 = [s.strip() for s in str(kvp.get("NetworkAddressIPv4") or "").split(";") if s.strip()]
    return {
        "ok": True,
        "phase": classify_phase(state, heartbeat, bool(kvp)),
        "vm": {"state": state, "uptime_s": int(rows.get("uptime_s") or 0)},
        "heartbeat": heartbeat,
        "guest": {
            "os_name": str(kvp.get("OSName") or ""),
            "os_build": str(kvp.get("OSBuildNumber") or ""),
            "ipv4": ipv4,
        },
        "kvp": {"available": bool(kvp), "items": kvp},
        "vm_name": ref.name,
    }
