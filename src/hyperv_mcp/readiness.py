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
from datetime import datetime, timezone

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
        if "<!DOCTYPE" in raw[:200] or "<!ENTITY" in raw[:200]:
            # M27 (PR #112 review): internal-entity expansion is unbounded on
            # expat < 2.6 and the caps bound only RAW bytes. A KVP item is
            # host-serialized CIM-XML and never legitimately carries a DTD —
            # skip the item instead of handing the parser an entity bomb.
            continue
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


def classify_phase(
    state: str, hb_enabled: bool, hb_primary: str | None, kvp_available: bool
) -> str:
    """Map (VM state, heartbeat-service enabled, heartbeat primary status,
    KVP presence) to the deployment phase.

    The seven-phase vocabulary (issue #32 AC5 + the retained 7th row):
    ``off`` — the VM is Off; readiness questions do not arise.
    ``suspended`` — Saved or Paused: suspended, not a live guest signal.
    ``heartbeat_disabled`` — Running but the Heartbeat integration service
    is absent or disabled on the host; the host cannot vouch for the guest
    (a disabled service beats even a primary "OK" reading, which a stale
    service object can carry).
    ``os_ready`` — Running, service enabled, heartbeat OK and KVP published.
    ``degraded`` — Running, service enabled, heartbeat OK, no KVP
    (integration services late, absent, or the guest is not Windows) — the
    retained 7th row, a documented superset over AC5's six.
    ``os_unresponsive`` — Running, service enabled, heartbeat Lost
    Communication or Error: the OS was contacted and is not responding.
    ``no_guest_signal`` — everything else (No Contact covers firmware,
    WinPE and an early boot; Starting/Stopping transitions).
    """
    if state == "Off":
        return "off"
    if state in ("Saved", "Paused"):
        return "suspended"
    if state == "Running":
        if not hb_enabled:
            return "heartbeat_disabled"
        if hb_primary == "OK":
            return "os_ready" if kvp_available else "degraded"
        if hb_primary in ("Lost Communication", "Error"):
            return "os_unresponsive"
    return "no_guest_signal"


def heartbeat_script(guid: str) -> str:
    """Standalone heartbeat leg: emit the Heartbeat status description."""
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        "$hb = Get-VMIntegrationService -VM $vm -Name Heartbeat -ErrorAction SilentlyContinue",
        "if ($hb) { [string]$hb.PrimaryStatusDescription } else { '' }",
    ])


def _action_script(guid: str) -> str:
    """The ONE action script: VM state + uptime + heartbeat (enabled,
    primary and secondary status) + KVP, GUID-keyed."""
    return guestexec.vm_target_preamble(guid) + "\n" + "\n".join([
        "$vm = Get-VM -Id $vmTarget -ErrorAction Stop",
        "$hb = Get-VMIntegrationService -VM $vm -Name Heartbeat -ErrorAction SilentlyContinue",
        "$kvp = Get-CimInstance -Namespace root/virtualization/v2"
        " -ClassName Msvm_KvpExchangeComponent"
        " -Filter \"SystemName='$vmTarget'\" -ErrorAction SilentlyContinue",
        "[PSCustomObject]@{",
        "  state = [string]$vm.State",
        "  uptime_s = [int]$vm.Uptime.TotalSeconds",
        "  heartbeat_enabled = [bool]($hb -and $hb.Enabled)",
        "  heartbeat = if ($hb) { [string]$hb.PrimaryStatusDescription } else { '' }",
        "  heartbeat_secondary = if ($hb) { [string]$hb.SecondaryStatusDescription } else { '' }",
        "  kvp_items = @($kvp.GuestIntrinsicExchangeItems)",
        "} | ConvertTo-Json -Compress",
    ])


def _run(cfg: Config, script: str, timeout_s: int = 60, ctx: str = "readiness") -> pswindows.PSResult:
    script, stdin = pswindows.compose_remote(cfg, script.strip())
    if stdin is None:
        result = pswindows.run_ps(script, timeout_s=timeout_s)
    else:
        result = pswindows.run_ps(script, timeout_s=timeout_s, stdin_b64=stdin)
    return pswindows.check_result(result, ctx)


def heartbeat_status(cfg: Config, ref: vmident.VMRef) -> str:
    """One PowerShell process: the heartbeat status description ("" if the
    integration service is absent). Used by hyperv_wait_vm_state's Running
    final leg — no KVP, no credentials."""
    return _run(cfg, heartbeat_script(ref.id)).stdout.strip()


def deployment_status(cfg: Config, vm_name: str = "", vm_id: str = "") -> dict:
    """Credential-free readiness: state + heartbeat + KVP in one phase.

    Exactly ONE action PowerShell process after vmident resolution; guest
    credentials are never resolved on any path of this function. Result is
    the issue #32 AC4 richer shape: top-level state/uptime_s, vm_id, the
    heartbeat struct {enabled, primary_status, application_status},
    guest.fqdn/ipv6 from the KVP pairs, phase_basis naming the producing
    signals, and checked_at (UTC ISO-8601 Z).
    """
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    raw = _run(cfg, _action_script(ref.id), timeout_s=60,
               ctx=f"deployment_status({ref.name})").stdout.strip()
    try:
        rows = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        # L13: a host-output fault must name its leg, not surface as a bare
        # "invalid" JSONDecodeError.
        raise RuntimeError(
            f"deployment_status({ref.name}): output parse failed: {exc} "
            f"| raw: {raw[:200]!r}") from None
    if not isinstance(rows, dict):
        rows = {}
    state = str(rows.get("state") or "")
    hb_enabled = bool(rows.get("heartbeat_enabled"))
    hb_primary = str(rows.get("heartbeat") or "")
    app_status = str(rows.get("heartbeat_secondary") or "")
    kvp_all = parse_kvp_items(rows.get("kvp_items") or [])
    # classify receives the RAW KVP presence; the OUTPUT kvp view stays
    # heartbeat-gated (a not-OK or disabled heartbeat invalidates stale
    # pairs the guest may still publish — issue #32 AC11).
    kvp_gated = kvp_all if (hb_enabled and hb_primary == "OK") else {}
    phase = classify_phase(state, hb_enabled, hb_primary, bool(kvp_all))
    if hb_enabled:
        basis = (
            f"state={state}; heartbeat={hb_primary or 'absent'}; "
            f"kvp={'present' if kvp_all else 'absent'}"
        )
    else:
        basis = (
            f"state={state}; heartbeat={hb_primary or 'absent'}; "
            f"heartbeat_enabled={str(hb_enabled).lower()}; "
            f"kvp={'present' if kvp_all else 'absent'}"
        )
    checked_at = (
        datetime.now(timezone.utc).isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    def _split(value: str | None) -> list[str]:
        return [s.strip() for s in str(value or "").split(";") if s.strip()]

    return {
        "ok": True,
        "phase": phase,
        "phase_basis": basis,
        "vm_id": ref.id,
        "state": state,
        "uptime_s": int(rows.get("uptime_s") or 0),
        "heartbeat": {
            "enabled": hb_enabled,
            "primary_status": hb_primary,
            "application_status": app_status,
        },
        # guest.* read the heartbeat-GATED view: stale pairs from a previous
        # OS must never surface as the guest's identity (issue #32 AC11).
        "guest": {
            "os_name": str(kvp_gated.get("OSName") or ""),
            "os_build": str(kvp_gated.get("OSBuildNumber") or ""),
            "fqdn": str(kvp_gated.get("FullyQualifiedDomainName") or ""),
            "ipv4": _split(kvp_gated.get("NetworkAddressIPv4")),
            "ipv6": _split(kvp_gated.get("NetworkAddressIPv6")),
        },
        "kvp": {"available": bool(kvp_gated), "items": kvp_gated},
        "checked_at": checked_at,
        "vm_name": ref.name,
    }
