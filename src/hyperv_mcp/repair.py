"""Narrow guest-access repair with a dry run by default (AC9).

Step 1 reuses diagnostics' GUID-native report builder (diagnose_report —
the no-re-resolve entry point that diagnose_vm_access wraps after its own
resolve, no copy and no
second name resolution). Step 2 maps findings
to narrow fix proposals. Only explicit apply=True with the destructive
confirm leg satisfied (category guest_repair) performs any guest mutation;
each mutation leg runs under its own vm_lock (never an outer lock across the
composite), and every applied action is re-verified by re-running the
diagnostic probes.

The fixes are deliberately narrow: rewrite stale sshd ListenAddress lines to
the OPERATOR-SUPPLIED intended bindings (intended_bindings — never a guessed
default; an absent, invalid, or length-ambiguous intent leaves the rewrite
not_attempted with a decision_required diagnostic), with a timestamped
backup of sshd_config, start stopped sshd / WinRM services, and enable
EXISTING disabled allow rules whose port filter matches the SSH/WinRM port
exactly or is port-Any — new firewall rules are never created, but widening
a disabled Any-port rule is possible and is stated verbatim in the dry-run
plan text so the operator approves it informed. A stale address seen only on
the runtime listener (e.g. a hostname ListenAddress line) matches no config
line: the backup and sshd restart still run with 0 replacements while
verification reports the binding still present.

Every change dict carries the tripartite outcome (issue #158): apply_outcome
(applied/failed/not_attempted), observation (positive/negative/partial/
unavailable) and postcondition (satisfied/unsatisfied/unknown) as separate
keys, plus an action-specific postcondition_detail. The legacy `verified`
boolean is DERIVED, never independent: verified = (apply_outcome == applied
and postcondition == satisfied and observation == positive). Staleness
itself is decided by the shared observation-aware planner
(diagnostics.classify_bind_address) so repair and diagnostics can never
disagree about which bindings are stale.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from . import diagnostics, policy, pswindows, vmident
from .config import Config
from .credentials import CredentialSet
from .diagnostics import run_guest_inner

_SSHD_CFG = "C:\\ProgramData\\ssh\\sshd_config"


# -- per-action apply scripts (inner guest scripts) -------------------------


def _apply_stale_binding_script(stale: list[str], intended: list[str]) -> str:
    """Rewrite script driven by the OPERATOR-SUPPLIED intended bindings
    (issue #158 C15): each stale ListenAddress line maps to its intended
    replacement — the hardcoded 0.0.0.0 default is retired."""
    entries = "; ".join(
        f"{pswindows.ps_quote(s)} = {pswindows.ps_quote(r)}"
        for s, r in zip(stale, intended, strict=True)
    )
    return f"""
$sshdCfg = '{_SSHD_CFG}'
$map = @{{ {entries} }}
$backup = $sshdCfg + '.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $sshdCfg -Destination $backup -Force
$lines = [System.IO.File]::ReadAllLines($sshdCfg)
$out = New-Object System.Collections.Generic.List[string]
$replaced = 0
foreach ($ln in $lines) {{
    $t = $ln.Trim()
    if ($t -match '^(?i)ListenAddress\\s+(.+)$') {{
        $addr = $Matches[1].Trim()
        if ($map.ContainsKey($addr)) {{
            $out.Add('ListenAddress ' + $map[$addr])
            $replaced++
            continue
        }}
    }}
    $out.Add($ln)
}}
[System.IO.File]::WriteAllLines($sshdCfg, $out.ToArray())
Restart-Service -Name sshd -Force -ErrorAction Stop
[PSCustomObject]@{{ backup = $backup; replaced = $replaced }} | ConvertTo-Json -Compress
""".strip()


def _apply_service_start_script(service: str) -> str:
    name = pswindows.ps_quote(service)
    return f"""
Start-Service -Name {name} -ErrorAction Stop
$s = Get-Service -Name {name} -ErrorAction Stop
[PSCustomObject]@{{ service = $s.Name; status = [string]$s.Status }} | ConvertTo-Json -Compress
""".strip()


def _apply_firewall_enable_script(port: int) -> str:
    return f"""
$port = '{port}'
$rules = @(Get-NetFirewallRule -Action Allow -Direction Inbound -ErrorAction Stop |
    Where-Object {{ -not $_.Enabled }} | Select-Object -First 200)
$enabled = @()
foreach ($rule in $rules) {{
    $f = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if ($null -ne $f) {{
        $lp = @($f.LocalPort) | ForEach-Object {{ [string]$_ }}
        if ($lp -contains $port -or $lp -contains 'Any') {{
            Set-NetFirewallRule -Name $rule.Name -Enabled True -ErrorAction Stop
            $enabled += $rule.Name
        }}
    }}
}}
[PSCustomObject]@{{ port = $port; enabled_rules = $enabled }} | ConvertTo-Json -Compress
""".strip()


# -- finding -> action mapping ----------------------------------------------


def _is_stale_address(raw: str, report: dict) -> bool:
    """Delegate to the shared observation-aware planner (issue #158): the
    heuristic lives in ONE place (diagnostics.classify_bind_address) and is
    family-aware — an address whose family was not successfully observed is
    never classified stale."""
    ip_section = (report.get("guest") or {}).get("ip_addresses") or {}
    return diagnostics.classify_bind_address(raw, ip_section) == "stale"


def _intent_state(
    stale: list[str], intended: list[str] | None,
) -> tuple[bool, str, list[str]]:
    """Validate the operator intent for the stale-binding rewrite (C15).

    Returns (ok, reason, per_line). A single intended address applies to
    every stale line (recorded per line); an exact-length list maps line by
    line. Anything else — absent/empty intent, an entry that does not parse
    as an IP address, or a length that is neither 1 nor len(stale) — is
    decision_required: the rewrite is never guessed, never cycled."""
    if not intended:
        return False, (
            "no operator intent supplied: pass intended_bindings (one "
            "ListenAddress for every stale line, or one per line)"
        ), []
    if len(intended) not in (1, len(stale)):
        return False, (
            f"ambiguous operator intent: {len(intended)} intended binding(s) "
            f"for {len(stale)} stale line(s) — pass exactly one address to "
            "apply to every line, or one per line"
        ), []
    per_line: list[str] = []
    for entry in intended:
        text = str(entry).strip()
        bare = text[1:-1] if text.startswith("[") and text.endswith("]") else text
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            return False, (
                f"invalid intended binding {text!r}: not a parseable IP address"
            ), []
        per_line.append(text)
    if len(per_line) == 1:
        per_line = per_line * len(stale)
    return True, "", per_line


def _plan_items(report: dict, intended_bindings: list[str] | None = None) -> list[dict[str, Any]]:
    """Turn diagnostic findings into narrow fix proposals."""
    items: list[dict[str, Any]] = []
    findings = report.get("findings") or []
    guest = report.get("guest") or {}
    ssh = guest.get("ssh") or {}
    for f in findings:
        fid = f.get("id")
        if fid == "ssh_stale_binding":
            stale = [
                str(a) for a in (ssh.get("config_listen") or [])
                if _is_stale_address(str(a), report)
            ]
            for listener in ssh.get("listeners") or []:
                raw = str(listener.get("address", ""))
                if _is_stale_address(raw, report) and raw not in stale:
                    stale.append(raw)
            ok, reason, per_line = _intent_state(stale, intended_bindings)
            item: dict[str, Any] = {
                "action": "rewrite_stale_ssh_bindings",
                "target": _SSHD_CFG,
                "before": {"stale_bindings": stale},
                "finding": fid,
                "verify_finding": "ssh_stale_binding",
            }
            if ok and stale:
                item["change"] = (
                    "rewrite each stale ListenAddress line to the intended "
                    "binding ("
                    + ", ".join(
                        f"{s} -> {r}"
                        for s, r in zip(stale, per_line, strict=True)
                    )
                    + "), back up the config, restart sshd"
                )
                item["intended_bindings"] = per_line
                item["apply_script"] = _apply_stale_binding_script(stale, per_line)
            else:
                item["decision_required"] = True
                item["change"] = (
                    "decision required — operator intent ambiguous or absent: "
                    + reason
                )
                item["apply_script"] = None
            items.append(item)
        elif fid == "ssh_service_stopped":
            items.append({
                "action": "start_service",
                "target": "sshd",
                "before": {"status": (ssh.get("service") or {}).get("status")},
                "change": "Start-Service sshd",
                "finding": fid,
                "apply_script": _apply_service_start_script("sshd"),
                "verify_finding": "ssh_service_stopped",
            })
        elif fid == "winrm_service_stopped":
            winrm = guest.get("winrm") or {}
            items.append({
                "action": "start_service",
                "target": "WinRM",
                "before": {"status": (winrm.get("service") or {}).get("status")},
                "change": "Start-Service WinRM",
                "finding": fid,
                "apply_script": _apply_service_start_script("WinRM"),
                "verify_finding": "winrm_service_stopped",
            })
        elif fid == "ssh_firewall_no_allow":
            items.append({
                "action": "enable_existing_firewall_rules",
                "target": "TCP 22 inbound allow rules",
                "before": {"port": 22},
                "change": "enable existing disabled inbound allow rules whose port filter matches TCP 22 exactly or is port-Any (may widen an existing Any-port rule; no new rules created)",
                "finding": fid,
                "apply_script": _apply_firewall_enable_script(22),
                "verify_finding": "ssh_firewall_no_allow",
            })
        elif fid == "winrm_firewall_no_allow":
            items.append({
                "action": "enable_existing_firewall_rules",
                "target": "TCP 5985 inbound allow rules",
                "before": {"port": 5985},
                "change": "enable existing disabled inbound allow rules whose port filter matches TCP 5985 exactly or is port-Any (may widen an existing Any-port rule; no new rules created)",
                "finding": fid,
                "apply_script": _apply_firewall_enable_script(5985),
                "verify_finding": "winrm_firewall_no_allow",
            })
    return items


# -- verification phase (tripartite evaluation) ------------------------------


def _verify_observation(report: dict) -> str:
    """Observation quality of a verification report (C11/C13).

    unavailable: PowerShell Direct could not reach the guest — no guest
    observation at all. partial: the guest answered but a probe section or
    an address-family enumeration errored, so facts derived from it cannot
    certify a postcondition. positive: every section observed cleanly.
    """
    if not (report.get("ps_direct") or {}).get("available"):
        return "unavailable"
    guest = report.get("guest") or {}
    for name in ("identity", "ip_addresses", "ssh", "winrm", "firewall"):
        if (guest.get(name) or {}).get("error"):
            return "partial"
    ip_section = guest.get("ip_addresses") or {}
    if ip_section.get("ipv4_error") or ip_section.get("ipv6_error"):
        return "partial"
    return "positive"


def _evaluate_change(
    item: dict[str, Any],
    change: dict[str, Any],
    report: dict,
    observation: str,
    remaining: set,
) -> None:
    """Fill one change's observation/postcondition channels from the verify
    report (positive observation only; the callers own the unknown path)."""
    change["observation"] = observation
    if observation != "positive":
        change["postcondition"] = "unknown"
        change["verified"] = False
        if not change["verify_detail"]:
            change["verify_detail"] = (
                f"verification observation {observation}: postcondition unknown"
            )
        return
    guest = report.get("guest") or {}
    finding = item["verify_finding"]
    cleared = finding not in remaining
    detail: dict[str, Any] = {"finding_cleared": cleared}
    satisfied = cleared
    uncertified = False
    action = item["action"]
    if action == "start_service":
        if item["target"] == "sshd":
            ssh = guest.get("ssh") or {}
            detail["service_status"] = str(
                (ssh.get("service") or {}).get("status") or ""
            )
            detail["listener_bindings"] = [
                str(listener.get("address", ""))
                for listener in (ssh.get("listeners") or [])
            ]
        else:
            winrm = guest.get("winrm") or {}
            detail["service_status"] = str(
                (winrm.get("service") or {}).get("status") or ""
            )
            detail["listener_bindings"] = [
                str(listener.get("address", ""))
                for listener in (winrm.get("tcp_listeners") or [])
            ]
        satisfied = cleared and detail["service_status"] == "Running"
    elif action == "rewrite_stale_ssh_bindings":
        ssh = guest.get("ssh") or {}
        observed = [
            str(a) for a in (ssh.get("config_listen") or [])
        ] + [
            str(listener.get("address", ""))
            for listener in (ssh.get("listeners") or [])
        ]
        still_stale = []
        uncertain = []
        ip_section = (report.get("guest") or {}).get("ip_addresses") or {}
        for addr in observed:
            cls = diagnostics.classify_bind_address(addr, ip_section)
            if cls == "stale":
                still_stale.append(addr)
            elif cls == "unknown":
                # R9-1 (delta review round 9): UNKNOWN is a third state, not
                # "not stale" — the production probe never enumerates fe80*
                # link-locals, so their presence in the readback can never
                # be certified. An unknown relevant binding prevents
                # positive certification entirely.
                uncertain.append(addr)
        detail["stale_bindings_remaining"] = still_stale
        detail["unverified_bindings"] = uncertain
        detail["config_listen"] = [str(a) for a in (ssh.get("config_listen") or [])]
        satisfied = cleared and not still_stale and not uncertain
        uncertified = bool(uncertain)
    elif action == "enable_existing_firewall_rules":
        fw = guest.get("firewall") or {}
        key = (
            "ssh22_allowed" if item["before"].get("port") == 22
            else "winrm5985_allowed"
        )
        detail[key] = fw.get(key)
        satisfied = cleared and fw.get(key) is True
    change["postcondition_detail"] = detail
    change["postcondition"] = (
        "satisfied" if satisfied else ("unknown" if uncertified else "unsatisfied")
    )
    change["verified"] = bool(change["applied"] and satisfied)
    if change.get("decision_required"):
        # C15: the not-attempted diagnostic (the operator-intent wording)
        # IS the change's story — keep it; the postcondition channel above
        # already carries the observed-state verdict.
        return
    change["verify_detail"] = (
        f"finding {finding} cleared"
        if cleared
        else f"finding {finding} still present after repair"
    )


# -- public API --------------------------------------------------------------


def repair_guest_access(
    cfg: Config,
    vm_name: str = "",
    *,
    apply: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
    vm_id: str = "",
    intended_bindings: list[str] | None = None,
) -> dict:
    """Dry-run-first narrow repair for guest access routes (AC9).

    Resolves the target ONCE (name or GUID) and threads the resolved GUID
    through every diagnostic/apply/verify leg — no follow-up leg re-resolves
    the (possibly renamed) name.

    intended_bindings is the operator intent for stale ListenAddress
    rewrites: one address applied to every stale line, or one per line.
    Absent, invalid, or ambiguous intent leaves the rewrite change
    not_attempted with a decision_required diagnostic — a replacement is
    never guessed.
    """
    if not vm_name and not vm_id:
        raise ValueError("vm_name or vm_id is required")
    if cred is None:
        raise ValueError("guest credentials are required")
    ref = vmident.resolve(cfg, vm_name=vm_name, vm_id=vm_id)
    if apply:
        policy.require_destructive(
            cfg, "guest_repair", confirm,
            f"apply guest access repairs on '{ref.name}'",
        )

    report = diagnostics.diagnose_report(cfg, ref.id, ref.name, cred, 90000)
    items = _plan_items(report, intended_bindings)

    result: dict[str, Any] = {
        "ok": True,
        "vm_name": ref.name,
        "applied": apply,
        "plan": [
            {k: v for k, v in item.items() if k != "apply_script"}
            for item in items
        ],
        "changes": [],
    }
    if not apply or not items:
        return result

    changes: list[dict[str, Any]] = []
    backup_path = ""
    for item in items:
        change: dict[str, Any] = {
            "action": item["action"],
            "target": item["target"],
            "before": item["before"],
            "applied": False,
            "apply_outcome": "not_attempted",
            "observation": "unavailable",
            "postcondition": "unknown",
            "verified": False,
            "verify_detail": "",
        }
        if item.get("decision_required"):
            change["decision_required"] = True
            change["verify_detail"] = f"not attempted: {item['change']}"
        if item.get("apply_script"):
            try:
                outcome = run_guest_inner(
                    cfg, ref.id, item["apply_script"], cred, timeout_ms=90000,
                )
                change["applied"] = True
                change["apply_outcome"] = "applied"
                change["outcome"] = outcome
                if item["action"] == "rewrite_stale_ssh_bindings":
                    backup_path = str(outcome.get("backup", ""))
            except Exception as exc:
                from . import errors  # late import: errors pulls the policy tree
                change["apply_outcome"] = "failed"
                change["error"] = pswindows.redact(str(exc))
                # Feedback PRR-004: classify so a lock expiry reports
                # "busy" (with the server envelope's holder upstream)
                # instead of an anonymous failure string.
                change["error_class"] = errors.classify(exc)
        changes.append(change)

    # Verification phase (C13): the ENTIRE phase — the re-diagnose call AND
    # the per-change evaluation — is guarded: a raising or lost observation
    # leg yields observation=unavailable + postcondition=unknown on every
    # change, and the changes are NEVER raised away.
    verify_report: dict | None = None
    verify_error = ""
    try:
        verify_report = diagnostics.diagnose_report(cfg, ref.id, ref.name, cred, 90000)
        observation = _verify_observation(verify_report)
        remaining = {f.get("id") for f in verify_report.get("findings") or []}
        for item, change in zip(items, changes, strict=True):
            _evaluate_change(item, change, verify_report, observation, remaining)
    except Exception as exc:  # noqa: BLE001 — losing the changes IS the defect
        verify_error = pswindows.redact(str(exc))
        for change in changes:
            change["observation"] = "unavailable"
            change["postcondition"] = "unknown"
            change["verified"] = False
            if not change["verify_detail"]:
                change["verify_detail"] = (
                    f"verification unavailable: {verify_error}"
                )

    if backup_path:
        result["backup_path"] = backup_path
    result["changes"] = changes
    result["verification_findings"] = (verify_report or {}).get("findings")
    if verify_error:
        result["verification_error"] = verify_error
    return result
