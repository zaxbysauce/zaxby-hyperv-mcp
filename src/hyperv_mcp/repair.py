"""Narrow guest-access repair with a dry run by default (AC9).

Step 1 reuses diagnostics.diagnose_vm_access (no copy). Step 2 maps findings
to narrow fix proposals. Only explicit apply=True with the destructive
confirm leg satisfied (category guest_repair) performs any guest mutation;
each mutation leg runs under its own vm_lock (never an outer lock across the
composite), and every applied action is re-verified by re-running the
diagnostic probes.

The fixes are deliberately narrow: rewrite stale sshd ListenAddress lines to
0.0.0.0 (with a timestamped backup of sshd_config), start stopped sshd /
WinRM services, and enable EXISTING disabled allow rules whose port filter
matches the SSH/WinRM port exactly or is port-Any — new firewall rules are
never created, but widening a disabled Any-port rule is possible and is
stated verbatim in the dry-run plan text so the operator approves it
informed.
"""

from __future__ import annotations

from typing import Any

from . import diagnostics, policy, pswindows
from .config import Config
from .credentials import CredentialSet
from .diagnostics import diagnose_vm_access, run_guest_inner

_SSHD_CFG = "C:\\ProgramData\\ssh\\sshd_config"


# -- per-action apply scripts (inner guest scripts) -------------------------


def _apply_stale_binding_script(stale: list[str]) -> str:
    stale_list = ",".join(pswindows.ps_quote(s) for s in stale)
    return f"""
$sshdCfg = '{_SSHD_CFG}'
$stale = @({stale_list})
$backup = $sshdCfg + '.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $sshdCfg -Destination $backup -Force
$lines = [System.IO.File]::ReadAllLines($sshdCfg)
$out = New-Object System.Collections.Generic.List[string]
$replaced = 0
foreach ($ln in $lines) {{
    $t = $ln.Trim()
    if ($t -match '^(?i)ListenAddress\\s+(.+)$') {{
        $addr = $Matches[1].Trim()
        if ($stale -contains $addr) {{
            $out.Add('ListenAddress 0.0.0.0')
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


def _plan_items(report: dict) -> list[dict[str, Any]]:
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
            items.append({
                "action": "rewrite_stale_ssh_bindings",
                "target": _SSHD_CFG,
                "before": {"stale_bindings": stale},
                "change": "rewrite each stale ListenAddress line to 0.0.0.0, back up the config, restart sshd",
                "finding": fid,
                "apply_script": _apply_stale_binding_script(stale) if stale else None,
                "verify_finding": "ssh_stale_binding",
            })
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


def _is_stale_address(raw: str, report: dict) -> bool:
    guest = report.get("guest") or {}
    ipv4: set[str] = set()
    for entry in (guest.get("ip_addresses") or {}).get("ipv4") or []:
        addr = entry.get("address")
        if addr:
            ipv4.add(str(addr).strip())
    host = diagnostics._addr_host(raw)
    if host.lower() in diagnostics._UNIVERSAL_ADDRESSES or host in ipv4:
        return False
    return not any(c.isalpha() for c in host)


# -- public API --------------------------------------------------------------


def repair_guest_access(
    cfg: Config,
    vm_name: str,
    *,
    apply: bool = False,
    confirm: bool = False,
    cred: CredentialSet | None = None,
) -> dict:
    """Dry-run-first narrow repair for guest access routes (AC9)."""
    if not vm_name:
        raise ValueError("vm_name is required")
    if cred is None:
        raise ValueError("guest credentials are required")
    policy.vm_allowed(cfg, vm_name)
    if apply:
        policy.require_destructive(
            cfg, "guest_repair", confirm,
            f"apply guest access repairs on '{vm_name}'",
        )

    report = diagnose_vm_access(cfg, vm_name, cred=cred)
    items = _plan_items(report)

    result: dict[str, Any] = {
        "ok": True,
        "vm_name": vm_name,
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
            "verified": False,
            "verify_detail": "",
        }
        if item.get("apply_script"):
            try:
                outcome = run_guest_inner(
                    cfg, vm_name, item["apply_script"], cred, timeout_ms=90000,
                )
                change["applied"] = True
                change["outcome"] = outcome
                if item["action"] == "rewrite_stale_ssh_bindings":
                    backup_path = str(outcome.get("backup", ""))
            except Exception as exc:
                change["error"] = pswindows.redact(str(exc))
        changes.append(change)

    verify_report = diagnose_vm_access(cfg, vm_name, cred=cred)
    remaining = {f.get("id") for f in verify_report.get("findings") or []}
    for item, change in zip(items, changes, strict=True):
        if item["verify_finding"] in remaining:
            change["verify_detail"] = f"finding {item['verify_finding']} still present after repair"
        else:
            change["verified"] = True
            change["verify_detail"] = f"finding {item['verify_finding']} cleared"

    if backup_path:
        result["backup_path"] = backup_path
    result["changes"] = changes
    result["verification_findings"] = verify_report.get("findings")
    return result
