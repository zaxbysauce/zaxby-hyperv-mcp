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
    replacement — the hardcoded 0.0.0.0 default is retired.

    FB-008 (PR #166 review): replacements bind to config-line OCCURRENCES,
    never to a hash keyed by the OLD address — two stale lines sharing one
    address each receive their own per-line replacement, and an
    address-keyed $map cannot even represent that (Windows PowerShell 5.1
    parse-rejects duplicate keys in a hash literal). $pairs is a list of
    single-entry hashtables consumed in order, one per matching
    occurrence."""
    pairs = "; ".join(
        f"@{{{pswindows.ps_quote(s)} = {pswindows.ps_quote(r)}}}"
        for s, r in zip(stale, intended, strict=True)
    )
    return f"""
$sshdCfg = '{_SSHD_CFG}'
$pairs = @({pairs})
$backup = $sshdCfg + '.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $sshdCfg -Destination $backup -Force
$lines = [System.IO.File]::ReadAllLines($sshdCfg)
$queues = @{{}}
foreach ($p in $pairs) {{
    foreach ($k in $p.Keys) {{
        if (-not $queues.ContainsKey($k)) {{
            $queues[$k] = New-Object System.Collections.Generic.List[string]
        }}
        $queues[$k].Add($p[$k])
    }}
}}
$out = New-Object System.Collections.Generic.List[string]
$replaced = 0
foreach ($ln in $lines) {{
    $t = $ln.Trim()
    if ($t -match '^(?i)ListenAddress\\s+(.+)$') {{
        $addr = $Matches[1].Trim()
        if ($queues.ContainsKey($addr) -and $queues[$addr].Count -gt 0) {{
            $new = $queues[$addr][0]
            $queues[$addr].RemoveAt(0)
            $out.Add('ListenAddress ' + $new)
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


# FB-002 (PR #166 review): the receipt keys each apply script's JSON emits.
# An apply leg that returns without them (a zero-exit, empty-stdout transport
# parses to {} on the non-pooled path) carries NO action evidence, and the
# apply-outcome channel must not assert application from nothing. Key
# PRESENCE alone is not enough either (wave 3): the VALUES must be usable —
# {"backup": null, "replaced": null} has every key and certifies nothing —
# while a valid zero-change receipt (replaced=0, enabled_rules=[]) is a
# receipt, not a missing one.
_APPLY_RECEIPT_KEYS: dict[str, tuple[str, ...]] = {
    "rewrite_stale_ssh_bindings": ("backup", "replaced"),
    "start_service": ("service", "status"),
    "enable_existing_firewall_rules": ("port", "enabled_rules"),
}


def _usable_text(value: object) -> bool:
    """A receipt string that carries evidence: a non-empty string."""
    return isinstance(value, str) and bool(value.strip())


def _usable_count(value: object) -> bool:
    """A receipt count: an int >= 0 — bool is an int subclass in Python, so
    True/False (a coerced null/garbage parse) is excluded explicitly."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _receipt_values_usable(action: str, outcome: dict) -> bool:
    """FB-002 (PR #166 review, wave 3): the action-specific receipt's VALUES
    must be usable, not merely present. A malformed receipt yields the same
    disclosed outcome as a missing one; a legitimate zero-change receipt
    (replaced=0, enabled_rules=[]) stays valid."""
    if action == "rewrite_stale_ssh_bindings":
        return _usable_text(outcome.get("backup")) and \
            _usable_count(outcome.get("replaced"))
    if action == "start_service":
        return _usable_text(outcome.get("service")) and \
            _usable_text(outcome.get("status"))
    if action == "enable_existing_firewall_rules":
        port = outcome.get("port")
        port_ok = _usable_text(port) or (
            isinstance(port, int) and not isinstance(port, bool)
        )
        return port_ok and isinstance(outcome.get("enabled_rules"), list)
    return True  # unmapped action: key presence (the caller's check) is the contract


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

    FB-007 (PR #166 review): a section the probe never DELIVERED is absent
    evidence, not clean evidence — a blank readback (a zero-exit, empty
    stdout probe parses to {}) must gate exactly like an errored section
    and can never certify a postcondition.
    """
    if not (report.get("ps_direct") or {}).get("available"):
        return "unavailable"
    guest = report.get("guest") or {}
    for name in ("identity", "ip_addresses", "ssh", "winrm", "firewall"):
        section = guest.get(name)
        if not isinstance(section, dict):
            return "partial"
        if section.get("error"):
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
    stale_remaining = False
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
        config_listen = ssh.get("config_listen")
        listeners = ssh.get("listeners")
        if not isinstance(config_listen, list) or not isinstance(listeners, list):
            # FB-007 (PR #166 review): the action-specific readback fields
            # must be PRESENT and usable before any certification — a
            # readback without them can neither satisfy nor refute.
            detail["readback_fields_usable"] = False
            change["postcondition_detail"] = detail
            change["postcondition"] = "unknown"
            change["verified"] = False
            if not change["verify_detail"]:
                change["verify_detail"] = (
                    "rewrite readback fields unavailable: postcondition unknown"
                )
            return
        observed = [str(a) for a in config_listen] + [
            str(listener.get("address", "")) for listener in listeners
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
        # FB-007 (PR #166 review): verify the REQUESTED replacement against
        # the OBSERVED config — a readback carrying only a DIFFERENT healthy
        # binding is definitive negative evidence for the requested rewrite,
        # not a satisfaction of it. Listener evidence is reported separately.
        requested = [str(b) for b in (item.get("intended_bindings") or [])]
        seen_config = {str(a).strip().lower() for a in config_listen}
        missing_requested = [
            b for b in requested if str(b).strip().lower() not in seen_config
        ]
        detail["stale_bindings_remaining"] = still_stale
        detail["unverified_bindings"] = uncertain
        detail["config_listen"] = [str(a) for a in config_listen]
        detail["requested_bindings"] = requested
        detail["requested_bindings_missing"] = missing_requested
        detail["listener_bindings"] = [
            str(listener.get("address", "")) for listener in listeners
        ]
        satisfied = (
            cleared and not still_stale and not uncertain and not missing_requested
        )
        uncertified = bool(uncertain)
        stale_remaining = bool(still_stale)
    elif action == "enable_existing_firewall_rules":
        fw = guest.get("firewall") or {}
        key = (
            "ssh22_allowed" if item["before"].get("port") == 22
            else "winrm5985_allowed"
        )
        detail[key] = fw.get(key)
        satisfied = cleared and fw.get(key) is True
    change["postcondition_detail"] = detail
    # R10-1 (delta review round 10): precedence — definitive evidence wins.
    # A positively observed stale binding means the postcondition is KNOWN
    # unsatisfied even when another binding is uncertifiable; 'unknown' is
    # only for the no-definite-failure-but-uncertifiable case.
    if satisfied:
        change["postcondition"] = "satisfied"
    elif stale_remaining:
        change["postcondition"] = "unsatisfied"
    elif uncertified:
        change["postcondition"] = "unknown"
    else:
        change["postcondition"] = "unsatisfied"
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
                receipt = _APPLY_RECEIPT_KEYS.get(item["action"], ())
                missing = not isinstance(outcome, dict) or any(
                    key not in outcome for key in receipt
                )
                malformed = (
                    isinstance(outcome, dict)
                    and not missing
                    and not _receipt_values_usable(item["action"], outcome)
                )
                if missing or malformed:
                    # FB-002 (PR #166 review): no USABLE action-specific
                    # receipt (missing keys, or values that carry no
                    # evidence — the wave-3 null-values case) — the effect
                    # is unconfirmed, so the apply-outcome channel reports
                    # failed instead of asserting application from an empty
                    # or malformed result. The readback below still
                    # evaluates the observed state independently; it just
                    # can never verify an unproven apply (verified derives
                    # from `applied`).
                    change["apply_outcome"] = "failed"
                    detail = (
                        f"the apply leg returned no {item['action']} receipt"
                        if missing else
                        f"the {item['action']} receipt is malformed "
                        "(its values carry no evidence)"
                    )
                    change["error"] = (
                        "apply result unavailable; effect unconfirmed: "
                        + detail
                    )
                else:
                    change["applied"] = True
                    change["apply_outcome"] = "applied"
                    if item["action"] == "rewrite_stale_ssh_bindings":
                        backup_path = str(outcome.get("backup", ""))
                if isinstance(outcome, dict):
                    change["outcome"] = outcome
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
