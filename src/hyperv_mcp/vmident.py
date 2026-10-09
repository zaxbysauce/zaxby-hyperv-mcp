"""VM identity resolution: name or GUID -> VMRef, once, before any lock.

Every VM-addressing operation resolves its target HERE before taking the
per-VM lock, so the lock key and the acted-on VM are the same identity (the
GUID) even when callers hold different names for it, and so a by-id caller
is policy-checked against the name the GUID actually resolves to. This is
the only place `guestexec.psdirect_vm_target` (by name) and
`guestexec.psdirect_vm_target_id` (by id) run; action scripts receive the
pre-resolved GUID via `guestexec.vm_target_preamble` and never re-resolve.

Ordering contract (issue #8):
  - name given: policy on the caller-supplied name FIRST — a denied name
    spawns no PowerShell at all.
  - id given (with or without a name): the GUID is regex-validated, one
    read-only `Get-VM -Id` leg resolves the real name, and policy runs on
    that resolved name; when a name was also supplied it must match the
    resolved one, else the call is invalid.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import guestexec, policy, pswindows
from .config import Config

_MAX_NAME_LEN = 260


@dataclass(frozen=True)
class VMRef:
    """A resolved VM identity. `id` is the lowercase CIM GUID (the lock key
    and script `$vmTarget` value); `name` is the ElementName it resolves to
    (policy target and audit display)."""

    id: str
    name: str


def _checked_caller_name(vm_name: str) -> str:
    if not vm_name or not vm_name.strip():
        raise ValueError("vm_name or vm_id is required")
    if len(vm_name) > _MAX_NAME_LEN:
        raise ValueError(f"vm_name exceeds {_MAX_NAME_LEN} characters")
    return vm_name


def _run(cfg: Config, script: str):
    """vmident's PowerShell choke (issue #43): composes the remote hop from
    the CALLER's cfg before spawning; identity in local mode."""
    return pswindows.run_ps(pswindows.remote_wrap(cfg, script), timeout_s=60)


def resolve(cfg: Config, vm_name: str = "", vm_id: str = "") -> VMRef:
    """Resolve a VM reference from an optional name and/or GUID.

    Exactly one identification path must produce the VM; when both are
    given they must agree. Raises ValueError for missing/invalid input
    (surfaces as error_class "invalid") and PolicyDenied when the governing
    name (caller-supplied, or the name resolved from the GUID) is outside
    allowed_vm_patterns.
    """
    if vm_id:
        if vm_name:
            # A caller-supplied name is still caller input: deny before the
            # spawn even though the GUID alone would identify the VM.
            _checked_caller_name(vm_name)
            policy.vm_allowed(cfg, vm_name)
        # Normalize caller whitespace BEFORE validation: a copied GUID with a
        # trailing newline would validate under a loose anchor and then split
        # the vm_lock key space (review PRR-012).
        vm_id = vm_id.strip()
        guestexec.validate_vm_guid(vm_id)
        result = _run(cfg, guestexec.psdirect_vm_target_id(vm_id))
        pswindows.check_result(result, f"resolve VM id {vm_id}")
        name = result.stdout.strip()
        if not name:
            raise ValueError(f"VM id {vm_id} resolved to an empty name")
        if vm_name and name.casefold() != vm_name.casefold():
            raise ValueError("vm_name and vm_id refer to different VMs")
        if not vm_name:
            policy.vm_allowed(cfg, name)
        return VMRef(id=vm_id.lower(), name=name)

    _checked_caller_name(vm_name)
    policy.vm_allowed(cfg, vm_name)
    result = _run(cfg, guestexec.psdirect_vm_target(vm_name) + "\n$vmTarget\n")
    pswindows.check_result(result, f"resolve VM '{vm_name}'")
    guid = result.stdout.strip()
    if not guid:
        raise ValueError(f"VM '{vm_name}' resolved to an empty Id")
    # The by-name GUID is host-derived but still passes the same shape gate as
    # caller-supplied ids before it reaches any generated script or the
    # console %GUID% templating (review PRR-028).
    guestexec.validate_vm_guid(guid)
    return VMRef(id=guid.lower(), name=vm_name)
