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

Lock-identity scope (issue #18): the GUID-keyed lock invariant below holds for
operations that resolve their target HERE, host-side. The console's folded
single-process transport resolves by-name callers INSIDE the one script it
spawns, so its console-input lock key is the caller-supplied name on that path
(the only identity available before the process); the by-id path keeps this
module's resolve leg and locks on the GUID. The residual cross-form exclusion
gap is tracked as a follow-up issue.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import guestexec, policy, pswindows
from .config import Config

_MAX_NAME_LEN = 260


@dataclass(frozen=True)
class VMRef:
    """A resolved VM identity. `id` is the lowercase CIM GUID (the lock key and
    script `$vmTarget` value) for operations that resolve through this module;
    on the console's folded by-name path (issue #18) it carries the
    caller-supplied name as the lock key because the GUID is only known after
    the single process runs. `name` is the ElementName it resolves to (policy
    target and audit display)."""

    id: str
    name: str


def _checked_caller_name(vm_name: str) -> str:
    if not vm_name or not vm_name.strip():
        raise ValueError("vm_name or vm_id is required")
    if len(vm_name) > _MAX_NAME_LEN:
        raise ValueError(f"vm_name exceeds {_MAX_NAME_LEN} characters")
    return vm_name


def checked_caller_name(vm_name: str) -> str:
    """The caller-name gate WITHOUT a spawn (issue #18).

    Exposed for callers that resolve the VM inside their own script (console's
    folded single-process transport): they cannot run resolve()'s PowerShell
    leg, but they still need its fail-fast input errors before anything starts.
    """
    return _checked_caller_name(vm_name)


def resolver_prelude(vm_name: str) -> str:
    """The PR #4 name resolver as an embedded script prelude (issue #18).

    The console's folded single-process transport resolves by-name callers
    INSIDE the one script it spawns, so the resolver EMISSION moves here — the
    resolver itself is unchanged and still lives in exactly one module (the
    pinned guardrail counts this call site, not the consumer).
    """
    return guestexec.psdirect_vm_target(vm_name)


def _run(cfg: Config, script: str):
    """vmident's PowerShell choke (issue #43): composes the remote hop from
    the CALLER's cfg before spawning, feeding run_ps the stdin the composed
    preamble reads (the host-password line in explicit-credential mode);
    identity in local mode."""
    script, stdin = pswindows.compose_remote(cfg, script)
    if stdin is None:
        return pswindows.run_ps(script, timeout_s=60)
    return pswindows.run_ps(script, timeout_s=60, stdin_b64=stdin)


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
