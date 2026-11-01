"""Per-agent VM-lifecycle cleanup seam (issue #31 supplement AC14/AC15).

The supplement's contract: fault-profile teardown and reconciliation must
happen BEFORE VM deletion so a network impairment cannot survive removal or
affect a replacement VM. This module is the optional, tested seam:

  * a provider registry (``register_cleanup_provider``) — the real provider
    ships with issue #102; until then only synthetic providers (the tests')
    are registered,
  * ``reconcile_before_remove`` — consulted by ``media.vm_remove`` before
    any deletion work; PENDING/UNKNOWN/FAILED provider verdicts and provider
    failures refuse fail-closed, and
  * ``FixtureOwnership`` — the synthetic owner-keyed test harness proving a
    VM boundary does not isolate application fixtures (no production
    application-account registry is introduced).

Config: ``agent_isolation.cleanup_provider`` (default ``"none"`` = no
provider, the seam is a no-op). Only the literal ``"none"`` disables the
seam; an unknown configured name fails closed.
"""

from __future__ import annotations

from typing import Any

CLEAN = "clean"

#: Bound on one provider reconcile call (review F5) — see
#: reconcile_before_remove.
_RECONCILE_TIMEOUT_S = 30.0
PENDING = "pending"
UNKNOWN = "unknown"
FAILED = "failed"

_PROVIDERS: dict[str, Any] = {}


class CleanupRefusal(RuntimeError):
    """The configured cleanup provider reports unreconciled state (or
    failed) for the VM: deletion is refused fail-closed."""


class NotOwnerError(RuntimeError):
    """Fixture teardown attempted by a non-owner (the synthetic ownership
    harness rejects it before any host operation)."""


def register_cleanup_provider(name: str, provider: Any) -> None:
    """Register a cleanup provider under ``name`` (idempotent overwrite)."""
    if not name or not isinstance(name, str):
        raise ValueError("cleanup provider name must be a non-empty string")
    _PROVIDERS[name] = provider


def resolve_cleanup_provider(cfg: Any) -> Any | None:
    """The provider for ``cfg``, or None when the seam is unconfigured.

    Only the literal ``"none"`` (the default) resolves to None; an unknown
    configured name raises CleanupRefusal — fail-closed, never a silent
    disable of the safety seam.
    """
    policy = getattr(cfg, "agent_isolation", None)
    # No falsy fallback (review F6): a misconfigured empty value must fail
    # closed at the registry lookup, never silently disable the seam.
    name = str(getattr(policy, "cleanup_provider", "none"))
    if name == "none":
        return None
    provider = _PROVIDERS.get(name)
    if provider is None:
        raise CleanupRefusal(
            f"cleanup provider {name!r} is configured but not registered: "
            "refusing rather than silently disabling the cleanup seam"
        )
    return provider


def reconcile_before_remove(cfg: Any, vm_guid: str) -> None:
    """Consult the configured provider BEFORE deletion work.

    No provider configured: no-op success (the unconfigured seam never
    blocks). Otherwise the provider's ``reconcile(vm_guid)`` must return
    CLEAN; PENDING/UNKNOWN/FAILED — or a provider that itself raises —
    refuse with CleanupRefusal (fail-closed).
    """
    provider = resolve_cleanup_provider(cfg)
    if provider is None:
        return None
    import threading

    outcome: dict[str, Any] = {}

    def _call() -> None:
        outcome["status"] = provider.reconcile(vm_guid)

    # Bound the provider call (review F5): the consult runs under the VM's
    # exclusive write scope, so a hung provider must surface as a refusal,
    # never an indefinite hold. On expiry the daemon worker is left running
    # (it holds no lock of ours) and the removal refuses.
    worker = threading.Thread(target=_call, daemon=True)
    worker.start()
    worker.join(_RECONCILE_TIMEOUT_S)
    if worker.is_alive():
        raise CleanupRefusal(
            f"cleanup provider did not return within {_RECONCILE_TIMEOUT_S:.0f}s "
            f"for {vm_guid}: refusing rather than holding the VM lock"
        )
    try:
        status = outcome["status"]
    except CleanupRefusal:
        raise
    except Exception as exc:  # noqa: BLE001 - fail-closed contract conversion
        raise CleanupRefusal(
            f"cleanup provider failed for {vm_guid}: {exc}") from exc
    if status != CLEAN:
        raise CleanupRefusal(
            f"cleanup provider reports {status!r} for {vm_guid}: "
            "reconciliation must complete before deletion"
        )
    return None


def preflight_cleanup_provider(cfg: Any) -> None:
    """Validate the configured provider name BEFORE any host work.

    Resolution-only: never calls the provider's reconcile method. An
    unknown configured name raises CleanupRefusal so ``media.vm_remove`` can
    refuse before its first PowerShell leg (plan-critic round-2 finding 3).
    """
    resolve_cleanup_provider(cfg)


class FixtureOwnership:
    """Synthetic owner-keyed fixture harness (issue #31 supplement AC15).

    Ownership is keyed by (owner, fixture name) and records the VM guid the
    fixture was registered against; teardown by anyone but the recorded
    owner raises NotOwnerError before any state change, so application
    fixtures stay ownership-isolated even when two agents share one VM.
    """

    def __init__(self) -> None:
        self._fixtures: dict[tuple[str, str], str] = {}

    def register(self, owner: str, vm_guid: str, fixture: str) -> None:
        if not owner or not fixture:
            raise ValueError("owner and fixture names must be non-empty")
        self._fixtures[(owner, fixture)] = vm_guid

    def teardown(self, owner: str, fixture: str) -> None:
        key = (owner, fixture)
        if key not in self._fixtures:
            raise NotOwnerError(
                f"fixture {fixture!r} is not owned by {owner!r}: "
                "non-owner teardown is rejected before any host operation"
            )
        del self._fixtures[key]

    def vm_guid_for(self, owner: str, fixture: str) -> str | None:
        return self._fixtures.get((owner, fixture))
