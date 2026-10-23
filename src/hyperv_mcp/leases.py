"""Leases with fencing tokens, bound to the authenticated agent identity.

Issue #23 (Workstream E PR 2). A test agent's unit of work spans several tool
calls -- restore a checkpoint, start the VM, run a probe, collect output -- and
the only exclusion that existed was ``vmlocks.vm_lock``, which lives exactly as
long as ONE call and in ONE process. This module adds a durable lease whose
holder is the authenticated agent identity, whose scope names what it protects,
whose TTL is renewed by heartbeat, and whose fencing token only ever increases.

Two shapes share one table:

``kind="explicit"``
    An agent-held lease minted by ``hyperv_lease_acquire`` and carried across
    calls as ``lease_id`` + ``fencing_token``, which ride as ordinary tool
    arguments. The 2026-07-28 MCP revision removes ``Mcp-Session-Id``, so
    nothing can ride a session; a capability the model passes back is the only
    handle that survives.

``kind="call"``
    The short row ``vmlocks.vm_lock`` writes around one mutating call. That is
    what turns an in-process lock into an exclusion spanning every process
    sharing the state database.

Identity comes ONLY from the authenticated request
(``auditlog.current_agent_id`` -> the bearer token's ``client_id``). It never
comes from a tool argument: a caller must not be able to present another
agent's name.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from . import statestore
from .config import Config

# What a lease protects. `lifecycle` is exclusive against every other scope: a
# restore, stop or reset invalidates all other activity on the VM.
SCOPES = ("lifecycle", "guest_exec", "transfer", "console")
LIFECYCLE = "lifecycle"

# The internal scope carried by call rows of tools that are NOT lease-gated
# (a read tool that still takes a write lock, for example). Two such rows
# interact only through the lock-mode rule, so it cannot leak a `console` call
# row into conflict with an explicit `console` lease.
CALL_SCOPE = "call"

DEFAULT_TTL_S = 300
MAX_TTL_S = 3600


class LeaseError(RuntimeError):
    """Base for every lease refusal. Subclasses RuntimeError, so errors.classify
    must test them BEFORE its catch-all or every refusal reports "transport"."""


class LeaseUnknown(LeaseError):
    """No such lease id at all."""


class LeaseExpired(LeaseError):
    """The lease exists but its TTL has passed."""


class LeaseNotOwned(LeaseError):
    """A different agent holds it. Deliberately indistinguishable from unknown
    to a caller that cannot see the row, so a leaked id is not an existence
    oracle."""


class LeaseFenced(LeaseError):
    """The presented fencing token is not the current one: the holder was
    superseded (by expiry plus takeover) and must not proceed."""


class LeaseRequired(LeaseError):
    """A mutating call with no lease where leases.required is on."""


class LeaseConflict(LeaseError):
    """Another agent holds something incompatible on this VM.

    Carries holder, scopes and expiry -- what a blocked agent needs to decide
    whether to wait, negotiate or give up -- and deliberately carries NO lease
    id and NO fencing token. ``retry_after_ms`` is milliseconds to expiry, for
    the error envelope; it is never the fencing token.
    """

    def __init__(
        self,
        message: str,
        *,
        holder_agent: str | None,
        scopes: Iterable[str],
        expires_at: float,
        retry_after_ms: int = 0,
    ) -> None:
        super().__init__(message)
        self.holder_agent = holder_agent
        self.scopes = sorted(str(s) for s in scopes)
        self.expires_at = float(expires_at)
        self.retry_after_ms = int(retry_after_ms)


@dataclass(frozen=True)
class Lease:
    """One scope's view of a lease. Several rows share a ``lease_id``: a
    multi-scope acquire writes one row per scope, and each carries its own
    fencing token for that ``(vm_key, scope)``."""

    lease_id: str
    scope: str
    vm_id: str
    vm_name: str
    holder_agent: str | None
    fencing_token: int
    acquired_at: float
    ttl_s: int
    expires_at: float
    kind: str

    def as_dict(self, *, reveal: bool) -> dict[str, Any]:
        """Wire shape. ``lease_id``/``fencing_token`` are the capability, so they
        are present only for a lease the caller HOLDS -- absent, not null, so
        the key's presence is itself the ownership signal."""
        out: dict[str, Any] = {
            "scope": self.scope,
            "vm_id": self.vm_id,
            "holder_agent": self.holder_agent,
            "acquired_at": self.acquired_at,
            "ttl_s": self.ttl_s,
            "expires_at": self.expires_at,
            "kind": self.kind,
        }
        if reveal:
            out["lease_id"] = self.lease_id
            out["fencing_token"] = self.fencing_token
        return out


# Column order per statestore.Store._LEASE_COLUMNS.
_IDX = {
    "row_key": 0, "lease_id": 1, "vm_key": 2, "vm_name": 3, "scope": 4,
    "holder_agent": 5, "fencing_seq": 6, "acquired_at": 7, "ttl_s": 8,
    "expires_at": 9, "kind": 10, "write_lock": 11,
}


@dataclass(frozen=True)
class _Row:
    """An internal lease row. ``write_lock`` lives here and NOT on the public
    Lease: the conflict predicate has to decide call-vs-call ACROSS processes,
    which means the lock mode has to be persisted, and no caller ever reads it."""

    row_key: str
    lease_id: str
    vm_key: str
    vm_name: str
    scope: str
    holder_agent: str | None
    fencing_token: int
    acquired_at: float
    ttl_s: int
    expires_at: float
    kind: str
    write_lock: bool


def _row(values: tuple) -> _Row:
    return _Row(
        row_key=str(values[_IDX["row_key"]]),
        lease_id=str(values[_IDX["lease_id"]]),
        vm_key=str(values[_IDX["vm_key"]]),
        vm_name=str(values[_IDX["vm_name"]] or ""),
        scope=str(values[_IDX["scope"]]),
        holder_agent=values[_IDX["holder_agent"]],
        fencing_token=int(values[_IDX["fencing_seq"]]),
        acquired_at=float(values[_IDX["acquired_at"]]),
        ttl_s=int(values[_IDX["ttl_s"]]),
        expires_at=float(values[_IDX["expires_at"]]),
        kind=str(values[_IDX["kind"]]),
        write_lock=bool(values[_IDX["write_lock"]]),
    )


def _to_lease(row: _Row) -> Lease:
    return Lease(
        lease_id=row.lease_id, scope=row.scope, vm_id=row.vm_key, vm_name=row.vm_name,
        holder_agent=row.holder_agent, fencing_token=row.fencing_token,
        acquired_at=row.acquired_at, ttl_s=row.ttl_s, expires_at=row.expires_at,
        kind=row.kind,
    )


# Every id is cryptographically random. A process-local counter would be a real
# hazard here: the conflict predicate exempts rows sharing a lease_id, so two
# processes that happened to mint equal ids would exempt each other's rows and
# the cross-process exclusion would silently never fire.
def _new_id() -> str:
    return secrets.token_urlsafe(24)


def _store(cfg: Config) -> statestore.Store:
    """Resolve the store through the module attribute at CALL TIME.

    Not a `from .statestore import store_for` binding: a test that patches
    `statestore.store_for` to inject a clock must reach us, and a bound name
    would not.
    """
    return statestore.store_for(cfg)


def _ttl(cfg: Config, ttl_s: int | None) -> int:
    if ttl_s is None:
        return int(getattr(cfg.leases, "default_ttl_s", DEFAULT_TTL_S))
    value = int(ttl_s)
    if value <= 0:
        raise ValueError(f"ttl_s must be a positive number of seconds, not {value}")
    if value > int(getattr(cfg.leases, "max_ttl_s", MAX_TTL_S)):
        # ValueError -> errors.classify maps it to "invalid".
        raise ValueError(
            f"ttl_s must be at most {int(getattr(cfg.leases, 'max_ttl_s', MAX_TTL_S))} seconds"
        )
    return value


def matches_hint(row: _Row, vm_hint: str, vm_name_hint: str) -> bool:
    """Whether a stored row is about the VM the caller named.

    `conflicts()` is row-versus-row and is never handed a synthetic row, so the
    caller-side match happens first. A caller who supplied a GUID is matched on
    it; a caller who supplied only a name is matched on the name. With neither
    hint the caller has not identified a VM and every row is a candidate.
    """
    # casefold on BOTH arms (review PRR-002): vmident stores the GUID
    # lower-cased while a caller may present the canonical upper-case Hyper-V
    # form, and Hyper-V names are case-preserving.
    if vm_hint:
        return row.vm_key.casefold() == vm_hint.casefold()
    if vm_name_hint:
        return row.vm_name.casefold() == vm_name_hint.casefold()
    return True


def conflicts(a: _Row, b: _Row) -> bool:
    """Do two UNEXPIRED rows block each other? Run only over live candidates."""
    if a.vm_key != b.vm_key:
        return False
    # One tool call's rows share a lease_id, and so do a lease's scope rows.
    if a.lease_id == b.lease_id:
        return False
    # An agent never blocks ITSELF. The `is not None` guard is load-bearing:
    # two unattributed (stdio) callers are NOT "the same agent", and AC1
    # depends on them reaching the call-vs-call arm below.
    if a.holder_agent is not None and a.holder_agent == b.holder_agent:
        return False
    if a.kind == "call" and b.kind == "call":
        # Read/write lock semantics, preserved across processes: two read legs
        # still coexist. Over-approximating here breaks the concurrent
        # guestexec polls; under-approximating breaks the cross-process
        # lifecycle exclusion.
        return a.write_lock or b.write_lock
    if a.scope == LIFECYCLE or b.scope == LIFECYCLE:
        return True
    return a.scope == b.scope


def _conflict_from(rows: list[_Row], now: float) -> LeaseConflict:
    """Build the refusal a blocked agent gets. Names the holder, the scopes and
    the expiry; states NO token and NO lease id."""
    holder = next((r.holder_agent for r in rows if r.holder_agent is not None), None)
    scopes = sorted({r.scope for r in rows})
    expiry = max(r.expires_at for r in rows)
    seconds = max(0, int(round(expiry - now)))
    return LeaseConflict(
        f"lease held by agent {holder!r} on this VM (scopes: {', '.join(scopes)}); "
        f"expires in {seconds}s",
        holder_agent=holder,
        scopes=scopes,
        expires_at=expiry,
        retry_after_ms=max(0, int((expiry - now) * 1000)),
    )


def _blocking(rows: Iterable[_Row], mine: _Row) -> list[_Row]:
    return [r for r in rows if conflicts(mine, r)]


def acquire(
    cfg: Config,
    vm_key: str,
    scopes: list[str],
    agent: str | None,
    *,
    ttl_s: int | None = None,
    kind: str = statestore.LEASE_KIND_EXPLICIT,
    vm_name: str = "",
) -> list[Lease]:
    """Grant `scopes` on `vm_key` to `agent`, or raise LeaseConflict.

    One BEGIN IMMEDIATE covers the whole decision: read the live rows, test
    compatibility, bump each scope's persisted fencing counter, insert. Two
    takers therefore cannot both win.
    """
    # Dedupe preserving order (review minor D): a duplicated scope would mint
    # two rows with two tokens under one lease id, and authorize -- reading
    # covers[0] -- would fence the second token the response itself advertised.
    wanted = list(dict.fromkeys(str(s) for s in (scopes or [])))
    if not wanted:
        raise ValueError("at least one scope is required")
    unknown = [s for s in wanted if s not in SCOPES]
    if unknown:
        raise ValueError(f"unknown lease scope(s): {sorted(unknown)}")
    ttl = _ttl(cfg, ttl_s)

    store = _store(cfg)
    now = store.now()
    lease_id = _new_id()

    with store.transaction():
        live = [
            _row(v)
            for v in store.lease_candidates_by_vm(vm_key, now, agent)
            if v[_IDX["kind"]] == statestore.LEASE_KIND_EXPLICIT
        ]
        # Probe BEFORE bumping so a refusal never consumes a token.
        for scope in wanted:
            mine = _Row(
                row_key="", lease_id=lease_id, vm_key=vm_key, vm_name=vm_name,
                scope=scope, holder_agent=agent, fencing_token=0,
                acquired_at=now, ttl_s=ttl, expires_at=now + ttl,
                kind=kind, write_lock=False,
            )
            blocking = _blocking(live, mine)
            if blocking:
                raise _conflict_from(blocking, now)

        granted: list[Lease] = []
        for scope in wanted:
            token = store.fence_bump(vm_key, scope)
            row_key = _new_id()
            store.lease_insert(
                (
                    row_key, lease_id, vm_key, vm_name, scope, agent, token,
                    now, ttl, now + ttl, kind, 0,
                )
            )
            granted.append(
                Lease(
                    lease_id=lease_id, scope=scope, vm_id=vm_key, vm_name=vm_name,
                    holder_agent=agent, fencing_token=token, acquired_at=now,
                    ttl_s=ttl, expires_at=now + ttl, kind=kind,
                )
            )
    return granted


def _owned_rows(
    cfg: Config, lease_id: str, agent: str | None
) -> tuple[list[_Row], list[_Row], float]:
    """(live rows, expired rows, now) for a lease id, ownership-checked.

    Ownership is checked BEFORE expiry so a foreign caller cannot distinguish
    "expired" from "yours".
    """
    store = _store(cfg)
    now = store.now()
    live = [_row(v) for v in store.lease_rows_by_id(lease_id)
            if float(v[_IDX["expires_at"]]) > now]
    if live:
        if any(r.holder_agent != agent for r in live):
            raise LeaseNotOwned("that lease belongs to another agent")
        return live, [], now
    expired = [_row(v) for v in store.lease_expired_by_id(lease_id, now)]
    if not expired:
        raise LeaseUnknown("no such lease")
    if any(r.holder_agent != agent for r in expired):
        raise LeaseNotOwned("that lease belongs to another agent")
    return [], expired, now


def owned_rows(cfg: Config, lease_id: str, agent: str | None) -> list[_Row]:
    """The caller's OWN live rows for a lease id, for pre-checks.

    Raises ValueError (not LeaseUnknown) when the id resolves to nothing the
    caller owns, so a tool that calls this first reports "invalid" -- the
    deny-all census's contract -- instead of the existence-leaking
    "lease_unknown". The owner-scoped renew/release path still uses
    _owned_rows for its richer unknown/expired/foreign distinction.
    """
    store = _store(cfg)
    now = store.now()
    live = [_row(v) for v in store.lease_rows_by_id(lease_id)
            if float(v[_IDX["expires_at"]]) > now]
    if live and all(r.holder_agent == agent for r in live):
        return live
    raise ValueError("unknown lease")


def renew(cfg: Config, lease_id: str, agent: str | None) -> Lease:
    """Extend the lease by its OWN ttl, from now.

    The ownership/expiry read and the touch share ONE transaction (review
    PRR-009): a lease that expires -- or is taken over -- between a read and a
    later write used to be silently resurrected, producing two live leases on
    one (vm, scope). The touch carries an `expires_at > now` predicate, so a
    row that lapsed before the write is reported expired, not re-armed.
    """
    store = _store(cfg)
    with store.transaction():
        live, expired, now = _owned_rows(cfg, lease_id, agent)
        if expired:
            raise LeaseExpired("that lease has expired and cannot be renewed")
        deadline = now + int(live[0].ttl_s)
        touched = 0
        for row in live:
            touched += store.lease_touch_if_live(row.row_key, now, deadline)
        if touched == 0:
            # Every row lapsed between the read and the write.
            raise LeaseExpired("that lease has expired and cannot be renewed")
    return Lease(
        lease_id=lease_id, scope=live[0].scope, vm_id=live[0].vm_key,
        vm_name=live[0].vm_name, holder_agent=agent,
        fencing_token=live[0].fencing_token, acquired_at=live[0].acquired_at,
        ttl_s=live[0].ttl_s, expires_at=deadline, kind=live[0].kind,
    )


def release(cfg: Config, lease_id: str, agent: str | None) -> None:
    live, expired, _now = _owned_rows(cfg, lease_id, agent)
    store = _store(cfg)
    with store.transaction():
        store.lease_delete_by_id(lease_id)
    _ = (live, expired)


def list_leases(cfg: Config, vm_id: str = "", agent: str | None = None) -> list[Lease]:
    """Every LIVE lease on a VM (or on any VM when `vm_id` is empty).

    `agent=None` means "no owner filter" here. That is deliberate: this is the
    store-level view the ownership checks build on, and a filter that treated
    None as "only mine" would make an unattributed caller see an empty world
    instead of the truth.
    """
    store = _store(cfg)
    now = store.now()
    # Listing is unfiltered by owner on purpose (the plan: "holder, scopes and
    # expiry for all"); the TOOL layer reveals ids/tokens only for the caller's
    # own leases. kind="call" rows are transient per-call state, not leases,
    # so they are not listed.
    values = store.lease_rows_live(vm_id, now, None)
    return [
        _to_lease(_row(v)) for v in values
        if float(v[_IDX["expires_at"]]) > now
        and v[_IDX["kind"]] == statestore.LEASE_KIND_EXPLICIT
    ]


def authorize(
    cfg: Config,
    lease_id: str,
    fencing_token: int,
    agent: str | None,
    scope: str,
    vm_hint: str = "",
    vm_name_hint: str = "",
) -> Lease:
    """Check a presented lease before any mutating work runs.

    Resolution-free: it reads the store, never the host. The caller-side VM
    match is `matches_hint`, so a lease for one VM cannot authorize a call
    against another.
    """
    live, expired, now = _owned_rows(cfg, lease_id, agent)
    if expired:
        raise LeaseExpired("that lease has expired")
    covers = [r for r in live if r.scope == scope]
    if not covers:
        # The lease is real and the caller's own, but does not cover this
        # scope: report what it DOES cover, never its id or token.
        raise _conflict_from(live, now)
    row = covers[0]
    store = _store(cfg)
    # Supersession fencing (review PRR-007): a token older than the highest
    # EXPLICIT grant on this (vm, scope) is stale, whoever minted the newer
    # one. Per-call rows bump the same counter and must never fence a lease,
    # so only explicit grants count. Call rows carry a different token, so the
    # exact-match selection below also cannot pick one (review PRR-019).
    if int(fencing_token) < store.fence_last_explicit(row.vm_key, scope):
        raise LeaseFenced(
            "the presented fencing token for that lease is stale; it was "
            "superseded on this VM"
        )
    matching = [r for r in covers if int(r.fencing_token) == int(fencing_token)]
    if not matching:
        raise LeaseFenced(
            "the presented fencing token for that lease is stale; it was "
            "superseded on this VM"
        )
    row = matching[0]
    if not matches_hint(row, vm_hint, vm_name_hint):
        raise LeaseConflict(
            "that lease is for a different VM",
            holder_agent=row.holder_agent,
            scopes=[row.scope],
            expires_at=row.expires_at,
            retry_after_ms=max(0, int((row.expires_at - now) * 1000)),
        )
    return _to_lease(row)


def candidates_exist_by_name(cfg: Config, vm_name_hint: str, agent: str | None) -> bool:
    """Whether ANY unexpired explicit lease is reachable by this VM name.

    The guard's cheap pre-probe: false means "no resolution needed", true
    forces the one GUID resolution before the conflict decision.
    """
    store = _store(cfg)
    return bool(store.lease_candidates_by_name(vm_name_hint, store.now(), agent))


def assert_unleased(
    cfg: Config,
    agent: str | None,
    scope: str,
    vm_hint: str = "",
    vm_name_hint: str = "",
) -> None:
    """Refuse an UNLEASED call that collides with someone else's lease.

    Returns immediately when no candidate row exists -- the default state of a
    fresh deployment -- so the common path costs one bounded, index-backed
    query and no VM resolution at all.
    """
    store = _store(cfg)
    now = store.now()
    if vm_hint:
        candidates = store.lease_candidates_by_vm(vm_hint, now, agent)
    elif vm_name_hint:
        candidates = store.lease_candidates_by_name(vm_name_hint, now, agent)
    else:
        return
    rows = [_row(v) for v in candidates if matches_hint(_row(v), vm_hint, vm_name_hint)]
    if not rows:
        return
    probe = _Row(
        row_key="", lease_id="", vm_key=vm_hint or vm_name_hint, vm_name=vm_name_hint,
        scope=scope, holder_agent=agent, fencing_token=0, acquired_at=now,
        ttl_s=0, expires_at=now, kind=statestore.LEASE_KIND_CALL, write_lock=False,
    )
    blocking = _blocking(rows, probe)
    if blocking:
        raise _conflict_from(blocking, now)


# -- the per-call row ---------------------------------------------------------

_call_lease_id: ContextVar[str | None] = ContextVar("hyperv_lease_call_id", default=None)
_presented_lease: ContextVar[str] = ContextVar("hyperv_lease_presented", default="")


def presented_lease_id() -> str:
    """The lease_id the in-flight tool call presented, if any."""
    return _presented_lease.get()


def set_presented_lease(lease_id: str) -> Any:
    return _presented_lease.set(lease_id or "")


def reset_presented_lease(token: Any) -> None:
    _presented_lease.reset(token)


def call_lease_id() -> str:
    return _call_lease_id.get() or ""


def begin_call_row(
    cfg: Config,
    vm_key: str,
    scope: str,
    write_lock: bool,
    agent: str | None,
    vm_name: str = "",
    lease_id: str | None = None,
) -> tuple[str, int]:
    """Insert this vm_lock's OWN call row and return its row_key.

    ALWAYS INSERTS a fresh row. It never upserts and never reuses: nested
    vm_locks under one call share a `lease_id` but are distinct rows, so each
    one's exit path deletes only its own. Upserting on
    `(lease_id, vm_key, scope)` would collapse them AND, when the call presents
    a valid lease, would adopt -- and then delete -- the agent's own lease.
    """
    store = _store(cfg)
    now = store.now()
    shared = lease_id or _call_lease_id.get()
    if not shared:
        shared = _new_id()
        _call_lease_id.set(shared)
    row_key = _new_id()
    ttl = int(getattr(cfg.leases, "default_ttl_s", DEFAULT_TTL_S))
    # ONE BEGIN IMMEDIATE covers the conflict re-check, the counter bump and
    # the insert. A pre-flight check plus a later insert are two transactions:
    # two processes can both pass the check before either inserts (review
    # finding B -- probe-confirmed TOCTOU), and BEGIN IMMEDIATE is what makes
    # the decision and the write one serialized unit.
    mine = _Row(
        row_key="", lease_id=shared, vm_key=vm_key, vm_name=vm_name,
        scope=scope, holder_agent=agent, fencing_token=0, acquired_at=now,
        ttl_s=ttl, expires_at=now + ttl, kind=statestore.LEASE_KIND_CALL,
        write_lock=write_lock,
    )
    with store.transaction():
        live = [
            _row(v) for v in store.lease_candidates_by_vm(vm_key, now, agent)
            # The presented lease's own rows never block this call: a call row
            # adopting it shares the id (predicate arm 2 would exempt it, but
            # the candidate filter runs BEFORE any predicate).
            if v[_IDX["lease_id"]] != shared
        ]
        _raise_call_conflict(_blocking(live, mine), vm_key, now)
        token = store.fence_bump(vm_key, scope)
        store.lease_insert(
            (row_key, shared, vm_key, vm_name, scope, agent, token, now, ttl,
             now + ttl, statestore.LEASE_KIND_CALL, 1 if write_lock else 0)
        )
    # The ttl rides back to vm_lock, whose heartbeat keeps the row alive for
    # as long as the holder's call actually runs (review PRR-003).
    return row_key, ttl


def touch_call_row(cfg: Config, row_key: str, ttl_s: int) -> None:
    """Heartbeat one call row: re-arm its expiry one more ttl (review PRR-003)."""
    store = _store(cfg)
    store.lease_touch(row_key, store.now() + int(ttl_s))


def end_call_row(cfg: Config, row_key: str) -> None:
    """Delete exactly one call row."""
    _store(cfg).lease_delete_row(row_key)


def reset_call_scope() -> None:
    _call_lease_id.set(None)


def _raise_call_conflict(blocking: list[_Row], vm_key: str, now: float) -> None:
    """Turn blocking rows into the right exception class.

    Contention with another CALL row is a plain busy VM (an in-flight operation
    elsewhere); contention with an EXPLICIT lease held by someone else is a
    lease conflict. The two classes stay distinct because callers act on them
    differently.
    """
    if not blocking:
        return
    if all(r.kind == statestore.LEASE_KIND_CALL for r in blocking):
        from .vmlocks import VMBusy

        raise VMBusy(
            f"another operation is already running on VM '{vm_key}'; "
            "wait for it to finish before starting a conflicting one"
        )
    raise _conflict_from(blocking, now)


def check_call_row(
    cfg: Config, vm_key: str, scope: str, write_lock: bool, agent: str | None
) -> None:
    """Friendly PRE-flight check (nice error classes before any work).

    NOT authoritative: the authoritative check runs inside begin_call_row's
    single BEGIN IMMEDIATE, because a check here and an insert later are two
    transactions and two processes can pass both (review finding B).
    """
    store = _store(cfg)
    now = store.now()
    live = [_row(v) for v in store.lease_candidates_by_vm(vm_key, now, agent)]
    mine = _Row(
        row_key="", lease_id=_call_lease_id.get() or _presented_lease.get(), vm_key=vm_key,
        vm_name="", scope=scope, holder_agent=agent, fencing_token=0, acquired_at=now,
        ttl_s=0, expires_at=now, kind=statestore.LEASE_KIND_CALL, write_lock=write_lock,
    )
    _raise_call_conflict(_blocking(live, mine), vm_key, now)
