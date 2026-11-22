"""PR #166 review-fix pins for the two review-validated session-pool defects
(trace 157-158-durable-identity-repair-outcomes; FB-001 and FB-006).

Every fix in src/hyperv_mcp/psdsessions.py for this PR has a pin here that
FAILED against the unfixed code (RED) and passes after the fix (GREEN):

FB-001 (HIGH) — fresh-bind workers bypass named-credential rotation
  retirement. The epoch fresh-bind dance returned a worker whose pool entry
  never received the establishment credential's fingerprint, so the
  named-profile reuse guard (which short-circuits on an empty fingerprint)
  kept handing the SAME worker out after the profile's credential rotated.
  Pins:
    test_fb001_dance_entry_carries_establishment_cred_fp      (acceptance a)
    test_fb001_named_profile_rotation_retires_dance_worker    (acceptance b)
    test_fb001_create_locked_reuse_branch_retires_mismatch    (the
      _create_locked reuse branch must validate the stored fingerprint too)
    test_fb001_ordinary_acquire_path_records_and_rotates      (acceptance c)
    test_fb001_default_profile_path_unchanged                  (acceptance d)

FB-006 (HIGH) — the epoch dance is local-only; a second process hands out a
  pre-bump worker. A pool never recorded the durable epoch its worker was
  established under and ignored the epoch number on reuse/return, so after
  ANOTHER pool's dance cleared the durable dirty state, the first pool kept
  handing out (and pooling) its pre-restore worker. Pins:
    test_fb006_entry_records_durable_epoch                     (acceptance a)
    test_fb006_foreign_cleared_bump_refuses_stale_worker       (acceptance b+d)
    test_fb006_return_after_foreign_epoch_mismatch_is_closed   (the return
      half of "refuse reuse or return after an epoch mismatch")
    test_fb006_single_pool_dance_still_works                   (acceptance c)

What is faked: only the pool's worker factory (the _StubFactory pattern from
test_t157_158_schedules.py) and the store-backed epoch consults. Every store
is closed in teardown (Windows file-lock teardown hazard) and every pool is
closed via close_all.
"""

from __future__ import annotations

import pytest

from hyperv_mcp import psdsessions, statestore
from hyperv_mcp.credentials import CredentialSet

VM = "77777777-8888-9999-aaaa-bbbbccccdddd"
AGENT = "agent-fb"


@pytest.fixture()
def store(tmp_path):
    """A real temp Store backing the epoch consults (the schedules-file
    pattern); ALWAYS closed on teardown (Windows file-lock teardown hazard)."""
    s = statestore.open(str(tmp_path / "pr166-fb-store.db"))
    yield s
    s.close()


class _StubWorker:
    def __init__(self, factory) -> None:
        self._factory = factory
        self.closed = False

    def is_alive(self) -> bool:
        return not self.closed

    def close(self) -> None:
        self.closed = True
        self._factory.closed_count += 1


class _StubFactory:
    """Worker factory that records every spawn and every close."""

    def __init__(self) -> None:
        self.calls = 0
        self.closed_count = 0

    def __call__(self, key, script, stdin_b64):
        self.calls += 1
        return _StubWorker(self)


def _pool(store, factory, **kw):
    return psdsessions.SessionPool(
        factory,
        epoch_reader=store.epoch_snapshot,
        epoch_clear=store.epoch_clear_dirty,
        **kw,
    )


def _named(username: str, password: str, profile: str) -> CredentialSet:
    return CredentialSet(username, password, "inline", profile)


# ---------------------------------------------------------------------------
# FB-001 — the dance-created entry must carry the establishment fingerprint
# ---------------------------------------------------------------------------


def test_fb001_dance_entry_carries_establishment_cred_fp(store):
    """FB-001 acceptance (a): a worker created by the epoch fresh-bind dance
    gets a pool entry whose cred_fp is the fingerprint of the credential the
    dance actually established it WITH — recorded at insertion, so the
    named-profile reuse guard can never short-circuit on an empty value."""
    store.epoch_bump(VM)
    cred = _named("Administrator", "dance-pass-1", "lab-a")
    key = (VM, psdsessions.credential_profile(cred), AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        worker = pool.acquire(key, cred=cred)
        assert worker is not None
        entry = pool._entries.get(key)
        assert entry is not None, "FB-001a: the dance must insert a pool entry"
        assert entry.cred_fp == psdsessions._cred_fp(cred), (
            f"FB-001a: the dance-created entry must carry the establishment "
            f"credential's fingerprint; got {entry.cred_fp!r}"
        )
        pool.release(worker)
    finally:
        pool.close_all()


def test_fb001_named_profile_rotation_retires_dance_worker(store):
    """FB-001 acceptance (b): after a named-profile credential rotation, the
    dance-created worker is RETIRED and a new one created under the rotated
    credential — the same named profile means the same session key, so only
    the fingerprint guard can detect the rotation."""
    store.epoch_bump(VM)
    cred_one = _named("Administrator", "dance-pass-1", "lab-a")
    cred_two = _named("Administrator", "ROTATED-pass-2", "lab-a")
    assert psdsessions.credential_profile(cred_one) == \
        psdsessions.credential_profile(cred_two)
    key = (VM, psdsessions.credential_profile(cred_one), AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        first = pool.acquire(key, cred=cred_one)
        assert store.epoch_snapshot(VM)[1] == "clean", (
            "FB-001b premise: the successful dance cleared the dirty epoch"
        )
        pool.release(first)
        # wait_s > 0: the retirement happens in one loop iteration and the
        # replacement create in the next (the pre-existing acquire shape; a
        # wait_s=0 call would surface the retryable SessionBusy instead).
        second = pool.acquire(key, 5.0, cred=cred_two)
        assert second is not first, (
            "FB-001b: the worker established under the rotated-out "
            "credential was reused after the named profile's credential "
            "rotated"
        )
        assert first.closed, (
            "FB-001b: the superseded worker must be closed (retired), not "
            "left open beside its replacement"
        )
        assert factory.calls == 2, (
            f"FB-001b: exactly one replacement spawn; got {factory.calls}"
        )
        pool.release(second)
    finally:
        pool.close_all()


def test_fb001_create_locked_reuse_branch_retires_mismatch(store):
    """FB-001 (critic's required correction): _create_locked can also return
    an EXISTING idle worker (its reuse branch), so that branch must validate
    the stored fingerprint too — retire on a mismatch instead of handing the
    stale worker out."""
    cred_one = _named("Administrator", "reuse-pass-1", "lab-b")
    cred_two = _named("Administrator", "reuse-pass-2", "lab-b")
    key = (VM, psdsessions.credential_profile(cred_one), AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        first = pool.acquire(key, cred=cred_one)
        pool.release(first)
        assert pool._entries.get(key) is not None
        # Drive the reuse branch directly: the entry exists and is idle.
        # (_create_locked is called with a normalized SessionKey — acquire
        # runs _as_key before its gate path, so the private call matches it.)
        handed = pool._create_locked(psdsessions.SessionKey(*key), cred_two)
        assert handed is not first, (
            "FB-001 reuse branch: a fingerprint mismatch must not hand out "
            "the stored worker"
        )
        assert first.closed, (
            "FB-001 reuse branch: the mismatched worker must be retired"
        )
        assert factory.calls == 2
        pool.release(handed)
    finally:
        pool.close_all()


def test_fb001_ordinary_acquire_path_records_and_rotates(store):
    """FB-001 acceptance (c): the ordinary (no-dance) acquire path still
    works — the fingerprint is recorded on creation, reuse with the SAME
    credential returns the SAME worker, and a rotation retires + replaces."""
    cred_one = _named("Administrator", "plain-pass-1", "lab-c")
    cred_two = _named("Administrator", "plain-pass-2", "lab-c")
    key = (VM, psdsessions.credential_profile(cred_one), AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        first = pool.acquire(key, cred=cred_one)
        entry = pool._entries.get(key)
        assert entry is not None, "FB-001c: the create must insert an entry"
        assert entry.cred_fp == psdsessions._cred_fp(cred_one), (
            f"FB-001c: the ordinary create path must record the fingerprint; "
            f"got {entry.cred_fp!r}"
        )
        pool.release(first)
        again = pool.acquire(key, cred=cred_one)
        assert again is first, (
            "FB-001c: reuse with the same credential must return the same "
            "worker"
        )
        pool.release(again)
        # wait_s > 0 so the retirement's replacement create lands in this
        # call (see the FB-001b note on the acquire loop's iteration shape).
        rotated = pool.acquire(key, 5.0, cred=cred_two)
        assert rotated is not first and first.closed and factory.calls == 2, (
            "FB-001c: the ordinary path must retire on rotation"
        )
        pool.release(rotated)
    finally:
        pool.close_all()


def test_fb001_default_profile_path_unchanged(store):
    """FB-001 acceptance (d): the DEFAULT profile (no named profile) path is
    unchanged — same-credential reuse keeps returning the same worker, and a
    rotated password yields a DIFFERENT key component so the sessions were
    never shared in the first place."""
    cred_one = CredentialSet("Administrator", "default-pass-1")
    cred_two = CredentialSet("Administrator", "default-pass-2")
    assert psdsessions.credential_profile(cred_one) != \
        psdsessions.credential_profile(cred_two)
    key_one = (VM, psdsessions.credential_profile(cred_one), AGENT, None)
    key_two = (VM, psdsessions.credential_profile(cred_two), AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        first = pool.acquire(key_one, cred=cred_one)
        pool.release(first)
        again = pool.acquire(key_one, cred=cred_one)
        assert again is first, (
            "FB-001d: default-profile same-credential reuse must keep the "
            "identity reuse guarantee"
        )
        pool.release(again)
        second = pool.acquire(key_two, cred=cred_two)
        assert second is not first and first.closed and factory.calls == 2, (
            "FB-001d: the rotated default credential gets its own session "
            "and retires the superseded one"
        )
        pool.release(second)
    finally:
        pool.close_all()


# ---------------------------------------------------------------------------
# FB-006 — bind every worker to the durable epoch; refuse stale reuse/return
# ---------------------------------------------------------------------------


def test_fb006_entry_records_durable_epoch(store):
    """FB-006 acceptance (a): a pool entry records the durable epoch its
    worker was established under — on the ordinary create path AND on the
    dance path."""
    factory = _StubFactory()
    pool = _pool(store, factory)
    key = (VM, "guest:Administrator", AGENT, None)
    try:
        worker = pool.acquire(key)
        entry = pool._entries.get(key)
        assert entry is not None
        assert getattr(entry, "durable_epoch", None) == 0, (
            "FB-006a: the ordinary create path must bind the entry to the "
            "durable epoch it was established under (0 here)"
        )
        pool.release(worker)

        bumped = store.epoch_bump(VM)
        reworker = pool.acquire(key)  # the dance re-binds after the bump
        entry = pool._entries.get(key)
        assert entry is not None
        assert getattr(entry, "durable_epoch", None) == bumped, (
            f"FB-006a: the dance path must bind the fresh entry to the "
            f"bumped epoch {bumped}; got "
            f"{getattr(entry, 'durable_epoch', None)!r}"
        )
        pool.release(reworker)
    finally:
        pool.close_all()


def test_fb006_foreign_cleared_bump_refuses_stale_worker(store):
    """FB-006 acceptance (b)+(d): pool A caches a worker BEFORE the epoch
    bump; pool B (a second process on the SAME state database) fresh-binds
    and CLEARS the epoch; pool A must then REFUSE to hand its pre-bump worker
    out (SessionEpochDirty, the dirty/no-session refusal) — the epoch reader
    is consulted on the reuse path, so the refusal happens even though the
    durable state is now clean. The refusal is transient: the stale worker is
    retired and the next borrow opens a fresh one."""
    key_a = (VM, "guest:Administrator", AGENT, None)
    key_b = (VM, "guest:Administrator", "agent-b", None)
    reader_calls = {"n": 0}
    snapshot = store.epoch_snapshot

    def counting_reader(vm_key):
        reader_calls["n"] += 1
        return snapshot(vm_key)

    factory_a = _StubFactory()
    pool_a = psdsessions.SessionPool(
        factory_a, epoch_reader=counting_reader,
        epoch_clear=store.epoch_clear_dirty,
    )
    factory_b = _StubFactory()
    pool_b = _pool(store, factory_b)
    try:
        pre_bump = pool_a.acquire(key_a)
        assert store.epoch_snapshot(VM) == (0, "clean")
        pool_a.release(pre_bump)

        # The restore commits (durable bump) and the OTHER pool's dance
        # invalidates ITS sessions, fresh-binds and clears the epoch.
        store.epoch_bump(VM)
        rebound = pool_b.acquire(key_b)
        assert store.epoch_snapshot(VM) == (1, "clean"), (
            "FB-006b premise: the foreign dance cleared the durable state"
        )
        pool_b.release(rebound)

        before = reader_calls["n"]
        with pytest.raises(psdsessions.SessionEpochDirty):
            pool_a.acquire(key_a)
        consulted = reader_calls["n"] - before
        assert consulted == 2, (
            f"FB-006d: the reuse path must consult the epoch reader beyond "
            f"the pre-borrow snapshot read; {consulted} extra read(s)"
        )
        assert pre_bump.closed, (
            "FB-006b: the refused pre-bump worker must be retired (closed)"
        )
        fresh = pool_a.acquire(key_a)
        assert fresh is not pre_bump and factory_a.calls == 2, (
            "FB-006b: the refusal must be transient — the next borrow opens "
            "a fresh session"
        )
        pool_a.release(fresh)
    finally:
        pool_a.close_all()
        pool_b.close_all()


def test_fb006_return_after_foreign_epoch_mismatch_is_closed(store):
    """FB-006 (the return half): a session CHECKED OUT across a foreign
    bump+clear must be CLOSED at its release, not pooled — the durable state
    reads clean at the new epoch, so only the entry's recorded establishment
    epoch can detect that the guest was restored mid-use."""
    key_a = (VM, "guest:Administrator", AGENT, None)
    key_b = (VM, "guest:Administrator", "agent-b", None)
    factory_a = _StubFactory()
    pool_a = _pool(store, factory_a)
    factory_b = _StubFactory()
    pool_b = _pool(store, factory_b)
    try:
        checked_out = pool_a.acquire(key_a)
        store.epoch_bump(VM)
        foreign = pool_b.acquire(key_b)
        assert store.epoch_snapshot(VM) == (1, "clean")
        pool_b.release(foreign)

        pool_a.release(checked_out)
        assert checked_out.closed, (
            "FB-006 return: a session returning under a DIFFERENT durable "
            "epoch must be closed even when the current state is clean"
        )
        reborn = pool_a.acquire(key_a)
        assert reborn is not checked_out and factory_a.calls == 2
        pool_a.release(reborn)
    finally:
        pool_a.close_all()
        pool_b.close_all()


def test_fb006_single_pool_dance_still_works(store):
    """FB-006 acceptance (c): the single-pool fresh-bind flow still works —
    the dirty borrow dances (invalidate -> fresh bind -> clear), the dance's
    worker is handed out, and the CLEAN reuse after the dance returns the
    SAME worker (the epoch binding does not break identity reuse)."""
    key = (VM, "guest:Administrator", AGENT, None)
    factory = _StubFactory()
    pool = _pool(store, factory)
    try:
        store.epoch_bump(VM)
        danced = pool.acquire(key)
        assert store.epoch_snapshot(VM) == (1, "clean")
        pool.release(danced)
        reused = pool.acquire(key)
        assert reused is danced, (
            "FB-006c: a clean post-dance reuse must return the same worker"
        )
        assert factory.calls == 1
        pool.release(reused)
    finally:
        pool.close_all()
