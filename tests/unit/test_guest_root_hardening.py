"""Frozen acceptance checks for issue #37: guest-root UNC validation must
reject share-less roots, and _makedirs_tracked must prune the directory
husks a partially failed creation leaves behind.

Token -> AC map:
  test_shareless_unc_guest_roots_rejected
      A configured guest_write_roots entry must name a full
      \\\\server\\\\share pair; the share-less \\\\server, \\\\server\\\\ and
      the extended \\\\?\\\\UNC\\\\srv\\\\share form all widen the lexical
      guest boundary and must fail Config.validate() — the same
      validation path Config.load()/from_dict() drive.
  test_wellformed_unc_guest_roots_accepted
      \\\\srv\\\\share and \\\\srv\\\\share\\\\sub stay loadable (hardening
      must not over-block well-formed roots).
  test_makedirs_tracked_failure_prunes_husks
      When the tracked makedirs fails partway through a chain, the
      directories the call created are pruned (leaf first) before the
      OSError re-raises; pre-existing directories are never removed.

Husk-scenario note: the deterministic mid-chain blocker is an INVALID
FINAL PATH COMPONENT ("leaf<blocked" — NTFS forbids "<"), which makes
os.makedirs create the head/middle prefix and then fail — exactly the
partial-failure shape issue #37 describes ("os.makedirs does not roll
back the head it already created"). A blocking FILE placed mid-chain
cannot exercise the pruning (verified: its parent directories already
exist, so makedirs creates nothing, and os.rmdir on the file raises
NotADirectoryError); the pinned assertions are the issue's own: the
OSError raises, the call-created husk is gone, and a pre-existing
directory survives.
"""

import pytest

from hyperv_mcp.config import Config, ConfigError


def test_shareless_unc_guest_roots_rejected():
    for root in ("\\\\server", "\\\\server\\", "\\\\?\\UNC\\srv\\share"):
        cfg = Config()
        cfg.guest_write_roots = [root]
        with pytest.raises(ConfigError):
            cfg.validate()


def test_wellformed_unc_guest_roots_accepted():
    for root in ("\\\\srv\\share", "\\\\srv\\share\\sub"):
        cfg = Config()
        cfg.guest_write_roots = [root]
        cfg.validate()  # must not raise ConfigError


def test_makedirs_tracked_failure_prunes_husks(tmp_path):
    from hyperv_mcp.filetransfer import _makedirs_tracked

    # The call creates head/middle, then the invalid final component fails
    # the creation: head is the husk a failed transfer must not leave.
    head = tmp_path / "head"
    target = str(head / "middle" / "leaf<blocked")
    with pytest.raises(OSError):
        _makedirs_tracked(target)
    assert not head.exists(), (
        "husk directory survived the failed makedirs: " + str(head)
    )

    # Pre-existing directories are never removed: keep predates the call,
    # so only the call-created level under it may be pruned.
    keep = tmp_path / "keep"
    keep.mkdir()
    with pytest.raises(OSError):
        _makedirs_tracked(str(keep / "middle2" / "leaf<blocked2"))
    assert keep.exists(), (
        "pre-existing directory was removed by the failure pruning: " + str(keep)
    )
    assert not head.exists(), "husk from the first scenario must stay pruned"
