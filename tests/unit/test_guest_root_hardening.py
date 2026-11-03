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

from hyperv_mcp import policy
from hyperv_mcp.config import Config, ConfigError
from hyperv_mcp.policy import PolicyDenied


def test_shareless_unc_guest_roots_rejected():
    # The share-less spellings in EVERY separator form: Windows accepts
    # forward slashes, so "//srv//" is the same root as "\\srv\\" and must
    # be rejected too (implementation-review round 4: the forward-slash
    # form skipped the pair check and widened the guest boundary to every
    # share on that server).
    for root in (
        "\\\\server",
        "\\\\server\\",
        "\\\\?\\UNC\\srv\\share",
        "//server",
        "//server//",
        "//server/",
        "\\\\?\\srv\\share",
        "\\\\.\\srv\\share",
        "\\\\.\\PhysicalDrive0",
        "\\\\?\\C:relative",
        "\\\\?\\C:",
    ):
        cfg = Config()
        cfg.guest_write_roots = [root]
        with pytest.raises(ConfigError):
            cfg.validate()


def test_wellformed_unc_guest_roots_accepted():
    # The well-formed pair in the BACKSLASH spelling (unchanged behavior:
    # green before and after the fix).
    for root in ("\\\\srv\\share", "\\\\srv\\share\\sub"):
        cfg = Config()
        cfg.guest_write_roots = [root]
        cfg.validate()  # must not raise ConfigError


def test_forward_slash_wellformed_unc_guest_roots_accepted():
    # The same well-formed pair in the FORWARD-slash and mixed spellings.
    # Windows accepts both, and the pre-fix validator rejected them (its
    # splitdrive parse only understood the backslash drive), so this leg is
    # RED at base and GREEN after the normalization fix.
    for root in (
        "//srv/share",
        "//srv/share/sub",
        "\\\\srv//share",
        "//srv\\\\share",
        "//srv//share",
    ):
        cfg = Config()
        cfg.guest_write_roots = [root]
        try:
            cfg.validate()
        except ConfigError as exc:
            # A well-formed UNC root must load; the pre-fix validator rejected
            # the forward-slash spellings (base-leg signature).
            pytest.fail(f"a well-formed UNC root was rejected: {exc}")


def test_shareless_unc_root_does_not_widen_the_guest_boundary():
    """The IMPACT of the share-less form, and what actually prevents it.

    The guest boundary is LEXICAL (policy compares the normalized root as a
    prefix), so a share-less root ("//srv//") WOULD widen the scope to
    every share of that server if it were configured at all - which is
    exactly why the CONFIG layer must refuse it. This pins both halves:
    the refusal (the load-bearing guard) and the boundary behaviour of a
    well-formed root (a configured share does NOT admit another share's
    paths)."""

    cfg = Config()
    cfg.guest_write_roots = ["//srv//"]
    with pytest.raises(ConfigError):
        cfg.validate()

    # A well-formed root is scoped to ITS share.
    scoped = Config()
    scoped.guest_write_roots = ["//srv/share"]
    scoped.validate()
    with pytest.raises(PolicyDenied):
        policy.check_guest_write(scoped, "\\\\srv\\other-share\\file.txt")
    with pytest.raises(PolicyDenied):
        policy.check_guest_read(scoped, "\\\\srv\\other-share\\file.txt")


def test_parent_reference_roots_are_rejected():
    """A root ending in a parent reference ("C:\\guest\\..") is the
    drive-side twin of the #37 hole: the guest boundary is lexical, so it
    normalizes to the drive root and widens the guest scope to the whole
    drive (implementation-review)."""
    for root in ("C:\\guest\\..", "C:/guest/..", "D:\\guest\\..\\"):
        cfg = Config()
        cfg.guest_write_roots = [root]
        with pytest.raises(ConfigError):
            cfg.validate()


def test_device_namespace_roots_are_rejected():
    """The \\\\.\\ device namespace is not canonicalized by the enforcement
    layer (policy strips only \\\\?\\), so a root spelled that way loads
    and then denies everything (implementation-review)."""
    for root in ("\\\\.\\C:\\guest", "\\\\.\\PhysicalDrive0"):
        cfg = Config()
        cfg.guest_write_roots = [root]
        with pytest.raises(ConfigError):
            cfg.validate()


def test_device_root_error_message_names_the_real_prefix():
    """Copilot comment 4449030892: the guidance in the device-root error
    must show the Windows extended-path prefix ("\\\\?\\\\"), not a
    malformed "\\\\*?\\\\" - a wrong prefix in the message sends the
    operator looking for a spelling that does not exist."""
    cfg = Config()
    cfg.guest_write_roots = ["\\\\?\\UNC\\srv\\share"]
    with pytest.raises(ConfigError) as excinfo:
        cfg.validate()
    message = str(excinfo.value)
    assert "\\\\?\\" in message, f"the message does not name the prefix: {message!r}"
    assert "\\\\*?\\" not in message, (
        f"the message shows a malformed prefix: {message!r}"
    )


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
