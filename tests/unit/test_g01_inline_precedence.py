"""Critic-round-3 acceptance check for issue #30 (per-VM credential
profiles), trace 30-per-vm-credential-profiles, driver repro/check-g01.sh.

Lives in its own file (the established pattern: critic-round checks never
move the frozen bytes of the earlier check files). One test, check id C28,
pinning fix-plan v4's final blocker:

  C28 (plan section 2, [R3-1]): inline-credential PRECEDENCE — inline
      arguments (policy-gated first) bypass profile matching entirely.
      (a) a full surviving inline pair resolves the inline identity with
          profile 'default' and source 'inline', and the password is the
          inline value, never the profile env var's (distinct canaries);
      (b) a username-only inline override still bypasses profile matching
          (profile 'default'), the password coming from the global env;
      (c) with allow_inline_credentials false the args are dropped and the
          PROFILE identity wins (username, profile name, profile secret).

Self-contained, deterministic, Hyper-V-free; placeholder secrets only,
always >= 3 characters. RED at the base tree: the `credential_profiles`
config key does not exist yet (the family signature).
"""

from hyperv_mcp import credentials
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import resolve_guest

LAB_A_PROFILE = {
    "name": "lab-a",
    "vm_patterns": ["lab-a-*"],
    "username": "LabAdminA",
    "password_env": "LAB_A_PW",
}
PROFILE_PW = "lab-a-pass-123"      # the profile secret canary
GLOBAL_PW = "global-pass-789"      # the global env secret canary
INLINE_PW = "inline-pass-456"      # the inline secret canary


def _profile_of(cred):
    """Read CredentialSet.profile without erroring at base (clean assert)."""
    return getattr(cred, "profile", "<no profile field>")


def test_inline_arguments_bypass_profile_matching():
    """C28 (plan v4 section 2 [R3-1]): with allow_inline_credentials true
    and profile lab-a matching the VM, surviving inline arguments bypass
    profile matching (profile 'default', source 'inline'); a username-only
    override bypasses it too; with the policy disabled the args are dropped
    and the profile identity wins. Every arm uses distinct secret canaries
    so a password sourced from the wrong place cannot pass."""
    inline_cfg = Config.from_dict({
        "allow_inline_credentials": True,
        "credential_profiles": [LAB_A_PROFILE],
    })
    credentials.init(inline_cfg)

    # (a) full surviving inline pair: the inline identity wins, NO profile
    # is selected, and the password is the inline value — never the value
    # of the profile's password_env (distinct canaries)
    full = resolve_guest(
        "InlineUser", INLINE_PW,
        environ={"LAB_A_PW": PROFILE_PW},
        vm_name="lab-a-01",
    )
    assert full.username == "InlineUser", (
        f"(a) full inline pair: the inline username must win; got "
        f"{full.username!r}"
    )
    assert _profile_of(full) == "default", (
        f"(a) full inline pair: no profile may be selected; got "
        f"{_profile_of(full)!r}"
    )
    assert full.source == "inline", (
        f"(a) full inline pair: source must record 'inline'; got "
        f"{full.source!r}"
    )
    assert full.password == INLINE_PW and full.password != PROFILE_PW, (
        "(a) full inline pair: the password must be the inline value, never "
        "the profile env var's"
    )

    # (b) username-only inline override: still bypasses profile matching;
    # the password falls to the global env, not the profile secret
    user_only = resolve_guest(
        "OverrideUser", "",
        environ={"HYPERV_GUEST_PASSWORD": GLOBAL_PW, "LAB_A_PW": PROFILE_PW},
        vm_name="lab-a-01",
    )
    assert user_only.username == "OverrideUser", (
        f"(b) username-only override: the inline username must win; got "
        f"{user_only.username!r}"
    )
    assert _profile_of(user_only) == "default", (
        f"(b) username-only override: no profile may be selected; got "
        f"{_profile_of(user_only)!r}"
    )
    assert user_only.password == GLOBAL_PW and user_only.password != PROFILE_PW, (
        "(b) username-only override: the password must come from the global "
        "env, never the profile env var's"
    )

    # (c) policy-disabled arm: the args are dropped, the profile identity
    # wins (username, profile name, and the profile's own secret)
    gated_cfg = Config.from_dict({
        "allow_inline_credentials": False,
        "credential_profiles": [LAB_A_PROFILE],
    })
    credentials.init(gated_cfg)
    profiled = resolve_guest(
        "InlineUser", INLINE_PW,
        environ={"LAB_A_PW": PROFILE_PW},
        vm_name="lab-a-01",
    )
    assert profiled.username == "LabAdminA", (
        f"(c) policy-disabled arm: the dropped args must let the profile "
        f"identity win; got {profiled.username!r}"
    )
    assert _profile_of(profiled) == "lab-a", (
        f"(c) policy-disabled arm: the matching profile must be selected; "
        f"got {_profile_of(profiled)!r}"
    )
    assert profiled.password == PROFILE_PW and profiled.password != INLINE_PW, (
        "(c) policy-disabled arm: the password must be the profile secret, "
        "never the dropped inline value"
    )
