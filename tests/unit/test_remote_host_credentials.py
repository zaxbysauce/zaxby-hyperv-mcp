"""AC4 acceptance checks: host credentials for the remote WS-Man hop.

Contract:
  * HYPERV_HOST_USERNAME + HYPERV_HOST_PASSWORD (or HYPERV_HOST_PASSWORD_FILE)
    resolve via credentials.resolve_host(environ=...) into a CredentialSet;
    the password is registered in the redaction registry.
  * Username without any password source is a CredentialError that names all
    three environment variable names.
  * Username absent (even with password sources set) => implicit current-user
    auth: resolve_host returns None and NO error is raised at resolve time.
  * pswindows._SECRET_ENV_NAMES gains HYPERV_HOST_PASSWORD and
    HYPERV_HOST_PASSWORD_FILE so child environments strip them (the existing
    anti-drift test tests/unit/test_ps_child_env.py then auto-enforces it).
  * The host-hop script carries -Credential ONLY when host credentials are
    configured; with none, the hop uses implicit current-user auth.

No real Hyper-V or network: list_vms scripts are captured via a FakePS stub.
"""

import pytest

from hyperv_mcp import credentials, lifecycle, pswindows
from hyperv_mcp.config import Config

HOST = "nuc01"
PW = "host-hop-pw-7f3a-not-shared"


class FakePS:
    def __init__(self):
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        return pswindows.PSResult(stdout="[]", returncode=0)


def _remote_cfg() -> Config:
    return Config.from_dict({"hyperv": {"host": HOST}, "unrestricted": True})


# ---------------------------------------------------------------------------
# resolve_host behavior
# ---------------------------------------------------------------------------

def test_resolve_host_via_password_file(tmp_path):
    pw_file = tmp_path / "host-password.txt"
    pw_file.write_text(PW, encoding="utf-8")
    cs = credentials.resolve_host(environ={
        "HYPERV_HOST_USERNAME": "lab\\admin",
        "HYPERV_HOST_PASSWORD_FILE": str(pw_file),
    })
    assert cs is not None
    assert cs.username == "lab\\admin"
    assert cs.password == PW
    # Registered for redaction: a leak of the password is scrubbed.
    assert credentials.redact(f"leak: {PW}") == "leak: ***REDACTED***"


def test_resolve_host_username_only_names_all_env_vars():
    with pytest.raises(credentials.CredentialError) as excinfo:
        credentials.resolve_host(environ={"HYPERV_HOST_USERNAME": "lab\\admin"})
    message = str(excinfo.value)
    for name in (
        "HYPERV_HOST_USERNAME",
        "HYPERV_HOST_PASSWORD",
        "HYPERV_HOST_PASSWORD_FILE",
    ):
        assert name in message, f"CredentialError must name {name}: {message!r}"


def test_resolve_host_username_absent_is_implicit_auth(tmp_path):
    """Both password sources set but no username => current-user auth (None),
    not an error — the config load must not fail on dangling password vars."""
    pw_file = tmp_path / "host-password.txt"
    pw_file.write_text(PW, encoding="utf-8")
    cs = credentials.resolve_host(environ={
        "HYPERV_HOST_PASSWORD": PW,
        "HYPERV_HOST_PASSWORD_FILE": str(pw_file),
    })
    assert cs is None


# ---------------------------------------------------------------------------
# child-env secret stripping
# ---------------------------------------------------------------------------

def test_secret_env_names_cover_host_passwords():
    names = pswindows._SECRET_ENV_NAMES
    assert "HYPERV_HOST_PASSWORD" in names
    assert "HYPERV_HOST_PASSWORD_FILE" in names


# ---------------------------------------------------------------------------
# host-hop -Credential discriminator
# ---------------------------------------------------------------------------

def test_host_hop_has_no_credential_without_host_credentials(monkeypatch):
    for var in ("HYPERV_HOST_USERNAME", "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE"):
        monkeypatch.delenv(var, raising=False)
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.list_vms(_remote_cfg())
    assert fake.scripts
    assert "-Credential" not in fake.scripts[0], fake.scripts[0][:120]


def test_host_hop_carries_credential_with_host_credentials(monkeypatch, tmp_path):
    pw_file = tmp_path / "host-password.txt"
    pw_file.write_text(PW, encoding="utf-8")
    monkeypatch.setenv("HYPERV_HOST_USERNAME", "lab\\admin")
    monkeypatch.setenv("HYPERV_HOST_PASSWORD_FILE", str(pw_file))
    fake = FakePS()
    monkeypatch.setattr(pswindows, "run_ps", fake)
    lifecycle.list_vms(_remote_cfg())
    assert fake.scripts
    assert "-Credential" in fake.scripts[0]
