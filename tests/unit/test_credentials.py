"""Credential resolution + redaction tests. Placeholder secrets only."""

import pytest

from hyperv_mcp import credentials
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialError, CredentialSet, resolve_guest, resolve_victim

PW = "placeholder-pass-w0rd"


@pytest.fixture(autouse=True)
def _fresh_config():
    credentials.init(Config())
    yield


def test_env_resolution():
    cs = resolve_guest(
        environ={"HYPERV_GUEST_USERNAME": "Administrator", "HYPERV_GUEST_PASSWORD": PW}
    )
    assert cs.username == "Administrator"
    assert cs.password == PW


def test_missing_creds_raise_with_guidance():
    with pytest.raises(CredentialError, match="HYPERV_GUEST_USERNAME"):
        resolve_guest(environ={})


def test_inline_args_ignored_by_default():
    """allow_inline_credentials=false: params must not bypass policy."""
    with pytest.raises(CredentialError):
        resolve_guest(username="Administrator", password=PW, environ={})


def test_inline_args_allowed_when_configured():
    credentials.init(Config(allow_inline_credentials=True))
    cs = resolve_guest(username="Administrator", password=PW, environ={})
    assert cs.password == PW


def test_password_file_provider(tmp_path):
    pf = tmp_path / "guest.pw"
    pf.write_text(PW + "\r\n", encoding="utf-8")  # trailing newline stripped
    cs = resolve_guest(
        environ={
            "HYPERV_GUEST_USERNAME": "Administrator",
            "HYPERV_GUEST_PASSWORD_FILE": str(pf),
        }
    )
    assert cs.password == PW


def test_password_file_preferred_over_env(tmp_path):
    pf = tmp_path / "guest.pw"
    pf.write_text("file-pass", encoding="utf-8")
    cs = resolve_guest(
        environ={
            "HYPERV_GUEST_USERNAME": "Administrator",
            "HYPERV_GUEST_PASSWORD": "env-pass",
            "HYPERV_GUEST_PASSWORD_FILE": str(pf),
        }
    )
    assert cs.password == "file-pass"


def test_unreadable_password_file_raises(tmp_path):
    with pytest.raises(CredentialError, match="unreadable"):
        resolve_guest(
            environ={
                "HYPERV_GUEST_USERNAME": "Administrator",
                "HYPERV_GUEST_PASSWORD_FILE": str(tmp_path / "nope.pw"),
            }
        )


def test_password_with_newline_rejected():
    with pytest.raises(CredentialError, match="line breaks"):
        resolve_guest(
            environ={"HYPERV_GUEST_USERNAME": "u", "HYPERV_GUEST_PASSWORD": "a\nb"}
        )


def test_victim_resolution_env_only():
    cs = resolve_victim(
        environ={
            "HYPERV_GUEST_VICTIM_USERNAME": "victim",
            "HYPERV_GUEST_VICTIM_PASSWORD": PW,
        }
    )
    assert cs.username == "victim"
    with pytest.raises(CredentialError, match="VICTIM"):
        resolve_victim(environ={})


def test_victim_password_file(tmp_path):
    pf = tmp_path / "victim.pw"
    pf.write_text("victim-pass", encoding="utf-8")
    cs = resolve_victim(
        environ={
            "HYPERV_GUEST_VICTIM_USERNAME": "victim",
            "HYPERV_GUEST_VICTIM_PASSWORD_FILE": str(pf),
        }
    )
    assert cs.password == "victim-pass"


def test_short_password_rejected():
    """Critic fix: sub-3-char passwords are rejected, not silently unredacted."""
    with pytest.raises(CredentialError, match="at least 3 characters"):
        resolve_guest(
            environ={"HYPERV_GUEST_USERNAME": "u", "HYPERV_GUEST_PASSWORD": "xy"}
        )


def test_credential_repr_hides_password():
    cs = CredentialSet("Administrator", PW)
    assert PW not in repr(cs)
    assert PW not in str(cs)
    assert "Administrator" in repr(cs)


def test_redaction_registry_scrubs_text():
    credentials.registry().register(PW)
    poisoned = f"error at line 1: $cred = new('{PW}') failed"
    cleaned = credentials.redact(poisoned)
    assert PW not in cleaned
    assert "***REDACTED***" in cleaned


def test_short_secrets_not_registered():
    credentials.registry().register("ab")
    assert "ab" not in credentials.registry().all()
