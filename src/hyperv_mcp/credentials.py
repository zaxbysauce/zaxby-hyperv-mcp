"""Guest credential resolution and secret redaction for hyperv-mcp.

Providers, in order:
  1. Inline arguments — only accepted when config.allow_inline_credentials is
     true (tool schemas omit username/password unless that is set).
  2. HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD environment variables.
  3. HYPERV_GUEST_PASSWORD_FILE — path to a UTF-8 file holding just the
     password (preferred over the env var when both are present; the file can
     sit under an ACL-restricted profile directory).
Victim credentials use HYPERV_GUEST_VICTIM_USERNAME / _PASSWORD / _PASSWORD_FILE.

Every resolved secret is registered in the redaction registry; pswindows.run_ps
scrubs all registered secrets out of stdout/stderr/exception text before they
can reach an MCP client. Credential objects redact themselves on repr/str.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from .config import Config


class CredentialError(RuntimeError):
    """Raised when required credentials are missing or malformed."""


@dataclass(frozen=True)
class CredentialSet:
    username: str
    password: str

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<CredentialSet username={self.username!r} password=***>"

    __str__ = __repr__


class _RedactionRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: list[str] = []

    def register(self, secret: str) -> None:
        if secret and len(secret) >= 3:
            with self._lock:
                if secret not in self._secrets:
                    self._secrets.append(secret)

    def all(self) -> list[str]:
        with self._lock:
            return list(self._secrets)

    def redact(self, text: str) -> str:
        for secret in self.all():
            if secret in text:
                text = text.replace(secret, "***REDACTED***")
        return text


_registry = _RedactionRegistry()
_config: Config | None = None


def init(cfg: Config) -> None:
    """Bootstrap with the loaded config (called once from server bootstrap)."""
    global _config
    _config = cfg


def registry() -> _RedactionRegistry:
    return _registry


def redact(text: str) -> str:
    return _registry.redact(text)


def _read_password_file(path_env: str, environ: dict[str, str]) -> str:
    path = environ.get(path_env, "").strip()
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return fh.read().rstrip("\r\n")
    except OSError as exc:
        raise CredentialError(f"credential file {path_env} unreadable: {exc}") from None


def _validated_password(password: str, source: str) -> str:
    if "\r" in password or "\n" in password:
        raise CredentialError(f"{source}: password must not contain line breaks")
    if len(password) < 3:
        # Sub-3-char passwords are outside the redaction registry's safe
        # range (they would corrupt ordinary output text when scrubbed), so
        # they are rejected rather than silently leaving a redaction hole.
        raise CredentialError(
            f"{source}: password must be at least 3 characters"
        )
    _registry.register(password)
    return password


def resolve_guest(
    username: str = "",
    password: str = "",
    environ: dict[str, str] | None = None,
) -> CredentialSet:
    """Resolve admin guest credentials. Inline args only when policy allows."""
    env = dict(os.environ if environ is None else environ)
    had_inline_args = bool(username or password)
    if _config is not None and not _config.allow_inline_credentials:
        username = password = ""
    u = username or env.get("HYPERV_GUEST_USERNAME", "")
    if password:
        p, p_source = password, "inline argument"
    else:
        p = _read_password_file("HYPERV_GUEST_PASSWORD_FILE", env)
        if p:
            p_source = "HYPERV_GUEST_PASSWORD_FILE"
        else:
            p = env.get("HYPERV_GUEST_PASSWORD", "")
            p_source = "HYPERV_GUEST_PASSWORD"
    if not u or not p:
        raise CredentialError(
            "Guest credentials are required. Set HYPERV_GUEST_USERNAME and "
            "HYPERV_GUEST_PASSWORD (or HYPERV_GUEST_PASSWORD_FILE)"
            + ("; inline arguments are disabled by policy (allow_inline_credentials)"
               if had_inline_args else "")
        )
    return CredentialSet(u, _validated_password(p, p_source))


def resolve_victim(environ: dict[str, str] | None = None) -> CredentialSet:
    """Resolve unprivileged victim credentials from environment only."""
    env = dict(os.environ if environ is None else environ)
    u = env.get("HYPERV_GUEST_VICTIM_USERNAME", "")
    p = (
        _read_password_file("HYPERV_GUEST_VICTIM_PASSWORD_FILE", env)
        or env.get("HYPERV_GUEST_VICTIM_PASSWORD", "")
    )
    if not u or not p:
        raise CredentialError(
            "No victim credential configured. Set HYPERV_GUEST_VICTIM_USERNAME and "
            "HYPERV_GUEST_VICTIM_PASSWORD (or HYPERV_GUEST_VICTIM_PASSWORD_FILE) "
            "to an unprivileged guest account."
        )
    p_source = (
        "HYPERV_GUEST_VICTIM_PASSWORD_FILE"
        if env.get("HYPERV_GUEST_VICTIM_PASSWORD_FILE", "").strip() and not env.get("HYPERV_GUEST_VICTIM_PASSWORD")
        else "HYPERV_GUEST_VICTIM_PASSWORD"
    )
    return CredentialSet(u, _validated_password(p, p_source))
