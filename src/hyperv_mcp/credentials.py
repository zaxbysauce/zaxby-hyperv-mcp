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

import fnmatch
import os
import threading
from dataclasses import dataclass

from .config import Config, CredentialProfile


class CredentialError(RuntimeError):
    """Raised when required credentials are missing or malformed."""


@dataclass(frozen=True)
class CredentialSet:
    username: str
    password: str
    # Where this credential came from. The durable state store records this
    # reference and never the secret, so a job restored after a server restart
    # re-resolves from the SAME source it started with. A hand-built set
    # defaults to "inline" and is therefore never re-resolvable: substituting
    # a different identity would run guest legs as the wrong account.
    source: str = "inline"
    # Issue #30: which credential profile produced this set. "default" is the
    # sentinel for the single global credential (unchanged behavior); a named
    # profile records its name so the pooled-session key can separate
    # identities and a restored job/relay can pin the identity it started
    # with. Appended last so positional constructions keep their order.
    profile: str = "default"

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

    def unregister(self, secret: str) -> None:
        """Withdraw a secret from the redaction set (feedback PRR-037).

        Exists for HARNESS teardown: the soak benchmark's fake mode sets a
        fake guest password that credential resolution then registers in this
        process-global registry, and without a withdrawal the fake password
        keeps scrubbing unrelated text in every later redaction the process
        performs. Nothing in the server calls this — a withdrawn secret stops
        being scrubbed everywhere, which is precisely why un-redacting a live
        credential is not a supported operation. Withdrawing a secret that was
        never registered is a no-op, so teardown stays idempotent.
        """
        if secret and len(secret) >= 3:
            with self._lock:
                try:
                    self._secrets.remove(secret)
                except ValueError:
                    pass

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
    *,
    vm_name: str = "",
    global_only: bool = False,
) -> CredentialSet:
    """Resolve admin guest credentials for a target VM (issue #30).

    Precedence is fixed: inline arguments (only when
    ``allow_inline_credentials`` is true) -> the single credential profile
    whose ``vm_patterns`` match ``vm_name`` (case-insensitive fnmatch, the
    ``policy.vm_allowed`` semantics) -> the global ``HYPERV_GUEST_*``
    variables. Surviving inline arguments SHORT-CIRCUIT profile matching: a
    caller's per-call identity is never replaced by the VM's profile.
    ``global_only=True`` (the restore path for pre-profile rows) skips
    profile matching entirely.

    Fail-closed shapes: two or more matching profiles raise naming every
    match; a matched profile whose secret is missing or unreadable raises
    naming the profile and never falls back to the global credential.
    """
    env = dict(os.environ if environ is None else environ)
    had_inline_args = bool(username or password)
    if _config is not None and not _config.allow_inline_credentials:
        username = ""
        password = ""
    # Surviving inline arguments bypass profile matching entirely (the
    # issue's fixed precedence, pinned by C28): a per-call identity wins over
    # the VM's profile.
    if (username or password) or global_only:
        return _resolve_global_guest(env, username, password, had_inline_args)

    matches = _match_profiles(vm_name)
    if len(matches) > 1:
        raise CredentialError(
            "VM name "
            f"{vm_name!r} matches multiple credential profiles "
            f"({', '.join(p.name for p in matches)}); rename the profiles or "
            "tighten their vm_patterns so one VM maps to one identity"
        )
    if len(matches) == 1:
        profile = matches[0]
        u = profile.username
        if profile.password_file:
            p = _read_profile_password_file(profile)
            p_source = f"profile {profile.name} password_file"
        else:
            p = _env_get(env, profile.password_env)
            p_source = f"profile {profile.name} {profile.password_env}"
        if not u or not p:
            raise CredentialError(
                f"credential profile {profile.name!r} matched VM "
                f"{vm_name!r} but its secret is missing (set "
                f"{profile.password_env or profile.password_file})"
            )
        # The profile's identity replaces the global one; the source records
        # the underlying secret's KIND so legacy by-ref restore paths keep
        # working, while the durable binding rides cred_profile/cred_username.
        cred_ref = "file" if profile.password_file else "env"
        return CredentialSet(
            u, _validated_password(p, p_source), cred_ref, profile.name,
        )
    return _resolve_global_guest(env, username, password, had_inline_args)


def _match_profiles(vm_name: str) -> list[CredentialProfile]:
    """The profiles whose vm_patterns match ``vm_name`` (issue #30).

    Case-folded fnmatch — the same matching semantics as
    ``policy.vm_allowed``. A profile never GRANTS access:
    ``allowed_vm_patterns`` stays the only VM gate.
    """
    if _config is None or not vm_name:
        return []
    folded = vm_name.casefold()
    return [
        p for p in _config.credential_profiles
        if any(
            fnmatch.fnmatchcase(folded, pattern.casefold())
            for pattern in p.vm_patterns
        )
    ]


def _env_get(env: dict[str, str], name: str, default: str = "") -> str:
    """Case-tolerant env lookup for operator-chosen names (PRR-001).

    Windows materializes os.environ with upper-cased keys, so a configured
    mixed-case secret-source name can never be found by plain dict lookup
    even though the variable is set (and check-env's os.environ membership
    test reports it as set). Exact hit first, then a case-insensitive
    fallback — on case-sensitive hosts the mapping is exact, so behavior
    there is unchanged.
    """
    if name in env:
        return env[name]
    return env.get(name.upper(), default)


def _read_profile_password_file(profile: CredentialProfile) -> str:
    path = profile.password_file
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return fh.read().rstrip("\r\n")
    except OSError as exc:
        raise CredentialError(
            f"credential profile {profile.name!r} password file {path!r} "
            f"unreadable: {exc}"
        ) from None
    except UnicodeDecodeError as exc:
        # A non-UTF-8 secret file (UTF-16 is common on Windows) must surface
        # as a credential error, not a raw ValueError (PRR-010).
        raise CredentialError(
            f"credential profile {profile.name!r} password file {path!r} is "
            f"not decodable as UTF-8: {exc}"
        ) from None


def _resolve_global_guest(
    env: dict[str, str],
    username: str,
    password: str,
    had_inline_args: bool,
) -> CredentialSet:
    """The pre-#30 global resolution path, byte-identical in behavior."""
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
    # A per-call credential is not an environment one. Key on whether ANY
    # surviving inline argument was used, not just the password source: a
    # username-only override still starts the job as that username, and
    # labelling it "env" would make a restored leg re-resolve the ENVIRONMENT
    # username and silently run a different account. Recording "inline" makes
    # reattach refuse instead. (resolve_victim and resolve_host take no inline
    # arguments, so they always fall through to the env/file branches.)
    cred_ref = (
        "inline" if (username or password)
        else "file" if p_source.endswith("_FILE")
        else "env"
    )
    return CredentialSet(u, _validated_password(p, p_source), cred_ref, "default")


def resolve_victim(
    environ: dict[str, str] | None = None,
    *,
    vm_name: str = "",
    global_only: bool = False,
) -> CredentialSet:
    """Resolve unprivileged victim credentials for a target VM (issue #30).

    The matched profile's victim fields win when the single matching profile
    carries them; otherwise the global ``HYPERV_GUEST_VICTIM_*`` variables
    apply. The profile ambiguity rule is identical to ``resolve_guest`` — a
    victim leg can never silently pick one of two matching admin profiles.
    Takes no inline arguments (unchanged).
    """
    env = dict(os.environ if environ is None else environ)
    if not global_only:
        matches = _match_profiles(vm_name)
        if len(matches) > 1:
            raise CredentialError(
                "VM name "
                f"{vm_name!r} matches multiple credential profiles "
                f"({', '.join(p.name for p in matches)}); rename the profiles or "
                "tighten their vm_patterns so one VM maps to one identity"
            )
        if len(matches) == 1:
            profile = matches[0]
            if profile.victim_username:
                if profile.victim_password_file:
                    p = _read_profile_password_file_victim(profile)
                    p_source = f"profile {profile.name} victim_password_file"
                else:
                    p = _env_get(env, profile.victim_password_env)
                    p_source = f"profile {profile.name} {profile.victim_password_env}"
                if not p:
                    raise CredentialError(
                        f"credential profile {profile.name!r} matched VM "
                        f"{vm_name!r} but its victim secret is missing (set "
                        f"{profile.victim_password_env or profile.victim_password_file})"
                    )
                cred_ref = "file" if profile.victim_password_file else "env"
                return CredentialSet(
                    profile.victim_username,
                    _validated_password(p, p_source),
                    cred_ref,
                    profile.name,
                )
            # The profile governs only the admin identity; victim resolution
            # reports the global sentinel (pinned by C8).
            return _resolve_global_victim(env)
    return _resolve_global_victim(env)


def _resolve_global_victim(env: dict[str, str]) -> CredentialSet:
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
    # "inline argument" is a per-call credential, not an environment one. It
    # must record "inline" so a restored job refuses to re-attach rather than
    # silently re-resolving a DIFFERENT identity from the environment.
    cred_ref = (
        "inline" if p_source == "inline argument"
        else "file" if p_source.endswith("_FILE")
        else "env"
    )
    return CredentialSet(u, _validated_password(p, p_source), cred_ref, "default")


def _read_profile_password_file_victim(profile: CredentialProfile) -> str:
    path = profile.victim_password_file
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return fh.read().rstrip("\r\n")
    except OSError as exc:
        raise CredentialError(
            f"credential profile {profile.name!r} victim password file "
            f"{path!r} unreadable: {exc}"
        ) from None


def resolve_host(environ: dict[str, str] | None = None) -> CredentialSet | None:
    """Resolve the remote Hyper-V host credential (issue #43).

    Used for the WS-Man hop when config declares hyperv.host. Precedence and
    validation mirror resolve_guest: HYPERV_HOST_USERNAME plus
    HYPERV_HOST_PASSWORD_FILE or HYPERV_HOST_PASSWORD; line-break/<3-char
    rejection and redaction registration ride _validated_password.

    Returns None — implicit current-user authentication for the hop — when
    the username is absent, even if password sources are set (dangling
    password variables must not break startup or every tool call).
    """
    env = dict(os.environ if environ is None else environ)
    u = env.get("HYPERV_HOST_USERNAME", "")
    if not u:
        return None
    p = _read_password_file("HYPERV_HOST_PASSWORD_FILE", env)
    if p:
        p_source = "HYPERV_HOST_PASSWORD_FILE"
    else:
        p = env.get("HYPERV_HOST_PASSWORD", "")
        p_source = "HYPERV_HOST_PASSWORD"
    if not p:
        raise CredentialError(
            "Remote host credentials are incomplete. Set HYPERV_HOST_USERNAME "
            "and HYPERV_HOST_PASSWORD (or HYPERV_HOST_PASSWORD_FILE)"
        )
    # "inline argument" is a per-call credential, not an environment one. It
    # must record "inline" so a restored job refuses to re-attach rather than
    # silently re-resolving a DIFFERENT identity from the environment.
    cred_ref = (
        "inline" if p_source == "inline argument"
        else "file" if p_source.endswith("_FILE")
        else "env"
    )
    return CredentialSet(u, _validated_password(p, p_source), cred_ref)
