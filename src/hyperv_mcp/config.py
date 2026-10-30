"""Versioned configuration and policy schema for hyperv-mcp.

Config sources, layered low to high:
  1. Built-in defaults (SECURE: every axis denied).
  2. JSON file named by HYPERV_MCP_CONFIG (optional).
  3. Environment overrides: HYPERV_MCP_UNRESTRICTED=1, HYPERV_MCP_HTTP_TOKEN, ...

A malformed config file aborts startup loudly. A missing config file is fine
(deny-all defaults) and produces a startup banner.

Schema version 1. Unknown keys are rejected so typos never silently disable
a control.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar

SCHEMA_VERSION = 1

# The remote Hyper-V host name. Strict charset (hostname / IPv4 / IPv6
# literal): the value is embedded into generated PowerShell inside a
# single-quoted literal, so quote/semicolon/space spellings are an injection
# vector — rejected at load time, ps_quote'd again at emission (defense in
# depth). Underscores included for workgroup machine names.
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9_.:-]+")

# Agent ids become audit `agent_id` values and verifier principals (issue #10).
# "local-cli" is the LEGACY shared-token principal — a configured agent must
# never collapse into it. fullmatch (not match+$) so a trailing newline can
# never smuggle a control character past the documented charset.
_AGENT_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_RESERVED_AGENT_IDS = {"local-cli"}
# Config values must BE environment variable NAMES: a token pasted here would
# otherwise be echoed to stderr by the missing-variable startup error.
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _set_agents(value: Any) -> dict[str, str]:
    """Validate the http.agents mapping (agent id -> env var NAME)."""
    if not isinstance(value, dict):
        raise ConfigError("http.agents must be an object of agent id -> env var name")
    agents: dict[str, str] = {}
    for agent_id, env_name in value.items():
        if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
            raise ConfigError(
                f"http.agents agent id {agent_id!r} must match "
                "[A-Za-z0-9_.-]{1,64}"
            )
        if agent_id in _RESERVED_AGENT_IDS:
            raise ConfigError(
                f"http.agents agent id {agent_id!r} is reserved for the legacy "
                "single-token principal"
            )
        if (
            not isinstance(env_name, str)
            or not env_name.strip()
            or not _ENV_NAME_RE.fullmatch(env_name.strip())
        ):
            raise ConfigError(
                f"http.agents[{agent_id!r}] must name a valid environment "
                "variable (a NAME like MY_AGENT_TOKEN — the token value "
                "itself never goes in config)"
            )
        agents[agent_id] = env_name.strip()
    return agents


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or is invalid."""


def default_state_db_path(environ: dict[str, str] | None = None) -> str:
    """Per-profile default location of the durable state store (issue #22).

    Resolved from the CALLER's environment rather than cached at import time,
    so a process (or a test) that repoints LOCALAPPDATA gets the path it asked
    for. ``statestore.resolve_state_db_path`` re-uses this so the precedence
    has exactly one definition.

    The terminal fallback is the platform temp dir, NEVER the CWD: a cwd
    fallback made the "default" a different store per process (each server
    resolved it against wherever it happened to be launched from), silently
    splitting the one cross-process registry the store exists to provide —
    the exact hazard the ``ps_slot_dir`` rule rejects (PRR-009).
    """
    env = dict(os.environ if environ is None else environ)
    base = (
        env.get("LOCALAPPDATA") or env.get("TEMP") or env.get("TMP")
        or tempfile.gettempdir()
    )
    return os.path.join(base, "hyperv-mcp", "state.db")


@dataclass
class DestructivePolicy:
    """Per-category switches for destructive and interactive operations."""

    stop: bool = False
    reset: bool = False
    checkpoint_restore: bool = False
    checkpoint_remove: bool = False
    kd_reboot: bool = False
    elevated_exec: bool = False
    guest_write: bool = False
    console_input: bool = False
    media: bool = False
    vm_provision: bool = False
    display: bool = False
    guest_repair: bool = False
    relay: bool = False
    # Issue #29: element-level UI actions through the in-session UIA helper
    # (invoke/set_value/focus) and helper provisioning (autologon secret +
    # scheduled task) each carry their own deny-by-default switch.
    ui_input: bool = False
    ui_provision: bool = False
    require_confirm: bool = True


@dataclass
class HttpPolicy:
    host: str = "127.0.0.1"
    port: int = 8787
    token_env: str = "HYPERV_MCP_HTTP_TOKEN"
    # Per-agent bearer tokens: agent id -> ENV VAR NAME holding that agent's
    # token (issue #10). Values are names, never token material; the token
    # values are resolved from the environment at startup only.
    agents: dict[str, str] = field(default_factory=dict)


@dataclass
class HyperVTarget:
    """Hyper-V host targeting (issue #43). host=None means the local host —
    the only mode before this section existed; every generated script stays
    byte-identical in that case."""
    host: str | None = None


@dataclass
class LeasePolicy:
    """Lease coordination (issue #23).

    `required` defaults to False so a standalone stdio server is unaffected;
    http_entry turns it on for the shared controller, where several agents
    share one process. TTLs are seconds: a lease expires that long after its
    last heartbeat, and `max_ttl_s` bounds what a caller may ask for."""

    required: bool = False
    default_ttl_s: int = 300
    max_ttl_s: int = 3600


@dataclass
class OperationsPolicy:
    """Durable operation handles (issue #24).

    Every knob bounds a store-growth or admission axis so a misconfigured
    deployment fails at startup rather than on the first detached call.
    `key_env` names an env var carrying an operator-supplied fingerprint key;
    when unset or empty the key is minted transactionally into the store's
    meta table. The key material itself is never logged."""

    enabled: bool = True
    retention_s: int = 86400
    idempotency_ttl_s: int = 86400
    heartbeat_ttl_s: int = 60
    runner_bound: int = 0
    event_retention_s: int = 7 * 86400
    event_max_rows: int = 10000
    key_env: str = ""


@dataclass(frozen=True)
class CredentialProfile:
    """One named per-VM admin (and optional victim) identity (issue #30).

    ``vm_patterns`` are matched case-insensitively against the target VM's
    canonical name with the same fnmatch semantics as
    ``policy.vm_allowed``. The secret never lives in the config: it comes
    from ``password_env`` (an environment variable NAME) or ``password_file``
    (a path read at resolve time). The optional victim fields follow the
    same rules for the unprivileged (Medium-IL) account.
    """

    name: str
    vm_patterns: tuple[str, ...]
    username: str
    password_env: str = ""
    password_file: str = ""
    victim_username: str = ""
    victim_password_env: str = ""
    victim_password_file: str = ""


@dataclass
class Config:
    allowed_vm_patterns: list[str] = field(default_factory=list)
    host_read_roots: list[str] = field(default_factory=list)
    host_write_roots: list[str] = field(default_factory=list)
    guest_read_roots: list[str] = field(default_factory=list)
    guest_write_roots: list[str] = field(default_factory=list)
    destructive: DestructivePolicy = field(default_factory=DestructivePolicy)
    allow_inline_credentials: bool = False
    unrestricted: bool = False
    audit_log_path: str | None = None
    max_output_bytes: int = 1024 * 1024
    host_powershell_path: str | None = None
    verify_sha256: bool = False
    ps_timeout_s: int = 120
    http: HttpPolicy = field(default_factory=HttpPolicy)
    # Appended AFTER the pre-existing fields (not before http) so positional
    # constructions of the pre-0.5 dataclass keep their argument order.
    hyperv: HyperVTarget = field(default_factory=HyperVTarget)
    # Provenance set by load() only (deliberately NOT in _FIELD_MAP, so a JSON
    # config can never set them and unknown-key rejection stays intact):
    # config_path is the effective HYPERV_MCP_CONFIG path, config_sha256 is
    # SHA-256 over the raw stored bytes (BOM included; sha256(b"") when no
    # file was read).
    config_path: str = ""
    config_sha256: str = hashlib.sha256(b"").hexdigest()
    # Issue #14 (ENH-02): bounded per-VM lock wait. 0 restores the pre-#14
    # fail-fast. Appended last so every pre-existing positional construction
    # keeps its argument order.
    vm_lock_wait_s: int = 30
    # Issue #15 (FND-13): host-wide PowerShell slot pool. max_host_powershell
    # bounds the number of concurrent host powershell.exe children across ALL
    # server processes on the host (slot lock files under ps_slot_dir);
    # host_powershell_wait_s bounds how long an oversubscribed caller waits
    # before failing with PowerShellBusy (0 = fail immediately). Appended
    # last for the same positional-compat reason.
    max_host_powershell: int = 8
    host_powershell_wait_s: float = 60.0
    ps_slot_dir: str | None = None
    # Issue #21 (ENH-05): reuse PowerShell Direct sessions across calls. On by
    # default; a lab turns it off for a fresh-session comparison run (the soak
    # harness's --session-reuse off leg). Appended last for the same
    # positional-compat reason as the fields above.
    psdirect_session_reuse: bool = True
    # Issue #22 (ENH-06): where the durable state store lives. None means "not
    # configured"; load() resolves it to the environment override, this key, or
    # the per-profile default, and statestore.resolve_state_db_path re-resolves a
    # blank at call time so a directly-constructed Config() still gets a path.
    # Appended last so every pre-existing positional construction keeps its
    # argument order.
    state_db_path: str | None = None
    # Issue #23: lease coordination. `required` stays False by default so a
    # standalone stdio server is unaffected; http_entry turns it on for the
    # shared controller, where several agents share one process. Appended last
    # for the same positional-compat reason as the fields above.
    leases: LeasePolicy = field(default_factory=LeasePolicy)
    # Issue #24: durable operation handles (op rows, events, idempotency).
    # Appended last for the same positional-compat reason as the fields above.
    operations: OperationsPolicy = field(default_factory=OperationsPolicy)
    # Issue #30 (FND-21/ENH-17): named per-VM credential profiles. Tuple so
    # the declared order is preserved and the config stays immutable in
    # spirit; empty means "one global credential" — behavior byte-identical
    # to the pre-profile server. Appended last for the same positional-compat
    # reason as the fields above.
    credential_profiles: tuple[CredentialProfile, ...] = ()

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> Config:
        env = dict(os.environ if environ is None else environ)
        data: dict[str, Any] = {}
        config_path = env.get("HYPERV_MCP_CONFIG", "").strip()
        raw: bytes | None = None
        if config_path:
            try:
                with open(config_path, "rb") as fh:
                    raw = fh.read()
            except FileNotFoundError:
                # Missing file = run on deny-all defaults (banner explains it).
                raw = None
            except OSError as exc:
                raise ConfigError(
                    f"HYPERV_MCP_CONFIG points to an unreadable file ({config_path}): {exc}"
                ) from None
            if raw is not None:
                try:
                    data = json.loads(raw.decode("utf-8-sig"))
                except json.JSONDecodeError as exc:
                    raise ConfigError(
                        f"HYPERV_MCP_CONFIG file is not valid JSON ({config_path}): {exc}"
                    ) from None
            if not isinstance(data, dict):
                raise ConfigError("HYPERV_MCP_CONFIG must contain a JSON object")

        cfg = cls.from_dict(data)
        if env.get("HYPERV_MCP_UNRESTRICTED", "") in ("1", "true", "yes"):
            cfg = replace(cfg, unrestricted=True)
        if env.get("HYPERV_MCP_LEASES_REQUIRED", "") in ("1", "true", "yes"):
            # Issue #23: operator override for lease-required mode. The shared
            # controller turns it on unconditionally (http_entry); this env var
            # forces it ON for a standalone server too. It never forces it OFF
            # for the controller -- set leases.required=false in the config for
            # that.
            cfg = replace(cfg, leases=replace(cfg.leases, required=True))
        # Issue #22: HYPERV_MCP_STATE_DB overrides the config-file key, exactly
        # as HYPERV_MCP_UNRESTRICTED overrides `unrestricted`; with neither, the
        # per-profile default applies. The store is always on — there is no
        # process-local mode.
        state_db = (env.get("HYPERV_MCP_STATE_DB") or "").strip()
        if state_db:
            cfg = replace(cfg, state_db_path=state_db)
        elif not (cfg.state_db_path or "").strip():
            cfg = replace(cfg, state_db_path=default_state_db_path(env))
        cfg = replace(
            cfg,
            config_path=config_path,
            config_sha256=hashlib.sha256(raw if raw is not None else b"").hexdigest(),
        )
        cfg.validate()
        return cfg

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        unknown = set(data) - set(cls._FIELD_MAP) - {"schema_version"}
        if unknown:
            raise ConfigError(f"unknown config key(s): {sorted(unknown)}")
        if "schema_version" in data and data["schema_version"] != SCHEMA_VERSION:
            raise ConfigError(
                f"unsupported config schema_version {data['schema_version']!r} "
                f"(expected {SCHEMA_VERSION})"
            )
        cfg = cls()
        for key, value in data.items():
            if key == "schema_version":
                continue
            cls._FIELD_MAP[key](cfg, value)
        cfg.validate()
        return cfg

    # -- validation ------------------------------------------------------

    def validate(self) -> None:
        if self.max_output_bytes < 1024:
            raise ConfigError("max_output_bytes must be >= 1024")
        if self.ps_timeout_s < 5:
            raise ConfigError("ps_timeout_s must be >= 5")
        if not isinstance(self.vm_lock_wait_s, int) or isinstance(self.vm_lock_wait_s, bool):
            raise ConfigError("vm_lock_wait_s must be an integer in 0..600")
        if not 0 <= self.vm_lock_wait_s <= 600:
            raise ConfigError("vm_lock_wait_s must be an integer in 0..600")
        if not isinstance(self.max_host_powershell, int) or isinstance(self.max_host_powershell, bool):
            raise ConfigError("max_host_powershell must be an integer in 1..64")
        if not 1 <= self.max_host_powershell <= 64:
            raise ConfigError("max_host_powershell must be an integer in 1..64")
        if not isinstance(self.host_powershell_wait_s, (int, float)) or isinstance(
            self.host_powershell_wait_s, bool
        ):
            raise ConfigError("host_powershell_wait_s must be a number in 0..600")
        if not 0 <= self.host_powershell_wait_s <= 600:
            raise ConfigError("host_powershell_wait_s must be a number in 0..600")
        if self.ps_slot_dir is not None:
            if not self.ps_slot_dir.strip():
                raise ConfigError("ps_slot_dir must be a non-empty path or null")
            # A relative slot dir resolves against each process's CWD, which
            # silently splits the host-wide pool (the cap stops being
            # host-wide). Reject it at load time.
            if not Path(self.ps_slot_dir).is_absolute():
                raise ConfigError("ps_slot_dir must be an absolute path or null")
        if self.state_db_path is not None:
            if not self.state_db_path.strip():
                raise ConfigError("state_db_path must be a non-empty path or null")
            # Same reasoning as ps_slot_dir (PRR-009): a relative store path
            # resolves against each process's CWD, so separate server
            # processes would each open their OWN store and silently lose the
            # cross-process registry the store exists to provide. Reject it
            # at load time — the simplest rule that still proves the value
            # can name an openable location: non-blank and absolute.
            if not Path(self.state_db_path).is_absolute():
                raise ConfigError("state_db_path must be an absolute path or null")
        # child_env() strips the token_env-named variable from every spawned
        # child; naming a functional variable would break that child (bare-name
        # resolution, PowerShell internals), so reject it at load time.
        reserved_functional_env = {
            "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
            "PATHEXT", "PSMODULEPATH", "PROGRAMFILES",
        }
        token_env = self.http.token_env.strip().upper()
        if token_env in reserved_functional_env:
            raise ConfigError(
                f"http.token_env must not shadow the functional environment "
                f"variable {token_env}"
            )
        for agent_id, env_name in self.http.agents.items():
            agent_env = env_name.strip().upper()
            if agent_env in reserved_functional_env:
                raise ConfigError(
                    f"http.agents[{agent_id!r}] must not shadow the functional "
                    f"environment variable {agent_env}"
                )
        for key in ("host_read_roots", "host_write_roots", "guest_read_roots", "guest_write_roots"):
            for root in getattr(self, key):
                if not isinstance(root, str) or not root.strip():
                    raise ConfigError(f"{key} entries must be non-empty strings")
                if key.startswith("guest_"):
                    self._require_absolute_guest_root(key, root)
        for pattern in self.allowed_vm_patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ConfigError("allowed_vm_patterns entries must be non-empty strings")

    @staticmethod
    def _require_absolute_guest_root(key: str, root: str) -> None:
        """Guest roots must be absolute Windows paths: drive+root or UNC.

        Guest policy is purely lexical — the host never resolves guest
        filesystem state — so a relative or drive-relative spelling
        ("\\g-write", "C:sub") would anchor the boundary to a guest cwd the
        host cannot see. Reject it loudly at load time instead.
        """
        drive, rest = ntpath.splitdrive(root)
        if not drive:
            raise ConfigError(f"{key} entries must be absolute Windows paths: {root!r}")
        if drive.startswith("\\\\"):  # UNC: \\server\share
            return
        if rest[:1] not in ("\\", "/"):
            raise ConfigError(f"{key} entries must be absolute Windows paths: {root!r}")

    # -- introspection ---------------------------------------------------

    def configured_axes(self) -> list[str]:
        """Axes with a configured allowlist (deny-by-default outside it).

        Naming note: configured is NOT the same as fully open — a configured
        axis still denies everything outside its allowlist. Fully open means
        `unrestricted` (or a literal "*" pattern / drive-root entry the
        operator chose). Used for the startup INFO line, not warnings.
        """
        axes: list[str] = []
        if self.unrestricted:
            axes.extend(["vm", "host_read", "host_write", "guest_read", "guest_write"])
            return axes
        if self.allowed_vm_patterns:
            axes.append("vm")
        if self.host_read_roots:
            axes.append("host_read")
        if self.host_write_roots:
            axes.append("host_write")
        if self.guest_read_roots:
            axes.append("guest_read")
        if self.guest_write_roots:
            axes.append("guest_write")
        return axes

    def policy_summary(self) -> str:
        mode = "UNRESTRICTED (explicit opt-in)" if self.unrestricted else "restrictive"
        lines = [
            f"mode={mode}",
            f"allowed_vm_patterns={self.allowed_vm_patterns or '[] (DENY ALL)'}",
            f"host_read_roots={self.host_read_roots or '[] (DENY ALL)'}",
            f"host_write_roots={self.host_write_roots or '[] (DENY ALL)'}",
            f"guest_read_roots={self.guest_read_roots or '[] (DENY ALL)'}",
            f"guest_write_roots={self.guest_write_roots or '[] (DENY ALL)'}",
            f"destructive={self.destructive}",
            f"allow_inline_credentials={self.allow_inline_credentials}",
            f"audit_log_path={self.audit_log_path or '(stderr)'}",
            f"max_host_powershell={self.max_host_powershell}",
            f"host_powershell_wait_s={self.host_powershell_wait_s:g}",
            f"ps_slot_dir={self.ps_slot_dir or '(derived default)'}",
            f"psdirect_session_reuse={self.psdirect_session_reuse}",
            f"state_db_path={self.state_db_path or '(derived default)'}",
            # Issue #23 (review PRR-017): the lease posture is an enforcement
            # axis -- operators must see it in the startup banner and
            # --check-env without opening the config file.
            f"leases.required={self.leases.required}",
            f"leases.default_ttl_s={self.leases.default_ttl_s}",
            f"leases.max_ttl_s={self.leases.max_ttl_s}",
            # Issue #24: the durable-operations posture is an enforcement
            # axis too. The fingerprint key material (key_env name aside) is
            # deliberately never surfaced here.
            f"operations.enabled={self.operations.enabled}",
            f"operations.retention_s={self.operations.retention_s}",
            f"operations.idempotency_ttl_s={self.operations.idempotency_ttl_s}",
            f"operations.heartbeat_ttl_s={self.operations.heartbeat_ttl_s}",
            f"operations.runner_bound={self.operations.runner_bound or self.max_host_powershell}",
            f"operations.event_retention_s={self.operations.event_retention_s}",
            f"operations.event_max_rows={self.operations.event_max_rows}",
            # Issue #30: profile posture is an operator axis too — names,
            # patterns and secret SOURCES are surfaced; secret values never.
            f"credential_profiles={[p.name for p in self.credential_profiles] or '[] (single global credential)'}",
        ]
        return "; ".join(lines)

    # -- field setters (keeps from_dict declarative) ----------------------

    _FIELD_MAP: ClassVar[dict]

    def _set_str_list(self, key: str, value: Any) -> None:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{key} must be a list of strings")
        object.__setattr__(self, key, value)

    def _set_bool(self, key: str, value: Any) -> None:
        if not isinstance(value, bool):
            raise ConfigError(f"{key} must be a boolean")
        object.__setattr__(self, key, value)

    def _set_int(self, key: str, value: Any) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConfigError(f"{key} must be an integer")
        object.__setattr__(self, key, value)

    def _set_number(self, key: str, value: Any) -> None:
        # int OR float (bool rejected): the PowerShell pool wait is a float
        # in nature but commonly configured as a whole number of seconds.
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f"{key} must be a number")
        object.__setattr__(self, key, float(value))

    def _set_str_opt(self, key: str, value: Any) -> None:
        if value is not None and not isinstance(value, str):
            raise ConfigError(f"{key} must be a string or null")
        object.__setattr__(self, key, value)

    def _set_destructive(self, value: Any) -> None:
        if not isinstance(value, dict):
            raise ConfigError("destructive must be an object")
        unknown = set(value) - set(DestructivePolicy.__dataclass_fields__)
        if unknown:
            raise ConfigError(f"unknown destructive key(s): {sorted(unknown)}")
        kwargs = {}
        for key, val in value.items():
            if not isinstance(val, bool):
                raise ConfigError(f"destructive.{key} must be a boolean")
            kwargs[key] = val
        object.__setattr__(self, "destructive", DestructivePolicy(**kwargs))

    def _set_http(self, value: Any) -> None:
        if not isinstance(value, dict):
            raise ConfigError("http must be an object")
        unknown = set(value) - {"host", "port", "token_env", "agents"}
        if unknown:
            raise ConfigError(f"unknown http key(s): {sorted(unknown)}")
        http = HttpPolicy()
        for key, val in value.items():
            if key == "port":
                if not isinstance(val, int) or isinstance(val, bool) or not (1 <= val <= 65535):
                    raise ConfigError("http.port must be an integer in 1..65535")
                http.port = val
            elif key == "agents":
                http.agents = _set_agents(val)
            elif isinstance(val, str) and val.strip():
                # token_env is matched by exact (case-insensitive) name
                # downstream; store it trimmed so padding cannot defeat the
                # match and the secret variable survives into children.
                trimmed = val.strip() if key == "token_env" else val
                if key == "token_env" and not _ENV_NAME_RE.fullmatch(trimmed):
                    # Same contract as http.agents values: config carries
                    # environment-variable NAMES only, so a value pasted
                    # here can never be echoed by the missing-var error
                    # paths (PRR-016).
                    raise ConfigError(
                        "http.token_env must be a valid environment "
                        "variable name (values are never printed — an "
                        "operator-pasted token must be removed from the "
                        "config)"
                    )
                setattr(http, key, trimmed)
            else:
                raise ConfigError(f"http.{key} must be a non-empty string")
        object.__setattr__(self, "http", http)

    def _set_hyperv(self, value: Any) -> None:
        """Validate the optional hyperv section (issue #43).

        host is the remote Hyper-V host name; it is embedded into generated
        PowerShell, so the charset is strict and empty/whitespace/malformed
        values fail loudly at load time (wording pinned by acceptance C1).
        """
        if not isinstance(value, dict):
            raise ConfigError("hyperv must be an object")
        unknown = set(value) - {"host"}
        if unknown:
            raise ConfigError(
                f"unknown hyperv key(s): {sorted(unknown)} — "
                f"offending key: {sorted(unknown)[0]}"
            )
        host = value.get("host")
        if not isinstance(host, str) or not host.strip():
            raise ConfigError("hyperv.host must be a non-empty string")
        if not _HOSTNAME_RE.fullmatch(host):
            raise ConfigError(
                "hyperv.host must be a hostname or IP literal "
                f"(letters, digits, '.', '-', '_', ':') — got: {host!r}"
            )
        object.__setattr__(self, "hyperv", HyperVTarget(host=host))

    def _set_leases(self, value: Any) -> None:
        """Validate the optional leases section (issue #23).

        TTLs are bounded at load time rather than at acquire time so a bad
        config fails at startup instead of on the first mutating call.
        """
        if not isinstance(value, dict):
            raise ConfigError("leases must be an object")
        unknown = set(value) - {"required", "default_ttl_s", "max_ttl_s"}
        if unknown:
            raise ConfigError(
                f"unknown leases key(s): {sorted(unknown)} — "
                f"offending key: {sorted(unknown)[0]}"
            )
        leases = LeasePolicy()
        if "required" in value:
            self._set_bool_on(leases, "required", value["required"])
        if "default_ttl_s" in value:
            self._set_int_on(leases, "default_ttl_s", value["default_ttl_s"], 1, 86400)
        if "max_ttl_s" in value:
            self._set_int_on(leases, "max_ttl_s", value["max_ttl_s"], 1, 86400)
        if leases.default_ttl_s > leases.max_ttl_s:
            raise ConfigError(
                f"leases.default_ttl_s ({leases.default_ttl_s}) must not exceed "
                f"leases.max_ttl_s ({leases.max_ttl_s})"
            )
        object.__setattr__(self, "leases", leases)

    @staticmethod
    def _set_bool_on(target: Any, name: str, value: Any) -> None:
        if not isinstance(value, bool):
            raise ConfigError(f"leases.{name} must be a boolean")
        object.__setattr__(target, name, value)

    @staticmethod
    def _set_int_on(target: Any, name: str, value: Any, low: int, high: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"leases.{name} must be an integer")
        if not low <= value <= high:
            raise ConfigError(f"leases.{name} must be between {low} and {high}")
        object.__setattr__(target, name, value)

    def _set_operations(self, value: Any) -> None:
        """Validate the optional operations section (issue #24).

        Same startup-fail shape as _set_leases: every bound is checked at
        load time so a bad deployment never reaches the first detached call.
        """
        if not isinstance(value, dict):
            raise ConfigError("operations must be an object")
        unknown = set(value) - {
            "enabled", "retention_s", "idempotency_ttl_s", "heartbeat_ttl_s",
            "runner_bound", "event_retention_s", "event_max_rows", "key_env",
        }
        if unknown:
            raise ConfigError(
                f"unknown operations key(s): {sorted(unknown)} — "
                f"offending key: {sorted(unknown)[0]}"
            )
        ops = OperationsPolicy()
        if "enabled" in value:
            self._set_ops_bool_on(ops, "enabled", value["enabled"])
        if "retention_s" in value:
            self._set_ops_int_on(ops, "retention_s", value["retention_s"], 60, 30 * 86400)
        if "idempotency_ttl_s" in value:
            self._set_ops_int_on(ops, "idempotency_ttl_s", value["idempotency_ttl_s"], 60, 30 * 86400)
        if "heartbeat_ttl_s" in value:
            self._set_ops_int_on(ops, "heartbeat_ttl_s", value["heartbeat_ttl_s"], 5, 3600)
        if "runner_bound" in value:
            self._set_ops_int_on(ops, "runner_bound", value["runner_bound"], 0, 64)
        if "event_retention_s" in value:
            self._set_ops_int_on(ops, "event_retention_s", value["event_retention_s"], 60, 90 * 86400)
        if "event_max_rows" in value:
            self._set_ops_int_on(ops, "event_max_rows", value["event_max_rows"], 100, 1_000_000)
        if "key_env" in value:
            key_env = value["key_env"]
            if not isinstance(key_env, str):
                raise ConfigError("operations.key_env must be a string")
            object.__setattr__(ops, "key_env", key_env.strip())
        object.__setattr__(self, "operations", ops)

    @staticmethod
    def _set_ops_bool_on(target: Any, name: str, value: Any) -> None:
        if not isinstance(value, bool):
            raise ConfigError(f"operations.{name} must be a boolean")
        object.__setattr__(target, name, value)

    @staticmethod
    def _set_ops_int_on(target: Any, name: str, value: Any, low: int, high: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"operations.{name} must be an integer")
        if not low <= value <= high:
            raise ConfigError(f"operations.{name} must be between {low} and {high}")
        object.__setattr__(target, name, value)

    def _set_credential_profiles(self, value: Any) -> None:
        """Validate the credential_profiles list (issue #30, FND-21/ENH-17).

        Each entry maps VM-name patterns to one named admin identity whose
        secret comes from an environment variable or a file — NEVER from the
        config itself: a literal ``password`` key (or any unknown key,
        application-account-shaped or otherwise) is refused with an error
        naming the key. Env references must be environment-variable NAMES so
        a pasted secret value can never be echoed by a validation error
        (same contract as http.token_env, PRR-016). The name ``default`` is
        reserved: it is the sentinel the resolver reports for the global
        credential, and a profile by that name would make persisted
        credential records ambiguous.
        """
        if not isinstance(value, list) or not value:
            raise ConfigError("credential_profiles must be a non-empty list")
        profiles: list[CredentialProfile] = []
        seen: set[str] = set()
        for idx, entry in enumerate(value):
            if not isinstance(entry, dict):
                raise ConfigError(f"credential_profiles[{idx}] must be an object")
            allowed = {
                "name", "vm_patterns", "username",
                "password_env", "password_file",
                "victim_username", "victim_password_env", "victim_password_file",
            }
            unknown = set(entry) - allowed
            if unknown:
                raise ConfigError(
                    f"unknown credential_profiles key(s): {sorted(unknown)}"
                )
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigError(f"credential_profiles[{idx}].name must be a non-empty string")
            if name.strip().casefold() == "default":
                raise ConfigError(
                    f"credential_profiles name {name!r} is reserved: 'default' names "
                    "the global (unprofiled) credential"
                )
            folded = name.strip().casefold()
            if folded in seen:
                raise ConfigError(
                    f"credential_profiles name {name!r} is declared more than once"
                )
            seen.add(folded)
            patterns = entry.get("vm_patterns")
            if (
                not isinstance(patterns, list)
                or not patterns
                or not all(isinstance(p, str) and p.strip() for p in patterns)
            ):
                raise ConfigError(
                    f"credential_profiles[{name}].vm_patterns must be a non-empty "
                    "list of non-empty strings"
                )
            username = entry.get("username")
            if not isinstance(username, str) or not username.strip():
                raise ConfigError(
                    f"credential_profiles[{name}].username must be a non-empty string"
                )
            secret = self._set_profile_secret(name, entry, "password_env", "password_file")
            victim_username = entry.get("victim_username", "")
            victim_env = entry.get("victim_password_env", "")
            victim_file = entry.get("victim_password_file", "")
            secret_v = ("", "")
            if victim_username or victim_env or victim_file:
                if not isinstance(victim_username, str) or not victim_username.strip():
                    raise ConfigError(
                        f"credential_profiles[{name}].victim_username must be a "
                        "non-empty string when victim credentials are configured"
                    )
                secret_v = self._set_profile_secret(
                    name, entry, "victim_password_env", "victim_password_file",
                )
            profiles.append(CredentialProfile(
                name=name.strip(),
                vm_patterns=tuple(p.strip() for p in patterns),
                username=username.strip(),
                password_env=secret[0],
                password_file=secret[1],
                victim_username=str(victim_username or "").strip(),
                # The VALIDATED/normalized values from _set_profile_secret,
                # not a re-derivation from the raw entry (PRR-015): the two
                # paths normalized differently (env stripped vs file not).
                victim_password_env=secret_v[0],
                victim_password_file=secret_v[1],
            ))
        object.__setattr__(self, "credential_profiles", tuple(profiles))

    @staticmethod
    def _set_profile_secret(
        name: str,
        entry: dict[str, Any],
        env_key: str,
        file_key: str,
    ) -> tuple[str, str]:
        """Exactly one of env/file secret sources; env must be a NAME."""
        env_val = entry.get(env_key)
        file_val = entry.get(file_key)
        both = env_val is not None and file_val is not None
        neither = env_val is None and file_val is None
        if both or neither:
            raise ConfigError(
                f"credential_profiles[{name}] must carry exactly one of "
                f"{env_key} or {file_key}"
            )
        chosen_env = ""
        chosen_file = ""
        if env_val is not None:
            if not isinstance(env_val, str) or not env_val.strip():
                raise ConfigError(
                    f"credential_profiles[{name}].{env_key} must be a non-empty string"
                )
            if not _ENV_NAME_RE.fullmatch(env_val.strip()):
                raise ConfigError(
                    f"credential_profiles[{name}].{env_key} must be a valid "
                    "environment variable name (values are never printed — a "
                    "pasted secret value is refused rather than echoed)"
                )
            chosen_env = env_val.strip()
        else:
            if not isinstance(file_val, str) or not file_val.strip():
                raise ConfigError(
                    f"credential_profiles[{name}].{file_key} must be a non-empty "
                    "string path"
                )
            chosen_file = file_val.strip()
        return chosen_env, chosen_file


Config._FIELD_MAP = {  # type: ignore[attr-defined]
    "allowed_vm_patterns": lambda c, v: c._set_str_list("allowed_vm_patterns", v),
    "host_read_roots": lambda c, v: c._set_str_list("host_read_roots", v),
    "host_write_roots": lambda c, v: c._set_str_list("host_write_roots", v),
    "guest_read_roots": lambda c, v: c._set_str_list("guest_read_roots", v),
    "guest_write_roots": lambda c, v: c._set_str_list("guest_write_roots", v),
    "destructive": lambda c, v: c._set_destructive(v),
    "allow_inline_credentials": lambda c, v: c._set_bool("allow_inline_credentials", v),
    "unrestricted": lambda c, v: c._set_bool("unrestricted", v),
    "audit_log_path": lambda c, v: c._set_str_opt("audit_log_path", v),
    "max_output_bytes": lambda c, v: c._set_int("max_output_bytes", v),
    "host_powershell_path": lambda c, v: c._set_str_opt("host_powershell_path", v),
    "verify_sha256": lambda c, v: c._set_bool("verify_sha256", v),
    "ps_timeout_s": lambda c, v: c._set_int("ps_timeout_s", v),
    "vm_lock_wait_s": lambda c, v: c._set_int("vm_lock_wait_s", v),
    "max_host_powershell": lambda c, v: c._set_int("max_host_powershell", v),
    "host_powershell_wait_s": lambda c, v: c._set_number("host_powershell_wait_s", v),
    "ps_slot_dir": lambda c, v: c._set_str_opt("ps_slot_dir", v),
    "psdirect_session_reuse": lambda c, v: c._set_bool("psdirect_session_reuse", v),
    "state_db_path": lambda c, v: c._set_str_opt("state_db_path", v),
    "hyperv": lambda c, v: c._set_hyperv(v),
    "http": lambda c, v: c._set_http(v),
    "leases": lambda c, v: c._set_leases(v),
    "operations": lambda c, v: c._set_operations(v),
    "credential_profiles": lambda c, v: c._set_credential_profiles(v),
}
