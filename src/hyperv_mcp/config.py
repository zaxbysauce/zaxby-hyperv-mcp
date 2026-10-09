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
from dataclasses import dataclass, field, replace
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
    guest_repair: bool = False
    relay: bool = False
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
                setattr(http, key, val.strip() if key == "token_env" else val)
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
    "hyperv": lambda c, v: c._set_hyperv(v),
    "http": lambda c, v: c._set_http(v),
}
