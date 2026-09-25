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

import json
import os
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar

SCHEMA_VERSION = 1


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or is invalid."""


@dataclass
class DestructivePolicy:
    """Per-category switches for destructive operations."""

    stop: bool = False
    reset: bool = False
    checkpoint_restore: bool = False
    checkpoint_remove: bool = False
    kd_reboot: bool = False
    elevated_exec: bool = False
    guest_write: bool = False
    require_confirm: bool = True


@dataclass
class HttpPolicy:
    host: str = "127.0.0.1"
    port: int = 8787
    token_env: str = "HYPERV_MCP_HTTP_TOKEN"


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

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> Config:
        env = dict(os.environ if environ is None else environ)
        data: dict[str, Any] = {}
        config_path = env.get("HYPERV_MCP_CONFIG", "").strip()
        if config_path:
            try:
                with open(config_path, encoding="utf-8-sig") as fh:
                    data = json.load(fh)
            except FileNotFoundError:
                # Missing file = run on deny-all defaults (banner explains it).
                data = {}
            except OSError as exc:
                raise ConfigError(
                    f"HYPERV_MCP_CONFIG points to an unreadable file ({config_path}): {exc}"
                ) from None
            except json.JSONDecodeError as exc:
                raise ConfigError(
                    f"HYPERV_MCP_CONFIG file is not valid JSON ({config_path}): {exc}"
                ) from None
            if not isinstance(data, dict):
                raise ConfigError("HYPERV_MCP_CONFIG must contain a JSON object")

        cfg = cls.from_dict(data)
        if env.get("HYPERV_MCP_UNRESTRICTED", "") in ("1", "true", "yes"):
            cfg = replace(cfg, unrestricted=True)
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
        for key in ("host_read_roots", "host_write_roots", "guest_read_roots", "guest_write_roots"):
            for root in getattr(self, key):
                if not isinstance(root, str) or not root.strip():
                    raise ConfigError(f"{key} entries must be non-empty strings")
        for pattern in self.allowed_vm_patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ConfigError("allowed_vm_patterns entries must be non-empty strings")

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
        unknown = set(value) - {"host", "port", "token_env"}
        if unknown:
            raise ConfigError(f"unknown http key(s): {sorted(unknown)}")
        http = HttpPolicy()
        for key, val in value.items():
            if key == "port":
                if not isinstance(val, int) or isinstance(val, bool) or not (1 <= val <= 65535):
                    raise ConfigError("http.port must be an integer in 1..65535")
                http.port = val
            elif isinstance(val, str) and val.strip():
                setattr(http, key, val)
            else:
                raise ConfigError(f"http.{key} must be a non-empty string")
        object.__setattr__(self, "http", http)


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
    "http": lambda c, v: c._set_http(v),
}
