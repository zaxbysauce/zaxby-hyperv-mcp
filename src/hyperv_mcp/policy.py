r"""Path and VM-name policy enforcement for hyperv-mcp.

Semantics (see plan.md "Policy defaults"):
  - unrestricted=True          -> every check passes (research mode, loud warnings).
  - non-empty list configured  -> allowlist; deny by default.
  - empty list                 -> deny (nothing is configured = nothing allowed).

Host path checks are syntactic-but-strong: \\?\ prefix handling, normpath,
drive-relative rejection, per-component realpath resolution of the existing
prefix (junctions/symlinks), case-insensitive root comparison. Guest paths get
the same host-side check PLUS an authoritative in-guest GetFullPath assertion
(done in the generated PowerShell), because guest reparse points are only
visible to the guest filesystem.
"""

from __future__ import annotations

import fnmatch
import ntpath
import os
import re
from dataclasses import dataclass

from .config import Config

_DRIVE_RELATIVE = re.compile(r"^[A-Za-z]:(?![\\/])")
_LONG_PREFIX = "\\\\?\\"
_UNC_PREFIX = "\\\\?\\UNC\\"
_UNC = "\\\\"


class PolicyDenied(RuntimeError):
    """Raised when an operation is denied by the configured policy."""

    def __init__(self, category: str, detail: str = "") -> None:
        self.category = category
        msg = f"policy: {category} denied"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)
        self.detail = detail


@dataclass(frozen=True)
class CanonicalPath:
    """A canonicalized Windows path plus the form used for comparisons."""

    original: str
    normalized: str  # normpath'd, drive letters upper-cased, no \\?\ prefix
    exists_prefix_resolved: str  # realpath-resolved (junctions/symlinks) form


def canonicalize_windows_path(path: str) -> CanonicalPath:
    r"""Canonicalize a Windows path for policy comparison.

    - Rejects empty and drive-relative paths ("C:foo") — the latter is
      ambiguous (per-drive cwd) and therefore always policy-invalid.
    - Strips the \\?\ long-path prefix (preserving UNC form).
    - normpath + case folding for comparison.
    - realpath resolves junctions/symlinks for the part of the path that
      exists; nonexistent tail stays lexical.
    """
    if not path or not path.strip():
        raise PolicyDenied("path", "empty path")
    p = path
    if p.startswith(_UNC_PREFIX):
        p = _UNC + p[len(_UNC_PREFIX):]
    elif p.startswith(_LONG_PREFIX):
        p = p[len(_LONG_PREFIX):]
    if _DRIVE_RELATIVE.match(p):
        raise PolicyDenied("path", f"drive-relative path is ambiguous: {path!r}")
    normalized = ntpath.normpath(p)
    # realpath: resolves the existing prefix (junctions/symlinks), leaves the
    # nonexistent tail lexical. On Windows this also normalizes case of the
    # existing components.
    try:
        resolved = os.path.realpath(normalized)
    except OSError:
        resolved = normalized
    return CanonicalPath(
        original=path,
        normalized=normalized,
        exists_prefix_resolved=resolved,
    )


def _is_within(path_cmp: str, root_cmp: str) -> bool:
    r"""Case-normalized root-prefix check, separator-aware, drive-root-safe.

    Roots are stripped of trailing separators first so both a drive root
    ("C:\") and a normal root ("C:\Temp") behave: the path must equal the
    root or sit under it with a separator boundary (C:\foo never matches
    C:\foobar).
    """
    root_cmp = root_cmp.rstrip("\\/")
    if path_cmp == root_cmp:
        return True
    if not path_cmp.startswith(root_cmp):
        return False
    rest = path_cmp[len(root_cmp):]
    return rest[:1] in ("\\", "/")


def _cmp_form(cp: CanonicalPath) -> str:
    # Prefer the resolved form when the path exists at least partially; fall
    # back to the normalized form otherwise. Both are compared case-folded.
    return cp.exists_prefix_resolved.replace("/", "\\").casefold()


def _root_cmp_form(root: str) -> str | None:
    try:
        cp = canonicalize_windows_path(root)
    except PolicyDenied:
        # An invalid root (e.g. bare drive-relative "C:") can never match —
        # returning None skips it instead of degrading to a loose prefix.
        return None
    return _cmp_form(cp)


def _check_roots(cfg: Config, key: str, category: str, path: str) -> CanonicalPath:
    cp = canonicalize_windows_path(path)
    if cfg.unrestricted:
        return cp
    roots = getattr(cfg, key)
    if not roots:
        raise PolicyDenied(category, f"no {key} configured")
    path_cmp = _cmp_form(cp)
    for root in roots:
        root_cmp = _root_cmp_form(root)
        if root_cmp is not None and _is_within(path_cmp, root_cmp):
            return cp
    raise PolicyDenied(category, f"path outside configured {key}")


def check_host_read(cfg: Config, path: str) -> CanonicalPath:
    return _check_roots(cfg, "host_read_roots", "host read", path)


def check_host_write(cfg: Config, path: str) -> CanonicalPath:
    return _check_roots(cfg, "host_write_roots", "host write", path)


def check_guest_read(cfg: Config, path: str) -> CanonicalPath:
    return _check_roots(cfg, "guest_read_roots", "guest read", path)


def check_guest_write(cfg: Config, path: str) -> CanonicalPath:
    return _check_roots(cfg, "guest_write_roots", "guest write", path)


def vm_allowed(cfg: Config, vm_name: str) -> None:
    """Raise PolicyDenied unless the VM name matches an allowed pattern."""
    if not vm_name or not vm_name.strip():
        raise PolicyDenied("vm", "empty VM name")
    if cfg.unrestricted:
        return
    if not cfg.allowed_vm_patterns:
        raise PolicyDenied("vm", "no allowed_vm_patterns configured")
    folded = vm_name.casefold()
    for pattern in cfg.allowed_vm_patterns:
        if fnmatch.fnmatchcase(folded, pattern.casefold()):
            return
    raise PolicyDenied("vm", "name does not match allowed_vm_patterns")


def require_destructive(cfg: Config, category: str, confirm: bool, detail: str) -> None:
    """Gate a destructive operation behind its config category + confirm.

    unrestricted=True skips only the category switches; the explicit
    confirmation (destructive.require_confirm) is ALWAYS enforced so an
    open research config still requires deliberate consent per call.
    """
    if not cfg.destructive.require_confirm:
        if cfg.unrestricted or getattr(cfg.destructive, category, False):
            return
        raise PolicyDenied(
            f"destructive:{category}",
            f"disabled by config (destructive.{category}=false) — would {detail}",
        )
    if not confirm:
        raise PolicyDenied(
            "confirm",
            f"pass confirm=true to {detail} (destructive.require_confirm=true)",
        )
    if cfg.unrestricted or getattr(cfg.destructive, category, False):
        return
    raise PolicyDenied(
        f"destructive:{category}",
        f"disabled by config (destructive.{category}=false) — would {detail}",
    )
