"""
hyperv_mcp.server -- MCP server for Hyper-V VM management (hardened fork).

Exposes 57 tools: VM lifecycle, checkpoints, kernel debug setup (KDNET/KDCOM),
guest execution and file transfer via PowerShell Direct, guest access
diagnostics/repair and managed guest jobs, reboot recovery verification,
host-to-guest HTTP relay, console observation and input (WMI), evidence
capture, VM/media/video provisioning, orchestration waits, and server runtime
provenance. Security model:

  - Credentials resolve from env vars / credential files; username/password
    tool parameters exist only when config allow_inline_credentials=true.
    Passwords never appear on process command lines (EncodedCommand + stdin).
  - Policy: VM-name patterns and host/guest read/write roots, deny-by-default.
    Every axis is DENIED until configured; explicit unrestricted mode exists
    for disposable labs (HYPERV_MCP_UNRESTRICTED=1 or config unrestricted=true).
  - Destructive operations (stop/reset/restore/remove/KD/elevated/guest-write)
    are gated per category plus a confirm parameter.
  - Structured audit log per operation (secret-safe).

Configuration: HYPERV_MCP_CONFIG (JSON file) — see README for the schema and
worked examples. Run `hyperv-mcp --check-env` to print the effective policy
and runtime provenance (PowerShell probe, config digest, git revision).
"""

import argparse
import dataclasses
import importlib.metadata
import json
import logging
import os
import re
import subprocess
import sys
import threading
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Image, MCPServer
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import LATEST_PROTOCOL_VERSION, CallToolResult, TextContent
from pydantic import AnyHttpUrl

from . import (
    auditlog,
    console,
    credentials,
    diagnostics,
    errors,
    evidence,
    filetransfer,
    guestexec,
    guestjobs,
    leases,
    lifecycle,
    media,
    operations,
    policy,
    psdsessions,
    pswindows,
    relay,
    repair,
    statestore,
    stdio_proxy,
    timing,
    vmident,
    vmlocks,
)
from .config import Config, ConfigError

__all__ = ["mcp", "main", "bootstrap", "configure_http_auth"]  # noqa: F822 (mcp: module __getattr__)

VERSION = "0.4.0"

#: Issue #24: the detached-op runner admission bound, sized once per
#: bootstrap (operations.runner_bound, defaulting to max_host_powershell).
#: Acquired synchronously in the guard/interceptor BEFORE an op row exists
#: and released by the runner when it finishes, so excess detached calls are
#: refused with a retryable busy envelope instead of queued without bound.
_RUNNER_SLOTS: Any = None


def _runner_slots() -> threading.BoundedSemaphore:
    """The current detached-runner admission semaphore (sized at bootstrap)."""
    global _RUNNER_SLOTS
    if _RUNNER_SLOTS is None:
        raise RuntimeError("bootstrap has not sized the runner slots yet")
    return _RUNNER_SLOTS


# Issue #24 (implementation-review R2/R13): the synchronous body gates a
# detached call must pass BEFORE any op row exists. The bodies re-check
# them anyway (they are pure functions of (cfg, confirm)); running them
# here means a denied call never yields an op_id and a mistyped argument
# (e.g. confirm: "banana", which pydantic-coercion would refuse on the sync
# path) never reaches the detached body as truthy.
_OPERATIONS_DESTRUCTIVE_GATES: dict[str, Callable[[Config, dict], None]] = {
    "hyperv_stop_vm": lambda cfg, a: policy.require_destructive(
        cfg, "stop", bool(a.get("confirm")),
        f"stop VM '{a.get('vm_name') or a.get('vm_id')}'"),
    "hyperv_reset_vm": lambda cfg, a: policy.require_destructive(
        cfg, "reset", bool(a.get("confirm")),
        f"hard reset VM '{a.get('vm_name') or a.get('vm_id')}'"),
    "hyperv_checkpoint_restore": lambda cfg, a: policy.require_destructive(
        cfg, "checkpoint_restore", bool(a.get("confirm")),
        f"restore VM '{a.get('vm_name') or a.get('vm_id')}' to '{a.get('checkpoint_name')}'"),
    "hyperv_checkpoint_remove": lambda cfg, a: policy.require_destructive(
        cfg, "checkpoint_remove", bool(a.get("confirm")),
        f"remove checkpoint '{a.get('checkpoint_name')}' from VM '{a.get('vm_name') or a.get('vm_id')}'"),
    "hyperv_vm_create": lambda cfg, a: policy.require_destructive(
        cfg, "vm_provision", bool(a.get("confirm")), f"create VM '{a.get('vm_name')}'"),
    "hyperv_guest_put": lambda cfg, a: policy.require_destructive(
        cfg, "guest_write", bool(a.get("confirm")),
        f"write '{a.get('remote_path')}' on '{a.get('vm_name') or a.get('vm_id')}'"),
    "hyperv_guest_run": lambda cfg, a: (
        policy.require_destructive(
            cfg, "elevated_exec", bool(a.get("confirm")),
            f"run an elevated script on '{a.get('vm_name') or a.get('vm_id')}'")
        if a.get("elevated") else None
    ),
    "hyperv_guest_run_ps": lambda cfg, a: (
        policy.require_destructive(
            cfg, "elevated_exec", bool(a.get("confirm")),
            f"run an elevated script on '{a.get('vm_name') or a.get('vm_id')}'")
        if a.get("elevated") else None
    ),
}


def _operations_preflight(name: str, arguments: dict, tool_obj: Any = None) -> None:
    """The synchronous preflight for a detached/tasks call: SDK argument
    validation (R13 - the runner invokes the raw fn, bypassing Tool.run's
    pydantic validation), the VM policy screen for every vm-bearing tool
    (including the wait_* tools that have no TOOL_SCOPES entry), and the
    destructive confirm/category gate (R2). Raises PolicyDenied /
    ValidationError / ValueError; the caller converts to its envelope."""
    cfg = CFG
    if cfg is None:
        raise RuntimeError("bootstrap has not run")
    if tool_obj is not None:
        validate = getattr(tool_obj, "fn_metadata", None)
        validate_args = getattr(validate, "validate_arguments", None)
        if validate_args is not None:
            validate_args(dict(arguments))
    vm_name = str(arguments.get("vm_name") or "")
    if vm_name:
        vmident.checked_caller_name(vm_name)
        policy.vm_allowed(cfg, vm_name)
    gate = _OPERATIONS_DESTRUCTIVE_GATES.get(name)
    if gate is not None:
        gate(cfg, arguments)


def _tool_fn_resolver(name: str) -> Callable[..., Any]:
    """The raw tool function behind a registered tool name, for a detached
    runner (the guard path passes tool.fn directly; the tasks interceptor
    resolves by name)."""
    tools = getattr(get_mcp(), "_tool_manager", None)
    registry = getattr(tools, "_tools", {}) or {}
    tool = registry.get(name)
    fn = getattr(tool, "fn", None)
    if fn is None:
        raise ValueError(f"no registered tool {name!r} to detach")
    return fn

_INSTRUCTIONS = (
    "Hyper-V VM management MCP (hardened). VM lifecycle, checkpoints, "
    "KDNET/KDCOM setup, PowerShell Direct guest execution and file "
    "transfer, guest access diagnostics and narrow repair, managed guest "
    "jobs, reboot recovery checks, a loopback host-to-guest HTTP relay, "
    "console observation/input, and evidence capture. Policy defaults are "
    "DENY-BY-DEFAULT: configure HYPERV_MCP_CONFIG (allowed VM patterns and "
    "path roots) or set HYPERV_MCP_UNRESTRICTED=1 for disposable labs. "
    "Destructive operations additionally need confirm=true. "
    "Run `hyperv-mcp --check-env` to print the effective policy and runtime "
    "provenance (PowerShell, config digest, git revision)."
)

_mcp: MCPServer | None = None
_http_token_verifier = None
_bootstrapped = False
_compat_warning_shown = False
CFG: Config | None = None

logger = logging.getLogger(__name__)


def configure_http_auth(token_verifier) -> None:
    """Install a bearer-token verifier BEFORE bootstrap().

    Only effective for streamable-http serving (stdio ignores it); must be
    called before the MCPServer instance is constructed.
    """
    global _http_token_verifier
    if _bootstrapped:
        raise RuntimeError("configure_http_auth() must be called before bootstrap()")
    _http_token_verifier = token_verifier


def __getattr__(name: str):
    """`from hyperv_mcp.server import mcp` keeps working (0xntpower serve_http
    compat): lazily bootstraps and returns the MCPServer instance.

    WARNING: this compat instance has NO bearer-token verifier installed —
    serving it over streamable-http yields an unauthenticated endpoint.
    Use the `hyperv-mcp-http` entry point for HTTP.
    """
    if name == "mcp":
        instance = get_mcp()
        if not _compat_warning_shown:
            print(
                "[hyperv-mcp] WARNING: compat import of `server.mcp` yields an "
                "MCPServer instance WITHOUT bearer-token auth; serving it over "
                "streamable-http exposes an unauthenticated endpoint. Prefer "
                "the `hyperv-mcp-http` entry point.",
                file=sys.stderr,
            )
            globals()["_compat_warning_shown"] = True
        return instance
    raise AttributeError(name)


def get_mcp() -> MCPServer:
    if _mcp is None:
        bootstrap()
    assert _mcp is not None
    return _mcp


def _make_tool_limiter_lifespan(cap: int):
    """Build the server lifespan that bounds tool concurrency.

    mcp 2.x runs every sync tool body on a worker thread via
    anyio.to_thread.run_sync, which draws from the DEFAULT thread limiter
    (40 tokens, scoped to the running event loop and shared with anything
    else using to_thread). Resize that default limiter to a dedicated bound
    above the host PowerShell slot pool (2 x max_host_powershell, default
    16) at server start: a tool thread queued on a PowerShell slot holds a
    limiter token, so PS-heavy saturation delays — it cannot deadlock,
    because slots are released when their child completes and no thread
    waits on another thread — and PS-free tools keep admission instead of
    inheriting anyio's global default. The sizing covers the slot queue and
    the VM-lock queue's single holder; it does not reserve a class for
    PS-free tools, so a fully lock-queued pool can still delay them (tracked
    as a follow-up). Entered once per server run on both transports (stdio
    and streamable-http); in-process embedders driving `call_tool` directly
    never enter it and keep anyio's 40-token default. The bound is not
    restored on exit — within one event loop the shrunken value persists for
    co-tenant to_thread users.
    """

    @asynccontextmanager
    async def _tool_limiter_lifespan(_server: MCPServer):
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = 2 * cap
        # The SDK's default lifespan yields {}; replacing it with a bare
        # yield would make request_context.lifespan_context None for any
        # embedder that subscripts it.
        try:
            yield {}
        finally:
            # Every pooled PowerShell Direct worker is a live host
            # powershell.exe holding a decrypted credential. Closing them here
            # is what returns the host process count to zero on server exit
            # without waiting out the idle TTL (issue #21).
            psdsessions.close_default_pool()

    return _tool_limiter_lifespan


def bootstrap(
    environ: dict[str, str] | None = None, *, config: Config | None = None
) -> Config:
    """Load config, wire modules, register tools. Idempotent.

    `config` (issue #23) lets an entry point that has already loaded and
    ADJUSTED the config -- http_entry forces leases.required on for the shared
    controller -- hand the adjusted object straight through. Without it the
    adjusted copy was dead: bootstrap re-loaded from the environment and the
    controller silently ran with required-mode off.
    """
    global CFG, _mcp, _bootstrapped
    if _bootstrapped:
        return CFG  # type: ignore[return-value]
    cfg = config if config is not None else Config.load(environ)
    credentials.init(cfg)
    pswindows.init(cfg, credentials.redact)
    auditlog.init(cfg)
    vmlocks.set_default_wait_s(cfg.vm_lock_wait_s)  # issue #14 bounded lock wait
    # issue #23: wire the cross-process lease row into vm_lock, plus the
    # scope/agent resolvers the row needs. http_entry turns leases.required
    # on for the shared controller; standalone stdio stays opt-in.
    vmlocks.set_store_provider(lambda: CFG)
    vmlocks.set_scope_resolver(
        lambda: TOOL_SCOPES.get(vmlocks.current_tool() or "", "call")
    )
    vmlocks.set_agent_resolver(auditlog.current_agent_id)
    # issue #21: install the reusable PS Direct session pool. A no-op when the
    # flag is off, and the session cap is derived from the host PowerShell cap
    # so pooled workers cannot starve the per-call legs of slots.
    psdsessions.install_default_pool(cfg)
    auth = None
    if _http_token_verifier is not None:
        # MCPServer requires AuthSettings when a token_verifier is installed.
        auth = AuthSettings(
            issuer_url=AnyHttpUrl("http://127.0.0.1"),  # static-token issuer (local)
            resource_server_url=AnyHttpUrl("http://127.0.0.1"),
            validate_token_resource=False,
        )
    # Issue #24: the runner admission bound and the SEP-2663 tasks bridge.
    # The semaphore is (re)sized at every bootstrap so a module reload in
    # tests rebuilds it; operations.guard_consult acquires it synchronously
    # before an op row exists.
    global _RUNNER_SLOTS
    _RUNNER_SLOTS = threading.BoundedSemaphore(
        max(1, int(cfg.operations.runner_bound or cfg.max_host_powershell))
    )
    _mcp = MCPServer(
        "hyperv_mcp",
        instructions=_INSTRUCTIONS,
        token_verifier=_http_token_verifier,
        auth=auth,
        version=VERSION,
        lifespan=_make_tool_limiter_lifespan(cfg.max_host_powershell),
        extensions=[operations.tasks_extension(
            cfg,
            gate_fn=_lease_gate,
            tool_fn_resolver=_tool_fn_resolver,
            runner_slots=_runner_slots,
            preflight_fn=_operations_task_preflight,
        )],
    )
    _register_tools(cfg, _mcp)
    _startup_banner(cfg)
    CFG = cfg
    _bootstrapped = True
    return cfg


def _startup_banner(cfg: Config) -> None:
    # The Hyper-V target line prints FIRST and unconditionally: unrestricted
    # mode early-returns below, and remote lab deployments are exactly the
    # unrestricted ones (issue #43) — the target must never be silenced.
    target = cfg.hyperv.host
    if target:
        print(
            f"[hyperv-mcp] Hyper-V target: remote host {target} "
            "(run `hyperv-mcp --check-env` to verify target reachability)",
            file=sys.stderr,
        )
    else:
        print("[hyperv-mcp] Hyper-V target: local host", file=sys.stderr)
    print(f"[hyperv-mcp] policy: {cfg.policy_summary()}", file=sys.stderr)
    # Issue #22: the durable state store is always on. Print where it lives so
    # an operator can find (and back up, or delete) it.
    print(f"[hyperv-mcp] state store: {statestore.resolve_state_db_path(cfg)}",
          file=sys.stderr)
    if cfg.unrestricted:
        print(
            "[hyperv-mcp] WARNING: UNRESTRICTED mode — every policy axis is "
            "fully open and destructive operations are category-enabled. "
            "Only appropriate on disposable lab hosts.",
            file=sys.stderr,
        )
        return
    configured = cfg.configured_axes()
    if configured:
        print(
            f"[hyperv-mcp] INFO: configured axes (deny-by-default outside "
            f"each allowlist): {', '.join(configured)}",
            file=sys.stderr,
        )
    else:
        print(
            "[hyperv-mcp] NOTE: every policy axis is currently DENIED. "
            "Set HYPERV_MCP_CONFIG or HYPERV_MCP_UNRESTRICTED=1 to allow work.",
            file=sys.stderr,
        )
    # A "*" pattern or a drive-root entry means the axis is effectively
    # fully open even though it is "configured" — keep a WARNING for it.
    if "*" in cfg.allowed_vm_patterns:
        print(
            "[hyperv-mcp] WARNING: allowed_vm_patterns contains '*' — every "
            "VM on this host can be targeted.",
            file=sys.stderr,
        )
    for axis in ("host_read_roots", "host_write_roots", "guest_read_roots", "guest_write_roots"):
        if any(r.rstrip("\\/").endswith(":") for r in getattr(cfg, axis)):
            print(
                f"[hyperv-mcp] WARNING: {axis} contains a drive root — the "
                "entire drive is within policy.",
                file=sys.stderr,
            )



def _cfg() -> Config:
    """Config is guaranteed set once bootstrap() has run (tools only run then)."""
    assert CFG is not None
    return CFG


# ---------------------------------------------------------------------------
# server provenance (ENH-16)
# ---------------------------------------------------------------------------

# Probe script for the PowerShell child pswindows would spawn. Mentions three
# of the four probe markers plus ConvertTo-Json, so the compact JSON contract
# holds for both a real run and a stubbed run_ps.
_PROVENANCE_SCRIPT = (
    "[pscustomobject]@{ "
    "path = [System.Diagnostics.Process]::GetCurrentProcess().Path; "
    "edition = [string]$PSEdition; "
    "version = [string]$PSVersionTable.PSVersion.ToString(); "
    "psmodulepath = [string]$env:PSModulePath "
    "} | ConvertTo-Json -Compress"
)


def _git_revision() -> str:
    """Git revision of the source tree; 'unknown' on any failure (never raises).

    Probes only when the derived root itself contains a ``.git`` entry, so a
    pip-installed package sitting inside an unrelated repository cannot have
    its reported revision hijacked by that enclosing repository. Runs with the
    sanitized child environment: the git process cannot see server secrets or
    inherit GIT_DIR/GIT_WORK_TREE redirections (child_env strips both).
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if not os.path.exists(os.path.join(repo_root, ".git")):
        return "unknown"
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            env=pswindows.child_env(),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            creationflags=pswindows.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    revision = proc.stdout.strip()
    if proc.returncode != 0 or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        return "unknown"
    return revision


def _powershell_provenance(cfg: Config) -> dict[str, str]:
    """PowerShell path/edition/version/psmodulepath for the child process.

    Best effort: any probe failure falls back per field (path -> the
    executable pswindows would spawn, edition/version -> 'unknown',
    psmodulepath -> the 5.1 system module directory), so the result is always
    four non-empty strings and never raises.
    """
    answers = {"path": "", "edition": "", "version": "", "psmodulepath": ""}
    try:
        result = pswindows.run_ps(_PROVENANCE_SCRIPT, timeout_s=10)
    except pswindows.PowerShellBusy:
        # Pool saturation is a capacity condition, not missing provenance:
        # report it as such instead of the "unknown" fallback (PR review).
        answers["edition"] = "unknown (host PowerShell pool busy)"
        answers["version"] = "unknown (host PowerShell pool busy)"
        answers["psmodulepath"] = "unknown (host PowerShell pool busy)"
        answers["path"] = pswindows.find_powershell(cfg.host_powershell_path)
        return answers
    except Exception:
        result = None
    if result is not None and result.ok():
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key in answers and isinstance(value, str):
                    answers[key] = value
    if not answers["path"].strip():
        answers["path"] = pswindows.find_powershell(cfg.host_powershell_path)
    if not answers["edition"].strip():
        answers["edition"] = "unknown"
    if not answers["version"].strip():
        answers["version"] = "unknown"
    if not answers["psmodulepath"].strip():
        answers["psmodulepath"] = pswindows.PS51_SYSTEM_MODULES
    return answers


def _mcp_sdk_version() -> str:
    """Installed 'mcp' distribution version; 'unknown' if the distribution
    metadata is unavailable (failure-soft, matching the other provenance
    legs — never raises)."""
    try:
        return importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _hyperv_target_block(cfg: Config) -> dict[str, Any]:
    """Effective Hyper-V target for hyperv_server_info (issue #43):
    local mode by default; the configured remote host when hyperv.host set."""
    host = cfg.hyperv.host
    return {"mode": "remote" if host else "local", "host": host}


def _server_info_payload(cfg: Config) -> dict[str, Any]:
    """Read-only runtime provenance payload for the hyperv_server_info tool."""
    return {
        "version": VERSION,
        "git_revision": _git_revision(),
        "powershell": _powershell_provenance(cfg),
        "hyperv_target": _hyperv_target_block(cfg),
        "config_path": cfg.config_path,
        "config_sha256": cfg.config_sha256,
        "mcp_sdk_version": _mcp_sdk_version(),
        "protocol_version": LATEST_PROTOCOL_VERSION,
        "feature_flags": {
            "unrestricted": cfg.unrestricted,
            "allow_inline_credentials": cfg.allow_inline_credentials,
            "verify_sha256": cfg.verify_sha256,
            "destructive": dataclasses.asdict(cfg.destructive),
        },
    }

# ---------------------------------------------------------------------------
# tool registration
# ---------------------------------------------------------------------------

def _register_tools(cfg: Config, mcp: MCPServer) -> None:
    """Register the full tool surface.

    Guest tools are defined in two mutually exclusive variants under the
    same source name: when allow_inline_credentials is set, the variant that
    accepts inline username/password parameters; otherwise the base variant.
    Exactly one variant registers per name (the branches are exclusive), so
    the runtime tool surface (names, parameters, docstrings) is identical
    across credential modes apart from those two parameters — pinned by
    test_server.py's inventory checks. mcp 2.x's typed @tool decorator
    returns the function it decorates, so the source-level conditional
    redefinition of each shared name is flagged by mypy as an incompatible
    redefinition; the ignores on the base-variant definitions below are
    intentional.
    """
    creds_allowed = cfg.allow_inline_credentials

    def _cred_args(u: str = "", p: str = "") -> credentials.CredentialSet:
        if creds_allowed and (u or p):
            return credentials.resolve_guest(u, p)
        return credentials.resolve_guest()

    def _audit(tool: str, vm: str, category: str, lease_ref: str | None = None):
        return auditlog.operation(tool=tool, vm_name=vm, category=category,
                                  lease_ref=lease_ref)

    def _image_meta_content(result: dict) -> list:
        """evidence.capture_evidence result -> [ImageContent, TextContent].

        The console layer already encoded this frame exactly once; those bytes
        are reused here rather than encoded again, and the metadata dict ships
        as the text sidecar. `image` is None when if_changed_from matched, so
        the unchanged frame ships as metadata alone — no image block.
        """
        image = result["image"]
        if image is None:
            return [result["meta"]]
        return [
            Image(data=image.encoded, format=image.pil_format).to_image_content(),
            result["meta"],
        ]

    def _run_guest_tool(
        tool: str, vm: str, category: str, fn, *args,
        cred_factory=None,
        audit_vm_name: str | Callable[[], str] = "",
        audit_job_id: str = "",
        audit_relay_id: str = "",
        **kwargs,
    ) -> Any:
        """Run a guest/transfer tool; every failure leaves as one envelope.

        cred_factory resolves credentials INSIDE the audited region so a
        CredentialError surfaces as an audited {ok:false,...,"credential"}
        envelope instead of escaping as a raw ToolError. Success shapes are
        unchanged; ok:false result dicts from module-level builders gain the
        retry fields and leave as isError CallToolResults (issue #9: one
        envelope with error_class/retryable/retry_after_ms for every tool,
        from the same errors.classify taxonomy the audit log uses).

        Audit-only kwargs (issue #10) — consumed here, never forwarded to
        fn: audit_vm_name (registry-resolved VM for by-id follow-ups that
        accept no vm_name argument), audit_job_id/audit_relay_id (the handle
        the call addresses). PRR-007: audit_vm_name may be a CALLABLE, and
        the by-id follow-ups pass one — the eager peek used to run
        statestore.open() (a write transaction) before this envelope existed
        and even for ids that were about to be refused; resolving it here is
        guarded, so a store failure reads as the honest empty name. Results
        that carry job_id/relay_id (start tools, and follow-ups echoing
        them) adopt them into the audit row after the call, the same way the
        resolved vm_name is adopted below.
        """
        if callable(audit_vm_name):
            try:
                audit_vm_name = str(audit_vm_name() or "")
            except Exception:
                audit_vm_name = ""
        op = auditlog.operation(
            tool=tool,
            vm_name=vm or audit_vm_name,
            category=category,
            job_id=audit_job_id or None,
            relay_id=audit_relay_id or None,
        )
        try:
            with op:
                if cred_factory is not None:
                    kwargs["cred"] = cred_factory()
                result = fn(*args, **kwargs)
                if isinstance(result, dict):
                    if result.get("exit_code") is not None:
                        op.exit_code = result["exit_code"]
                    op.ok = bool(result.get("ok", True))
                    op.error_class = str(result.get("error_class") or "")
                    # Issue #8 audit clause: a by-id call audited under an
                    # empty caller name adopts the RESOLVED display name
                    # (never fabricated — modules return ref.name; where a
                    # result carries none, the empty caller input stands).
                    # get_vm_info and vm_create results key the VM display
                    # name as `name`; every other wrapped result with a
                    # bare `name` key is also a VM name (audited grep).
                    display = result.get("vm_name") or result.get("name")
                    if not vm and display:
                        op.vm_name = str(display)
                    # Issue #10 audit clause: adopt the resource handle the
                    # result carries so start rows can be joined to the
                    # follow-up rows that address the same job/relay.
                    if result.get("job_id"):
                        op.job_id = str(result["job_id"])
                    if result.get("relay_id"):
                        op.relay_id = str(result["relay_id"])
                    if not op.ok:
                        # Enrich FIRST, then audit from the enriched dict so
                        # the audit's error_class is the envelope's by
                        # construction, never an independent default (issue
                        # #9 review PRR-003/PRR-004).
                        enriched = errors.enrich_failure(result)
                        op.error_class = enriched["error_class"]
                        return errors.failure_result(enriched)
                    op.error_class = str(result.get("error_class") or "")
                return result
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    # ---- server provenance ----------------------------------------------

    @mcp.tool()
    def hyperv_server_info() -> CallToolResult:
        """Read-only runtime provenance for this hyperv-mcp server process.

        Returns: {version, git_revision, powershell:{path, edition, version,
        psmodulepath}, config_path, config_sha256, mcp_sdk_version,
        protocol_version, feature_flags}. Never contains secrets.
        """
        try:
            with _audit("hyperv_server_info", "", "read"):
                return errors.success_result([_server_info_payload(cfg)])
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    # ---- VM lifecycle --------------------------------------------------

    @mcp.tool()
    def hyperv_list_vms() -> CallToolResult:
        """List all Hyper-V virtual machines and their current state.

        Returns: [{id, name, state, status, memory_mb, cpu_count, uptime_seconds}]
        (Deprecated PascalCase aliases Name/State/... are also included
        through the 0.2.x series.)
        """
        try:
            with _audit("hyperv_list_vms", "", "read"):
                return errors.success_result(list(lifecycle.list_vms(_cfg())))
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_get_vm_info(vm_name: str = "", vm_id: str = "") -> dict:
        """Get detailed info about a Hyper-V VM: state, generation, COM ports,
        network adapters, hard drives, checkpoint count, checkpoint type.

        Args:
            vm_name: Name of the VM (must match allowed_vm_patterns)
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {id, name, state, generation, memory_mb, cpu_count,
                  checkpoint_count, checkpoint_type, com_ports, network_adapters,
                  hard_drives, ...}
        """
        return _run_guest_tool(
            "hyperv_get_vm_info", vm_name, "read",
            lifecycle.get_vm_info, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_start_vm(
        vm_name: str = "", vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Start a Hyper-V VM and wait until it reports Running.

        Idempotent: an already-running VM returns status "already_running".

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {status, vm_name, state}

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_start_vm", vm_name, "lifecycle",
            lifecycle.start_vm, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_stop_vm(
        vm_name: str = "", method: str = "shutdown", confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Stop a Hyper-V VM and wait until it reaches the final state.

        Args:
            vm_name: Name of the VM
            method:  "shutdown" — graceful guest shutdown via Integration
                     Services, then waits for Off (default)
                     "shutdown-force" — force shutdown (data-loss risk)
                     "save" — suspend to disk (final state Saved)
                     "turnoff" — hard power-off
            confirm: Must be true (destructive.require_confirm)
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {status, vm_name, method, state}

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_stop_vm", vm_name, "destructive",
            lifecycle.stop_vm, _cfg(), vm_name,
            method=method, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_reset_vm(
        vm_name: str = "", confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Hard-reset a Hyper-V VM (power off immediately, start again) and
        wait until it reports Running. Equivalent to the physical reset button.

        Args:
            vm_name: Name of the VM
            confirm: Must be true (destructive.require_confirm)
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {status, vm_name, state}

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_reset_vm", vm_name, "destructive",
            lifecycle.reset_vm, _cfg(), vm_name, confirm=confirm, vm_id=vm_id,
        )

    # ---- checkpoints ----------------------------------------------------

    @mcp.tool()
    def hyperv_checkpoint_create(
        vm_name: str = "", checkpoint_name: str = "", vm_id: str = "", checkpoint_type: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Create a checkpoint (snapshot) of a Hyper-V VM.

        With checkpoint_type set, the VM's CheckpointType setting is temporarily
        changed for the single Checkpoint-VM call and restored in the same
        script. On a timeout or cancellation the host kills the script before
        that restore can run: the setting may stay at the requested value, and
        the pre-call original is then unrecoverable from the tool result —
        repair from your own records, or set it deliberately with
        `Get-VM "<name>" | Set-VM -CheckpointType <value>`. A stranded Standard
        makes every later default (no-type) checkpoint memory-bearing. Both
        paths share a 600s budget; a large-VM checkpoint can still hit it.

        Args:
            vm_name:         Name of the VM
            checkpoint_name: Label (auto timestamp if omitted)
            vm_id:           Optional VM GUID; exactly one of vm_name/vm_id must be given
            checkpoint_type: "standard", "production", "production_only", or "" (default:
                             the VM's own setting). Production falls back to Standard on
                             guests without production-checkpoint support, and ProductionOnly
                             fails instead. A Standard checkpoint — including a Production
                             fallback — writes guest memory to the host checkpoint store:
                             it can persist secrets held in guest memory (for example an
                             autologon password).

        Returns: {status, vm_name, checkpoint_name} (+ checkpoint_type: the type you
        requested, and vm_checkpoint_type: the VM's pre-call CheckpointType setting, when a
        type was requested)

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_checkpoint_create", vm_name, "checkpoint",
            lifecycle.checkpoint_create, _cfg(), vm_name,
            checkpoint_name=checkpoint_name, vm_id=vm_id, checkpoint_type=checkpoint_type,
        )

    @mcp.tool()
    def hyperv_checkpoint_list(vm_name: str = "", vm_id: str = "") -> list:
        """List checkpoints of a Hyper-V VM.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: [{name, type, created, parent_name}]
        """
        # list on success, {"ok": False, ...} envelope on failure (the one
        # list-returning tool routed through the envelope mapping).
        # Audit-attribution exclusion (PRR-005): rows are per-checkpoint and
        # carry no VM name, and the wrapper's adoption gate is dict-only, so
        # by-id calls here audit under the empty caller name — documented
        # permanent fallback, never a fabricated name.
        return _run_guest_tool(  # type: ignore[return-value]
            "hyperv_checkpoint_list", vm_name, "read",
            lifecycle.checkpoint_list, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_checkpoint_restore(
        vm_name: str = "", checkpoint_name: str = "", confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Restore a VM to a checkpoint. ALL STATE SINCE THE CHECKPOINT IS
        DISCARDED. The VM ends in the state the checkpoint captured — most
        often Off for Production checkpoints and Saved/Running for Standard
        ones, but the reported state (and note) is always what was observed,
        never inferred from the checkpoint type.

        Args:
            vm_name:         Name of the VM
            checkpoint_name: Name of the checkpoint to restore
            confirm:         Must be true (destructive.require_confirm)
            vm_id:           Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {status, vm_name, checkpoint_name, state, note}

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_checkpoint_restore", vm_name, "destructive",
            lifecycle.checkpoint_restore, _cfg(), vm_name,
            checkpoint_name=checkpoint_name, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_checkpoint_remove(
        vm_name: str = "", checkpoint_name: str = "", include_subtree: bool = False,
        confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Remove a checkpoint, optionally with its whole child subtree.
        Merged disks cannot be undone afterwards.

        Args:
            vm_name:         Name of the VM
            checkpoint_name: Name of the checkpoint to remove
            include_subtree: Also remove all child checkpoints
            confirm:         Must be true (destructive.require_confirm)
            vm_id:           Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {status, vm_name, checkpoint_name}

        Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).        """
        return _run_guest_tool(
            "hyperv_checkpoint_remove", vm_name, "destructive",
            lifecycle.checkpoint_remove, _cfg(), vm_name,
            checkpoint_name=checkpoint_name, include_subtree=include_subtree,
            confirm=confirm, vm_id=vm_id,
        )

    # ---- KD setup ---------------------------------------------------------

    if creds_allowed:

        @mcp.tool()
        def hyperv_configure_kdnet(
            vm_name: str = "", host_ip: str = "", port: int = 50000, key: str = "",
            reboot: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Configure KDNET (network kernel debugging) in a guest via
            PowerShell Direct + bcdedit. Returns kernel_attach_string for
            kd-mcp. Credentials from env/credential-file, or inline
            username/password (inline requires allow_inline_credentials=true).

            Args:
                vm_name:  Name of the VM
                host_ip:  Debugger host IP on the VM's vSwitch (IPv4/IPv6)
                port:     UDP port (1024-65535)
                key:      kdnet key a.b.c.d hex — auto-generated if omitted
                reboot:   Reboot the guest after configuring
                confirm:  Must be true (destructive.require_confirm)
                vm_id:    Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {status, vm_name, host_ip, port, key,
                      kernel_attach_string, bcdedit_output, rebooting}
            Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
            """
            return _run_guest_tool(
                "hyperv_configure_kdnet", vm_name, "destructive",
                lifecycle.configure_kdnet, _cfg(), vm_name,
                host_ip=host_ip, port=port, key=key, reboot=reboot,
                confirm=confirm, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_configure_kdcom(
            vm_name: str = "", pipe_name: str = "", com_port: int = 1,
            reboot: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Configure COM-port/named-pipe kernel debugging. Maps the VM COM
            port to a host named pipe (VM must be Off/Saved) and runs bcdedit
            in the guest. Use only when KDNET is unavailable.

            Args:
                vm_name:   Name of the VM
                pipe_name: Named pipe path — auto-generated if omitted
                com_port:  1 or 2 (default 1)
                confirm:   Must be true (destructive.require_confirm)
                vm_id:     Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {status, vm_name, com_port, pipe_path,
                      kernel_attach_string, bcdedit_output, rebooting}
            Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
            """
            return _run_guest_tool(
                "hyperv_configure_kdcom", vm_name, "destructive",
                lifecycle.configure_kdcom, _cfg(), vm_name,
                pipe_name=pipe_name, com_port=com_port, reboot=reboot,
                confirm=confirm, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

    else:

        @mcp.tool()
        def hyperv_configure_kdnet(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", host_ip: str = "", port: int = 50000, key: str = "",
            reboot: bool = False, confirm: bool = False, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Configure KDNET (network kernel debugging) in a guest via
            PowerShell Direct + bcdedit. Returns kernel_attach_string for
            kd-mcp. Credentials come from HYPERV_GUEST_USERNAME +
            HYPERV_GUEST_PASSWORD (or HYPERV_GUEST_PASSWORD_FILE).

            Args:
                vm_name:  Name of the VM
                host_ip:  Debugger host IP on the VM's vSwitch (IPv4/IPv6)
                port:     UDP port (1024-65535)
                key:      kdnet key a.b.c.d hex — auto-generated if omitted
                reboot:   Reboot the guest after configuring
                confirm:  Must be true (destructive.require_confirm)
                vm_id:    Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {status, vm_name, host_ip, port, key,
                      kernel_attach_string, bcdedit_output, rebooting}
            Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
            """
            return _run_guest_tool(
                "hyperv_configure_kdnet", vm_name, "destructive",
                lifecycle.configure_kdnet, _cfg(), vm_name,
                host_ip=host_ip, port=port, key=key, reboot=reboot,
                confirm=confirm, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_configure_kdcom(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", pipe_name: str = "", com_port: int = 1,
            reboot: bool = False, confirm: bool = False, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Configure COM-port/named-pipe kernel debugging. Maps the VM COM
            port to a host named pipe (VM must be Off/Saved) and runs bcdedit
            in the guest. Credentials come from HYPERV_GUEST_USERNAME +
            HYPERV_GUEST_PASSWORD (or HYPERV_GUEST_PASSWORD_FILE).

            Args:
                vm_name:   Name of the VM
                pipe_name: Named pipe path — auto-generated if omitted
                com_port:  1 or 2 (default 1)
                confirm:   Must be true (destructive.require_confirm)
                vm_id:     Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {status, vm_name, com_port, pipe_path,
                      kernel_attach_string, bcdedit_output, rebooting}
            Failure: {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
            """
            return _run_guest_tool(
                "hyperv_configure_kdcom", vm_name, "destructive",
                lifecycle.configure_kdcom, _cfg(), vm_name,
                pipe_name=pipe_name, com_port=com_port, reboot=reboot,
                confirm=confirm, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
            )

    # ---- guest execution ------------------------------------------------

    if creds_allowed:

        @mcp.tool()
        def hyperv_guest_run_ps(
            vm_name: str = "", script: str = "", timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Run a PowerShell script inside a guest via PowerShell Direct.
            stdout/stderr are SEPARATE (0.2.0 change); exit codes are real.
            elevated=true runs at High IL via UAC RunAs (merged streams; needs
            destructive.elevated_exec + confirm).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_run_ps", vm_name, "exec",
                guestexec.guest_run_ps, _cfg(), vm_name, script,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                vm_id=vm_id, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_run(
            vm_name: str = "", command: str = "", args: list[str] | None = None,
            cwd: str | None = None, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Run an executable inside a guest via PowerShell Direct.
            Separate stdout/stderr, real exit codes. elevated=true needs
            destructive.elevated_exec + confirm.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_run", vm_name, "exec",
                guestexec.guest_run, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                vm_id=vm_id, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_put(
            vm_name: str = "", local_path: str = "", remote_path: str = "",
            confirm: bool = False, verify: bool | None = None,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Copy a host file into a guest via PowerShell Direct. Staged
            rename, parent dirs created, optional SHA-256 verification
            (verify=True, or config verify_sha256). Needs guest_write policy.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_put", vm_name, "transfer",
                filetransfer.guest_put, _cfg(), vm_name, local_path, remote_path,
                confirm=confirm, verify=verify, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_get(
            vm_name: str = "", remote_path: str = "", local_path: str = "",
            verify: bool | None = None,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Copy a guest file to the host via PowerShell Direct. Staged
            rename, local parent dirs created, optional SHA-256 verification.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_get", vm_name, "transfer",
                filetransfer.guest_get, _cfg(), vm_name, remote_path, local_path,
                verify=verify, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_read_file(
            vm_name: str = "", remote_path: str = "", max_bytes: int = 262144,
            username: str = "", password: str = "",
            vm_id: str = "",
        ) -> dict:
            """Read up to max_bytes of a guest file (base64). Bounded stream
            read; max_bytes must be >= 1.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, content_b64, bytes_read, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_read_file", vm_name, "transfer",
                filetransfer.guest_read_file, _cfg(), vm_name, remote_path, max_bytes,
                vm_id=vm_id, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_list_dir(
            vm_name: str = "", remote_path: str = "",
            username: str = "", password: str = "",
            vm_id: str = "",
        ) -> dict:
            """List a directory in the guest.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, entries: [{name, is_dir, size_bytes, modified}]}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_list_dir", vm_name, "transfer",
                filetransfer.guest_list_dir, _cfg(), vm_name, remote_path,
                vm_id=vm_id, cred_factory=lambda: _cred_args(username, password),
            )

    else:

        @mcp.tool()
        def hyperv_guest_run_ps(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", script: str = "", timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Run a PowerShell script inside a guest via PowerShell Direct.
            stdout/stderr are SEPARATE (0.2.0 change); exit codes are real.
            Credentials: HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD /
            HYPERV_GUEST_PASSWORD_FILE. elevated=true needs
            destructive.elevated_exec + confirm.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_run_ps", vm_name, "exec",
                guestexec.guest_run_ps, _cfg(), vm_name, script,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_run(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", command: str = "", args: list[str] | None = None,
            cwd: str | None = None, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Run an executable inside a guest via PowerShell Direct.
            Separate stdout/stderr, real exit codes. Credentials:
            HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD /
            HYPERV_GUEST_PASSWORD_FILE. elevated=true needs
            destructive.elevated_exec + confirm.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_run", vm_name, "exec",
                guestexec.guest_run, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_put(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", local_path: str = "", remote_path: str = "",
            confirm: bool = False, verify: bool | None = None, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Copy a host file into a guest via PowerShell Direct. Staged
            rename, parent dirs created, optional SHA-256 verification.
            Needs guest_write policy + confirm.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_put", vm_name, "transfer",
                filetransfer.guest_put, _cfg(), vm_name, local_path, remote_path,
                confirm=confirm, verify=verify, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_get(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", remote_path: str = "", local_path: str = "",
            verify: bool | None = None, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """Copy a guest file to the host via PowerShell Direct. Staged
            rename, local parent dirs created, optional SHA-256 verification.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_get", vm_name, "transfer",
                filetransfer.guest_get, _cfg(), vm_name, remote_path, local_path,
                verify=verify, vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_read_file(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", remote_path: str = "", max_bytes: int = 262144,
            vm_id: str = "",
        ) -> dict:
            """Read up to max_bytes of a guest file (base64). Bounded stream
            read; max_bytes must be >= 1.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, content_b64, bytes_read, truncated}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_read_file", vm_name, "transfer",
                filetransfer.guest_read_file, _cfg(), vm_name, remote_path, max_bytes,
                vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_list_dir(vm_name: str = "", remote_path: str = "", vm_id: str = "") -> dict:  # type: ignore[misc]  # dual registration — see _register_tools
            """List a directory in the guest.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, entries: [{name, is_dir, size_bytes, modified}]}
            or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
            """
            return _run_guest_tool(
                "hyperv_guest_list_dir", vm_name, "transfer",
                filetransfer.guest_list_dir, _cfg(), vm_name, remote_path,
                vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

    # ---- victim execution (env-only credentials, never elevated) --------

    @mcp.tool()
    def hyperv_victim_run(
        vm_name: str = "", command: str = "", args: list[str] | None = None,
        cwd: str | None = None, timeout_ms: int = 60000, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Run an executable in the guest as the unprivileged victim account
        (Medium IL). Credentials: HYPERV_GUEST_VICTIM_USERNAME /
        HYPERV_GUEST_VICTIM_PASSWORD / HYPERV_GUEST_VICTIM_PASSWORD_FILE.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
        or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_guest_tool(
            "hyperv_victim_run", vm_name, "victim",
            guestexec.victim_run, _cfg(), vm_name, command, args, cwd,
            timeout_ms=timeout_ms, vm_id=vm_id,
            cred_factory=credentials.resolve_victim,
        )

    @mcp.tool()
    def hyperv_victim_run_ps(
        vm_name: str = "", script: str = "", timeout_ms: int = 60000, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Run a PowerShell script in the guest as the unprivileged victim
        account (Medium IL). Victim credentials from environment only.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
        or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_guest_tool(
            "hyperv_victim_run_ps", vm_name, "victim",
            guestexec.victim_run_ps, _cfg(), vm_name, script,
            timeout_ms=timeout_ms, vm_id=vm_id,
            cred_factory=credentials.resolve_victim,
        )

    # ---- console (WMI screenshot / keyboard / mouse) --------------------
    # Image-returning tools (screenshot/wait_frame_change/capture_sequence)
    # return a LIST [Image, meta_dict] on success and the failure envelope
    # (as a CallToolResult) on failure, so the success shape is uniformly
    # image content + a metadata text block (the SDK converts the list:
    # ImageContent + TextContent). Input tools use the {ok,...} envelope on
    # success; every failure leaves as the shared failure envelope
    # (+ holder on busy).

    def _run_console_tool(tool: str, vm: str, category: str, fn, *args, **kwargs) -> Any:
        op = _audit(tool, vm, category)
        try:
            with op:
                result = fn(*args, **kwargs)
                # Issue #8 audit clause (PRR-004): a by-id call audited under
                # an empty caller name adopts the RESOLVED display name the
                # console module returns; never fabricated.
                if isinstance(result, dict):
                    display = result.get("vm_name") or result.get("name")
                    if not vm and display:
                        op.vm_name = str(display)
                    op.ok = bool(result.get("ok", True))
                    if not op.ok:
                        # Same contract as _run_guest_tool: module-built
                        # ok:false dicts leave as enriched failure envelopes
                        # with the audit class derived from them.
                        enriched = errors.enrich_failure(result)
                        op.error_class = enriched["error_class"]
                        return errors.failure_result(enriched)
                return result
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_console_screenshot(
        vm_name: str = "", width: int = 1024, height: int = 768, save_path: str = "",
        vm_id: str = "", format: str = "", quality: int | None = None,
        scale: float | None = None, crop: list[int] | None = None,
        if_changed_from: str = "",
    ) -> CallToolResult:
        """Capture the VM console via Hyper-V WMI (works from firmware through
        WinPE; independent of VMConnect, host foreground, guest login/network).
        Returns MCP image content plus a metadata text block:
        vm_id, dimensions, frame_hash, head resolution and scale note,
        fallback_used, capture method, and timing — the per-call cost
        breakdown (lock_wait_ms, ps_ms, ps_spawns, total_ms; the guest-marker
        trio ps_startup_ms/psdirect_session_ms/guest_ms stays null on console
        tools, whose scripts emit no marker). Fallback chain: requested → head
        native → 640x480 → 320x240. A corrupt/short payload is a structured
        error, never a successful image.

        Args:
            vm_name:  VM name (must match allowed_vm_patterns)
            vm_id:    Optional VM GUID; exactly one of vm_name/vm_id must be given
            width:    requested snapshot width (160..4096)
            height:   requested snapshot height (160..4096)
            save_path: optional host path to also save the image (host_write policy);
                      the bytes written are exactly the bytes returned
            format:   png (default), jpeg/jpg, or webp; an unsupported format is
                      refused as an invalid-input error, never silently ignored
            quality:  1..100; applies to jpeg/webp only. An out-of-range value is
                      refused whatever the format, including png — png has no
                      quality axis, so an in-range value there is accepted and
                      has no effect (it is echoed in the metadata as `quality`)
            scale:    downscale factor in (0, 1] applied after crop; 1.0 is a
                      no-op and leaves the frame byte-identical
            crop:     [left, top, right, bottom] in captured-frame pixels
            if_changed_from: a frame_hash from a previous capture, as 64 lowercase
                      hex characters; when it equals the current capture's hash
                      the tool returns metadata only (no image) and skips decode,
                      encode and the file write — but still applies the save_path
                      policy check, so an out-of-roots path is denied on both paths

        Returns: [ImageContent, TextContent(json metadata)] — the metadata alone
        when if_changed_from matches (unchanged: true).
        """
        try:
            with _audit("hyperv_console_screenshot", vm_name, "read") as op:
                img, meta = console.screenshot(
                    _cfg(), vm_name, width, height, save_path, vm_id=vm_id,
                    fmt=format, quality=quality, scale=scale, crop=crop,
                    if_changed_from=if_changed_from,
                )
                # PRR-004: by-id adoption from the console module's metadata.
                if not vm_name and meta.get("vm_name"):
                    op.vm_name = str(meta["vm_name"])
                # ImageContent is a pydantic model; the raw SDK Image
                # wrapper is not and breaks serialization across the mcp
                # versions in the CI matrix. The frame's single encoding
                # is reused instead of encoding the image a second time.
                if img is None:
                    return errors.success_result([meta])
                return errors.success_result(
                    [Image(data=img.encoded, format=img.pil_format).to_image_content(), meta]
                )
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_console_get_display_info(vm_name: str = "", vm_id: str = "") -> dict:
        """Display head resolution, keyboard/mouse device presence and state,
        and guest-channel readiness (console works in firmware/WinPE;
        PowerShell Direct needs a running supported guest OS).

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, enabled_state, head_horizontal, head_vertical,
                  keyboard_present, keyboard_enabled, mouse_present,
                  mouse_enabled, boot_epoch, guest_channel, guest_channel_note,
                  vm_id}
        """
        return _run_console_tool(
            "hyperv_console_get_display_info", vm_name, "read",
            console.get_display_info, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_type_text(
        vm_name: str = "", text: str = "", vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Type ASCII text into the VM console via Msvm_Keyboard.TypeText
        (works pre-login, in WinPE). Text rides the stdin channel — it never
        appears in process argv, the PowerShell script, or error records.
        Chunks over 512 chars with pacing. For non-ASCII input use
        hyperv_console_type_scancodes. Policy: console_input category.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, chunks, chars} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_type_text", vm_name, "console_input",
            console.type_text, _cfg(), vm_name, text, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_press_key(
        vm_name: str = "", key: str = "", modifiers: list[str] | None = None,
        vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Press a named key (scan-code make/break pair) with optional
        modifiers (ctrl/alt/shift incl. right- variants, win/leftwin/
        rightwin — held while key is tapped). Supported keys: enter, escape
        (esc), tab, backspace, space, capslock, up/down/left/right, delete,
        home, end, pageup, pagedown, insert, f1-f12, a-z, 0-9, punctuation
        (minus, equals, leftbracket, rightbracket, semicolon, apostrophe,
        grave, backslash, comma, period, slash — single-character aliases
        - = [ ] \\ ; ' ` , . / map to the same bytes), numpad (num0-num9,
        numdecimal, nummultiply, numsubtract, numadd, numlock, numdivide,
        numenter), and the GUI/Application keys win (alias leftwin),
        rightwin, menu (alias apps) — modifier-named keys are also valid
        bare presses (press_key(key="win") taps Win alone). Follow the press
        with hyperv_console_wait_frame_stable instead of a fixed sleep so the
        UI transition is allowed to finish. Policy:
        console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_press_key", vm_name, "console_input",
            console.press_key, _cfg(), vm_name, key, modifiers, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_key_combo(
        vm_name: str = "", keys: list[str] | None = None, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Send a key combination: modifier makes first, keys in order,
        modifier breaks last (e.g. ["ctrl", "alt", "delete"], ["win", "r"]).
        Modifiers: ctrl/alt/shift (incl. right- variants) and win/leftwin/
        rightwin; every other accepted key name is a tapped key.
        Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_key_combo", vm_name, "console_input",
            console.key_combo, _cfg(), vm_name, keys, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_type_scancodes(
        vm_name: str = "", scancodes: list[int] | None = None, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Send raw PS/2 scan codes (0..255 ints, make/break pairs included)
        via Msvm_Keyboard.TypeScancodes; chunked at 64 codes with pacing.
        Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_type_scancodes", vm_name, "console_input",
            console.type_scancodes, _cfg(), vm_name, scancodes, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_mouse_move(
        vm_name: str = "", x: int | None = None, y: int | None = None,
        frame_width: int = 0, frame_height: int = 0, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Position the synthetic mouse. Coordinates are in the space of the
        image you observed; give frame_width/frame_height (the snapshot
        dimensions) to scale them to display-head space. Without frame dims
        the head resolution must be available, else the tool errors rather
        than clicking blind. x and y are REQUIRED — omission is an invalid
        call (it never means (0,0); call hyperv_console_click with no
        coordinates for a click at the current position). Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, operation, vm_name, head_x, head_y} or the failure
        envelope {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_console_tool(
            "hyperv_console_mouse_move", vm_name, "console_input",
            console.mouse_move, _cfg(), vm_name, x, y, frame_width, frame_height,
            vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_click(
        vm_name: str = "", x: int | None = None, y: int | None = None,
        frame_width: int = 0, frame_height: int = 0, button: int = 1,
        vm_id: str = "", lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Click at frame-space coordinates (optional; positions first when
        both x/y are given — (0,0) is a real coordinate and moves the pointer
        to the frame origin — else clicks at the current position when both
        are omitted; exactly one raises an error). Coordinates are in the
        space of the image you observed; frame_width/frame_height (the
        snapshot dimensions) only scale them — the display head resolution
        must be resolvable either way, else the tool errors rather than
        clicking blind, and absolute positioning needs the synthetic mouse
        (PS/2-fallback guests support only click-at-current-position, i.e.
        omitting x/y). button: 1=left, 2=right. Verify placement with a
        screenshot between steps — never assume focus from a prior frame —
        and follow the click with hyperv_console_wait_frame_stable instead of
        a fixed sleep so the UI transition is allowed to finish.
        Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, operation, head_x?, head_y?} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_click", vm_name, "console_input",
            console.click, _cfg(), vm_name, x, y, frame_width, frame_height, button,
            vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_button(
        vm_name: str = "", button: int = 1, is_down: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Hold or release a mouse button (raw SetButtonState; for drag
        gestures). Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, operation} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_button", vm_name, "console_input",
            console.mouse_button, _cfg(), vm_name, button, is_down, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_scroll(
        vm_name: str = "", delta: int = 0, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Scroll the console wheel by delta (positive = down).
        Policy: console_input.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, operation} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy)
        """
        return _run_console_tool(
            "hyperv_console_scroll", vm_name, "console_input",
            console.scroll, _cfg(), vm_name, delta, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_console_wait_frame_change(
        vm_name: str = "", baseline_hash: str = "", width: int = 640, height: int = 480,
        timeout_s: int = 60, interval_s: int = 2, vm_id: str = "",
    ) -> CallToolResult:
        """Poll the console until the frame changes (or the deadline passes).
        Bounded: polls = ceil(timeout_s/interval_s), deadline enforced
        host-side. Returns [ImageContent(image/png), TextContent(json)] when
        changed — {stop_reason: changed|deadline, polls, elapsed_ms,
        frame_hash, width, height} in the text block — or a deadline dict
        with no image. Never invents text for what is on screen: interpret
        the returned image visually.

        Args:
            vm_name:        VM name (must match allowed_vm_patterns)
            vm_id:          Optional VM GUID; exactly one of vm_name/vm_id must be given
            baseline_hash:  frame_hash from a previous capture ("" compares
                            against nothing — first poll's frame is baseline)
        """
        try:
            with _audit("hyperv_console_wait_frame_change", vm_name, "read") as op:
                out = console.wait_frame_change(
                    _cfg(), vm_name, baseline_hash, width, height, timeout_s,
                    interval_s, vm_id=vm_id
                )
                meta = {k: v for k, v in out.items() if k != "image"}
                # PRR-004: by-id adoption from the console module's metadata.
                if not vm_name and meta.get("vm_name"):
                    op.vm_name = str(meta["vm_name"])
                if "image" in out:
                    return errors.success_result(
                        [Image(data=out["image"].png, format="png").to_image_content(), meta]
                    )
                return errors.success_result([meta])
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_console_wait_frame_stable(
        vm_name: str = "", stable_ms: int = 1500, timeout_s: int = 30,
        interval_ms: int = 250, width: int = 640, height: int = 480,
        baseline_hash: str = "", vm_id: str = "",
    ) -> CallToolResult:
        """Poll the console until the frame has been unchanged for stable_ms
        (the settle wait: the animation finished, the dialog painted). Bounded:
        polls = ceil(timeout_s*1000/interval_ms), deadline enforced host-side,
        interval_ms floor 100. With baseline_hash the quiet window starts only
        at the first frame that DIFFERS from it — "my input did nothing" is
        then stop_reason=unchanged, not stable. Returns [ImageContent,
        meta_text] when settled — {stop_reason: stable|unchanged|deadline,
        stable, polls, elapsed_ms, frame_hash, stable_ms_measured, width,
        height, hash_domain} — or a meta-only dict with stable=false otherwise.
        The returned frame_hash chains into baseline_hash and carries
        hash_domain (refuse a baseline recorded in a different domain, as with
        wait_frame_change). A quiet window longer than
        (polls - 1) * interval_ms cannot be observed within the poll cap and
        honestly reports deadline. Never invents screen text: interpret the
        returned image visually. Follow every click or key press with this
        instead of a fixed sleep.

        Args:
            vm_name:        VM name (must match allowed_vm_patterns)
            vm_id:          Optional VM GUID; exactly one of vm_name/vm_id must be given
            stable_ms:      Required quiet window (>= 1 and < timeout_s*1000)
            timeout_s:      Overall deadline (>= 1); the host-side child bound is timeout_s + 15
            baseline_hash:  frame_hash from before the input ("" settles on the
                            current screen — first poll starts the quiet window)
        """
        try:
            with _audit("hyperv_console_wait_frame_stable", vm_name, "read") as op:
                out = console.wait_frame_stable(
                    _cfg(), vm_name, stable_ms, timeout_s, interval_ms,
                    width, height, baseline_hash, vm_id=vm_id,
                )
                meta = {k: v for k, v in out.items() if k != "image"}
                # PRR-004: by-id adoption from the console module's metadata.
                if not vm_name and meta.get("vm_name"):
                    op.vm_name = str(meta["vm_name"])
                if "image" in out:
                    return errors.success_result(
                        [Image(data=out["image"].png, format="png").to_image_content(), meta]
                    )
                return errors.success_result([meta])
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_console_capture_sequence(
        vm_name: str = "", count: int = 3, interval_s: int = 2,
        width: int = 640, height: int = 480, vm_id: str = "",
    ) -> CallToolResult:
        """Capture a bounded sequence of console frames with per-frame hashes
        and changed-byte counts vs the previous frame (transition evidence,
        not progress inference). Returns [first Image, last Image, meta_text]
        (a single Image when count==1) where meta carries frames[] (index,
        vm_id — the GUID that frame actually captured, null when its process
        emitted no identity; a sequence spanning two identities aborts with a
        structured error), frame_hash, changed_bytes_vs_previous,
        captured_at), elapsed_ms, dimensions.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given
        """
        try:
            with _audit("hyperv_console_capture_sequence", vm_name, "read") as op:
                out = console.capture_sequence(
                    _cfg(), vm_name, count, interval_s, width, height, vm_id=vm_id
                )
                meta = {k: v for k, v in out.items() if k != "images"}
                # PRR-004: by-id adoption from the console module's metadata.
                if not vm_name and meta.get("vm_name"):
                    op.vm_name = str(meta["vm_name"])
                parts: list = []
                for frame in out["images"]:
                    parts.append(
                        Image(data=frame.png, format="png").to_image_content()
                    )
                parts.append(meta)
                return errors.success_result(parts)
        except UrlElicitationRequiredError:
            raise
        except Exception as exc:
            return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_console_sequence(
        steps: list[dict], vm_name: str = "", vm_id: str = "",
        expect_frame_hash: str = "", expect_boot_epoch: int | None = None,
        timeout_s: int = 60, request_key: str = "",
        width: int = 640, height: int = 480,
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Run a batched console action sequence as ONE plan under ONE
        per-VM lock: host-side validation of every step before anything
        spawns, one PowerShell process after GUID resolution, preconditions
        evaluated inside the locked region before the first input, per-step
        results with stop-on-failure (later steps reported skipped, never
        dropped). Step grammar (mirrors the single-step tools):
        {"action": "press_key", "key", "modifiers"?},
        {"action": "key_combo", "keys"},
        {"action": "type_text", "text"} (ASCII; rides stdin base64, never the
        script), {"action": "type_scancodes", "scancodes"},
        {"action": "mouse_move", "x", "y", "frame_width"?, "frame_height"?},
        {"action": "click", "x"?, "y"?, "frame_width"?, "frame_height"?,
        "button"?}, {"action": "mouse_button", "button", "is_down"},
        {"action": "scroll", "delta"}, {"action": "wait_frame_stable",
        "stable_ms", "timeout_s"?, "interval_ms"?, "baseline_hash"?} (in-sequence
        wait steps accept interval_ms >= 1; the call timeout_s bounds the whole
        plan, so the standalone tool's >= 100 floor does not apply). Bounded:
        at most 50 steps, every wait budget capped by timeout_s, summed wait
        budgets must fit timeout_s, the PowerShell child deadline at
        timeout_s + 15. expect_frame_hash (the
        pixel-only frame_hash captured at the same width/height) and
        expect_boot_epoch (get_display_info's boot_epoch, ±5 s tolerance) are
        checked AFTER admission and BEFORE any input; a mismatch returns
        {ok: false, error_class: "precondition", steps: []} with the actual
        value and sends nothing. With request_key, an uncertain post-dispatch
        outcome (timed-out leg) records UNKNOWN once and a retry with the
        same key returns the recorded result instead of re-driving the guest
        (no automatic replay). request_key is a caller-managed namespace — keys
        are not validated against VM or plan, and the replay lookup happens
        before addressing/policy checks, so keep keys unique per plan. The
        UNKNOWN record and deadline enforcement are PowerShell-transport
        behaviors; the WMI transport carries no per-call timeout. One audit
        record replaces N single-step calls.
        Policy: console_input category; no confirm parameter.

        Args:
            steps:             1..50 step dicts (grammar above); invalid steps
                               raise ValueError naming the step index before
                               any PowerShell runs
            vm_name:           VM name (must match allowed_vm_patterns)
            vm_id:             Optional VM GUID; exactly one of vm_name/vm_id must be given
            expect_frame_hash: "" or 64-char hex sha256 captured at width x height
            expect_boot_epoch: integer from hyperv_console_get_display_info, or None
            timeout_s:         Overall deadline (>= 1); child bound is timeout_s + 15
            request_key:       Optional correlation key for the UNKNOWN
                               no-replay contract
            width:             Capture geometry shared by preconditions and wait steps
            height:            Capture geometry shared by preconditions and wait steps
        """
        return _run_console_tool(
            "hyperv_console_sequence", vm_name, "console_input",
            console.run_sequence, _cfg(), vm_name, steps, vm_id=vm_id,
            expect_frame_hash=expect_frame_hash,
            expect_boot_epoch=expect_boot_epoch, timeout_s=timeout_s,
            request_key=request_key, width=width, height=height,
        )

    @mcp.tool()
    def hyperv_wait_vm_state(
        vm_name: str = "", states: list[str] | None = None, timeout_s: int = 300,
        vm_id: str = "",
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Wait (bounded) until the VM reaches one of the requested states.
        states must be from: Off, Running, Saved, Paused, Starting, Stopping,
        Resuming, Pausing. Reports guest-channel readiness for handoff:
        console input works in firmware/WinPE, PowerShell Direct only after
        Windows boots — verify hyperv_console_get_display_info before
        switching channels.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, final_state, guest_channel} — {ok: false, error_class:
        "transport"} carrying the last observed state if the deadline
        expires first.
        """

        def _wait() -> dict:
            if not states:
                raise ValueError("states list is required")
            for s in states:
                if s not in lifecycle.VALID_STATES:
                    raise ValueError(
                        f"invalid state {s!r}; must be one of {lifecycle.VALID_STATES} "
                        "(strict validation: no shell metacharacters possible)"
                    )
            final = lifecycle.wait_for_vm_state(
                _cfg(), vm_name, list(states), timeout_s, vm_id=vm_id
            )
            # wait_for_vm_state returns the bare state string; by-id waits
            # audit under the empty caller name (documented PRR-005 fallback —
            # no fabricated name).
            return {"ok": True, "final_state": final, "guest_channel": "ps_direct_unverified"}

        return _run_guest_tool("hyperv_wait_vm_state", vm_name, "read", _wait)

    # ---- VM / media preparation (deployment testing) ---------------------

    @mcp.tool()
    def hyperv_vm_create(
        name: str, vhd_path: str, memory_mb: int = 2048, cpu_count: int = 1,
        generation: int = 2, vhd_size_gb: int = 64, switch_name: str = "",
        confirm: bool = False,
        lease_id: str = "", fencing_token: int = 0,
        detach: bool = False, idempotency_key: str = "",
    ) -> dict:
        """Create a disposable VM with a fresh VHDX (New-VHD + New-VM). The
        new name must match allowed_vm_patterns so it stays policy-scoped.
        Policy: vm_provision category + confirm=true.

        Returns: {ok, id, name, state, generation} or the failure envelope
        {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_create", name, "vm_provision",
            media.vm_create, _cfg(), name,
            memory_mb=memory_mb, cpu_count=cpu_count, generation=generation,
            vhd_path=vhd_path, vhd_size_gb=vhd_size_gb, switch_name=switch_name,
            confirm=confirm,
        )

    @mcp.tool()
    def hyperv_vm_disk_add(
        vm_name: str = "", path: str = "", size_gb: int = 0,
        controller_type: str = "SCSI", confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Create and attach an additional VHDX (for multi-disk deployment
        tests). Policy: vm_provision + confirm=true.

        Args:
            vm_name: Name of the VM
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, vhd_path, disk_count} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        disk_count is null if the post-add read failed (the disk is attached
        either way).
        """
        return _run_guest_tool(
            "hyperv_vm_disk_add", vm_name, "vm_provision",
            media.vm_disk_add, _cfg(), vm_name,
            path=path, size_gb=size_gb, controller_type=controller_type,
            confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_disk_list(vm_name: str = "", vm_id: str = "") -> dict:
        """List the VM's hard disks (controller type/number, LUN, path) —
        use to verify disk topology before deployment runs.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, disks: [...]}
        """
        return _run_guest_tool(
            "hyperv_vm_disk_list", vm_name, "read",
            media.vm_disk_list, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_media_attach(
        vm_name: str = "", iso_path: str = "", vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Attach an ISO to a virtual DVD drive (Add-VMDvdDrive). Verify the
        ISO is the intended, freshly built media before claiming a deployment
        tests new fixes. Policy: media category (reversible, no confirm).
        iso_path requires host_read policy.

        Args:
            vm_name: Name of the VM
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, iso_path, attached} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        attached is null if the post-attach read failed (the ISO is attached
        either way).
        """
        return _run_guest_tool(
            "hyperv_vm_media_attach", vm_name, "media",
            media.vm_media_attach, _cfg(), vm_name, iso_path=iso_path, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_media_detach(
        vm_name: str = "", vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Detach all virtual DVD drives; returns the removed ISO paths.
        Policy: media category (reversible, no confirm).

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, removed: [...]} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_media_detach", vm_name, "media",
            media.vm_media_detach, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_media_list(vm_name: str = "", vm_id: str = "") -> dict:
        """List virtual DVD drives and attached ISO paths.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, media: [...]}
        """
        return _run_guest_tool(
            "hyperv_vm_media_list", vm_name, "read",
            media.vm_media_list, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_firmware_get(vm_name: str = "", vm_id: str = "") -> dict:
        """Firmware state for Gen2 VMs: SecureBoot, template, boot order,
        TPM enabled. Generation 1 returns an explicit error.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, secure_boot, secure_boot_template, boot_order, tpm_enabled}
        """
        return _run_guest_tool(
            "hyperv_vm_firmware_get", vm_name, "read",
            media.vm_firmware_get, _cfg(), vm_name, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_firmware_set_boot_order(
        vm_name: str = "", boot_type: str = "Drive", confirm: bool = False,
        vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Set the first boot device by type (Drive | Network | File) — e.g.
        boot from attached DVD media. Policy: vm_provision + confirm=true.
        Generation 1 returns an explicit error.

        Args:
            vm_name: Name of the VM
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, first_boot} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_firmware_set_boot_order", vm_name, "vm_provision",
            media.vm_firmware_set_boot_order, _cfg(), vm_name,
            boot_type=boot_type, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_tpm_set(
        vm_name: str = "", *, enabled: bool, confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Enable or disable the virtual TPM (Gen2 only).
        Policy: vm_provision + confirm=true.

        Args:
            vm_name: Name of the VM
            enabled: REQUIRED — true to enable, false to disable (omission is
                     a schema error; it never silently defaults to disable)
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, tpm_enabled, vm_name} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_tpm_set", vm_name, "vm_provision",
            media.vm_tpm_set, _cfg(), vm_name,
            enabled=enabled, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_secureboot_set(
        vm_name: str = "", *, enabled: bool, template: str = "",
        confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Enable or disable Secure Boot (Gen2 only), optionally setting the
        template (e.g. MicrosoftWindows, MicrosoftUEFICertificateAuthority).
        Policy: vm_provision + confirm=true.

        Args:
            vm_name: Name of the VM
            enabled: REQUIRED — true to enable, false to disable (omission is
                     a schema error; it never silently defaults to disable)
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, secure_boot, secure_boot_template, vm_name} or the
        failure envelope {ok: false, error, error_class, retryable,
        retry_after_ms}.
        """
        return _run_guest_tool(
            "hyperv_vm_secureboot_set", vm_name, "vm_provision",
            media.vm_secureboot_set, _cfg(), vm_name,
            enabled=enabled, template=template, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_get_video(vm_name: str = "", vm_id: str = "") -> dict:
        """Current VM video settings: the host-configured resolution type
        (returned Title-case: Single/Maximum/Default) and dimensions from
        Get-VMVideo, plus the observed head resolution read from
        Msvm_VideoHead (meaningful only while the VM is running; null
        otherwise). Read-only.

        vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, resolution_type, horizontal, vertical,
                  observed_horizontal, observed_vertical, vm_name} or the
        failure envelope {ok: false, error, error_class, retryable,
        retry_after_ms}.
        """
        return _run_guest_tool(
            "hyperv_vm_get_video", vm_name, "read",
            media.vm_get_video, _cfg(), vm_name,
            vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_set_resolution(
        vm_name: str = "", width: int = 0, height: int = 0,
        resolution_type: str = "single", restart: bool = False,
        confirm: bool = False, vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Set the VM display resolution via Set-VMVideo so modern apps are
        not stuck at 1024x768. resolution_type "single" forces exactly
        width x height; "maximum" allows that size and smaller standard
        modes; "default" reverts and ignores width/height. The host REFUSES
        Set-VMVideo on a running VM: without restart=true the VM must be
        stopped (the change applies at its next start and the result says
        effective_after_restart: true). With restart=true the tool stops the
        VM first (hard power-off via TurnOff — NOT a graceful shutdown; an
        already-stopped VM is simply started), sets the mode while off, then
        starts it — behind the destructive stop category + confirm=true —
        and reports the observed post-start head (a mid-leg failure
        compensates with a best-effort start so the VM is not stranded
        off). Observed_* values come from Msvm_VideoHead, never from the
        request, and the guest's display driver may keep its own mode, so
        observed_* can differ from the configured values (or be null while
        the VM is off).
        Gen1 VMs are unverified; unsupported modes are refused by the host.
        Enhanced Session Mode is out of scope.
        Policy: display (no confirm); restart=true additionally
        destructive.stop + confirm=true. Audit category: "destructive" when
        restart=true (the power-cycle), else "display".

        Args:
            vm_name: Name of the VM
            width: Horizontal resolution in pixels (160..4096; required
                   unless resolution_type is "default")
            height: Vertical resolution in pixels (160..4096; required
                    unless resolution_type is "default")
            resolution_type: single | maximum | default
            restart: stop/start the VM now so the mode applies immediately
            confirm: required for the stop/start when restart=true
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, resolution_type, horizontal, vertical,
                  observed_horizontal, observed_vertical,
                  effective_after_restart, vm_name} (state added on the
                  restart path) or the failure envelope {ok: false, error,
                  error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_set_resolution", vm_name,
            "destructive" if restart else "display",
            media.vm_set_resolution, _cfg(), vm_name,
            width=width, height=height, resolution_type=resolution_type,
            restart=restart, confirm=confirm, vm_id=vm_id,
        )

    @mcp.tool()
    def hyperv_vm_network_set(
        vm_name: str = "", switch_name: str = "", vm_id: str = "",
        lease_id: str = "", fencing_token: int = 0,
    ) -> dict:
        """Connect the VM's network adapter to a virtual switch.
        Policy: media category (reversible, no confirm).

        Args:
            vm_name: Name of the VM
            vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

        Returns: {ok, switch_name} or {ok: false, error, error_class, retryable, retry_after_ms} (+ holder on busy).
        """
        return _run_guest_tool(
            "hyperv_vm_network_set", vm_name, "media",
            media.vm_network_set, _cfg(), vm_name,
            switch_name=switch_name, vm_id=vm_id,
        )

    # ---- guest access diagnostics, repair, jobs, recovery, relay,
    # evidence (0.3.0). Cred tools come in dual variants like the guest
    # family above; job/relay follow-ups address the host-side registries
    # (credentials were resolved and stored at start time).

    if creds_allowed:

        @mcp.tool()
        def hyperv_diagnose_vm_access(
            vm_name: str = "", timeout_ms: int = 90000,
            username: str = "", password: str = "",
            vm_id: str = "",
        ) -> dict:
            """One-call guest access diagnostic: host VM state, guest
            identity, current guest IPs, PowerShell Direct availability,
            sshd/WinRM service state, SSH/WinRM listeners, and findings
            naming the exact failure (e.g. SSH bound to obsolete guest IPs).
            Read-only (vm policy only).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, vm, ps_direct, guest, findings, checked_at}.
            """
            return _run_guest_tool(
                "hyperv_diagnose_vm_access", vm_name, "read",
                diagnostics.diagnose_vm_access, _cfg(), vm_name,
                timeout_ms=timeout_ms, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_repair_guest_access(
            vm_name: str = "", apply: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Propose (dry run, default) or apply narrow guest access fixes:
            stale SSH ListenAddress bindings (config backed up first;
            firewall repair may widen an existing disabled Any-port rule,
            disclosed in the plan text), starting stopped sshd/WinRM,
            enabling EXISTING disabled firewall allow rules. Apply requires
            guest_repair=true AND confirm=true;
            every applied change is re-verified and reported.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, applied, plan, changes,
            verification_findings[, backup_path]}.
            """
            return _run_guest_tool(
                "hyperv_repair_guest_access", vm_name, "guest_repair",
                repair.repair_guest_access, _cfg(), vm_name,
                apply=apply, confirm=confirm, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_job_start(
            vm_name: str = "", command: str = "", args: list[str] | None = None,
            cwd: str = "", timeout_ms: int = 60000,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Start a guest command as a managed job WITHOUT waiting.
            Returns a job_id plus the guest PID, the process start time used
            to identify it, and the output-file paths; poll with
            hyperv_guest_job_status, read with hyperv_guest_job_output, stop
            that process and its descendants with hyperv_guest_job_stop
            (descendants are killed even when the wrapper already exited).
            The wrapper records the observed outcome — a native exit code,
            or 1 for a failed cmdlet / command-not-found; caveat: a .ps1
            target whose final statement is a failed cmdlet without an
            explicit exit records the last code the script set (0 when it
            never set one), because PS 5.1 does not propagate a failed
            callee across the script boundary.
            Non-elevated (elevated start cannot capture output).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, job_id, vm_name, pid, start_time_ticks, job_dir, out_path, err_path, exit_path, started_at}.
            """
            return _run_guest_tool(
                "hyperv_guest_job_start", vm_name, "exec",
                guestjobs.job_start, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
                owner=auditlog.current_agent_id(),
            )

        @mcp.tool()
        def hyperv_wait_guest_recovery(
            vm_name: str = "", services: list[str] | None = None,
            processes: list[str] | None = None, timeout_s: int = 300,
            interval_s: int = 3, username: str = "", password: str = "",
            vm_id: str = "",
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """After a restart, wait (bounded) for PowerShell Direct to
            answer, then verify each named service is Running and each named
            process exists; reports per-item results and what failed.

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, ps_direct, services, processes, failures, checked_at}.
            """
            return _run_guest_tool(
                "hyperv_wait_guest_recovery", vm_name, "read",
                diagnostics.wait_guest_recovery, _cfg(), vm_name,
                services, processes, timeout_s=timeout_s, interval_s=interval_s,
                vm_id=vm_id, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_relay_start(
            vm_name: str = "", guest_port: int = 0, host_port: int = 0,
            username: str = "", password: str = "",
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Start a loopback-only host HTTP listener forwarding requests
            through PowerShell Direct to the guest's 127.0.0.1:guest_port —
            reach guest-local web endpoints and DevTools HTTP APIs with no
            dependence on guest network addresses. Policy: relay category.
            HTTP only (no WebSocket proxying).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, relay_id, url, host_port, ...}. The url is a
            capability URL embedding the relay's per-relay secret (the only
            place the secret is returned); requests without it get 401.
            """
            return _run_guest_tool(
                "hyperv_relay_start", vm_name, "relay",
                relay.relay_start, _cfg(), vm_name, guest_port,
                host_port=host_port, vm_id=vm_id,
                cred_factory=lambda: _cred_args(username, password),
                owner=auditlog.current_agent_id(),
            )

        @mcp.tool()
        def hyperv_capture_evidence(
            vm_name: str = "", width: int = 1024, height: int = 768,
            save_path: str = "", ui_tree: bool = False,
            ui_tree_depth: int = 3, ui_tree_max_elements: int = 200,
            username: str = "", password: str = "",
            vm_id: str = "", format: str = "", quality: int | None = None,
            scale: float | None = None, crop: list[int] | None = None,
            if_changed_from: str = "",
        ) -> CallToolResult:
            """Capture console evidence in one call: screenshot paired with
            captured_at, vm_id, dimensions and frame hash, plus an optional
            bounded guest UI element tree (requires guest credentials; the
            screenshot alone does not). The metadata also carries the per-call
            timing breakdown (lock_wait_ms, ps_ms, ps_spawns, total_ms;
            guest-marker keys null unless a leg emitted a marker).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given
                width:  requested screenshot width in pixels (160..4096)
                height: requested screenshot height in pixels (160..4096)
                save_path: optional host path to also write the PNG/encoded image
                ui_tree: also fetch a bounded guest UI element tree (needs credentials)
                ui_tree_depth: tree walk depth, clamped to 1..6
                ui_tree_max_elements: element cap, clamped to 1..500
                username: guest username for the UI-tree leg (or set HYPERV_GUEST_USERNAME)
                password: guest password for the UI-tree leg (or set HYPERV_GUEST_PASSWORD)
                format:  png (default), jpeg/jpg, or webp; an unsupported format
                         is refused as an invalid-input error
                quality: 1..100; applies to jpeg/webp only. An out-of-range value
                         is refused whatever the format, including png — png has
                         no quality axis, so an in-range value there is accepted
                         and has no effect
                scale:   downscale factor in (0, 1] applied after crop
                crop:    [left, top, right, bottom] in captured-frame pixels
                if_changed_from: a frame_hash from a previous capture, as 64
                         lowercase hex characters; when it equals the current
                         capture's hash the tool returns metadata only and skips
                         decode, encode, the file write AND the UI-tree leg
                         (meta["ui_tree"] then reports why it was skipped)

            Returns: [ImageContent, TextContent(metadata)] on success — the
            metadata alone when if_changed_from matches.
            """
            try:
                with _audit("hyperv_capture_evidence", vm_name, "read"):
                    cred = _cred_args(username, password) if ui_tree else None
                    result = evidence.capture_evidence(
                        _cfg(), vm_name, width, height, save_path,
                        ui_tree=ui_tree, ui_tree_depth=ui_tree_depth,
                        ui_tree_max_elements=ui_tree_max_elements, cred=cred,
                        vm_id=vm_id, fmt=format, quality=quality, scale=scale,
                        crop=crop, if_changed_from=if_changed_from,
                    )
                    return errors.success_result(_image_meta_content(result))
            except UrlElicitationRequiredError:
                raise
            except Exception as exc:
                return errors.failure_result(errors.envelope(exc))

    else:

        @mcp.tool()
        def hyperv_diagnose_vm_access(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", timeout_ms: int = 90000, vm_id: str = ""
        ) -> dict:
            """One-call guest access diagnostic: host VM state, guest
            identity, current guest IPs, PowerShell Direct availability,
            sshd/WinRM service state, SSH/WinRM listeners, and findings
            naming the exact failure (e.g. SSH bound to obsolete guest IPs).
            Read-only (vm policy only). Credentials from environment only.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, vm, ps_direct, guest, findings, checked_at}.
            """
            return _run_guest_tool(
                "hyperv_diagnose_vm_access", vm_name, "read",
                diagnostics.diagnose_vm_access, _cfg(), vm_name,
                timeout_ms=timeout_ms, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_repair_guest_access(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", apply: bool = False, confirm: bool = False,
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Propose (dry run, default) or apply narrow guest access fixes:
            stale SSH ListenAddress bindings (config backed up first;
            firewall repair may widen an existing disabled Any-port rule,
            disclosed in the plan text), starting stopped sshd/WinRM,
            enabling EXISTING disabled firewall allow rules. Apply requires
            guest_repair=true AND confirm=true;
            every applied change is re-verified and reported. Credentials
            from environment only.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, applied, plan, changes, verification_findings[, backup_path]}.
            """
            return _run_guest_tool(
                "hyperv_repair_guest_access", vm_name, "guest_repair",
                repair.repair_guest_access, _cfg(), vm_name,
                apply=apply, confirm=confirm, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_job_start(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", command: str = "", args: list[str] | None = None,
            cwd: str = "", timeout_ms: int = 60000, vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Start a guest command as a managed job WITHOUT waiting.
            Returns a job_id plus the guest PID, the process start time used
            to identify it, and the output-file paths; poll with
            hyperv_guest_job_status, read with hyperv_guest_job_output, stop
            that process and its descendants with hyperv_guest_job_stop
            (descendants are killed even when the wrapper already exited).
            The wrapper records the observed outcome — a native exit code,
            or 1 for a failed cmdlet / command-not-found; caveat: a .ps1
            target whose final statement is a failed cmdlet without an
            explicit exit records the last code the script set (0 when it
            never set one), because PS 5.1 does not propagate a failed
            callee across the script boundary.
            Non-elevated (elevated start cannot capture output). Credentials from
            environment only.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, job_id, vm_name, pid, start_time_ticks, job_dir, out_path, err_path, exit_path, started_at}.
            """
            return _run_guest_tool(
                "hyperv_guest_job_start", vm_name, "exec",
                guestjobs.job_start, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
                owner=auditlog.current_agent_id(),
            )

        @mcp.tool()
        def hyperv_wait_guest_recovery(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", services: list[str] | None = None,
            processes: list[str] | None = None, timeout_s: int = 300,
            interval_s: int = 3, vm_id: str = "",
        detach: bool = False, idempotency_key: str = "",
        ) -> dict:
            """After a restart, wait (bounded) for PowerShell Direct to
            answer, then verify each named service is Running and each named
            process exists; reports per-item results and what failed.
            Credentials from environment only.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, vm_name, ps_direct, services, processes, failures, checked_at}.
            """
            return _run_guest_tool(
                "hyperv_wait_guest_recovery", vm_name, "read",
                diagnostics.wait_guest_recovery, _cfg(), vm_name,
                services, processes, timeout_s=timeout_s, interval_s=interval_s,
                vm_id=vm_id, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_relay_start(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", guest_port: int = 0, host_port: int = 0,
            vm_id: str = "",
            lease_id: str = "", fencing_token: int = 0,
        ) -> dict:
            """Start a loopback-only host HTTP listener forwarding requests
            through PowerShell Direct to the guest's 127.0.0.1:guest_port —
            reach guest-local web endpoints and DevTools HTTP APIs with no
            dependence on guest network addresses. Policy: relay category.
            HTTP only (no WebSocket proxying). Credentials from environment
            only.

            vm_id: Optional VM GUID; exactly one of vm_name/vm_id must be given

            Returns: {ok, relay_id, url, host_port, ...}. The url is a
            capability URL embedding the relay's per-relay secret (the only
            place the secret is returned); requests without it get 401.
            """
            return _run_guest_tool(
                "hyperv_relay_start", vm_name, "relay",
                relay.relay_start, _cfg(), vm_name, guest_port,
                host_port=host_port, vm_id=vm_id,
                cred_factory=credentials.resolve_guest,
                owner=auditlog.current_agent_id(),
            )

        @mcp.tool()
        def hyperv_capture_evidence(  # type: ignore[misc]  # dual registration — see _register_tools
            vm_name: str = "", width: int = 1024, height: int = 768,
            save_path: str = "", ui_tree: bool = False,
            ui_tree_depth: int = 3, ui_tree_max_elements: int = 200,
            vm_id: str = "", format: str = "", quality: int | None = None,
            scale: float | None = None, crop: list[int] | None = None,
            if_changed_from: str = "",
        ) -> CallToolResult:
            """Capture console evidence in one call: screenshot paired with
            captured_at, vm_id, dimensions and frame hash, plus an optional
            bounded guest UI element tree (requires guest credentials; the
            screenshot alone does not). Credentials from environment only.
            The metadata also carries the per-call timing breakdown
            (lock_wait_ms, ps_ms, ps_spawns, total_ms; guest-marker keys null
            unless a leg emitted a marker).

            Args:
                vm_name: Name of the VM
                vm_id:   Optional VM GUID; exactly one of vm_name/vm_id must be given
                width:  requested screenshot width in pixels (160..4096)
                height: requested screenshot height in pixels (160..4096)
                save_path: optional host path to also write the encoded image
                ui_tree: also fetch a bounded guest UI element tree (needs credentials)
                ui_tree_depth: tree walk depth, clamped to 1..6
                ui_tree_max_elements: element cap, clamped to 1..500
                format:  png (default), jpeg/jpg, or webp; an unsupported format
                         is refused as an invalid-input error
                quality: 1..100; applies to jpeg/webp only. An out-of-range value
                         is refused whatever the format, including png — png has
                         no quality axis, so an in-range value there is accepted
                         and has no effect
                scale:   downscale factor in (0, 1] applied after crop
                crop:    [left, top, right, bottom] in captured-frame pixels
                if_changed_from: a frame_hash from a previous capture, as 64
                         lowercase hex characters; when it equals the current
                         capture's hash the tool returns metadata only and skips
                         decode, encode, the file write AND the UI-tree leg
                         (meta["ui_tree"] then reports why it was skipped)

            Returns: [ImageContent, TextContent(metadata)] on success — the
            metadata alone when if_changed_from matches.
            """
            try:
                with _audit("hyperv_capture_evidence", vm_name, "read"):
                    cred = credentials.resolve_guest() if ui_tree else None
                    result = evidence.capture_evidence(
                        _cfg(), vm_name, width, height, save_path,
                        ui_tree=ui_tree, ui_tree_depth=ui_tree_depth,
                        ui_tree_max_elements=ui_tree_max_elements, cred=cred,
                        vm_id=vm_id, fmt=format, quality=quality, scale=scale,
                        crop=crop, if_changed_from=if_changed_from,
                    )
                    return errors.success_result(_image_meta_content(result))
            except UrlElicitationRequiredError:
                raise
            except Exception as exc:
                return errors.failure_result(errors.envelope(exc))

    @mcp.tool()
    def hyperv_guest_job_status(job_id: str) -> dict:
        """Report a managed guest job: running / exited (with exit code) /
        exiting / stopped (`exiting` is not terminal: if the guest wrapper
        died before writing its exit-code file, status stays `exiting`
        until hyperv_guest_job_stop is called). A live process is only
        reported `running` when its start time still matches the one
        recorded at start (PID reuse falls through to exited/exiting).
        Addresses the host-side job registry (credentials
        were stored at start time).

        Returns: {ok, job_id, pid, status[, exit_code, process_name]}.
        """
        return _run_guest_tool(
            "hyperv_guest_job_status", "", "exec",
            guestjobs.job_status, _cfg(), job_id,
            owner=auditlog.current_agent_id(),
            audit_job_id=job_id,
            # PRR-007: lazy — the store read happens inside the envelope, is
            # owner-filtered, and never runs for a local registry hit.
            audit_vm_name=lambda: guestjobs.peek_vm_name(
                job_id, _cfg(), owner=auditlog.current_agent_id()),
        )

    @mcp.tool()
    def hyperv_guest_job_output(job_id: str, tail_bytes: int = 65536) -> dict:
        """Read the captured stdout/stderr of a managed guest job, bounded to
        the last tail_bytes per stream. Encoding is BOM-sniffed from the
        stream head (PS 5.1 redirection may write UTF-16LE) and reported.

        Returns: {ok, job_id, pid, tail_bytes, stdout, stderr, *_truncated, *_encoding, *_size}.
        """
        return _run_guest_tool(
            "hyperv_guest_job_output", "", "exec",
            guestjobs.job_output, _cfg(), job_id, tail_bytes=tail_bytes,
            owner=auditlog.current_agent_id(),
            audit_job_id=job_id,
            audit_vm_name=lambda: guestjobs.peek_vm_name(
                job_id, _cfg(), owner=auditlog.current_agent_id()),
        )

    @mcp.tool()
    def hyperv_guest_job_stop(job_id: str, lease_id: str = "", fencing_token: int = 0) -> dict:
        """Stop the guest process of a managed job and all of its descendants,
        then report what was observed. Descendants are enumerated and killed
        EVEN when the wrapper has already exited (an orphaned child keeps
        the dead recorded PID as its Win32_Process parent, so the walk still
        finds it); `stopped` is true only when no member of the recorded
        tree was observed alive afterward. The guest temp directory is
        removed and the stored credentials released only when nothing
        survived; otherwise the job stays stoppable for a retry
        (ok: false, stopped: false, alive_pids lists the survivors, and the
        retry re-walks and re-kills whatever survived). The result carries
        the same key set on every path; a transport failure adds
        error/error_class with stopped: false. `pid_reused: true`
        means the recorded process was already gone and the PID now belongs
        to an unrelated process, which is never killed (an unreadable
        start time is an unknown, not a mismatch — nothing is killed and
        pid_reused stays false).

        Returns: {ok, job_id, pid, stopped, alive_pids, job_dir_removed, pid_reused}.
        """
        return _run_guest_tool(
            "hyperv_guest_job_stop", "", "exec",
            guestjobs.job_stop, _cfg(), job_id,
            owner=auditlog.current_agent_id(),
            audit_job_id=job_id,
            audit_vm_name=lambda: guestjobs.peek_vm_name(
                job_id, _cfg(), owner=auditlog.current_agent_id()),
        )

    @mcp.tool()
    def hyperv_relay_status(relay_id: str = "") -> dict:
        """List relays (or one) with liveness, request counters and latency.

        Returns: {ok, relays: [{relay_id, url, counters, stopped, latency,
        ...}]}. `latency` is always present and reports the guest leg's
        duration for every COMPLETED request as {cap, samples, p50_ms,
        p95_ms, p99_ms}; each percentile is null until a request has been
        recorded, so "nothing recorded yet" reads differently from
        "requests were instantaneous".
        """
        return _run_guest_tool(
            "hyperv_relay_status", "", "relay",
            relay.relay_status, _cfg(), relay_id,
            owner=auditlog.current_agent_id(),
            audit_relay_id=relay_id,
            audit_vm_name=(
                lambda: relay.peek_vm_name(
                    relay_id, _cfg(), owner=auditlog.current_agent_id())
                if relay_id else ""
            ),
        )

    @mcp.tool()
    def hyperv_relay_stop(relay_id: str, lease_id: str = "", fencing_token: int = 0) -> dict:
        """Stop a relay: close the loopback listener and release the stored
        credentials.

        Returns: {ok, relay_id, host_port, stopped}.
        """
        return _run_guest_tool(
            "hyperv_relay_stop", "", "relay",
            relay.relay_stop, _cfg(), relay_id,
            owner=auditlog.current_agent_id(),
            audit_relay_id=relay_id,
            audit_vm_name=lambda: relay.peek_vm_name(
                relay_id, _cfg(), owner=auditlog.current_agent_id()),
        )

    # ---- issue #23: the lease surface -------------------------------------
    @mcp.tool()
    def hyperv_lease_acquire(
        vm_name: str = "", vm_id: str = "", scopes: list[str] | None = None,
        ttl_s: int = 0,
    ) -> dict:
        """Acquire a lease on a VM for the calling agent.

        A lease is a multi-call exclusion: while you hold it, another agent's
        mutating tool call on the same VM is refused with the holder named.
        Scopes: lifecycle (exclusive against everything), guest_exec,
        transfer, console. Returns lease_id and fencing_token -- pass BOTH on
        every subsequent mutating call. The lease expires ttl_s seconds after
        its last renew (0 or omitted = the configured default, 300; max 3600)
        and is renewed by hyperv_lease_renew. For a VM that does not exist yet
        (hyperv_vm_create workflow) the lease keys on the raw NAME and does not
        follow a rename. Release it with hyperv_lease_release when done.
        """
        wanted = list(scopes or [])
        if not vm_name and not vm_id:
            raise ValueError("vm_name or vm_id is required")
        if not wanted:
            raise ValueError("scopes is required (at least one of: "
                             + ", ".join(leases.SCOPES) + ")")
        with _audit("hyperv_lease_acquire", vm_name, "lease") as _lease_op:
            # PolicyDenied propagates unchanged (deny-all must stay "policy").
            # Only a RESOLUTION failure -- the VM does not exist yet -- falls
            # back to the name namespace, because hyperv_vm_create must be
            # leasable before the VM exists. PolicyDenied is a RuntimeError
            # subclass, so it is caught and re-raised FIRST, unconditionally
            # (round-2 B3: the naive widening was a policy bypass).
            try:
                ref = vmident.resolve(_cfg(), vm_name=vm_name, vm_id=vm_id)
            except policy.PolicyDenied:
                raise
            except Exception:
                if vm_id:
                    raise
                # Review PRR-001: resolve can fail BEFORE the policy check
                # (vmident validates the name string first), so the fallback
                # must run the full screen itself -- checked-caller-name then
                # vm_allowed -- or a deny-all host minted lease rows for an
                # unvalidated caller-supplied string. Review PRR-008: the
                # lease keys on the RAW name (no prefix) so it matches the
                # call row hyperv_vm_create's vm_lock writes.
                name_ref = str(vm_name or "")
                vmident.checked_caller_name(name_ref)
                policy.vm_allowed(_cfg(), name_ref)
                ref = vmident.VMRef(id=name_ref, name=name_ref)
            granted = leases.acquire(
                _cfg(), ref.id, wanted, auditlog.current_agent_id(),
                ttl_s=(ttl_s or None),
                vm_name=ref.name,
            )
            # Review PRR-012: correlate the audit row with a 16-hex prefix —
            # never the full handle.
            _lease_op.lease_ref = granted[0].lease_id[:16]
            return {
                "ok": True,
                "vm_id": ref.id,
                "vm_name": ref.name,
                "lease_id": granted[0].lease_id,
                "fencing_token": granted[0].fencing_token,
                "scopes": [g.scope for g in granted],
                "expires_at": granted[0].expires_at,
                "ttl_s": granted[0].ttl_s,
                "leases": [g.as_dict(reveal=True) for g in granted],
            }

    def _owned_lease_or_invalid(lease_id: str) -> list:
        """The caller's own live lease rows, or raise ValueError -> "invalid".

        Owner-scoped ON PURPOSE (round-2 B6): under deny-all, an arbitrary
        lease_id finds no row this caller owns and is refused "unknown lease"
        as "invalid" -- never "lease_unknown", which would leak that the id
        exists and would break the deny-all census's class contract. The
        lease's VM is also policy-checked, so a lease on a VM this caller may
        not even see is refused "policy".
        """
        cfg = _cfg()
        agent = auditlog.current_agent_id()
        rows = leases.owned_rows(cfg, lease_id, agent)
        policy.vm_allowed(cfg, rows[0].vm_name or rows[0].vm_key)
        return rows

    @mcp.tool()
    def hyperv_lease_renew(lease_id: str) -> dict:
        """Renew a lease you hold: pushes its expiry to now + its own ttl.

        Call this periodically from a long workflow (a heartbeat) so the lease
        does not expire mid-flight and another agent takes the VM over. A
        lease whose TTL lapsed reports "lease_expired" and must be re-acquired.
        """
        with _audit("hyperv_lease_renew", "", "lease", lease_ref=str(lease_id)[:16]):
            _owned_lease_or_invalid(lease_id)
            renewed = leases.renew(_cfg(), lease_id, auditlog.current_agent_id())
            return {"ok": True, **renewed.as_dict(reveal=True)}

    @mcp.tool()
    def hyperv_lease_release(lease_id: str) -> dict:
        """Release a lease you hold, so other agents can use the VM again."""
        with _audit("hyperv_lease_release", "", "lease", lease_ref=str(lease_id)[:16]):
            _owned_lease_or_invalid(lease_id)
            leases.release(_cfg(), lease_id, auditlog.current_agent_id())
            return {"ok": True, "released": True}

    @mcp.tool()
    def hyperv_lease_list(vm_name: str = "", vm_id: str = "") -> dict:
        """List the leases on a VM (or on every VM when neither argument is
        given). Holder, scopes and expiry are public; lease_id and
        fencing_token appear ONLY for leases the calling agent holds."""
        with _audit("hyperv_lease_list", vm_name, "lease"):
            cfg = _cfg()
            agent = auditlog.current_agent_id()
            if vm_id or vm_name:
                ref = vmident.resolve(_cfg(), vm_name=vm_name, vm_id=vm_id)
                rows = leases.list_leases(cfg, vm_id=ref.id)
            else:
                # Review PRR-011: the unaddressed enumeration is policy-
                # filtered per row, so a deny-all (or narrow-pattern) caller
                # cannot enumerate leases on VMs it may not even see. vm_allowed
                # is a pure config check -- no spawn.
                ref = None
                rows = [
                    row for row in leases.list_leases(cfg)
                    if row.holder_agent == agent
                    or _row_vm_allowed(cfg, row)
                ]
            return {
                "ok": True,
                "vm_id": ref.id if ref else "",
                "leases": [
                    row.as_dict(reveal=bool(agent is not None
                                            and row.holder_agent == agent))
                    for row in rows
                ],
            }

    # ---- issue #24: the durable-operation / event surface ------------------
    @mcp.tool()
    def hyperv_op_status(op_id: str) -> dict:
        """Report the status of one durable operation handle.

        Returns {ok, op_id, tool, status, error_class, poll_interval_ms, ...}.
        Statuses: working, completed, failed, cancelled (input_required is
        reserved). An op whose runner heartbeat lapsed reports failed with
        error_class "interrupted" and notes the VM-side outcome is unknown.
        Operation ids are scoped to the calling agent: another agent's (or an
        unknown) id answers exactly the same refusal.
        """
        with _audit("hyperv_op_status", "", "operations"):
            return operations.op_status(_cfg(), op_id, auditlog.current_agent_id() or "")

    @mcp.tool()
    def hyperv_op_result(op_id: str, cursor: str = "") -> dict:
        """Read one operation's stored result, cursor-paged.

        Returns {ok, op_id, status, chunk, done, next_cursor}. Pages are at
        most 64 KiB of the stored (redacted) result text; re-reading from an
        earlier cursor returns identical bytes, including after a server
        restart. Refuses while the op is still working.
        """
        with _audit("hyperv_op_result", "", "operations"):
            return operations.op_result(
                _cfg(), op_id, auditlog.current_agent_id() or "", cursor
            )

    @mcp.tool()
    def hyperv_op_cancel(op_id: str) -> dict:
        """Request cooperative cancellation of a working operation.

        Returns {ok, op_id, status, cancel_requested}. The runner honours the
        request at its next leg boundary; cancelling a terminal op is a no-op
        that reports its terminal status. Scoped to the calling agent like
        every op tool.
        """
        with _audit("hyperv_op_cancel", "", "operations"):
            return operations.op_cancel(_cfg(), op_id, auditlog.current_agent_id() or "")

    @mcp.tool()
    def hyperv_op_list(include_terminal: bool = False) -> dict:
        """List the calling agent's operation handles.

        Returns {ok, ops: [{op_id, status, tool, ...}]}. Only the caller's
        own ops are listed; pass include_terminal=true to see finished ones.
        """
        with _audit("hyperv_op_list", "", "operations"):
            return operations.op_list(
                _cfg(), auditlog.current_agent_id() or "", include_terminal
            )

    @mcp.tool()
    def hyperv_events(after: str = "", limit: int = 100) -> dict:
        """Read the append-only event log from a cursor.

        Returns {ok, events: [{seq, ts, kind, ref_id, vm_id, data}],
        next_cursor}. Pass the next_cursor of a previous read as `after` to
        resume where you left off — across restarts too. A cursor older than
        the retention window answers {cursor_expired: true, oldest_cursor}.
        Events are scoped to the calling agent.
        """
        with _audit("hyperv_events", "", "operations"):
            return operations.events_read(
                _cfg(), auditlog.current_agent_id() or "", after, limit
            )

    _harden_tools(mcp)


# Issue #23: the mutating tools that accept (and require, where
# leases.required is on) a lease, mapped to the scope of VM activity each one
# belongs to. HAND-WRITTEN on purpose: deriving it from the audit categories
# over-includes hyperv_guest_read_file / hyperv_guest_list_dir, which are
# categorized "transfer" but mutate nothing. hyperv_guest_get is leased on the
# issue's own "guest put/get -> transfer" scope map although it writes only the
# host filesystem -- recorded, not silently corrected.
TOOL_SCOPES: dict[str, str] = {
    # lifecycle
    "hyperv_start_vm": "lifecycle", "hyperv_stop_vm": "lifecycle",
    "hyperv_reset_vm": "lifecycle", "hyperv_checkpoint_create": "lifecycle",
    "hyperv_checkpoint_restore": "lifecycle", "hyperv_checkpoint_remove": "lifecycle",
    "hyperv_configure_kdnet": "lifecycle", "hyperv_configure_kdcom": "lifecycle",
    "hyperv_vm_create": "lifecycle", "hyperv_vm_disk_add": "lifecycle",
    "hyperv_vm_media_attach": "lifecycle", "hyperv_vm_media_detach": "lifecycle",
    "hyperv_vm_network_set": "lifecycle",
    "hyperv_vm_firmware_set_boot_order": "lifecycle",
    "hyperv_vm_tpm_set": "lifecycle", "hyperv_vm_secureboot_set": "lifecycle",
    "hyperv_vm_set_resolution": "lifecycle",
    # guest_exec
    "hyperv_guest_run_ps": "guest_exec", "hyperv_guest_run": "guest_exec",
    "hyperv_victim_run": "guest_exec", "hyperv_victim_run_ps": "guest_exec",
    "hyperv_guest_job_start": "guest_exec", "hyperv_guest_job_stop": "guest_exec",
    "hyperv_relay_start": "guest_exec", "hyperv_relay_stop": "guest_exec",
    "hyperv_repair_guest_access": "guest_exec",
    # transfer
    "hyperv_guest_put": "transfer", "hyperv_guest_get": "transfer",
    # console
    "hyperv_console_type_text": "console", "hyperv_console_press_key": "console",
    "hyperv_console_key_combo": "console", "hyperv_console_type_scancodes": "console",
    "hyperv_console_mouse_move": "console", "hyperv_console_click": "console",
    "hyperv_console_button": "console", "hyperv_console_scroll": "console",
    "hyperv_console_sequence": "console",
}


def _row_vm_allowed(cfg: Config, row) -> bool:
    """Whether a stored lease row's VM passes the caller's vm policy."""
    try:
        policy.vm_allowed(cfg, row.vm_name or row.vm_id)
        return True
    except policy.PolicyDenied:
        return False


def _lease_gate(name: str, arguments: dict) -> tuple[dict | None, object | None]:
    """The pre-body lease check for a mutating tool (issue #23).

    Returns an ok:false envelope when the call is refused, else None. It reads
    the RAW arguments -- the two parameters exist on the signatures so the SDK
    validates them and the schema advertises them; the bodies never read them.

    Order matters: a presented lease is authorized first (unknown / not-owned /
    expired / fenced / wrong scope / wrong VM); then the required-without-lease
    refusal; then the unleased path, which is a no-op whenever nobody else
    holds a lease on the VM -- the default state of a fresh deployment.
    """
    scope = TOOL_SCOPES.get(name)
    if scope is None:
        return None, None
    cfg = _cfg()
    agent = auditlog.current_agent_id()
    lease_id = str(arguments.get("lease_id") or "")
    raw_token = arguments.get("fencing_token") or 0
    try:
        token = int(raw_token)
    except (TypeError, ValueError):
        # MINOR-13: the gate returns an ENVELOPE, never raises. A malformed
        # fencing_token used to escape the guard as a raw ValueError (the
        # SDK validates types only after this gate runs).
        env = {
            "ok": False,
            "error": "fencing_token must be an integer",
            "error_class": "invalid",
        }
        return errors.enrich_failure(env), None
    vm_hint = str(arguments.get("vm_id") or "")
    vm_name = str(arguments.get("vm_name") or "")
    vm_name_hint = vm_name
    try:
        # Review PRR-006: policy runs BEFORE any lease logic, matching
        # vmident.resolve's own ordering (checked-caller-name then vm_allowed
        # on the caller-supplied name, both before any spawn). Both are pure
        # config checks -- no PowerShell. Without this, a policy-denied caller
        # presenting a lease id got `lease_unknown` instead of `policy` (an
        # existence oracle), which B1 confirmed by probe. A call that supplies
        # neither name nor id cannot be screened here; the body's own
        # resolution raises the authoritative invalid/policy error.
        if vm_name:
            vmident.checked_caller_name(vm_name)
            policy.vm_allowed(cfg, vm_name)
        if lease_id:
            leases.authorize(cfg, lease_id, token, agent, scope,
                             vm_hint=vm_hint, vm_name_hint=vm_name_hint)
            # Issue #23 (review critical 2): present the lease to THIS call's
            # body, so the per-call row the body's vm_lock writes ADOPTS the
            # id instead of conflicting with the agent's own lease. Without
            # this, an unattributed (stdio) caller holding a lease is refused
            # by its OWN lease the moment it presents it. The ContextVar is
            # copied into the worker thread that runs the body; the guard
            # resets it in its finally.
            reset_token = leases.set_presented_lease(lease_id)
            return None, reset_token
        if getattr(cfg.leases, "required", False):
            env = {
                "ok": False,
                "error": (
                    f"{name} needs a lease on this shared controller: acquire one with "
                    f"hyperv_lease_acquire and pass its lease_id and fencing_token"
                ),
                "error_class": "lease_required",
            }
            return errors.enrich_failure(env), None
        # Unleased path. For id-addressed tools the store row supplies the VM
        # (round-3 MAJOR-6); resolution is deferred until candidates exist, so
        # a quiet system pays one indexed query and no spawn.
        if not vm_hint and not vm_name_hint and name in (
            "hyperv_guest_job_stop", "hyperv_relay_stop",
        ):
            if name == "hyperv_guest_job_stop":
                row_vm = guestjobs.peek_vm_id(arguments.get("job_id") or "", cfg,
                                              owner=agent)
            else:
                row_vm = relay.peek_vm_id(arguments.get("relay_id") or "", cfg,
                                          owner=agent)
            vm_hint = row_vm or ""
        # The conflict comparison is GUID-keyed, so the caller's name is
        # resolved to its GUID BEFORE any conflict test (round-6 note). A
        # lease probed with the raw name would have vm_key="test-vm" while the
        # stored row's vm_key is the resolved GUID, and the comparison would
        # silently miss -- which is exactly the bug the frozen AC10 run found.
        #
        # Deferred until a lease ACTUALLY exists that could conflict: this is
        # the branch that would resolve (spawn PowerShell), and paying that on
        # every mutating call would be a real regression. assert_unleased's
        # by-name query answers the common "nobody holds anything" case with
        # an indexed lookup and no spawn; only candidate rows force the GUID.
        if vm_name and not vm_hint:
            # One indexed by-name query answers the common "nobody holds
            # anything" case with no spawn. When it DOES find candidates, the
            # conflict decision still has to be made against the GUID-keyed
            # rows, so resolve the GUID (one spawn, paid only here) and
            # re-check. Resolution failing means the VM does not exist (yet):
            # the name-namespace rows ARE the authoritative identity for that
            # case (review PRR-008 -- deferring here used to leave vm_create's
            # lease with no gate at all), so probe by name and refuse on a
            # hit. The body's own vm_lock re-checks with whatever identity it
            # resolves.
            if not leases.candidates_exist_by_name(cfg, vm_name_hint, agent):
                return None, None
            try:
                ref = vmident.resolve(cfg, vm_name=vm_name)
            except Exception:
                leases.assert_unleased(cfg, agent, scope,
                                       vm_name_hint=vm_name_hint)
                return None, None
            vm_hint = ref.id
        if vm_hint or vm_name_hint:
            leases.assert_unleased(cfg, agent, scope, vm_hint=vm_hint,
                                   vm_name_hint=vm_name_hint)
        return None, None
    except leases.LeaseError as exc:
        return errors.envelope(exc), None
    except policy.PolicyDenied as exc:
        return errors.envelope(exc), None


def _harden_tools(mcp: MCPServer) -> None:
    """Stamp additionalProperties:false and reject bad calls at Tool.run.

    mcp 2.x builds argument models with pydantic's default
    extra="ignore", so an undeclared key is silently dropped before the
    tool body runs — a misspelled confirm/verify/elevated flag would fail
    open. The guard below sits at the Tool.run chokepoint (both
    MCPServer.call_tool and direct _tool_manager.call_tool traverse it) and
    handles, with one audited envelope each:

    - UNDECLARED argument keys: rejected as "invalid", argument named,
      tool body never runs.
    - Wrong-TYPED declared arguments: 2.x Tool.run wraps the pydantic
      ValidationError into ToolError before any tool body runs; the guard
      classifies it via the cause ("invalid") and delivers the same audited
      envelope instead of a raw protocol error (issue #9 review
      PRR-001/PRR-002).

    Rejections are audited HERE (one record each) because they happen
    before any tool body's audit region; the audit write is best-effort so
    a broken sink cannot turn a rejection into a raw exception. Tool is a
    pydantic BaseModel, so the wrap is installed with object.__setattr__;
    the marker attribute keeps re-registration from stacking guards.

    Note the 2.x signature: Tool.run takes `context` as a required
    positional argument (2.x passes it positionally through
    ToolManager.call_tool), so the guard must accept and forward it.
    """
    tm = getattr(mcp, "_tool_manager", None)
    tools = list(getattr(tm, "_tools", {}).values()) if tm is not None else []
    if not tools:
        # PRR-015: a silent no-op would revert unknown-argument handling to
        # pydantic's extra="ignore" fail-open. Make the SDK coupling loud.
        print(
            "[hyperv-mcp] WARNING: _harden_tools found no registered tools; "
            "unknown-argument rejection and additionalProperties stamping "
            "were NOT installed (mcp SDK shape changed?)",
            file=sys.stderr,
        )
        return
    for tool in tools:
        params = getattr(tool, "parameters", None)
        if isinstance(params, dict):
            params["additionalProperties"] = False
        if getattr(tool.run, "_unknown_arg_guard", False):
            continue
        original_run = tool.run

        def _audited_rejection(name: str, arguments: dict, env: dict) -> CallToolResult:
            args = arguments or {}
            # str()-coerce before redaction (credentials.redact raises on
            # non-str) and normalize the empty string to None, so absent ids
            # serialize as JSON null like every other audit row (issue #10).
            def _opt_id(key: str) -> str | None:
                value = str(args.get(key) or "")
                return value or None

            job_id = _opt_id("job_id")
            relay_id = _opt_id("relay_id")
            vm_name = str(args.get("vm_name") or "")
            # A short-lived collector so the rejection row reports an honest
            # breakdown: no tool body ran, so no lock was taken and no process
            # started. The peek calls below can raise, hence the try/finally.
            timing_token = timing.start()
            finished = False
            try:
                if not vm_name:
                    # A rejected by-id follow-up still knows its registry
                    # entry: resolve the VM so the row joins to the start row
                    # like the success path does (impl-review PRR-003).
                    # PRR-007: owner-filtered and guarded, so a foreign id
                    # reads "" and a store failure cannot turn a rejection
                    # into a raw exception.
                    agent_id = auditlog.current_agent_id()
                    try:
                        if job_id:
                            vm_name = guestjobs.peek_vm_name(
                                job_id, _cfg(), owner=agent_id)
                        elif relay_id:
                            vm_name = relay.peek_vm_name(
                                relay_id, _cfg(), owner=agent_id)
                    except Exception:
                        vm_name = ""
                timing_snapshot = timing.finish(timing_token)
                finished = True
            finally:
                # A peek that raised must still reset the ContextVar, or the
                # collector leaks into the event-loop task's context and every
                # later worker-thread hop inherits it.
                if not finished:
                    timing.finish(timing_token)

            try:
                auditlog.log_operation(
                    tool=name,
                    vm_name=vm_name,
                    category="",
                    ok=False,
                    error_class=str(env.get("error_class") or ""),
                    job_id=job_id,
                    relay_id=relay_id,
                    timing=timing_snapshot,
                )
            except Exception as audit_exc:  # noqa: BLE001 - best-effort: a
                # broken audit sink must not turn a rejection into a raw
                # exception with no envelope (issue #9 review PRR-014).
                print(
                    f"[hyperv-mcp] WARNING: audit write failed for a "
                    f"rejected call on {name}: {audit_exc}",
                    file=sys.stderr,
                )
            return errors.failure_result(env)

        async def guard(arguments, context=None, convert_result=False, _tool=tool, _run=original_run, **kwargs):
            declared = set((getattr(_tool, "parameters", None) or {}).get("properties", {}))
            unknown = sorted(k for k in (arguments or {}) if k not in declared)
            name = str(getattr(_tool, "name", "unknown-tool"))
            if unknown:
                shown = ", ".join(unknown[:8]) + (", ..." if len(unknown) > 8 else "")
                message = (
                    f"unknown argument(s) {shown} for {name}; "
                    f"declared arguments: {sorted(declared)}"
                )[:500]
                retryable, retry_after_ms = errors.retry_fields("invalid")
                return _audited_rejection(name, arguments, {
                    "ok": False,
                    "error": message,
                    "error_class": "invalid",
                    "retryable": retryable,
                    "retry_after_ms": retry_after_ms,
                })
            # Issue #23: the lease gate. It returns an ENVELOPE (never raises)
            # and is audited exactly like the unknown-argument rejection,
            # because it fires before any tool body's audit region. MINOR-13:
            # a raised LeaseError would escape the enveloping try below and
            # fail the deny-all census's raised == [] assertion.
            lease_env, lease_reset = _lease_gate(name, arguments or {})
            if lease_env is not None:
                return _audited_rejection(name, arguments, lease_env)
            # Issue #24: durable-operation interception - idempotency replay
            # or conflict refusal, or the detach divert. Gates have already
            # run, so a denied call never reaches here and never mints an op
            # row. The runner's context copy happens inside the consult,
            # BEFORE this finally resets the presented lease, and every exit
            # below flows through the same reset (plan-critic F4).
            try:
                tool_fn = _tool.fn
                try:
                    ops_response, ops_ctx = operations.guard_consult(
                        _cfg(), name, dict(arguments or {}),
                        tool_fn, _runner_slots,
                        preflight=lambda: _operations_preflight(
                            name, dict(arguments or {}), _tool),
                    )
                except UrlElicitationRequiredError:
                    raise
                except Exception as preflight_exc:
                    # Issue #24 (review F2): a preflight refusal
                    # (confirm/category policy, VM policy, SDK argument
                    # validation) is an ORDINARY audited rejection - the same
                    # envelope shape the sync route and the tasks route answer
                    # - never a raw escape, and it must leave the same audit
                    # record every other guard refusal writes. (MINOR-13:
                    # gates answer, they do not raise.)
                    env = errors.envelope(
                        preflight_exc.__cause__ or preflight_exc)
                    return _audited_rejection(name, arguments, env)
                if ops_response is not None:
                    if ops_response.get("ok") is False:
                        return _audited_rejection(name, arguments, ops_response)
                    return errors.success_result([
                        TextContent(text=json.dumps(
                            ops_response, separators=(",", ":"), default=str,
                        ))
                    ])
                try:
                    result = await _run(arguments, context, convert_result=convert_result, **kwargs)
                    if ops_ctx is not None:
                        operations.complete_inline(ops_ctx, result)
                    return result
                except UrlElicitationRequiredError as exc:
                    if ops_ctx is not None:
                        operations.fail_inline(ops_ctx, exc)
                    raise
                except Exception as exc:
                    # 2.x Tool.run wraps both failure shapes into a ToolError /
                    # UnexpectedToolError whose OWN text drops the original: the
                    # pydantic ValidationError for a declared-but-mistyped
                    # argument, and any tool-body crash. Classify the CAUSE so
                    # validation failures say "invalid" and crashes carry the
                    # real message (1.x ToolError parity).
                    cause = exc.__cause__
                    if cause is not None and not isinstance(cause, ValueError):
                        # A crash also never reaches the SDK's own crash logger
                        # once this guard returns an envelope, so log it here.
                        logger.exception("tool %s raised an unexpected exception", name)
                    env = errors.envelope(cause if cause is not None else exc)
                    if ops_ctx is not None:
                        operations.fail_inline(ops_ctx, cause if cause is not None else exc)
                    return _audited_rejection(name, arguments, env)
                except BaseException as exc:
                    # Review rb-1: CancelledError (client disconnect / server
                    # shutdown) is a BaseException - without this arm a sync
                    # keyed row stays working forever after a disconnect.
                    # fail_inline records the outcome; the cancellation still
                    # propagates. This arm MUST come after `except Exception`
                    # so ordinary tool errors still get the envelope path.
                    if ops_ctx is not None:
                        operations.fail_inline(ops_ctx, exc)
                    raise
            finally:
                # Issue #23: the presented lease rides only THIS call. The
                # reset must cover every exit (success, failure, rejection,
                # replay, detach) or a stale lease id leaks into the next call
                # on the same request context.
                if lease_reset is not None:
                    leases.reset_presented_lease(lease_reset)

        guard._unknown_arg_guard = True  # type: ignore[attr-defined]
        object.__setattr__(tool, "run", guard)


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hyperv-mcp", description="Hyper-V MCP server (stdio transport)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--check-env", action="store_true",
        help="print the effective policy and credential configuration, plus "
             "runtime provenance (PowerShell probe, config digest, git "
             "revision), then exit",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--proxy", metavar="URL", default=None,
        help="run as a thin stdio->streamable-HTTP proxy to the shared "
             "controller at URL (e.g. http://127.0.0.1:8787/mcp) instead of "
             "serving in-process; never starts a controller",
    )
    mode.add_argument(
        "--standalone", action="store_true",
        help="serve this client with a private in-process server (the "
             "pre-0.4.0 behavior) instead of proxying to the shared "
             "controller; coordination state stays per-process",
    )
    ns = parser.parse_args(argv)

    if ns.check_env:
        try:
            cfg = bootstrap()
        except ConfigError as exc:
            print(f"CONFIG ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"hyperv-mcp {VERSION}")
        print(cfg.policy_summary())
        host_target = cfg.hyperv.host
        print(f"hyperv.target {'remote host ' + host_target if host_target else 'local host'}")
        for name in (
            "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_PASSWORD_FILE",
            "HYPERV_GUEST_VICTIM_USERNAME", "HYPERV_GUEST_VICTIM_PASSWORD",
            "HYPERV_GUEST_VICTIM_PASSWORD_FILE", "HYPERV_HOST_USERNAME",
            "HYPERV_HOST_PASSWORD", "HYPERV_HOST_PASSWORD_FILE",
            "HYPERV_MCP_CONFIG",
            "HYPERV_MCP_UNRESTRICTED", "HYPERV_MCP_HTTP_TOKEN",
            "HYPERV_MCP_STATE_DB",
        ):
            print(f"{name:36}{'set' if name in os.environ else 'not set'}")
        # http.agents decides proxy/controller auth in agents-mode; name the
        # variables this run actually depends on (they are env VAR NAMES only).
        listed = (
            "HYPERV_GUEST_USERNAME HYPERV_GUEST_PASSWORD HYPERV_GUEST_PASSWORD_FILE "
            "HYPERV_GUEST_VICTIM_USERNAME HYPERV_GUEST_VICTIM_PASSWORD "
            "HYPERV_GUEST_VICTIM_PASSWORD_FILE HYPERV_HOST_USERNAME "
            "HYPERV_HOST_PASSWORD HYPERV_HOST_PASSWORD_FILE HYPERV_MCP_CONFIG "
            "HYPERV_MCP_UNRESTRICTED HYPERV_MCP_HTTP_TOKEN HYPERV_MCP_STATE_DB"
        ).split()
        for agent_var in sorted(set(cfg.http.agents.values())):
            if agent_var not in listed:
                print(f"{agent_var:36}{'set' if agent_var in os.environ else 'not set'}")
        if host_target:
            # The composed hop IS the probe: it validates exactly the
            # agent→host leg (and identity) the tools use — no inner
            # self-hop (cubic PR #47 round: a probe-body Invoke-Command
            # double-hopped host→host→self and could misreport UNREACHABLE
            # while tools succeeded). Transport-missing is fail-soft like
            # _powershell_provenance.
            probe_script, probe_stdin = pswindows.compose_remote(cfg, "'OK'")
            try:
                result = pswindows.run_ps(
                    probe_script, timeout_s=8, stdin_b64=probe_stdin
                )
            except pswindows.PowerShellTransportError as exc:
                result = pswindows.PSResult(returncode=1, stderr=f"unavailable: {exc}")
            except pswindows.PowerShellBusy as exc:
                result = pswindows.PSResult(returncode=1, stderr=f"pool busy: {exc}")
            if result.ok() and result.stdout.strip() == "OK":
                detail = "OK"
            elif "pool busy" in result.stderr:
                # Pool saturation is a capacity condition, not connectivity:
                # label it distinctly so operators are not sent to WinRM
                # remedies (README troubleshooting has the matching row).
                detail = "POOL_BUSY: " + result.stderr.strip()
            else:
                detail = "UNREACHABLE: " + (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "unknown error"
                )
            print(f"hyperv.target_probe {pswindows.redact(detail)}")
        ps_info = _powershell_provenance(cfg)
        print(f"powershell.path {ps_info['path']}")
        print(f"powershell.edition {ps_info['edition']}")
        print(f"powershell.version {ps_info['version']}")
        print(f"powershell.psmodulepath {ps_info['psmodulepath']}")
        print(f"config.path {cfg.config_path or '(none)'}")
        print(f"config.sha256 {cfg.config_sha256}")
        print(f"git.revision {_git_revision()}")
        return 0

    if ns.standalone:
        try:
            bootstrap()
        except ConfigError as exc:
            print(f"CONFIG ERROR: {exc}", file=sys.stderr)
            return 2

        mcp_run = get_mcp()
        mcp_run.run()
        return 0

    # Default and --proxy mode: a thin bridge to the ONE shared controller,
    # so per-VM locks, job/relay registries and the audit sink cover every
    # agent. The proxy never bootstraps Hyper-V machinery and never falls
    # back to in-process serving; an unreachable or rejecting controller is
    # a JSON-RPC error to the client, not a private server.
    try:
        cfg = Config.load()
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        token, token_env_name = stdio_proxy.resolve_proxy_token(cfg)
        if ns.proxy:
            url = stdio_proxy.validate_proxy_url(ns.proxy)
        else:
            url = stdio_proxy.validate_proxy_url(
                stdio_proxy.default_controller_url(cfg.http.host, cfg.http.port)
            )
            if not stdio_proxy.port_listening(cfg.http.host, cfg.http.port):
                stdio_proxy.ensure_controller(cfg)
        return stdio_proxy.run_proxy(url, token, token_env_name)
    except stdio_proxy.ProxyRefused as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())


def _operations_task_preflight(name: str, arguments: dict) -> None:
    """The tasks-interceptor preflight: resolves the registered Tool so the
    SDK argument validation runs (R13), then the shared synchronous gates."""
    tools = getattr(get_mcp(), "_tool_manager", None)
    tool = (getattr(tools, "_tools", {}) or {}).get(name)
    _operations_preflight(name, arguments, tool)
