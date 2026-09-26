"""
hyperv_mcp.server -- MCP server for Hyper-V VM management (hardened fork).

Exposes 19 tools: VM lifecycle, checkpoints, kernel debug setup (KDNET/KDCOM),
guest execution and file transfer via PowerShell Direct. Security model:

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
worked examples. Run `hyperv-mcp --check-env` to print the effective policy.
"""

import argparse
import io
import os
import sys
from typing import Any

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP, Image
from pydantic import AnyHttpUrl

from . import auditlog, console, credentials, filetransfer, guestexec, lifecycle, media, policy, pswindows
from .config import Config, ConfigError
from .credentials import CredentialError
from .vmlocks import VMBusy

__all__ = ["mcp", "main", "bootstrap", "configure_http_auth"]  # noqa: F822 (mcp: module __getattr__)

VERSION = "0.2.0"

_INSTRUCTIONS = (
    "Hyper-V VM management MCP (hardened). VM lifecycle, checkpoints, "
    "KDNET/KDCOM setup, PowerShell Direct guest execution and file "
    "transfer. Policy defaults are DENY-BY-DEFAULT: configure "
    "HYPERV_MCP_CONFIG (allowed VM patterns and path roots) or set "
    "HYPERV_MCP_UNRESTRICTED=1 for disposable labs. Destructive "
    "operations additionally need confirm=true. "
    "Run `hyperv-mcp --check-env` to print the effective policy."
)

_mcp: FastMCP | None = None
_http_token_verifier = None
_bootstrapped = False
_compat_warning_shown = False
CFG: Config | None = None


def configure_http_auth(token_verifier) -> None:
    """Install a bearer-token verifier BEFORE bootstrap().

    Only effective for streamable-http serving (stdio ignores it); must be
    called before the FastMCP instance is constructed.
    """
    global _http_token_verifier
    if _bootstrapped:
        raise RuntimeError("configure_http_auth() must be called before bootstrap()")
    _http_token_verifier = token_verifier


def __getattr__(name: str):
    """`from hyperv_mcp.server import mcp` keeps working (0xntpower serve_http
    compat): lazily bootstraps and returns the FastMCP instance.

    WARNING: this compat instance has NO bearer-token verifier installed —
    serving it over streamable-http yields an unauthenticated endpoint.
    Use the `hyperv-mcp-http` entry point for HTTP.
    """
    if name == "mcp":
        instance = get_mcp()
        if not _compat_warning_shown:
            print(
                "[hyperv-mcp] WARNING: compat import of `server.mcp` yields a "
                "FastMCP instance WITHOUT bearer-token auth; serving it over "
                "streamable-http exposes an unauthenticated endpoint. Prefer "
                "the `hyperv-mcp-http` entry point.",
                file=sys.stderr,
            )
            globals()["_compat_warning_shown"] = True
        return instance
    raise AttributeError(name)


def get_mcp() -> FastMCP:
    if _mcp is None:
        bootstrap()
    assert _mcp is not None
    return _mcp


def bootstrap(environ: dict[str, str] | None = None) -> Config:
    """Load config, wire modules, register tools. Idempotent."""
    global CFG, _mcp, _bootstrapped
    if _bootstrapped:
        return CFG  # type: ignore[return-value]
    cfg = Config.load(environ)
    credentials.init(cfg)
    pswindows.init(cfg, credentials.redact)
    auditlog.init(cfg)
    auth = None
    if _http_token_verifier is not None:
        # FastMCP requires AuthSettings when a token_verifier is installed.
        auth = AuthSettings(
            issuer_url=AnyHttpUrl("http://127.0.0.1"),  # static-token issuer (local)
            resource_server_url=AnyHttpUrl("http://127.0.0.1"),
            validate_token_resource=False,
        )
    _mcp = FastMCP(
        "hyperv_mcp",
        instructions=_INSTRUCTIONS,
        token_verifier=_http_token_verifier,
        auth=auth,
    )
    _register_tools(cfg, _mcp)
    _startup_banner(cfg)
    CFG = cfg
    _bootstrapped = True
    return cfg


def _startup_banner(cfg: Config) -> None:
    print(f"[hyperv-mcp] policy: {cfg.policy_summary()}", file=sys.stderr)
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
# tool registration
# ---------------------------------------------------------------------------

def _register_tools(cfg: Config, mcp: FastMCP) -> None:
    creds_allowed = cfg.allow_inline_credentials

    def _cred_args(u: str = "", p: str = "") -> credentials.CredentialSet:
        if creds_allowed and (u or p):
            return credentials.resolve_guest(u, p)
        return credentials.resolve_guest()

    def _audit(tool: str, vm: str, category: str):
        return auditlog.operation(tool=tool, vm_name=vm, category=category)

    def _run_guest_tool(tool: str, vm: str, category: str, fn, *args, cred_factory=None, **kwargs) -> dict:
        """Run a guest/transfer tool, mapping policy/cred errors to ok:false.

        cred_factory resolves credentials INSIDE the audited region so a
        CredentialError surfaces as {ok:false, error_class:"credential"} and
        is audited, instead of escaping as a raw ToolError.
        """
        op = auditlog.operation(tool=tool, vm_name=vm, category=category)
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
                return result
        except policy.PolicyDenied as exc:
            op.ok = False
            op.error_class = "policy"
            return {"ok": False, "error": str(exc), "error_class": "policy"}
        except CredentialError as exc:
            op.ok = False
            op.error_class = "credential"
            return {"ok": False, "error": str(exc), "error_class": "credential"}
        except VMBusy as exc:
            op.ok = False
            op.error_class = "busy"
            return {"ok": False, "error": str(exc), "error_class": "busy"}
        except ValueError as exc:
            op.ok = False
            op.error_class = "invalid"
            return {"ok": False, "error": str(exc), "error_class": "invalid"}
        except RuntimeError as exc:
            op.ok = False
            op.error_class = "transport"
            return {"ok": False, "error": str(exc), "error_class": "transport"}

    # ---- VM lifecycle --------------------------------------------------

    @mcp.tool()
    def hyperv_list_vms() -> list:
        """List all Hyper-V virtual machines and their current state.

        Returns: [{name, state, status, memory_mb, cpu_count, uptime_seconds}]
        (Deprecated PascalCase aliases Name/State/... are also included
        through the 0.2.x series.)
        """
        with _audit("hyperv_list_vms", "", "read"):
            return lifecycle.list_vms(_cfg())

    @mcp.tool()
    def hyperv_get_vm_info(vm_name: str) -> dict:
        """Get detailed info about a Hyper-V VM: state, generation, COM ports,
        network adapters, hard drives, checkpoint count.

        Args:
            vm_name: Name of the VM (must match allowed_vm_patterns)

        Returns: {name, state, generation, memory_mb, cpu_count,
                  checkpoint_count, com_ports, network_adapters, hard_drives, ...}
        """
        with _audit("hyperv_get_vm_info", vm_name, "read"):
            return lifecycle.get_vm_info(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_start_vm(vm_name: str) -> dict:
        """Start a Hyper-V VM and wait until it reports Running.

        Idempotent: an already-running VM returns status "already_running".

        Returns: {status, vm_name, state}
        """
        with _audit("hyperv_start_vm", vm_name, "lifecycle"):
            return lifecycle.start_vm(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_stop_vm(vm_name: str, method: str = "shutdown", confirm: bool = False) -> dict:
        """Stop a Hyper-V VM and wait until it reaches the final state.

        Args:
            vm_name: Name of the VM
            method:  "shutdown" — graceful guest shutdown via Integration
                     Services, then waits for Off (default)
                     "shutdown-force" — force shutdown (data-loss risk)
                     "save" — suspend to disk (final state Saved)
                     "turnoff" — hard power-off
            confirm: Must be true (destructive.require_confirm)

        Returns: {status, vm_name, method, state}
        """
        with _audit("hyperv_stop_vm", vm_name, "destructive"):
            return lifecycle.stop_vm(_cfg(), vm_name, method, confirm)

    @mcp.tool()
    def hyperv_reset_vm(vm_name: str, confirm: bool = False) -> dict:
        """Hard-reset a Hyper-V VM (power off immediately, start again) and
        wait until it reports Running. Equivalent to the physical reset button.

        Args:
            confirm: Must be true (destructive.require_confirm)

        Returns: {status, vm_name, state}
        """
        with _audit("hyperv_reset_vm", vm_name, "destructive"):
            return lifecycle.reset_vm(_cfg(), vm_name, confirm)

    # ---- checkpoints ----------------------------------------------------

    @mcp.tool()
    def hyperv_checkpoint_create(vm_name: str, checkpoint_name: str = "") -> dict:
        """Create a checkpoint (snapshot) of a Hyper-V VM.

        Args:
            vm_name:         Name of the VM
            checkpoint_name: Label (auto timestamp if omitted)

        Returns: {status, vm_name, checkpoint_name}
        """
        with _audit("hyperv_checkpoint_create", vm_name, "checkpoint"):
            return lifecycle.checkpoint_create(_cfg(), vm_name, checkpoint_name)

    @mcp.tool()
    def hyperv_checkpoint_list(vm_name: str) -> list:
        """List checkpoints of a Hyper-V VM.

        Returns: [{name, type, created, parent_name}]
        """
        with _audit("hyperv_checkpoint_list", vm_name, "read"):
            return lifecycle.checkpoint_list(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_checkpoint_restore(
        vm_name: str, checkpoint_name: str, confirm: bool = False
    ) -> dict:
        """Restore a VM to a checkpoint. ALL STATE SINCE THE CHECKPOINT IS
        DISCARDED. The VM ends powered off; call hyperv_start_vm afterwards.

        Args:
            checkpoint_name: Name of the checkpoint to restore
            confirm:         Must be true (destructive.require_confirm)

        Returns: {status, vm_name, checkpoint_name, state, note}
        """
        with _audit("hyperv_checkpoint_restore", vm_name, "destructive"):
            return lifecycle.checkpoint_restore(_cfg(), vm_name, checkpoint_name, confirm)

    @mcp.tool()
    def hyperv_checkpoint_remove(
        vm_name: str, checkpoint_name: str, include_subtree: bool = False, confirm: bool = False
    ) -> dict:
        """Remove a checkpoint, optionally with its whole child subtree.
        Merged disks cannot be undone afterwards.

        Args:
            include_subtree: Also remove all child checkpoints
            confirm:         Must be true (destructive.require_confirm)

        Returns: {status, vm_name, checkpoint_name}
        """
        with _audit("hyperv_checkpoint_remove", vm_name, "destructive"):
            return lifecycle.checkpoint_remove(
                _cfg(), vm_name, checkpoint_name, include_subtree, confirm
            )

    # ---- KD setup ---------------------------------------------------------

    if creds_allowed:

        @mcp.tool()
        def hyperv_configure_kdnet(
            vm_name: str, host_ip: str, port: int = 50000, key: str = "",
            reboot: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
        ) -> dict:
            """Configure KDNET (network kernel debugging) in a guest via
            PowerShell Direct + bcdedit. Returns kernel_attach_string for
            kd-mcp. Credentials from env/credential-file, or inline
            username/password (inline requires allow_inline_credentials=true).

            Args:
                host_ip:  Debugger host IP on the VM's vSwitch (IPv4/IPv6)
                port:     UDP port (1024-65535)
                key:      kdnet key a.b.c.d hex — auto-generated if omitted
                reboot:   Reboot the guest after configuring
                confirm:  Must be true (destructive.require_confirm)

            Returns: {status, vm_name, host_ip, port, key,
                      kernel_attach_string, bcdedit_output, rebooting}
            """
            with _audit("hyperv_configure_kdnet", vm_name, "destructive"):
                return lifecycle.configure_kdnet(
                    _cfg(), vm_name, host_ip, port, key, reboot, confirm,
                    cred=_cred_args(username, password),
                )

        @mcp.tool()
        def hyperv_configure_kdcom(
            vm_name: str, pipe_name: str = "", com_port: int = 1,
            reboot: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
        ) -> dict:
            """Configure COM-port/named-pipe kernel debugging. Maps the VM COM
            port to a host named pipe (VM must be Off/Saved) and runs bcdedit
            in the guest. Use only when KDNET is unavailable.

            Args:
                pipe_name: Named pipe path — auto-generated if omitted
                com_port:  1 or 2 (default 1)
                confirm:   Must be true (destructive.require_confirm)

            Returns: {status, vm_name, com_port, pipe_path,
                      kernel_attach_string, bcdedit_output, rebooting}
            """
            with _audit("hyperv_configure_kdcom", vm_name, "destructive"):
                return lifecycle.configure_kdcom(
                    _cfg(), vm_name, pipe_name, com_port, reboot, confirm,
                    cred=_cred_args(username, password),
                )

    else:

        @mcp.tool()
        def hyperv_configure_kdnet(
            vm_name: str, host_ip: str, port: int = 50000, key: str = "",
            reboot: bool = False, confirm: bool = False,
        ) -> dict:
            """Configure KDNET (network kernel debugging) in a guest via
            PowerShell Direct + bcdedit. Returns kernel_attach_string for
            kd-mcp. Credentials come from HYPERV_GUEST_USERNAME +
            HYPERV_GUEST_PASSWORD (or HYPERV_GUEST_PASSWORD_FILE).

            Args:
                host_ip:  Debugger host IP on the VM's vSwitch (IPv4/IPv6)
                port:     UDP port (1024-65535)
                key:      kdnet key a.b.c.d hex — auto-generated if omitted
                reboot:   Reboot the guest after configuring
                confirm:  Must be true (destructive.require_confirm)

            Returns: {status, vm_name, host_ip, port, key,
                      kernel_attach_string, bcdedit_output, rebooting}
            """
            with _audit("hyperv_configure_kdnet", vm_name, "destructive"):
                return lifecycle.configure_kdnet(
                    _cfg(), vm_name, host_ip, port, key, reboot, confirm,
                    cred=credentials.resolve_guest(),
                )

        @mcp.tool()
        def hyperv_configure_kdcom(
            vm_name: str, pipe_name: str = "", com_port: int = 1,
            reboot: bool = False, confirm: bool = False,
        ) -> dict:
            """Configure COM-port/named-pipe kernel debugging. Maps the VM COM
            port to a host named pipe (VM must be Off/Saved) and runs bcdedit
            in the guest. Credentials come from HYPERV_GUEST_USERNAME +
            HYPERV_GUEST_PASSWORD (or HYPERV_GUEST_PASSWORD_FILE).

            Args:
                pipe_name: Named pipe path — auto-generated if omitted
                com_port:  1 or 2 (default 1)
                confirm:   Must be true (destructive.require_confirm)

            Returns: {status, vm_name, com_port, pipe_path,
                      kernel_attach_string, bcdedit_output, rebooting}
            """
            with _audit("hyperv_configure_kdcom", vm_name, "destructive"):
                return lifecycle.configure_kdcom(
                    _cfg(), vm_name, pipe_name, com_port, reboot, confirm,
                    cred=credentials.resolve_guest(),
                )

    # ---- guest execution ------------------------------------------------

    if creds_allowed:

        @mcp.tool()
        def hyperv_guest_run_ps(
            vm_name: str, script: str, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
        ) -> dict:
            """Run a PowerShell script inside a guest via PowerShell Direct.
            stdout/stderr are SEPARATE (0.2.0 change); exit codes are real.
            elevated=true runs at High IL via UAC RunAs (merged streams; needs
            destructive.elevated_exec + confirm).

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_run_ps", vm_name, "exec",
                guestexec.guest_run_ps, _cfg(), vm_name, script,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_run(
            vm_name: str, command: str, args: list[str] | None = None,
            cwd: str | None = None, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
            username: str = "", password: str = "",
        ) -> dict:
            """Run an executable inside a guest via PowerShell Direct.
            Separate stdout/stderr, real exit codes. elevated=true needs
            destructive.elevated_exec + confirm.

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_run", vm_name, "exec",
                guestexec.guest_run, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_put(
            vm_name: str, local_path: str, remote_path: str,
            confirm: bool = False, verify: bool | None = None,
            username: str = "", password: str = "",
        ) -> dict:
            """Copy a host file into a guest via PowerShell Direct. Staged
            rename, parent dirs created, optional SHA-256 verification
            (verify=True, or config verify_sha256). Needs guest_write policy.

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_put", vm_name, "transfer",
                filetransfer.guest_put, _cfg(), vm_name, local_path, remote_path,
                confirm=confirm, verify=verify, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_get(
            vm_name: str, remote_path: str, local_path: str,
            verify: bool | None = None,
            username: str = "", password: str = "",
        ) -> dict:
            """Copy a guest file to the host via PowerShell Direct. Staged
            rename, local parent dirs created, optional SHA-256 verification.

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_get", vm_name, "transfer",
                filetransfer.guest_get, _cfg(), vm_name, remote_path, local_path,
                verify=verify, cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_read_file(
            vm_name: str, remote_path: str, max_bytes: int = 262144,
            username: str = "", password: str = "",
        ) -> dict:
            """Read up to max_bytes of a guest file (base64). Bounded stream
            read; max_bytes must be >= 1.

            Returns: {ok, content_b64, bytes_read, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_read_file", vm_name, "transfer",
                filetransfer.guest_read_file, _cfg(), vm_name, remote_path, max_bytes,
                cred_factory=lambda: _cred_args(username, password),
            )

        @mcp.tool()
        def hyperv_guest_list_dir(
            vm_name: str, remote_path: str,
            username: str = "", password: str = "",
        ) -> dict:
            """List a directory in the guest.

            Returns: {ok, entries: [{name, is_dir, size_bytes, modified}]}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_list_dir", vm_name, "transfer",
                filetransfer.guest_list_dir, _cfg(), vm_name, remote_path,
                cred_factory=lambda: _cred_args(username, password),
            )

    else:

        @mcp.tool()
        def hyperv_guest_run_ps(
            vm_name: str, script: str, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
        ) -> dict:
            """Run a PowerShell script inside a guest via PowerShell Direct.
            stdout/stderr are SEPARATE (0.2.0 change); exit codes are real.
            Credentials: HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD /
            HYPERV_GUEST_PASSWORD_FILE. elevated=true needs
            destructive.elevated_exec + confirm.

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_run_ps", vm_name, "exec",
                guestexec.guest_run_ps, _cfg(), vm_name, script,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_run(
            vm_name: str, command: str, args: list[str] | None = None,
            cwd: str | None = None, timeout_ms: int = 60000,
            elevated: bool = False, confirm: bool = False,
        ) -> dict:
            """Run an executable inside a guest via PowerShell Direct.
            Separate stdout/stderr, real exit codes. Credentials:
            HYPERV_GUEST_USERNAME / HYPERV_GUEST_PASSWORD /
            HYPERV_GUEST_PASSWORD_FILE. elevated=true needs
            destructive.elevated_exec + confirm.

            Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_run", vm_name, "exec",
                guestexec.guest_run, _cfg(), vm_name, command, args, cwd,
                timeout_ms=timeout_ms, elevated=elevated, confirm=confirm,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_put(
            vm_name: str, local_path: str, remote_path: str,
            confirm: bool = False, verify: bool | None = None,
        ) -> dict:
            """Copy a host file into a guest via PowerShell Direct. Staged
            rename, parent dirs created, optional SHA-256 verification.
            Needs guest_write policy + confirm.

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_put", vm_name, "transfer",
                filetransfer.guest_put, _cfg(), vm_name, local_path, remote_path,
                confirm=confirm, verify=verify, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_get(
            vm_name: str, remote_path: str, local_path: str,
            verify: bool | None = None,
        ) -> dict:
            """Copy a guest file to the host via PowerShell Direct. Staged
            rename, local parent dirs created, optional SHA-256 verification.

            Returns: {ok, bytes_copied, sha256_local?, sha256_remote?}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_get", vm_name, "transfer",
                filetransfer.guest_get, _cfg(), vm_name, remote_path, local_path,
                verify=verify, cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_read_file(
            vm_name: str, remote_path: str, max_bytes: int = 262144,
        ) -> dict:
            """Read up to max_bytes of a guest file (base64). Bounded stream
            read; max_bytes must be >= 1.

            Returns: {ok, content_b64, bytes_read, truncated}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_read_file", vm_name, "transfer",
                filetransfer.guest_read_file, _cfg(), vm_name, remote_path, max_bytes,
                cred_factory=credentials.resolve_guest,
            )

        @mcp.tool()
        def hyperv_guest_list_dir(vm_name: str, remote_path: str) -> dict:
            """List a directory in the guest.

            Returns: {ok, entries: [{name, is_dir, size_bytes, modified}]}
            or {ok: false, error, error_class}
            """
            return _run_guest_tool(
                "hyperv_guest_list_dir", vm_name, "transfer",
                filetransfer.guest_list_dir, _cfg(), vm_name, remote_path,
                cred_factory=credentials.resolve_guest,
            )

    # ---- victim execution (env-only credentials, never elevated) --------

    @mcp.tool()
    def hyperv_victim_run(
        vm_name: str, command: str, args: list[str] | None = None,
        cwd: str | None = None, timeout_ms: int = 60000,
    ) -> dict:
        """Run an executable in the guest as the unprivileged victim account
        (Medium IL). Credentials: HYPERV_GUEST_VICTIM_USERNAME /
        HYPERV_GUEST_VICTIM_PASSWORD / HYPERV_GUEST_VICTIM_PASSWORD_FILE.

        Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
        or {ok: false, error, error_class}
        """
        return _run_guest_tool(
            "hyperv_victim_run", vm_name, "victim",
            guestexec.victim_run, _cfg(), vm_name, command, args, cwd,
            timeout_ms=timeout_ms, cred_factory=credentials.resolve_victim,
        )

    @mcp.tool()
    def hyperv_victim_run_ps(vm_name: str, script: str, timeout_ms: int = 60000) -> dict:
        """Run a PowerShell script in the guest as the unprivileged victim
        account (Medium IL). Victim credentials from environment only.

        Returns: {ok, exit_code, stdout, stderr, timed_out, truncated}
        or {ok: false, error, error_class}
        """
        return _run_guest_tool(
            "hyperv_victim_run_ps", vm_name, "victim",
            guestexec.victim_run_ps, _cfg(), vm_name, script,
            timeout_ms=timeout_ms, cred_factory=credentials.resolve_victim,
        )

    # ---- console (WMI screenshot / keyboard / mouse) --------------------
    # Image-returning tools (screenshot/wait_frame_change/capture_sequence)
    # return a LIST [Image, meta_dict] on success and RAISE on failure, so
    # the success shape is uniformly image content + a metadata text block
    # (FastMCP converts the list: ImageContent + TextContent). Input tools
    # use the {ok,...}/{ok:false,error,error_class} envelope.

    def _run_console_tool(tool: str, vm: str, category: str, fn, *args, **kwargs):
        try:
            with _audit(tool, vm, category):
                return fn(*args, **kwargs)
        except policy.PolicyDenied as exc:
            return {"ok": False, "error": str(exc), "error_class": "policy"}
        except console.ConsoleError as exc:
            return {"ok": False, "error": str(exc), "error_class": "transport"}
        except VMBusy as exc:
            return {"ok": False, "error": str(exc), "error_class": "busy"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "error_class": "invalid"}
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc), "error_class": "transport"}

    @mcp.tool()
    def hyperv_console_screenshot(
        vm_name: str, width: int = 1024, height: int = 768, save_path: str = ""
    ) -> Any:
        """Capture the VM console via Hyper-V WMI (works from firmware through
        WinPE; independent of VMConnect, host foreground, guest login/network).
        Returns MCP image content (image/png) plus a metadata text block:
        vm_id, dimensions, frame_hash, head resolution and scale note,
        fallback_used, capture method. Fallback chain: requested → head
        native → 640x480 → 320x240. A corrupt/short payload is a structured
        error, never a successful image.

        Args:
            vm_name:  VM name (must match allowed_vm_patterns)
            width:    requested snapshot width (160..4096)
            height:   requested snapshot height (160..4096)
            save_path: optional host path to also save the PNG (host_write policy)

        Returns: [ImageContent(image/png), TextContent(json metadata)]
        """
        try:
            with _audit("hyperv_console_screenshot", vm_name, "read"):
                img, meta = console.screenshot(_cfg(), vm_name, width, height, save_path)
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                return [Image(data=buf.getvalue(), format="png"), meta]
        except policy.PolicyDenied as exc:
            return {"ok": False, "error": str(exc), "error_class": "policy"}

    @mcp.tool()
    def hyperv_console_get_display_info(vm_name: str) -> dict:
        """Display head resolution, keyboard/mouse device presence and state,
        and guest-channel readiness (console works in firmware/WinPE;
        PowerShell Direct needs a running supported guest OS).

        Returns: {ok, enabled_state, head_horizontal, head_vertical,
                  keyboard_present, keyboard_enabled, mouse_present,
                  mouse_enabled, guest_channel, guest_channel_note, vm_id}
        """
        return _run_console_tool(
            "hyperv_console_get_display_info", vm_name, "read",
            console.get_display_info, _cfg(), vm_name,
        )

    @mcp.tool()
    def hyperv_console_type_text(vm_name: str, text: str) -> dict:
        """Type ASCII text into the VM console via Msvm_Keyboard.TypeText
        (works pre-login, in WinPE). Text rides the stdin channel — it never
        appears in process argv, the PowerShell script, or error records.
        Chunks over 512 chars with pacing. For non-ASCII input use
        hyperv_console_type_scancodes. Policy: console_input category.

        Returns: {ok, chunks, chars} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_type_text", vm_name, "console_input",
            console.type_text, _cfg(), vm_name, text,
        )

    @mcp.tool()
    def hyperv_console_press_key(
        vm_name: str, key: str, modifiers: list[str] | None = None,
    ) -> dict:
        """Press a named key (scan-code make/break pair) with optional
        modifiers (ctrl/alt/shift). Supported keys: enter, escape, tab,
        backspace, space, up/down/left/right, delete, home, end, pageup,
        pagedown, insert, f1-f12, a-z, 0-9. Policy: console_input.

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_press_key", vm_name, "console_input",
            console.press_key, _cfg(), vm_name, key, modifiers,
        )

    @mcp.tool()
    def hyperv_console_key_combo(vm_name: str, keys: list[str]) -> dict:
        """Send a key combination: modifier makes first, keys in order,
        modifier breaks last (e.g. ["ctrl", "alt", "delete"]).
        Policy: console_input.

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_key_combo", vm_name, "console_input",
            console.key_combo, _cfg(), vm_name, keys,
        )

    @mcp.tool()
    def hyperv_console_type_scancodes(vm_name: str, scancodes: list[int]) -> dict:
        """Send raw PS/2 scan codes (0..255 ints, make/break pairs included)
        via Msvm_Keyboard.TypeScancodes; chunked at 64 codes with pacing.
        Policy: console_input.

        Returns: {ok, scancodes_sent, chunks} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_type_scancodes", vm_name, "console_input",
            console.type_scancodes, _cfg(), vm_name, scancodes,
        )

    @mcp.tool()
    def hyperv_console_mouse_move(
        vm_name: str, x: int, y: int, frame_width: int = 0, frame_height: int = 0,
    ) -> dict:
        """Position the synthetic mouse. Coordinates are in the space of the
        image you observed; give frame_width/frame_height (the snapshot
        dimensions) to scale them to display-head space. Without frame dims
        the head resolution must be available, else the tool errors rather
        than clicking blind. Policy: console_input.

        Returns: {ok, operation, head_x, head_y} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_mouse_move", vm_name, "console_input",
            console.mouse_move, _cfg(), vm_name, x, y, frame_width, frame_height,
        )

    @mcp.tool()
    def hyperv_console_click(
        vm_name: str, x: int = 0, y: int = 0, frame_width: int = 0,
        frame_height: int = 0, button: int = 1,
    ) -> dict:
        """Click at frame-space coordinates (optional; positions first when
        x/y are given, else clicks at the current position). button: 1=left,
        2=right. Verify placement with a screenshot between steps — never
        assume focus from a prior frame. Policy: console_input.

        Returns: {ok, operation, head_x?, head_y?} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_click", vm_name, "console_input",
            console.click, _cfg(), vm_name, x, y, frame_width, frame_height, button,
        )

    @mcp.tool()
    def hyperv_console_button(vm_name: str, button: int, is_down: bool) -> dict:
        """Hold or release a mouse button (raw SetButtonState; for drag
        gestures). Policy: console_input.

        Returns: {ok, operation} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_button", vm_name, "console_input",
            console.mouse_button, _cfg(), vm_name, button, is_down,
        )

    @mcp.tool()
    def hyperv_console_scroll(vm_name: str, delta: int) -> dict:
        """Scroll the console wheel by delta (positive = down).
        Policy: console_input.

        Returns: {ok, operation} or {ok: false, error, error_class}
        """
        return _run_console_tool(
            "hyperv_console_scroll", vm_name, "console_input",
            console.scroll, _cfg(), vm_name, delta,
        )

    @mcp.tool()
    def hyperv_console_wait_frame_change(
        vm_name: str, baseline_hash: str = "", width: int = 640, height: int = 480,
        timeout_s: int = 60, interval_s: int = 2,
    ) -> Any:
        """Poll the console until the frame changes (or the deadline passes).
        Bounded: polls = ceil(timeout_s/interval_s), deadline enforced
        host-side. Returns [ImageContent(image/png), TextContent(json)] when
        changed — {stop_reason: changed|deadline, polls, elapsed_ms,
        frame_hash, width, height} in the text block — or a deadline dict
        with no image. Never invents text for what is on screen: interpret
        the returned image visually.

        Args:
            baseline_hash: frame_hash from a previous capture ("" compares
                           against nothing — first poll's frame is baseline)
        """
        try:
            with _audit("hyperv_console_wait_frame_change", vm_name, "read"):
                out = console.wait_frame_change(
                    _cfg(), vm_name, baseline_hash, width, height, timeout_s, interval_s
                )
                meta = {k: v for k, v in out.items() if k != "image"}
                if "image" in out:
                    buf = io.BytesIO()
                    out["image"].save(buf, format="PNG")
                    return [Image(data=buf.getvalue(), format="png"), meta]
                return meta
        except policy.PolicyDenied as exc:
            return {"ok": False, "error": str(exc), "error_class": "policy"}

    @mcp.tool()
    def hyperv_console_capture_sequence(
        vm_name: str, count: int = 3, interval_s: int = 2,
        width: int = 640, height: int = 480,
    ) -> Any:
        """Capture a bounded sequence of console frames with per-frame hashes
        and changed-byte counts vs the previous frame (transition evidence,
        not progress inference). Returns [first Image, last Image, meta_text]
        where meta carries frames[] (index, frame_hash, changed_bytes,
        captured_at), elapsed_ms, dimensions.
        """
        try:
            with _audit("hyperv_console_capture_sequence", vm_name, "read"):
                out = console.capture_sequence(
                    _cfg(), vm_name, count, interval_s, width, height
                )
                meta = {k: v for k, v in out.items() if k != "images"}
                parts: list = []
                imgs = list(out["images"])
                for img in imgs:
                    buf = io.BytesIO()
                    img.save(buf, format="PNG")
                    parts.append(Image(data=buf.getvalue(), format="png"))
                parts.append(meta)
                return parts
        except policy.PolicyDenied as exc:
            return {"ok": False, "error": str(exc), "error_class": "policy"}

    @mcp.tool()
    def hyperv_wait_vm_state(
        vm_name: str, states: list[str], timeout_s: int = 300,
    ) -> dict:
        """Wait (bounded) until the VM reaches one of the requested states.
        states must be from: Off, Running, Saved, Paused, Starting, Stopping,
        Resuming, Pausing. Reports guest-channel readiness for handoff:
        console input works in firmware/WinPE, PowerShell Direct only after
        Windows boots — verify hyperv_console_get_display_info before
        switching channels.

        Returns: {ok, final_state, elapsed_ms} or raises with the last state.
        """
        valid = ("Off", "Running", "Saved", "Paused", "Starting", "Stopping", "Resuming", "Pausing")
        for s in states:
            if s not in valid:
                raise ValueError(
                    f"invalid state {s!r}; must be one of {valid} "
                    "(strict validation: no shell metacharacters possible)"
                )
        with _audit("hyperv_wait_vm_state", vm_name, "read"):
            final = lifecycle.wait_for_vm_state(_cfg(), vm_name, list(states), timeout_s)
            return {"ok": True, "final_state": final, "guest_channel": "ps_direct_unverified"}

    # ---- VM / media preparation (deployment testing) ---------------------

    @mcp.tool()
    def hyperv_vm_create(
        name: str, vhd_path: str, memory_mb: int = 2048, cpu_count: int = 1,
        generation: int = 2, vhd_size_gb: int = 64, switch_name: str = "",
        confirm: bool = False,
    ) -> dict:
        """Create a disposable VM with a fresh VHDX (New-VHD + New-VM). The
        new name must match allowed_vm_patterns so it stays policy-scoped.
        Policy: vm_provision category + confirm=true.

        Returns: {ok, id, name, state, generation} or raises.
        """
        with _audit("hyperv_vm_create", name, "vm_provision"):
            return media.vm_create(
                _cfg(), name, memory_mb, cpu_count, generation,
                vhd_path, vhd_size_gb, switch_name, confirm,
            )

    @mcp.tool()
    def hyperv_vm_disk_add(
        vm_name: str, path: str, size_gb: int, controller_type: str = "SCSI",
        confirm: bool = False,
    ) -> dict:
        """Create and attach an additional VHDX (for multi-disk deployment
        tests). Policy: vm_provision + confirm=true.

        Returns: {ok, vhd_path, disk_count} or raises.
        """
        with _audit("hyperv_vm_disk_add", vm_name, "vm_provision"):
            return media.vm_disk_add(
                _cfg(), vm_name, path, size_gb, controller_type, confirm,
            )

    @mcp.tool()
    def hyperv_vm_disk_list(vm_name: str) -> dict:
        """List the VM's hard disks (controller type/number, LUN, path) —
        use to verify disk topology before deployment runs.

        Returns: {ok, disks: [...]}
        """
        with _audit("hyperv_vm_disk_list", vm_name, "read"):
            return media.vm_disk_list(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_vm_media_attach(vm_name: str, iso_path: str) -> dict:
        """Attach an ISO to a virtual DVD drive (Add-VMDvdDrive). Verify the
        ISO is the intended, freshly built media before claiming a deployment
        tests new fixes. Policy: media category (reversible, no confirm).
        iso_path requires host_read policy.

        Returns: {ok, iso_path} or raises.
        """
        with _audit("hyperv_vm_media_attach", vm_name, "media"):
            return media.vm_media_attach(_cfg(), vm_name, iso_path)

    @mcp.tool()
    def hyperv_vm_media_detach(vm_name: str) -> dict:
        """Detach all virtual DVD drives; returns the removed ISO paths.
        Policy: media category (reversible, no confirm).

        Returns: {ok, removed: [...]} or raises.
        """
        with _audit("hyperv_vm_media_detach", vm_name, "media"):
            return media.vm_media_detach(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_vm_media_list(vm_name: str) -> dict:
        """List virtual DVD drives and attached ISO paths.

        Returns: {ok, media: [...]}
        """
        with _audit("hyperv_vm_media_list", vm_name, "read"):
            return media.vm_media_list(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_vm_firmware_get(vm_name: str) -> dict:
        """Firmware state for Gen2 VMs: SecureBoot, template, boot order,
        TPM enabled. Generation 1 returns an explicit error.

        Returns: {ok, secure_boot, secure_boot_template, boot_order, tpm_enabled}
        """
        with _audit("hyperv_vm_firmware_get", vm_name, "read"):
            return media.vm_firmware_get(_cfg(), vm_name)

    @mcp.tool()
    def hyperv_vm_firmware_set_boot_order(
        vm_name: str, boot_type: str = "Drive", confirm: bool = False,
    ) -> dict:
        """Set the first boot device by type (Drive | Network | File) — e.g.
        boot from attached DVD media. Policy: vm_provision + confirm=true.
        Generation 1 returns an explicit error.

        Returns: {ok, first_boot} or raises.
        """
        with _audit("hyperv_vm_firmware_set_boot_order", vm_name, "vm_provision"):
            return media.vm_firmware_set_boot_order(_cfg(), vm_name, boot_type, confirm)

    @mcp.tool()
    def hyperv_vm_tpm_set(vm_name: str, enabled: bool, confirm: bool = False) -> dict:
        """Enable or disable the virtual TPM (Gen2 only).
        Policy: vm_provision + confirm=true.

        Returns: {ok, tpm_enabled} or raises.
        """
        with _audit("hyperv_vm_tpm_set", vm_name, "vm_provision"):
            return media.vm_tpm_set(_cfg(), vm_name, enabled, confirm)

    @mcp.tool()
    def hyperv_vm_secureboot_set(
        vm_name: str, enabled: bool, template: str = "", confirm: bool = False,
    ) -> dict:
        """Enable or disable Secure Boot (Gen2 only), optionally setting the
        template (e.g. MicrosoftWindows, MicrosoftUEFICertificateAuthority).
        Policy: vm_provision + confirm=true.

        Returns: {ok, secure_boot, secure_boot_template} or raises.
        """
        with _audit("hyperv_vm_secureboot_set", vm_name, "vm_provision"):
            return media.vm_secureboot_set(_cfg(), vm_name, enabled, template, confirm)

    @mcp.tool()
    def hyperv_vm_network_set(vm_name: str, switch_name: str) -> dict:
        """Connect the VM's network adapter to a virtual switch.
        Policy: media category (reversible, no confirm).

        Returns: {ok, switch_name} or raises.
        """
        with _audit("hyperv_vm_network_set", vm_name, "media"):
            return media.vm_network_set(_cfg(), vm_name, switch_name)


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
        help="print the effective policy and credential configuration, then exit",
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
        for name in (
            "HYPERV_GUEST_USERNAME", "HYPERV_GUEST_PASSWORD", "HYPERV_GUEST_PASSWORD_FILE",
            "HYPERV_GUEST_VICTIM_USERNAME", "HYPERV_GUEST_VICTIM_PASSWORD",
            "HYPERV_GUEST_VICTIM_PASSWORD_FILE", "HYPERV_MCP_CONFIG",
            "HYPERV_MCP_UNRESTRICTED", "HYPERV_MCP_HTTP_TOKEN",
        ):
            print(f"{name:36}{'set' if name in os.environ else 'not set'}")
        return 0

    try:
        bootstrap()
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2

    mcp_run = get_mcp()
    mcp_run.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
