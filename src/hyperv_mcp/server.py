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
import os
import sys

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from . import auditlog, credentials, filetransfer, guestexec, lifecycle, policy, pswindows
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
    compat): lazily bootstraps and returns the FastMCP instance."""
    if name == "mcp":
        return get_mcp()
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
    if not cfg.unrestricted:
        open_axes = cfg.open_axes()
        if open_axes:
            print(
                f"[hyperv-mcp] WARNING: policy axes fully open: {', '.join(open_axes)}",
                file=sys.stderr,
            )
        else:
            print(
                "[hyperv-mcp] NOTE: every policy axis is currently DENIED. "
                "Set HYPERV_MCP_CONFIG or HYPERV_MCP_UNRESTRICTED=1 to allow work.",
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

    def _run_guest_tool(tool: str, vm: str, category: str, fn, *args, **kwargs) -> dict:
        """Run a guest/transfer tool, mapping policy/cred errors to ok:false."""
        op = auditlog.operation(tool=tool, vm_name=vm, category=category)
        try:
            with op:
                result = fn(*args, **kwargs)
                if isinstance(result, dict) and result.get("exit_code") is not None:
                    op.exit_code = result["exit_code"]
                return result
        except policy.PolicyDenied as exc:
            return {"ok": False, "error": str(exc), "error_class": "policy"}
        except CredentialError as exc:
            return {"ok": False, "error": str(exc), "error_class": "credential"}
        except VMBusy as exc:
            return {"ok": False, "error": str(exc), "error_class": "busy"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "error_class": "invalid"}
        except RuntimeError as exc:
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
                cred=_cred_args(username, password),
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
                cred=_cred_args(username, password),
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
                confirm=confirm, verify=verify, cred=_cred_args(username, password),
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
                verify=verify, cred=_cred_args(username, password),
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
                cred=_cred_args(username, password),
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
                cred=_cred_args(username, password),
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
                cred=credentials.resolve_guest(),
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
                cred=credentials.resolve_guest(),
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
                confirm=confirm, verify=verify, cred=credentials.resolve_guest(),
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
                verify=verify, cred=credentials.resolve_guest(),
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
                cred=credentials.resolve_guest(),
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
                cred=credentials.resolve_guest(),
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
            timeout_ms=timeout_ms, cred=credentials.resolve_victim(),
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
            timeout_ms=timeout_ms, cred=credentials.resolve_victim(),
        )


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
