# hyperv-mcp (hardened fork)

An MCP (Model Context Protocol) server for Hyper-V VM management and guest
execution. Exposes 19 tools for VM lifecycle, checkpoint management, kernel
debug setup (KDNET/KDCOM), and guest file transfer/command execution via
PowerShell Direct (no WinRM required).

This fork hardens the upstream tool for dependable use on a dedicated Windows
test host: deny-by-default policy, secret-safe credential handling, destructive
-operation gates, real exit codes and stream separation, integrity-checked
file transfer, structured audit logging, and a unit/integration test split.

> Designed to pair with [kd-mcp](https://github.com/originsec/kd-mcp), which
> wraps `kd.exe` for kernel debugging. `hyperv_configure_kdnet` returns a
> `kernel_attach_string` you can pass directly to kd-mcp's `kernel_attach`.

---

## Requirements

- Windows 10/11 or Windows Server with the Hyper-V role/module installed
  (the `vmms` service running; verified with `Get-Service vmms`)
- Python 3.10+
- Guest OS: any Windows guest supported by PowerShell Direct (Windows
  Server 2012 R2+ / Windows 8.1+) with working Integration Services
- The **process running the server** must be able to drive Hyper-V: membership
  of the **Hyper-V Administrators** local group is preferred; full elevation
  also works. See [Permissions](#permissions).

---

## Permissions

`Get-VM` and every Hyper-V cmdlet fail with
`You do not have the required permission...` unless the server process token
carries Hyper-V rights. Two supported fixes:

1. **Hyper-V Administrators group (preferred, no UAC anywhere):**

   ```powershell
   # Run once in an elevated session, then LOG OUT AND BACK IN
   Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$env:USERNAME"
   ```

   The group SID stays enabled in a normal (filtered) Medium-IL token, but a
   **process only picks up group membership at logon** — a session started
   before the change still fails. Verify after re-login: `Get-VM`.

2. **Elevated server via streamable-http** (fallback when group membership is
   not available — pattern adopted from
   [0xntpower/hyperv-mcp](https://github.com/0xntpower/hyperv-mcp/commit/08a721f28b165b09fd7c65d3c34db972b20c9fb1)):

   ```powershell
   # from an elevated shell
   $env:HYPERV_MCP_HTTP_TOKEN = [convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
   hyperv-mcp-http --port 8787
   # client config: {"command": "...", "url": "http://127.0.0.1:8787/mcp"}
   ```

   The bearer token is REQUIRED unless you pass `--allow-anonymous` explicitly
   (an unauthenticated localhost endpoint lets any local process invoke every
   tool, including destructive ones — disposable labs only). Loopback bind is
   the default; binding beyond it prints a loud warning.

**Do not run your MCP client as Administrator.** With stdio the client spawns
the server, so the server inherits the client's token — prefer fix 1.

---

## Installation

```powershell
pip install git+https://github.com/zaxbysauce/zaxby-hyperv-mcp.git
```

Development install:

```powershell
git clone https://github.com/zaxbysauce/zaxby-hyperv-mcp.git
cd zaxby-hyperv-mcp
pip install -e ".[dev]"
```

Console scripts: `hyperv-mcp` (stdio server; `--version`, `--check-env`) and
`hyperv-mcp-http` (streamable-http server). `python -m hyperv_mcp` also works.

---

## Credential model

All guest-facing tools authenticate to the guest via PowerShell Direct.
Resolution order:

1. `HYPERV_GUEST_USERNAME` + one of:
   - `HYPERV_GUEST_PASSWORD`
   - `HYPERV_GUEST_PASSWORD_FILE` (path to a UTF-8 file holding just the
     password; preferred — put it in a profile directory with a restrictive
     ACL)
2. `HYPERV_GUEST_VICTIM_USERNAME` + `HYPERV_GUEST_VICTIM_PASSWORD` /
   `HYPERV_GUEST_VICTIM_PASSWORD_FILE` for the Medium-IL victim tools.

Hardening properties:

- **Passwords never appear on any process command line.** Host PowerShell is
  invoked with `-EncodedCommand`; the password rides an ASCII-base64 channel
  on **stdin**. This is enforced by regression test.
- Passwords (and any guest error text) pass a redaction filter before they can
  reach an MCP client, log line, or audit record. Passwords shorter than 3
  characters are rejected at resolution time (they cannot be redacted safely).
- **Tool schemas expose no password fields by default.** Opt in via
  `allow_inline_credentials: true` only if your client flow requires passing
  credentials per call (they then appear in client-side request logs — your
  risk).
- DPAPI / Windows Credential Manager storage is documented future work; the
  file provider is the current non-env option.

---

## Configuration

No configuration file = **deny everything** (safe default; the server prints
its effective policy to stderr at startup and on every denied call).
`hyperv-mcp --check-env` prints the effective policy.

Configuration file (JSON), selected with `HYPERV_MCP_CONFIG`:

```jsonc
{
  "schema_version": 1,
  // allowlists — deny-by-default; empty list = deny ALL on that axis
  "allowed_vm_patterns": ["test-vm-*"],
  "host_read_roots":    ["C:\\Lab\\Tools"],
  "host_write_roots":   ["C:\\Lab\\Out"],
  "guest_read_roots":   ["C:\\Windows\\Temp", "C:\\"],
  "guest_write_roots":  ["C:\\Windows\\Temp"],
  // destructive operations: category switches + confirmation
  "destructive": {
    "stop": true, "reset": false, "checkpoint_restore": true,
    "checkpoint_remove": true, "kd_reboot": true, "elevated_exec": true,
    "guest_write": true,
    "require_confirm": true       // tools additionally need confirm=true
  },
  "allow_inline_credentials": false,   // expose username/password tool params
  "unrestricted": false,               // explicit research mode: allow all
  "audit_log_path": "C:\\Lab\\audit.jsonl",
  "max_output_bytes": 1048576,         // guest output cap (truncated flag)
  "host_powershell_path": null,        // default: Windows PowerShell 5.1
  "verify_sha256": false,              // default integrity check for transfers
  "ps_timeout_s": 120,                 // default host PowerShell timeout
  "http": { "host": "127.0.0.1", "port": 8787, "token_env": "HYPERV_MCP_HTTP_TOKEN" }
}
```

Unknown keys are rejected at startup (typos must not disable a control).
`HYPERV_MCP_UNRESTRICTED=1` is the environment equivalent of
`"unrestricted": true` for disposable labs; unrestricted mode also forces a
visible audit line per operation.

**Path checks** canonicalize before comparing: `..` collapse, mixed
separators, drive-relative rejection, `\\?\`/UNC prefixes, case-insensitive
root comparison (drive roots like `C:\` are valid), and junction/symlink
resolution of the existing path prefix (the guest re-checks authoritatively
inside the VM). Guest roots are enforced host-side *and* re-asserted inside
the guest (`[IO.Path]::GetFullPath`), failing closed.

**VM inventory is policy-filtered too**: `hyperv_list_vms` returns only VMs
matching `allowed_vm_patterns` (and errors under the unconfigured deny-all
default). List/info/checkpoint rows carry snake_case keys plus deprecated
PascalCase aliases (`Name`, `State`, `MemoryMB`, ...) through the 0.2.x
series; snake_case is canonical from 0.3.0.

**Minimal safe config** (interact with one lab VM, writes only into the guest
temp dir):

```json
{
  "allowed_vm_patterns": ["lab-*"],
  "guest_write_roots": ["C:\\Windows\\Temp"],
  "destructive": { "stop": true, "checkpoint_restore": true, "guest_write": true }
}
```

**Disposable-lab unrestricted config:** set `HYPERV_MCP_UNRESTRICTED=1` (all
axes open, destructive categories enabled, confirmation still required unless
`destructive.require_confirm: false`).

---

## Destructive-operation policy

These tools refuse to run unless their category is enabled **and** (when
`require_confirm` is true) called with `confirm=true`:

| Tool | Category |
|------|----------|
| `hyperv_stop_vm` | `stop` |
| `hyperv_reset_vm` | `reset` |
| `hyperv_checkpoint_restore` | `checkpoint_restore` |
| `hyperv_checkpoint_remove` (esp. subtree) | `checkpoint_remove` |
| `hyperv_configure_kdnet` / `hyperv_configure_kdcom` | `kd_reboot` |
| `hyperv_guest_run(_ps)` with `elevated=true` | `elevated_exec` |
| `hyperv_guest_put` (guest write) | `guest_write` |

Denials return a structured `policy` error (no secrets, no speculative paths).
Concurrency is also guarded: one operation per VM at a time (`busy` error
otherwise).

---

## Connecting to MCP clients

```powershell
claude mcp add hyperv -- hyperv-mcp
```

`.mcp.json`:

```json
{
  "mcpServers": {
    "hyperv": {
      "command": "hyperv-mcp",
      "env": {
        "HYPERV_MCP_CONFIG": "C:\\Lab\\hyperv-mcp.json",
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD_FILE": "C:\\Lab\\secrets\\guest.pw"
      }
    }
  }
}
```

---

## Available Tools (19 total)

### VM Lifecycle

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_list_vms` | — | `[{name, state, status, memory_mb, cpu_count, uptime_seconds}]` |
| `hyperv_get_vm_info` | `vm_name` | `{name, state, generation, memory_mb, cpu_count, checkpoint_count, com_ports, network_adapters, hard_drives, ...}` |
| `hyperv_start_vm` | `vm_name` | `{status: started\|already_running, vm_name, state}` — waits for Running |
| `hyperv_stop_vm` | `vm_name`, `method`, `confirm` | `{status, vm_name, method, state}` — waits for final state |
| `hyperv_reset_vm` | `vm_name`, `confirm` | `{status, vm_name, state}` — waits for Running |

**`hyperv_stop_vm` methods:** `shutdown` (graceful via Integration Services,
default), `shutdown-force` (forced), `save` (suspend to disk), `turnoff`
(hard power-off). The default no longer passes `-Force` (0.2.0 change).
Lifecycle calls are idempotent where the target state allows and poll to the
requested final state; a state-wait timeout is a structured error carrying the
last observed state.

### Checkpoints

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_checkpoint_create` | `vm_name`, `checkpoint_name?` | `{status, vm_name, checkpoint_name}` |
| `hyperv_checkpoint_list` | `vm_name` | `[{name, type, created, parent_name}]` |
| `hyperv_checkpoint_restore` | `vm_name`, `checkpoint_name`, `confirm` | `{status, vm_name, checkpoint_name, state, note}` |
| `hyperv_checkpoint_remove` | `vm_name`, `checkpoint_name`, `include_subtree`, `confirm` | `{status, vm_name, checkpoint_name}` |

`checkpoint_name` auto-generates (`MCP-YYYYMMDD-HHMMSS`) only on **create**;
restore/remove require it. Restore powers the VM off — call `hyperv_start_vm`
afterwards. Removal merges disks; it cannot be undone.

### Kernel Debug Setup

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_configure_kdnet` | `vm_name`, `host_ip`, `port=50000`, `key?`, `reboot`, `confirm` | `{status, kernel_attach_string, key, bcdedit_output, rebooting, ...}` |
| `hyperv_configure_kdcom` | `vm_name`, `pipe_name?`, `com_port=1`, `reboot`, `confirm` | `{status, kernel_attach_string, pipe_path, bcdedit_output, rebooting, ...}` |

`host_ip` must be a valid IP; `key` must match kdnet hex-group format
(auto-generated cryptographically if omitted — save it, you need it for
`kernel_attach`). KD setup runs `bcdedit` inside the guest via PowerShell
Direct with separately-quoted arguments. Both tools are gated by the
`kd_reboot` category. KDNET is the default; KDCOM is for no-NIC / early-boot
cases and requires the VM Off/Saved for the `Set-VMComPort` step.

### Guest Execution (PowerShell Direct — no WinRM required)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_guest_run` | `vm_name`, `command`, `args[]`, `cwd?`, `timeout_ms`, `elevated`, `confirm` | `{ok, exit_code, stdout, stderr, timed_out, truncated}` |
| `hyperv_guest_run_ps` | `vm_name`, `script`, `timeout_ms`, `elevated`, `confirm` | same envelope |
| `hyperv_guest_put` | `vm_name`, `local_path`, `remote_path`, `confirm`, `verify?` | `{ok, bytes_copied, sha256_local?, sha256_remote?}` |
| `hyperv_guest_get` | `vm_name`, `remote_path`, `local_path`, `verify?` | same envelope |
| `hyperv_guest_read_file` | `vm_name`, `remote_path`, `max_bytes>=1` | `{ok, content_b64, bytes_read, truncated}` |
| `hyperv_guest_list_dir` | `vm_name`, `remote_path` | `{ok, entries[{name, is_dir, size_bytes, modified}]}` |

**0.2.0 behavior changes (documented breaking):**

- **stdout and stderr are SEPARATE fields with real exit codes** (upstream
  merged them via `2>&1` and reported `0` for guest PowerShell errors).
  Elevation caveat: `Start-Process -Verb RunAs` cannot redirect streams, so
  elevated runs merge both into `stdout` (the result carries a `note`).
- Failures return `{ok: false, error, error_class}` where `error_class` is
  one of `timeout | transport | policy | credential | busy | invalid | parse |
  integrity | not_found | guest`. Host-side tools (lifecycle, checkpoints)
  still raise — both styles are the contract.
- **Timeout semantics:** the host kills its whole PowerShell process tree
  (Job Object) at the timeout and reports `timed_out: true` with an explicit
  warning — **the guest-side child may still be running**. Guest temp scripts
  are cleaned in `finally` blocks, but a host timeout can leak them in the
  guest `%TEMP%`; the integration suite reports such leaks.

### Victim Execution (Medium IL — EoP testing)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_victim_run` | `vm_name`, `command`, `args[]`, `cwd?`, `timeout_ms` | standard guest envelope |
| `hyperv_victim_run_ps` | `vm_name`, `script`, `timeout_ms` | standard guest envelope |

Environment-only victim credentials; never elevated.

---

## Typical Workflow — Kernel Debugging a Hyper-V VM

```
# 1. Take a clean snapshot
hyperv_checkpoint_create(vm_name="lab-vm", checkpoint_name="pre-kd")

# 2. Configure KDNET and reboot the guest (destructive: confirm required)
result = hyperv_configure_kdnet(vm_name="lab-vm", host_ip="192.0.2.1",
                                reboot=True, confirm=True)
# result["kernel_attach_string"] => "net:port=50000,key=a1b2c.d3e4f.5a6b7.c8d9e"

# 3. In kd-mcp, attach using the returned string
kernel_attach(connect_string=result["kernel_attach_string"])

# 4. When done, restore to clean state
hyperv_checkpoint_restore(vm_name="lab-vm", checkpoint_name="pre-kd", confirm=True)
hyperv_start_vm(vm_name="lab-vm")
```

**Host IP for KDNET** — use the host adapter IP on the same vSwitch as the VM
(`Get-VMNetworkAdapter -VMName "lab-vm"` matched against `ipconfig`).

---

## Testing: unit vs real-Hyper-V integration

- `pytest` (default) runs **unit tests only**: policy, quoting, credential
  redaction, schema shape, result parsing, error mapping — plus real local
  Windows PowerShell 5.1 behavior probes (native-argument binding, UTF-8,
  EncodedCommand/stdin transport, timeout tree-kill). **None of these touch
  Hyper-V**; passing them does NOT validate any Hyper-V behavior.
- `pytest tests/integration` drives a REAL disposable VM. It skips (with the
  exact reason) unless `HYPERV_MCP_INTEGRATION=1`, `HYPERV_MCP_TEST_VM=<name>`
  and guest credentials are set. The suite follows the lab protocol: record
  state → checkpoint → read-only → exec/transfer → lifecycle → restore.

```powershell
$env:HYPERV_MCP_INTEGRATION = "1"
$env:HYPERV_MCP_TEST_VM     = "lab-vm-01"
$env:HYPERV_GUEST_USERNAME  = "Administrator"
$env:HYPERV_GUEST_PASSWORD_FILE = "C:\Lab\secrets\guest.pw"
pytest tests/integration
```

CI (`.github/workflows/ci.yml`) runs ruff + mypy + unit tests on
`windows-latest`; it does **not** validate real Hyper-V behavior.

---

## Security limitations

- A stdio MCP server is trusted with the rights of its own process token;
  any process that can talk to it can attempt every enabled tool. Policy
  allowlists and confirm gates are the mitigation — keep `unrestricted`
  off on shared hosts.
- The streamable-http endpoint is single-token: possession of the token is
  full authority. Loopback + file ACLs are the boundary.
- Guest command/script contents are executed as-is inside the guest by
  design (this is a research tool); guest-path allowlists govern *file
  transfer* roots, not arguments inside commands you choose to run.
- VM-name wildcards (`*?[`) in tool arguments are neutralized
  (`WildcardPattern`-compatible escaping) before reaching cmdlets, and must
  also match `allowed_vm_patterns`.
- DPAPI/Credential-Manager credential storage is future work.

---

## Troubleshooting

**`You do not have the required permission to complete this task`** — see
[Permissions](#permissions). Remember the fresh-logon requirement after group
changes.

**`policy: vm denied (no allowed_vm_patterns configured)`** — the server is
in its safe default state. Provide `HYPERV_MCP_CONFIG` (see
[Configuration](#configuration)) or set `HYPERV_MCP_UNRESTRICTED=1`.

**`MCP module not found`** — reinstall so `mcp` is pulled in:
`pip install git+https://github.com/zaxbysauce/zaxby-hyperv-mcp.git`.

**Dependency pin** — this fork pins `mcp>=1.0.0,<2`; the server uses the mcp
v1 `FastMCP` API, which mcp 2.x renamed.

---

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough
edges and breaking changes between versions.

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Built by [Origin](https://originhq.com) for security research and red team
operations; hardened fork maintained at
[zaxbysauce/zaxby-hyperv-mcp](https://github.com/zaxbysauce/zaxby-hyperv-mcp).
