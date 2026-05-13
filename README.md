# hyperv-mcp

An MCP (Model Context Protocol) server for Hyper-V VM management and guest execution.
Exposes 19 tools for VM lifecycle, checkpoint management, kernel debug setup
(KDNET/KDCOM), and guest file transfer/command execution via PowerShell Direct
(no WinRM required).

> Designed to pair with [kd-mcp](https://github.com/originsec/kd-mcp), which wraps
> `kd.exe` for kernel debugging. `hyperv_configure_kdnet` returns a
> `kernel_attach_string` you can pass directly to kd-mcp's `kernel_attach` tool —
> end-to-end VM snapshot → KDNET config → kernel attach in one workflow.

---

## Requirements

- Windows 10/11 Pro or Enterprise with Hyper-V enabled
- Python 3.10+
- The process running the server **must be elevated** (run as Administrator) or the
  user account must be a member of the **Hyper-V Administrators** local group

---

## Installation

Install directly from GitHub:

```powershell
pip install git+https://github.com/originsec/hyperv-mcp.git
```

This installs the `hyperv-mcp` console script and pulls in the `mcp` dependency
automatically.

To install a specific revision (tag or commit):

```powershell
pip install git+https://github.com/originsec/hyperv-mcp.git@v0.1.0
```

### Set guest credentials

`hyperv_configure_kdnet`, `hyperv_configure_kdcom`, and all `hyperv_guest_*` tools
connect to VM guests via PowerShell Direct and need local admin credentials.
Set them once as env vars:

```powershell
$env:HYPERV_GUEST_USERNAME = "Administrator"
$env:HYPERV_GUEST_PASSWORD = "your_guest_password"
```

The `hyperv_victim_*` tools use a separate unprivileged account for EoP testing:

```powershell
$env:HYPERV_GUEST_VICTIM_USERNAME = "victim"
$env:HYPERV_GUEST_VICTIM_PASSWORD = "your_victim_password"
```

---

## Connecting to MCP clients

### Claude Code (CLI)

```powershell
claude mcp add hyperv -- hyperv-mcp
```

### .mcp.json

```json
{
  "mcpServers": {
    "hyperv": {
      "command": "hyperv-mcp"
    }
  }
}
```

If you need to pin guest credentials per-config:

```json
{
  "mcpServers": {
    "hyperv": {
      "command": "hyperv-mcp",
      "env": {
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD": "your_guest_password"
      }
    }
  }
}
```

You can also invoke the module directly without the console script:

```powershell
python -m hyperv_mcp
```

---

## Development install

```powershell
git clone https://github.com/originsec/hyperv-mcp.git
cd hyperv-mcp
pip install -e .
```

---

## Available Tools (19 total)

### VM Lifecycle

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_list_vms` | — | `[{name, state, status, memory_mb, cpu_count, uptime_seconds}]` |
| `hyperv_get_vm_info` | `vm_name` | `{name, state, generation, com_ports, network_adapters, hard_drives, ...}` |
| `hyperv_start_vm` | `vm_name` | `{status, vm_name, state}` |
| `hyperv_stop_vm` | `vm_name`, `method` | `{status, vm_name, method, state}` |
| `hyperv_reset_vm` | `vm_name` | `{status, vm_name, state}` |

**`hyperv_stop_vm` method values:**
- `"shutdown"` (default) — graceful guest OS shutdown via Integration Services
- `"save"` — suspend and save VM state to disk
- `"turnoff"` — hard power-off (equivalent to pulling the power cord)

### Checkpoints

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_checkpoint_create` | `vm_name`, `checkpoint_name` | `{status, vm_name, checkpoint_name}` |
| `hyperv_checkpoint_list` | `vm_name` | `[{name, type, created, parent_name}]` |
| `hyperv_checkpoint_restore` | `vm_name`, `checkpoint_name` | `{status, vm_name, checkpoint_name}` |
| `hyperv_checkpoint_remove` | `vm_name`, `checkpoint_name`, `include_subtree` | `{status, vm_name, checkpoint_name}` |

`checkpoint_name` is auto-generated from the current timestamp if omitted.
`checkpoint_restore` powers off the VM; call `hyperv_start_vm` to bring it back up.

### Kernel Debug Setup

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_configure_kdnet` | `vm_name`, `host_ip`, `port`, `key`, `reboot`, `username`, `password` | `{status, kernel_attach_string, key, ...}` |
| `hyperv_configure_kdcom` | `vm_name`, `pipe_name`, `com_port`, `reboot`, `username`, `password` | `{status, kernel_attach_string, ...}` |

**`hyperv_configure_kdnet`** — Default kernel debug method. Runs `bcdedit` inside
the guest via PowerShell Direct to configure KDNET. No host-side Hyper-V changes
needed. Returns `kernel_attach_string` to pass directly to kd-mcp's `kernel_attach`.

**`hyperv_configure_kdcom`** — Use when KDNET is unavailable (no NIC, or early-boot
debugging needed). Maps a VM COM port to a named pipe, then configures the guest
via `bcdedit`. VM must be Off or Saved before calling this.

Credentials are resolved from arguments first, then `HYPERV_GUEST_USERNAME` /
`HYPERV_GUEST_PASSWORD` env vars.

### Guest Execution (PowerShell Direct — no WinRM required)

All `hyperv_guest_*` tools communicate over the VMBus channel, so the guest
network does not need to be configured. Credentials follow the same env-var
resolution as the KD setup tools.

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_guest_run` | `vm_name`, `command`, `args[]`, `cwd?`, `timeout_ms`, `elevated`, `username`, `password` | `{ok, exit_code, stdout, stderr}` |
| `hyperv_guest_run_ps` | `vm_name`, `script`, `timeout_ms`, `elevated`, `username`, `password` | `{ok, exit_code, stdout, stderr}` |
| `hyperv_guest_put` | `vm_name`, `local_path`, `remote_path`, `username`, `password` | `{ok, bytes_copied}` |
| `hyperv_guest_get` | `vm_name`, `remote_path`, `local_path`, `username`, `password` | `{ok, bytes_copied}` |
| `hyperv_guest_read_file` | `vm_name`, `remote_path`, `max_bytes?`, `username`, `password` | `{ok, content_b64, bytes_read, truncated}` |
| `hyperv_guest_list_dir` | `vm_name`, `remote_path`, `username`, `password` | `{ok, entries[]}` |

`hyperv_guest_run_ps` and `hyperv_guest_run` run the script/binary in a child
`powershell.exe` process inside the guest; stdout and stderr are merged and
returned in `stdout`.

**`elevated=True`** launches the script/binary via `Start-Process -Verb RunAs -Wait`
so binaries that need High IL (e.g. `bcdedit.exe`, anything with a
`highestAvailable` / `requireAdministrator` manifest) run correctly and their
exit code is captured. This works without UAC prompts when the guest credential
is the **built-in Administrator** account; for other admin accounts the guest
must have UAC auto-elevation enabled (`ConsentPromptBehaviorAdmin=0`) or UAC
disabled.

`hyperv_guest_put` creates destination parent directories automatically.
`hyperv_guest_read_file` returns base64-encoded content; use `hyperv_guest_get`
for files larger than ~1 MB.

### Victim Execution (Medium IL — EoP testing)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_victim_run` | `vm_name`, `command`, `args[]`, `cwd?`, `timeout_ms` | `{ok, exit_code, stdout, stderr}` |
| `hyperv_victim_run_ps` | `vm_name`, `script`, `timeout_ms` | `{ok, exit_code, stdout, stderr}` |

These tools use `HYPERV_GUEST_VICTIM_USERNAME` / `HYPERV_GUEST_VICTIM_PASSWORD` instead of
the admin credentials. The session runs at **Medium IL** (non-elevated), making them the
correct trigger path for EoP vulnerability testing where the bug must be reached from an
unprivileged context.

---

## Typical Workflow — Kernel Debugging a Hyper-V VM

```
# 1. Take a clean snapshot
hyperv_checkpoint_create(vm_name="debug-vm", checkpoint_name="pre-kd")

# 2. Configure KDNET and reboot the guest
result = hyperv_configure_kdnet(
    vm_name="debug-vm",
    host_ip="192.0.2.1",     # host IP on the same vSwitch as the VM
    reboot=True,
)
# result["kernel_attach_string"] => "net:port=50000,key=a1b2c.d3e4f.5a6b7.c8d9e"

# 3. In kd-mcp, attach using the returned string
kernel_attach(connect_string=result["kernel_attach_string"])

# 4. When done, restore to clean state
hyperv_checkpoint_restore(vm_name="debug-vm", checkpoint_name="pre-kd")
hyperv_start_vm(vm_name="debug-vm")
```

**KDCOM (no NIC / early boot):**
```
hyperv_stop_vm(vm_name="debug-vm", method="save")
result = hyperv_configure_kdcom(vm_name="debug-vm", reboot=True)
# result["kernel_attach_string"] => "com:pipe,port=\\.\pipe\kd_debug-vm,resets=0,reconnect"
```

---

## Tips

**Host IP for KDNET** — Use the IP of the host adapter on the same Hyper-V virtual
switch as the VM. Run `Get-VMNetworkAdapter -VMName "YourVM"` and match against
`ipconfig` output.

**Auto-generated key** — If you omit `key`, `hyperv_configure_kdnet` generates a
cryptographically random key and returns it. Save it — you need it each time you call
`kernel_attach`.

---

## Troubleshooting

### `You do not have the required permission to complete this task`

`Get-VM` and all Hyper-V PowerShell cmdlets require either UAC elevation or membership
in the **Hyper-V Administrators** local group.

**Do not run the server or the MCP client as Administrator.** With the stdio MCP
transport, the client (Claude Code, Claude Desktop) spawns the server process, so the
server inherits the client's token. Elevating one without the other does nothing useful.

The correct fix is to add your account to the Hyper-V Administrators group. This grants
access to Hyper-V cmdlets from a normal non-elevated session — no UAC anywhere:

```powershell
# Run once in an elevated session, then log out and back in
Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$env:USERNAME"
```

After re-logging in, verify membership and confirm `Get-VM` works from a normal session:

```powershell
Get-LocalGroupMember -Group "Hyper-V Administrators"
Get-VM
```

### `MCP module not found`

Re-run the install so `mcp` is pulled in:

```powershell
pip install git+https://github.com/originsec/hyperv-mcp.git
```

---

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough edges and breaking changes between versions.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE)

Built by [Origin](https://originhq.com) for security research and red team operations.
