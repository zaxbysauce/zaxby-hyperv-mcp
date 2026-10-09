# hyperv-mcp (hardened fork)

An MCP (Model Context Protocol) server for Hyper-V VM management and guest
execution. Exposes 55 tools for VM lifecycle, checkpoint management, kernel
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

- **Hyper-V host** (the machine whose `vmms` service is managed): Windows
  10/11 or Windows Server with the Hyper-V role/module installed (the `vmms`
  service running; verified with `Get-Service vmms`).
  - **Local mode (default)**: the server runs ON the Hyper-V host.
  - **Remote host mode**: the server runs on another box (e.g. an agent
    desktop with the GPUs) and manages Hyper-V over WS-Man remoting — see
    [Remote Hyper-V host](#remote-hyper-v-host). The remote host needs WS-Man
    remoting enabled (`Enable-PSRemoting -SkipNetworkProfileCheck`; Hyper-V
    Manager connectivity implies it is already on); the **agent box** needs
    the WS-Man client and, in workgroup deployments (the common
    desktop→NUC layout), must trust the host:
    `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<host>' -Concatenate`
    (or use HTTPS/CredSSP instead).
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

   **Per-agent tokens** (issue #10): to tell multiple agents apart, configure
   one token variable per agent and each caller authenticates as its own
   principal — audit rows record the caller's agent id and a server-generated
   request id:

   ```json
   { "http": { "agents": { "agent-a": "HYPERV_MCP_TOKEN_AGENT_A",
                           "agent-b": "HYPERV_MCP_TOKEN_AGENT_B" } } }
   ```

   The values are ENVIRONMENT VARIABLE NAMES — token material lives only in
   the environment, never in the config file. Every agent's variable must be
   set at startup (blank counts as unset); two agents resolving to the same
   token value (or an agent token equal to the legacy `token_env` value) is a
   startup error naming the agent ids, never the values. With `agents`
   configured, `http.token_env` stays optional: when its variable is also
   set, the legacy shared principal (`local-cli`) keeps working alongside the
   agents. Agent ids match `[A-Za-z0-9_.-]{1,64}` (`local-cli` is reserved);
   agent token variables are stripped from every spawned child process
   environment like the other server secrets. `--allow-anonymous` overrides
   both modes (explicit opt-out).

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
3. Optional, remote-host mode only: `HYPERV_HOST_USERNAME` +
   `HYPERV_HOST_PASSWORD` / `HYPERV_HOST_PASSWORD_FILE` authenticates the
   WS-Man hop to the remote Hyper-V host. When unset, the hop uses the
   current user's implicit credentials (works for domain or matching local
   accounts; workgroup boxes typically need the explicit pair or
   TrustedHosts). The host password rides the same stdin channel as guest
   passwords and is redacted everywhere.

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
`hyperv-mcp --check-env` prints the effective policy plus runtime provenance
(PowerShell path/edition/version, config path and SHA-256, git revision).

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
    "console_input": true,        // virtual keyboard + mouse input
    "media": true,                // ISO attach/detach, network connect
    "vm_provision": true,         // VM create, disk add, firmware, TPM, SecureBoot
    "guest_repair": true,         // APPLY guest access repairs (dry run needs no switch)
    "relay": true,                // host->guest HTTP relay listener
    "require_confirm": true       // tools additionally need confirm=true
  },
  "allow_inline_credentials": false,   // expose username/password tool params
  "unrestricted": false,               // explicit research mode: allow all
  "audit_log_path": "C:\\Lab\\audit.jsonl",  // default: one line per op on stderr
  "max_output_bytes": 1048576,         // guest output cap (applied after capture; truncated flag)
  "host_powershell_path": null,        // default: Windows PowerShell 5.1
  "verify_sha256": false,              // default integrity check for transfers
  "ps_timeout_s": 120,                 // default host PowerShell timeout
  // "hyperv": { "host": "nuc01" },    // remote Hyper-V host (issue #43);
  //                                    // OMIT the section entirely for local mode
  //                                    // (the section requires a non-empty host)
  "http": { "host": "127.0.0.1", "port": 8787, "token_env": "HYPERV_MCP_HTTP_TOKEN",
            "agents": { "agent-a": "HYPERV_MCP_TOKEN_AGENT_A" } }
}
```

Unknown keys are rejected at startup (typos must not disable a control).
`HYPERV_MCP_UNRESTRICTED=1` is the environment equivalent of
`"unrestricted": true` for disposable labs; unrestricted mode also forces a
visible audit line per operation.

`host_powershell_path` limitation: the child environment handed to every
spawn always carries a PowerShell 5.1-shaped `PSModulePath` (pwsh7 module
directories stripped, the 5.1 system module directory appended). Pointing
`host_powershell_path` at a `pwsh.exe` (PowerShell 7) executable is therefore
not recommended: the pwsh7 child would lose its pwsh7 module directories on
every spawn. The knob exists for exotic 5.1 layouts; leave it `null` for
PowerShell 7 hosts.

## Remote Hyper-V host

Set `hyperv.host` to manage Hyper-V on another machine — the layout where
the agent (and its GPUs) live on a desktop while the Hyper-V role and VMs
live on, say, a NUC:

```jsonc
{ "hyperv": { "host": "nuc01" } }
```

How it works: with a host configured, every Hyper-V operation is wrapped in
`Invoke-Command -ComputerName '<host>'` so the cmdlets, the
`root\virtualization\v2` CIM/WMI queries, and the PowerShell Direct
(`-VMId`) hops execute ON the Hyper-V host; secrets cross the WS-Man hop as
scriptblock parameters over the existing stdin channel, never in script
text. With `hyperv.host` unset (default) every generated script is
byte-identical to the local-mode emissions. `hyperv_server_info` reports the
effective target (`hyperv_target.mode`/`hyperv_target.host`), the startup
banner names it, and `hyperv-mcp --check-env` runs a one-shot reachability
probe of the target.

### Setup walkthrough (desktop agent + NUC host)

One-time preparation, then a config line. In this walkthrough the Hyper-V
host is `nuc01` and the agent box is the desktop where hyperv-mcp runs.

**Step 1 — prepare the Hyper-V host (`nuc01`, elevated PowerShell):**

```powershell
# WS-Man remoting (skip the network-profile guard on a private/home LAN)
Enable-PSRemoting -SkipNetworkProfileCheck
# The box needs the Hyper-V role (or at minimum the Hyper-V PowerShell
# module) and an account that may manage VMs — membership of the remote
# machine's "Hyper-V Administrators" group is preferred (see Permissions).
```

**Step 2 — prepare the agent box (desktop, elevated PowerShell):**

```powershell
# WORKGROUP deployments (the common desktop->NUC case): the WS-Man client
# must trust the host, and NTLM auth needs explicit credentials (step 3).
Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'nuc01' -Concatenate
# Domain-joined boxes usually need neither TrustedHosts nor explicit
# credentials (Kerberos current-user auth works); HTTPS/CredSSP are the
# hardened alternatives to TrustedHosts.
# Quick connectivity test before touching hyperv-mcp:
Test-WSMan -ComputerName nuc01
```

**Step 3 — host credentials for the hop (agent box):** set
`HYPERV_HOST_USERNAME` plus `HYPERV_HOST_PASSWORD_FILE` (preferred — a
UTF-8 file holding just the password, restrictive ACL) or
`HYPERV_HOST_PASSWORD` in the **server's** environment (see the
`.mcp.json` example in step 4). Set BOTH the username and a password
source: a password without a username is ignored (the hop silently uses
your current Windows user), while a username without any password source
fails with a naming error. With all three unset the hop uses your current
Windows user (implicit auth) — fine on a domain, usually not on a
workgroup. The host password rides the hop as `-Credential` (built from a
stdin-fed value, never in script text); the GUEST password crosses to the
remote host as a scriptblock parameter — meaning the remote Hyper-V host
must be trusted with the guest's credentials, the same trust level as
running PowerShell Direct there. Both secrets are redacted from all output
and stripped from every child process environment. File transfers stage a
temporary copy of the file in the remote host's TEMP during the hop
(removed on success and failure; a hard timeout can leave it).

**Step 4 — point hyperv-mcp at the host** (add the section to your
`HYPERV_MCP_CONFIG` JSON; `hyperv.host` accepts a DNS hostname or IPv4
literal — letters, digits, `.`, `-`, `_`, `:` — because it is
embedded in generated PowerShell):

```jsonc
{
  "schema_version": 1,
  "hyperv": { "host": "nuc01" },
  "allowed_vm_patterns": ["lab-*"],
  "guest_read_roots":  ["C:\\Windows\\Temp"],
  "guest_write_roots": ["C:\\Windows\\Temp"]
}
```

And wire the client (`.mcp.json`) with the host credentials alongside the
usual guest credentials:

```json
{
  "mcpServers": {
    "hyperv": {
      "command": "hyperv-mcp",
      "env": {
        "HYPERV_MCP_CONFIG": "C:\\Lab\\hyperv-mcp.json",
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD_FILE": "C:\\Lab\\secrets\\guest.pw",
        "HYPERV_HOST_USERNAME": "nuc01\\vmadmin",
        "HYPERV_HOST_PASSWORD_FILE": "C:\\Lab\\secrets\\host.pw"
      }
    }
  }
}
```

**Step 5 — verify:**

```text
$ hyperv-mcp --check-env
hyperv-mcp 0.4.0
hyperv.target remote host nuc01
HYPERV_HOST_USERNAME                set
HYPERV_HOST_PASSWORD                not set
HYPERV_HOST_PASSWORD_FILE           set
...
hyperv.target_probe OK
```

The server's stderr banner also names the target on every start
(`[hyperv-mcp] Hyper-V target: remote host nuc01 ...`), and
`hyperv_server_info` reports
`"hyperv_target": {"mode": "remote", "host": "nuc01"}` at runtime. A probe
that prints `hyperv.target_probe UNREACHABLE: ...` names the exact WS-Man
error — fix that before calling tools (see Troubleshooting).

### Notes for agents (MCP clients driving this server)

- **Detect the mode before assuming one:** call `hyperv_server_info` and
  read `hyperv_target`. `{"mode": "local", "host": null}` means every path
  in `host_*_roots` is on this machine; `{"mode": "remote", "host": ...}`
  means VM operations execute on that host while file-transfer policy still
  applies to the machine running the server.
- **File transfers are split-brained in remote mode:** `hyperv_guest_put`'s
  source and `hyperv_guest_get`'s destination live on the **agent box**
  (governed by `host_read_roots`/`host_write_roots`); the guest side lives
  on the VM. Transfers cross the WS-Man hop in bounded base64 chunks
  (192 KiB of file data per hop), so large files are slow — warn the user, and for bulk moves suggest the
  alternative layout below instead of looping retries.
- **Know which host you are operating on.** WS-Man connection failures
  quote the configured host in their message text; other failures (policy,
  credentials, timeouts) do not name it — call `hyperv_server_info` and
  report `hyperv_target` alongside the error instead of re-running blind.
  If `hyperv-mcp --check-env` printed `hyperv.target_probe UNREACHABLE`,
  fix connectivity first; tool calls will keep failing until the hop works.
  The probe composes through the same credential hop as the tools (it uses
  `HYPERV_HOST_*` when configured, your current user otherwise), so its
  verdict reflects what real tool calls will do.
- **Destructive operations hit the remote host.** The same category
  switches (`stop`, `reset`, `checkpoint_restore`, ...) plus `confirm=true`
  gate them, exactly as locally — treat a remote production host with the
  same care, and confirm with the user which host a destructive call will
  land on when both a local and a remote deployment exist.
- **Credentials never go in config values or tool arguments.** Host
  credentials come from the environment / password files; if a user pastes
  a password into chat, direct them to a password file instead of
  `allow_inline_credentials`.
- **File-backed media ops are local-mode only in this release** (VHD/ISO
  paths are consumed by the remote host, not the agent box) — steer users
  to local mode for `hyperv_vm_create`/`hyperv_vm_disk_add`/
  `hyperv_vm_media_attach`; all other media/firmware operations work
  remotely.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `hyperv.target_probe UNREACHABLE: The client cannot connect to the destination specified` | WinRM not listening on the host, or the agent box does not trust it (workgroup) | `Enable-PSRemoting -SkipNetworkProfileCheck` on the host; `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<host>' -Concatenate` on the agent box; retest with `Test-WSMan -ComputerName <host>` |
| `Access is denied` (or 0x80070005) on every remote tool | Wrong `HYPERV_HOST_*` credentials, or the account lacks remote VM rights | Check the credential env vars are in the **server's** environment (restart the MCP client after editing `.mcp.json`); put the account in the host's `Hyper-V Administrators` group |
| Tools worked locally; after adding `hyperv.host` every call fails | Server process started before the env/config landed | Config is read at server start; env per call but from the server's process — restart the MCP client and re-check the banner line |
| `CONFIG ERROR: hyperv.host must be a hostname or IP literal` | Metacharacters in the configured host | Use the bare hostname/IP; quoting is applied by the server |
| Transfers of large files are much slower than local mode | Remote put/get cross the hop in bounded base64 chunks (192 KiB of file data per hop, sized under the WS-Man envelope limit) | Expected; for bulk transfers run the server on the Hyper-V host (local mode) instead |
| A tool reported timeout but the VM state kept changing | The local kill does not reach a command already running on the remote host | Inherent to WS-Man remoting; re-check state with `hyperv_get_vm_info` before retrying |
| `hyperv_vm_create`/`hyperv_vm_disk_add`/`hyperv_vm_media_attach` fail with "does not support ... in this release" | File-backed media ops validate VHD/ISO paths on the agent box but consume them on the remote host — unsupported remotely in this release | Pre-place the file on the remote host and run the operation in local mode; path-free operations (`hyperv_media_detach`, `hyperv_vm_disk_list`, firmware/TPM/SecureBoot) work remotely |
| Remote screenshots fail on large resolutions | The capture payload crosses one WS-Man hop; very large captures can exceed the envelope limit | Lower the resolution, or run the server locally for screenshot-heavy work |

Alternative layout: running the server ON the Hyper-V host and pointing
the agent at `hyperv-mcp-http` (with a token) over an SSH tunnel also
works and needs no remote-mode config.

**Path checks** canonicalize before comparing: `..` collapse, mixed
separators, drive-relative rejection, `\\?\`/UNC prefixes, and
case-insensitive root comparison (drive roots like `C:\` are valid). Host
axes additionally resolve junctions/symlinks of the existing path prefix.
Guest axes are checked *purely lexically* against the path spelling — the
host never consults guest filesystem state — so guest roots must be
spelled exactly as they appear in the guest (8.3 short names, trailing
dots/spaces, and other aliases are not normalized host-side). Guest paths
are re-asserted inside the VM (`[IO.Path]::GetFullPath`, configured-root
containment, and a reparse-point walk of every existing component strictly
*below* the matched root — a reparse at or above the root is the
operator's own spelling of the boundary), failing closed.

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
| `hyperv_console_type_text` / `press_key` / `key_combo` / `type_scancodes` / `mouse_move` / `click` / `button` / `scroll` | `console_input` (no confirm — non-destructive interactive input) |
| `hyperv_vm_media_attach` / `media_detach` / `network_set` | `media` (reversible, no confirm) |
| `hyperv_vm_create` / `disk_add` / `firmware_set_boot_order` / `tpm_set` / `secureboot_set` | `vm_provision` + `confirm` |
| `hyperv_repair_guest_access` with `apply=true` | `guest_repair` + `confirm` (dry run is read-only) |
| `hyperv_relay_start` | `relay` (standing loopback listener, no confirm) |
| `hyperv_repair_guest_access` (dry run) | none (read-only) |

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

## Available Tools (55 total)

Every registered tool in the tables below returns failures the same way:
the one-envelope contract (`ok/error/error_class/retryable/retry_after_ms`,
delivered with `isError: true`) applies to ALL of them — lifecycle,
checkpoints, guest, console, VM/media, and orchestration alike. The
detailed contract is documented under "Behavior changes" below.

### VM identity: `vm_name` and `vm_id` (0.4.0)

Every tool that takes `vm_name` also takes an optional `vm_id` (the VM's CIM
GUID); at least one of `vm_name`/`vm_id` is required (both may be given when
they refer to the same VM). VMs are resolved by GUID end to
end: operations lock on the resolved GUID (stable across renames),
`hyperv_list_vms` and `hyperv_get_vm_info` report each VM's `id`, and a name
that matches more than one VM fails closed with an error listing every
candidate as `name=guid` so the call can be retried with `vm_id`. When both
`vm_name` and `vm_id` are given they must resolve to the same VM, otherwise
the call is rejected as `invalid`. Policy (`allowed_vm_patterns`) applies to
the caller-supplied name first, and to the name resolved from a `vm_id`
before anything runs. `hyperv_vm_create` refuses a name that already exists
(the in-script guard matches the resolver's notion of same-name). TPM and
Secure Boot changes require an explicit `enabled` argument (true or false) —
omission is rejected rather than defaulting to a disable.

### VM Lifecycle

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_list_vms` | — | `[{id, name, state, status, memory_mb, cpu_count, uptime_seconds}]` |
| `hyperv_get_vm_info` | `vm_name` or `vm_id` | `{id, name, state, generation, memory_mb, cpu_count, checkpoint_count, com_ports, network_adapters, hard_drives, ...}` |
| `hyperv_start_vm` | `vm_name` or `vm_id` | `{status: started\|already_running, vm_name, state}` — waits for Running |
| `hyperv_stop_vm` | `vm_name` or `vm_id`, `method`, `confirm` | `{status, vm_name, method, state}` — waits for final state |
| `hyperv_reset_vm` | `vm_name` or `vm_id`, `confirm` | `{status, vm_name, state}` — waits for Running |

**`hyperv_stop_vm` methods:** `shutdown` (graceful via Integration Services,
default), `shutdown-force` (forced), `save` (suspend to disk), `turnoff`
(hard power-off). The default no longer passes `-Force` (0.2.0 change).
Lifecycle calls are idempotent where the target state allows and poll to the
requested final state; a state-wait timeout is a structured error carrying the
last observed state.

### Checkpoints

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_checkpoint_create` | `vm_name` or `vm_id`, `checkpoint_name?` | `{status, vm_name, checkpoint_name}` |
| `hyperv_checkpoint_list` | `vm_name` or `vm_id` | `[{name, type, created, parent_name}]` |
| `hyperv_checkpoint_restore` | `vm_name` or `vm_id`, `checkpoint_name`, `confirm` | `{status, vm_name, checkpoint_name, state, note}` |
| `hyperv_checkpoint_remove` | `vm_name` or `vm_id`, `checkpoint_name`, `include_subtree`, `confirm` | `{status, vm_name, checkpoint_name}` |

`checkpoint_name` auto-generates (`MCP-YYYYMMDD-HHMMSS`) only on **create**;
restore/remove require it. Restore stops the VM (waits up to 600 s for
Off/Saved/Paused while any checkpoint merge completes) — call
`hyperv_start_vm` afterwards. Removal merges disks; it cannot be undone.

### Kernel Debug Setup

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_configure_kdnet` | `vm_name` or `vm_id`, `host_ip`, `port=50000`, `key?`, `reboot`, `confirm` | `{status, kernel_attach_string, key, bcdedit_output, rebooting, ...}` |
| `hyperv_configure_kdcom` | `vm_name` or `vm_id`, `pipe_name?`, `com_port=1`, `reboot`, `confirm` | `{status, kernel_attach_string, pipe_path, bcdedit_output, rebooting, ...}` |

`host_ip` must be a valid IP; `key` must match kdnet hex-group format
(auto-generated cryptographically if omitted — save it, you need it for
`kernel_attach`). KD setup runs `bcdedit` inside the guest via PowerShell
Direct with separately-quoted arguments. Both tools are gated by the
`kd_reboot` category. KDNET is the default; KDCOM is for no-NIC / early-boot
cases and requires the VM Off/Saved for the `Set-VMComPort` step.

### Guest Execution (PowerShell Direct — no WinRM required)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_guest_run` | `vm_name` or `vm_id`, `command`, `args[]`, `cwd?`, `timeout_ms` (default 60000), `elevated`, `confirm` | `{ok, exit_code, stdout, stderr, timed_out, truncated}` |
| `hyperv_guest_run_ps` | `vm_name` or `vm_id`, `script`, `timeout_ms` (default 60000), `elevated`, `confirm` | same envelope |
| `hyperv_guest_put` | `vm_name` or `vm_id`, `local_path`, `remote_path`, `confirm`, `verify?` | `{ok, bytes_copied, sha256_local?, sha256_remote?}` |
| `hyperv_guest_get` | `vm_name` or `vm_id`, `remote_path`, `local_path`, `verify?` | same envelope |
| `hyperv_guest_read_file` | `vm_name` or `vm_id`, `remote_path`, `max_bytes>=1` (default 262144) | `{ok, content_b64, bytes_read, truncated}` |
| `hyperv_guest_list_dir` | `vm_name` or `vm_id`, `remote_path` | `{ok, entries[{name, is_dir, size_bytes, modified}]}` |

**Behavior changes (documented breaking):**

- (0.2.0) **stdout and stderr are SEPARATE fields with real exit codes** (upstream
  merged them via `2>&1` and reported `0` for guest PowerShell errors).
  Elevation caveat: `Start-Process -Verb RunAs` cannot redirect streams, so
  elevated runs merge both into `stdout` (the result carries a `note`).
- (0.4.0) Failures return ONE envelope `{ok: false, error, error_class,
  retryable, retry_after_ms}` where `error_class` is one of `timeout | transport |
  policy | credential | busy | invalid | parse | integrity | not_found |
  guest`. Every registered tool returns this envelope on failure (0.4.0
  documented breaking change: host-side tools no longer raise through the
  protocol), delivered with `isError: true` so failures are visible at the
  MCP protocol level — the envelope rides as the text content AND as
  `structuredContent`. The five keys are the minimum set; module-level
  diagnostics (`timed_out`, `stopped`, `alive_pids`, ...) ride alongside.
  The envelope and the audit log share one isinstance-based taxonomy, so a
  record's `error_class` always equals the envelope's.
- (0.4.0) **Retry guidance:** `busy` is the only retryable class
  (`retry_after_ms` is a fixed ~2s hint until per-holder waits land); every
  other class — `policy`, `invalid`, `credential`, `timeout`, `transport`,
  `parse`, `integrity`, `not_found`, `guest` — is never retryable. A
  `timeout` is not safe to retry for guest execution because the
  guest-side child may still be running.
- (0.4.0) **Unknown arguments and mistyped arguments are rejected:** a
  call carrying an argument the tool's schema does not declare — or a
  declared argument whose value fails schema validation — returns an
  `isError: true` envelope with `error_class: "invalid"` (the argument is
  named), never runs the tool, and is audited. Every published inputSchema
  advertises `additionalProperties: false`.
- (0.4.0) **Success results carry no `structuredContent`** (it is `null`);
  only failure envelopes populate it. Mistyped-declaration validation
  errors that used to surface as bare protocol errors now arrive as the
  same audited envelope. Related: the image/evidence tools' advertised
  `outputSchema` (and its `structuredContent` sidecar) is intentionally
  gone on every Python version — a side effect of their new
  `CallToolResult` return annotations, not a 3.10-only change.
- **Timeout semantics:** the host kills its whole PowerShell process tree
  (Job Object) at the timeout and reports `timed_out: true` with an explicit
  warning — **the guest-side child may still be running**. Guest temp scripts
  are cleaned in `finally` blocks, but a host timeout can leak them in the
  guest `%TEMP%`; the integration suite reports such leaks.

### Victim Execution (Medium IL — EoP testing)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_victim_run` | `vm_name` or `vm_id`, `command`, `args[]`, `cwd?`, `timeout_ms` | standard guest envelope |
| `hyperv_victim_run_ps` | `vm_name` or `vm_id`, `script`, `timeout_ms` | standard guest envelope |

Environment-only victim credentials; never elevated.

### Guest Access Diagnostics & Repair (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_diagnose_vm_access` | `vm_name` or `vm_id`, `timeout_ms=90000` | `{ok, vm_name, vm, ps_direct, guest, findings[], checked_at}` |
| `hyperv_repair_guest_access` | `vm_name` or `vm_id`, `apply=false`, `confirm=false` | `{ok, vm_name, applied, plan[], changes[], verification_findings[], backup_path?}` |

`hyperv_diagnose_vm_access` is ONE read-only call that reports host VM state,
guest identity (hostname/OS), current guest IPv4/IPv6 addresses, PowerShell
Direct availability (a transport failure is a RESULT with `ps_direct.available:
false`, not an error), sshd and WinRM service state, SSH/WinRM listeners, and
a `findings` list naming the exact failure — including `ssh_stale_binding`
when SSH is bound to an address that is no longer a guest IP (the
post-subnet-change incident class). Probe sections are individually
fault-isolated; one failing probe never aborts the report.

`hyperv_repair_guest_access` dry-runs by default (propose only, read-only).
With `apply=true` it performs the narrow fixes — stale `ListenAddress` lines
rewritten to `0.0.0.0` (sshd_config backed up first), stopped sshd/WinRM
started, EXISTING disabled firewall allow rules enabled — a rule whose port filter matches the target port exactly or is port-Any may be widened (disclosed verbatim in the dry-run plan; no new rules are created). A
stale address seen only on the runtime listener matches no config line:
the backup and restart still run with 0 replacements while verification
reports the binding still present — and re-verifies every action, returning per-change
`applied`/`verified` results. Apply requires `guest_repair: true` AND
`confirm=true`.

### Managed Guest Jobs (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_guest_job_start` | `vm_name` or `vm_id`, `command`, `args[]?`, `cwd?`, `timeout_ms=60000` | `{ok, job_id, vm_name, pid, start_time_ticks, job_dir, out_path, err_path, exit_path, started_at}` |
| `hyperv_guest_job_status` | `job_id` | `{ok, job_id, pid, status: running\|exited\|exiting\|stopped, process_name?, exit_code?}` |
| `hyperv_guest_job_output` | `job_id`, `tail_bytes=65536` | `{ok, job_id, pid, tail_bytes, stdout, stderr, *_truncated, *_encoding, *_size}` |
| `hyperv_guest_job_stop` | `job_id` | `{ok, job_id, pid, stopped, alive_pids, job_dir_removed, pid_reused}` (same key set on every path; every failure adds `error`/`error_class`/`retryable`/`retry_after_ms` with `stopped: false`; a repeat stop adds `note: "was already stopped"`) |

Start returns immediately with a job id bound to the exact guest PID and its
start time (`start_time_ticks`; the wrapper resets `$LASTEXITCODE` to null
immediately before invoking the command so a stale code can never mask the
command's own outcome, then records the observed result to a file — a native
exit code, or 1 for a failed cmdlet or a command-not-found — and streams go
to per-job logs under guest `%TEMP%\hyperv-mcp-job-<id>`), replacing
scheduled-task and SSH-tunnel babysitting for long probes. Known
PowerShell-5.1 limit, stated precisely: when the target is a `.ps1` script
the wrapper invokes it as a script callee, so a FAILED FINAL CMDLET inside
it does not propagate `$? = false` across the callee boundary — the wrapper
records the last exit code the script set (0 when it never set one), not 1;
a `.ps1` that wants a truthful code must end with an explicit `exit`.
Output reads are byte-tail bounded and
BOM-sniffed against the stream HEAD (PowerShell 5.1 `1>`/`2>` may write
UTF-16LE; the reported `*_encoding` says which was used). Stop kills the
recorded process AND its descendants, then reports what it observed:
descendants are enumerated and killed EVEN WHEN the wrapper has already
exited (an orphaned child keeps the dead recorded PID as its
`Win32_Process` parent, so the parent-chain walk from the recorded PID
still finds it), and `stopped` is true only when no member of the recorded
tree was observed alive afterward — the job dir is removed and the stored
credentials dropped only in that case; otherwise a survivor comes back as
`ok: false, stopped: false` with `alive_pids` and an `error` string, and
the job stays stoppable for a retry (the retry re-walks and re-kills
whatever survived). The stop result carries the same key set on every path
— success, survivor (which adds `error` plus the standard
`error_class`/`retryable`/`retry_after_ms`), repeat stop (`note: "was
already stopped"`, observation fields as honest unknowns), and transport
failure (which adds the same error fields with `stopped: false`). The PID is
re-validated against `start_time_ticks` first, so a reused PID belonging to
an unrelated process is never killed (a confirmed start-time mismatch
returns `pid_reused: true`, and the already-gone job reports stopped; an
UNREADABLE start time is an unknown, not a mismatch — nothing is killed
and `pid_reused` stays false). Non-elevated
only (RunAs cannot redirect streams). The in-process registry is capped at
128 active jobs (oldest stopped entries are evicted first; new starts are
rejected once the cap is reached) and holds the start-time credentials until
a successful stop, cap eviction, or process exit — plan accordingly on
shared hosts. Every job belongs to the agent that started it: a
status/output/stop call from a different agent gets the same `unknown
job_id` error as an absent id (a foreign caller's id is never distinguishable
from a made-up one, and no guest leg runs for it). `exiting` is not a
terminal state: if the guest wrapper dies
before writing its exit-code file, status stays `exiting` until you call
`hyperv_guest_job_stop`. Every job/relay tool call writes an audit row
naming the caller's agent id (null on stdio or `--allow-anonymous`) and a
server-generated request id. When the call addresses or creates a specific
handle, the row also carries that `job_id`/`relay_id` and — for known ids —
the VM from the registry, so a follow-up row joins to the start row that
created the handle (issue #10). Shapes that honestly audit empty/null
attribution: `hyperv_relay_status` without a relay id (list-all), calls on
unknown ids, rejections of calls addressing unknown ids, and (for the VM
half) follow-ups racing a still-starting job.

### Reboot Recovery (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_wait_guest_recovery` | `vm_name` or `vm_id`, `services[]?`, `processes[]?`, `timeout_s=300`, `interval_s=3` | `{ok, vm_name, ps_direct, services[], processes[], failures[], checked_at}` |

Waits a bounded time for PowerShell Direct to answer (the first thing that
comes back after a reboot), then verifies each named service is Running and
each named process exists. `failures` lists exactly what did not return
(`ps_direct`, `service:<name>`, `process:<name>`). Empty lists = wait for PS
Direct only.

### Host-to-Guest HTTP Relay (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_relay_start` | `vm_name` or `vm_id`, `guest_port`, `host_port=0` (ephemeral) | `{ok, relay_id, url, host_port, ...}` |
| `hyperv_relay_status` | `relay_id?` | `{ok, relays[{relay_id, url, counters, stopped, ...}]}` |
| `hyperv_relay_stop` | `relay_id` | `{ok, relay_id, host_port, stopped}` |

A loopback-only host listener (127.0.0.1; non-loopback binds are refused)
forwarding each HTTP request through PowerShell Direct to
`http://127.0.0.1:<guest_port><path>` INSIDE the guest — reach guest-local
web endpoints and DevTools HTTP APIs (`/json/version`, ...) with zero
dependence on the guest's external addresses and no guest-side component.
Gated by the `relay` category (`hyperv_relay_start` only — status/stop
address the host-side registry and carry no category gate). Limits: HTTP
only (no WebSocket/CDP socket proxying); request bodies <= 1 MiB with
Content-Length (chunked bodies are rejected with 411; a negative
Content-Length is rejected with 400), responses <= 4 MiB; only path-absolute
request targets are forwarded (authority/absolute-form targets are rejected
with 400, so a caller can never steer the guest-side request to another
host); error replies close the connection so a rejected request's body can
never be re-parsed as a follow-up request; handler sockets time out, so a
stalled client cannot park a thread forever; per-request PS Direct legs
deliberately do not serialize behind the per-VM lock and are not audited
(the relay HTTP legs address the guest endpoint, not a tool call — every
tool call itself writes an audit row). The guest endpoint's
redirect responses are followed BY THE GUEST (Invoke-WebRequest default) —
a guest endpoint serving a 3xx sends the guest to the redirect target.
Trust model: the listener binds 127.0.0.1 and requires the relay's own
secret on every request (issue #11): `hyperv_relay_start` returns a
capability URL, `http://127.0.0.1:<port>/<secret>/`, and the listener
verifies (constant-time) and strips that first path segment before
forwarding; any request without the correct secret — including a bare
`curl http://127.0.0.1:<port>/json/version` — answers 401 with the
connection closed and no PowerShell process spawned. The secret (>=128
bits, `secrets`-generated) exists ONLY in the starting agent's
`relay_start` result: `hyperv_relay_status` row urls are identifiers, not
request-capable URLs. The capability path must be followed by a
non-empty path segment starting with `/`: a request to the bare capability
URL (`http://127.0.0.1:<port>/<secret>/`) answers 401 like any other
unauthenticated request, and appending a path WITHOUT its leading slash
(e.g. `<capability-url>json/version`) answers 400 — address the guest as
`<capability-url>/json/version`, i.e. keep the url exactly as returned and
append `/` plus the target path. Ownership (issue #11): a relay belongs
to the agent that started it (the bearer token's agent identity); `relay_status` lists
only the calling agent's relays, and `relay_status`/`relay_stop` with
another agent's id return the same `unknown relay_id` error as an absent
id, so ids cannot be probed through the tools. Without an identity (stdio in-process,
`--allow-anonymous`), all callers form one local principal and behavior
is unchanged. The registry is capped at 16 active relays; stopped entries
are evicted oldest-first (their stored credentials released) when the cap
is reached, and the duplicate-target check and the registry reservation
are one atomic step, so two concurrent starts for the same VM and guest
port admit exactly one (the loser gets the duplicate-target error, which
names the existing relay's id — an accepted residual disclosure: the
secret, not the id, is the capability). The relay holds the start-time
credentials until `hyperv_relay_stop`, cap-time eviction, or process
exit. Relay ids carry 128 bits of randomness and job ids 122 (a v4 UUID's
32 hex chars fix 6 version/variant bits), so an id learned from a
transcript or audit row cannot be guessed either. Guest-side HTTP error statuses pass through to the caller (a
guest 404 arrives as 404 with the relay error envelope); a request racing
`hyperv_relay_stop` receives a clean 503 relay-stopped envelope.

### Evidence Capture (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_capture_evidence` | `vm_name` or `vm_id`, `width=1024`, `height=768`, `save_path?`, `ui_tree=false`, `ui_tree_depth=3`, `ui_tree_max_elements=200` | `[ImageContent, TextContent(meta)]` |

One call pairing the console screenshot with `captured_at` (UTC ISO-8601),
`vm_id`, capture dimensions, `frame_hash`, and — when `ui_tree=true` — a
bounded UIAutomation element tree from the guest (depth/element caps;
requires guest credentials, which the screenshot alone does not). The UI
tree is best-effort: a PowerShell Direct session may not see an interactive
desktop, in which case `ui_tree.ok=false` carries the reason while the
screenshot still ships.

---

### VM Console (WMI — works from firmware through WinPE)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_console_screenshot` | `vm_name` or `vm_id`, `width=1024`, `height=768`, `save_path?` | MCP ImageContent(image/png) + metadata text (vm_id, frame_hash, head res, scale note, fallback_used, captured_at) |
| `hyperv_console_get_display_info` | `vm_name` or `vm_id` | `{ok, enabled_state, head_horizontal, head_vertical, keyboard_present, keyboard_enabled, mouse_present, mouse_enabled, guest_channel, guest_channel_note, vm_id}` |
| `hyperv_console_type_text` | `vm_name` or `vm_id`, `text` (ASCII) | `{ok, chunks, chars}` |
| `hyperv_console_press_key` | `vm_name` or `vm_id`, `key`, `modifiers[]` | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_key_combo` | `vm_name` or `vm_id`, `keys[]` | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_type_scancodes` | `vm_name` or `vm_id`, `scancodes[]` (0..255) | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_mouse_move` | `vm_name` or `vm_id`, `x`, `y`, `frame_width?`, `frame_height?` | `{ok, operation, head_x, head_y}` |
| `hyperv_console_click` | `vm_name` or `vm_id`, `x?=0`, `y?=0`, `frame_width?=0`, `frame_height?=0`, `button=1` | `{ok, operation, head_x?, head_y?}` |
| `hyperv_console_button` | `vm_name` or `vm_id`, `button`, `is_down` | `{ok, operation}` |
| `hyperv_console_scroll` | `vm_name` or `vm_id`, `delta` | `{ok, operation}` |
| `hyperv_console_wait_frame_change` | `vm_name` or `vm_id`, `baseline_hash=""`, `width=640`, `height=480`, `timeout_s=60`, `interval_s=2` | list[ImageContent(image/png), TextContent({stop_reason: changed\|deadline, polls, elapsed_ms, frame_hash})] or deadline dict |
| `hyperv_console_capture_sequence` | `vm_name` or `vm_id`, `count=3`, `interval_s=2`, `width=640`, `height=480` | [first Image, last Image (a single Image when count==1), meta_text(frames[] with per-frame hash + changed_bytes_vs_previous)] |

Console notes: text rides the stdin channel (never in argv/script/errors); non-ASCII input must use type_scancodes; mouse coordinates are in the space of the observed image — pass `frame_width`/`frame_height` matching your screenshot dimensions to scale to head space, or omit them to use head coordinates directly; `wait_frame_change` with `baseline_hash=""` treats the first polled frame as the baseline, and a returned `frame_hash` can be passed back as `baseline_hash` to detect changes across calls (both are the full lowercase-hex sha256 of the raw frame payload); WinPE errors and wizard screens are returned as images for visual interpretation (no OCR is performed).

### VM & Media Preparation (deployment testing)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_vm_create` | `name`, `vhd_path`, `memory_mb=2048`, `cpu_count=1`, `generation=2`, `vhd_size_gb=64`, `switch_name?`, `confirm` | `{ok, id, name, state, generation}` |
| `hyperv_vm_disk_add` | `vm_name` or `vm_id`, `path`, `size_gb`, `controller_type=SCSI`, `confirm` | `{ok, vhd_path, disk_count}` (`disk_count` is `null` if the post-add read failed) |
| `hyperv_vm_disk_list` | `vm_name` or `vm_id` | `{ok, disks[]}` |
| `hyperv_vm_media_attach` | `vm_name` or `vm_id`, `iso_path` | `{ok, iso_path, attached}` (`attached` is `null` if the post-attach read failed) |
| `hyperv_vm_media_detach` | `vm_name` or `vm_id` | `{ok, removed[]}` |
| `hyperv_vm_media_list` | `vm_name` or `vm_id` | `{ok, media[]}` |
| `hyperv_vm_firmware_get` | `vm_name` or `vm_id` | `{ok, secure_boot, secure_boot_template, boot_order, tpm_enabled}` |
| `hyperv_vm_firmware_set_boot_order` | `vm_name` or `vm_id`, `boot_type (Drive\|Network\|File)`, `confirm` | `{ok, first_boot}` |
| `hyperv_vm_tpm_set` | `vm_name` or `vm_id`, `enabled`, `confirm` | `{ok, tpm_enabled}` |
| `hyperv_vm_secureboot_set` | `vm_name` or `vm_id`, `enabled`, `template?`, `confirm` | `{ok, secure_boot, secure_boot_template}` |
| `hyperv_vm_network_set` | `vm_name` or `vm_id`, `switch_name` | `{ok, switch_name}` |

### Orchestration

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_wait_vm_state` | `vm_name` or `vm_id`, `states[]` (Off/Running/Saved/Paused/...), `timeout_s=300` | `{ok, final_state, guest_channel: "ps_direct_unverified"}` |

### Server Provenance (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_server_info` | — | `{version, git_revision, powershell: {path, edition, version, psmodulepath}, config_path, config_sha256, mcp_sdk_version, protocol_version, feature_flags}` — read-only; never contains secrets |

### MDT Deployment Playbook (agent-driven)

1. **Identify** — `hyperv_list_vms`; pick a disposable VM matching allowed_vm_patterns.
2. **Verify media** — `hyperv_vm_media_list` on the VM or known-good ISO path; confirm freshness.
3. **Checkpoint/recreate** — `hyperv_checkpoint_create` (restore later) or `hyperv_vm_create` + `hyperv_vm_disk_add` (multi-disk: separate OS and data disks).
4. **Attach media** — `hyperv_vm_media_attach` with the LiteTouch ISO.
5. **Boot** — `hyperv_vm_firmware_set_boot_order` (Drive for blank-disk fallthrough, or Network for PXE) then `hyperv_start_vm`.
6. **Observe** — `hyperv_console_screenshot` then `hyperv_console_wait_frame_change` (chain via `frame_hash`). WinPE errors appear as images — interpret visually, never answer blindly.
7. **Answer wizard** — `hyperv_console_click` (coordinates from the screenshot) then `hyperv_console_type_text` for harmless fields. For the disk-selection step: verify which disk you are targeting against `hyperv_vm_disk_list` — an early cleanup prompt and the later "Select OS Disk" step are DIFFERENT stages; never target the deployment-media disk.
8. **Monitor** — repeated `wait_frame_change` (static frame = no progress, not success).
9. **Switch channels** — once Windows is up and an admin account exists, switch to `hyperv_guest_run_ps` / `filetransfer` tools. PS Direct failures during WinPE are expected, not evidence the VM is down. Report the switch explicitly.
10. **Collect** — guest logs: `C:\Windows\Temp\DeploymentLogs\SMSTS.log`, `...\BDD.log`. Results.xml lives on the deployment share (host-side) — inspect via host_read_roots, not guest_get. RetVal=0 does not mean zero errors.
11. **Classify & restore** — success/prompt/error from the final image; `hyperv_checkpoint_restore` or recreate the VM.

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
- The streamable-http endpoint's authority is its bearer token(s): with one
  shared token, possession is full authority; with `http.agents`, each token
  carries the same tool authority but calls are attributable to their agent
  in the audit log, and guest jobs and relays are OWNED by the agent that
  started them — follow-ups from another agent get the same unknown-id
  error as an absent id (issue #11). What is still shared: VM-lifecycle
  tools (start/stop/checkpoint/…) are authorized by category, not by
  agent, and the relay registry cap is a host-wide resource.
  Loopback + file ACLs are the boundary.
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

**Dependency pin** — this fork pins `mcp>=1.30.0,<2`; the server uses the mcp
v1 `FastMCP` API, which mcp 2.x renamed, and relies on CallToolResult
passthrough behavior guaranteed from mcp 1.30.

---

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough
edges and breaking changes between versions.

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Built by [Origin](https://originhq.com) for security research and red team
operations; hardened fork maintained at
[zaxbysauce/zaxby-hyperv-mcp](https://github.com/zaxbysauce/zaxby-hyperv-mcp).
