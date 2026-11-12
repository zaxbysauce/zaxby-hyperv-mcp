# hyperv-mcp (hardened fork)

An MCP (Model Context Protocol) server for Hyper-V VM management and guest
execution. Exposes 80 tools for VM lifecycle, checkpoint management, kernel
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

   (`--port` accepts an integer in 1..65535 and is validated at the serve
   and logon-task-install paths; the conventional ephemeral request
   `--port 0` is refused with exit code 2 rather than silently binding the
   configured port.)

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

**Do not run your MCP client as Administrator.** With `--standalone` the
client spawns a private server that inherits the client's token — prefer fix 1.

## Shared controller (default proxy mode; 0.4.0 breaking change)

Since 0.4.0, `hyperv-mcp` is a **thin proxy** by default: it forwards MCP
messages unchanged between the client's stdio and the ONE shared
`hyperv-mcp-http` controller, so every agent shares the same per-VM locks,
job/relay registries and audit sink. With `http.agents` configured, every
audit row names the calling agent; with the shared token alone, rows carry
the shared principal (`local-cli`). Since 0.4.0 the controller no longer
serializes tool calls (FND-01): every tool body runs on an anyio worker
thread, so a second agent's conflicting call fast-fails with
`error_class: "busy"` (carrying the holder's tool, mode and held_ms) instead
of queueing behind the first — and a fast call no longer waits behind a slow
one. Tool concurrency is bounded by the anyio thread limiter resized at
server start to 2x the host PowerShell cap (`max_host_powershell`) on both
transports (in-process embedders driving `call_tool` directly keep anyio's
40-token default).

- **Default (no flags):** proxy to the controller at `http.host`/`http.port`
  from your config (default `127.0.0.1:8787`). If nothing is listening
  there, `hyperv-mcp` auto-starts a detached `hyperv-mcp-http` with the same
  config and environment, waits up to 15 s (one wall-clock budget covering
  spawn and the port wait), and proxies. Under a concurrent second launch
  the bind loser exits cleanly and its proxy connects to the winner.
  NOTE: the auto-started controller inherits the launching client's full
  environment — including its security token — so the controller runs with
  the same rights as the client that started it; if you need a privileged
  shared controller, start `hyperv-mcp-http` yourself from a shell with the
  right token rather than letting a client auto-start it. Auto-start works
  for a single shared token (the `http.token_env` variable must already be
  set — auto-start refuses immediately, naming the variable, rather than
  spawning a controller that would die without it) or a single-agent
  `http.agents` deployment (the
  one agent's variable must be set); with MULTIPLE configured agents
  auto-start is unsupported by design — the controller validates every
  agent variable at startup while a proxy may present exactly one — so
  start `hyperv-mcp-http` manually from a shell that has them all.
  Auto-start checks only that the port accepts connections — it does not
  handshake versions — so stop any stale pre-0.4.0 `hyperv-mcp-http` before
  upgrading.
- **`--proxy URL`:** proxy to an explicit controller URL; never auto-starts.
- **`--standalone`:** the pre-0.4.0 behavior — a private in-process server.
  Use it for disposable single-agent work.
- **`--check-env`:** unchanged (prints policy/provenance, exits; never
  contacts or starts a controller).

### 0.4.0 breaking changes

- **SDK major: mcp 2.x.** The package now requires `mcp>=2.3,<3` (was
  1.x) and the server object is an `mcp.server.mcpserver.MCPServer` (was
  `FastMCP`). New dependencies arrive with it: `httpx2` (also a direct
  dependency — the stdio proxy's upstream HTTP client), plus the transitives
  `mcp-types`, `opentelemetry-api`, and `pywin32` on Windows.
- **`frame_hash` covers the pixel payload only.** `frame_hash` is the SHA-256
  of the thumbnail's PIXEL bytes — the payload after the 4-byte opaque prefix —
  not of the whole payload. The prefix is outside the frame identity, so an
  unchanged screen now produces one hash even if the prefix drifts between
  captures. This changes the VALUE of every `frame_hash`, so a `baseline_hash`
  or `if_changed_from` recorded by an earlier version no longer matches: take a
  fresh capture and chain from that. Both hash values are 64 lowercase hex
  characters, so the two domains are indistinguishable by shape — the tools
  that consume a baseline return a `hash_domain` string
  (`sha256/pixels-after-4-byte-prefix`) so a client can refuse a baseline
  recorded in the other domain instead of reporting a fabricated change. The
  host and the in-guest `wait_frame_change` poll loop hash the same slice with
  the same lowercase-hex encoding, so a returned `frame_hash` still round-trips
  as a `baseline_hash`.
- **Console images are not always PNG any more, and `ImageContent.mimeType`
  says so.** `hyperv_console_screenshot` and `hyperv_capture_evidence` accept
  `format` (`png` — still the default — `jpeg`/`jpg`, or `webp`) and
  `quality` (1..100, lossy formats only). A non-PNG request puts
  `image/jpeg` or `image/webp` on the wire, where every earlier version
  emitted `image/png` unconditionally, and the saved file's bytes are the
  returned bytes in the requested format. `console.Frame` is a public exported
  type, and its `.png` property — previously the only way to get the encoding —
  now raises `AttributeError` for a non-PNG frame: use `.encoded` (the frame's
  own format) and `.mime`/`.pil_format` to learn which. Copying, deep-copying
  or pickling a frame reuses its existing encoding bytes rather than
  re-encoding, so a copy of a JPEG frame is byte-identical to the original.
- **Wire-visible fields.** `hyperv_server_info`'s `protocol_version` now
  reports the 2.x `LATEST_PROTOCOL_VERSION` (2026-07-28, was 2025-11-25),
  and the initialize handshake's `serverInfo.version` now reports this
  package's version (0.18.0 today) instead of
  the SDK's (the release contract, the complete bump-site
  enumeration, and how to read `version`/`git_revision` live in
  [docs/versioning-policy.md](docs/versioning-policy.md)).
- **In-process embedders see the 2.x call shape.** `call_tool()` returns a
  `CallToolResult` (`.content`, `.structured_content`, `.is_error`) instead
  of the 1.x `(content_list, structured)` tuple, and `list_tools()` exposes
  each tool's schema as
  `input_schema` (was `inputSchema`). Tool NAMES, parameters, docstrings,
  `confirm` gating and the failure envelope are unchanged. Embedders that
  drive `hyperv_mcp.server.get_mcp()` in process should port to the 2.x
  shapes; clients over stdio or streamable-http see no change.
- **`from hyperv_mcp.server import mcp`** (the 0xntpower compat import)
  now yields an `MCPServer` — still without a bearer-token verifier; prefer
  the `hyperv-mcp-http` entry point for HTTP.
- **Concurrency is real.** One server process now runs tool calls
  concurrently (bounded by the 2x-`max_host_powershell` thread limiter), the
  event loop stays responsive during long calls, and a cancelled request
  kills its PowerShell tree and releases its VM lock promptly (the unit
  checks pin 1.5 s; the real-host integration check allows 5 s for the tree
  to be gone).

Failure behavior: if the controller is unreachable, a pending request is
answered with a JSON-RPC error (code -32000) and the proxy exits non-zero.
If the controller REJECTS the token, the SDK (mcp 2.x) collapses the non-2xx
response into a generic JSON-RPC error that is forwarded to the client
(typically code -32603, not -32000) and the proxy logs a one-line hint
naming the token environment variable; the proxy no longer classifies the
rejection by HTTP status, because 2.x does not surface the status to the
transport consumer. There is **no silent fallback** to in-process serving.
Cleartext `http://` is accepted for loopback controller addresses only.

The proxy's token comes from the environment variable named by
`http.token_env` (or, when `http.agents` is configured, from the single
agent token variable you set) — never from argv, and never logged or echoed.

Client config snippet:

```json
{ "command": "hyperv-mcp", "env": { "HYPERV_MCP_HTTP_TOKEN": "<this agent's token>" } }
```

Controller as a service: `hyperv-mcp-http --install-logon-task` registers a
per-user logon scheduled task (`hyperv-mcp-http`, RunLevel Limited — Hyper-V
Administrators membership, no UAC — no execution time limit, IgnoreNew,
restart-on-failure) and `--uninstall-logon-task` removes it. The task
definition stores no secrets: set the token variable once for the user
(`setx HYPERV_MCP_HTTP_TOKEN the-token-value-you-generated` — available from the next logon; PowerShell rejects angle-bracket placeholders, so the line above is literally executable once you substitute your value) and
the task-spawned controller reads it from the environment.

## 0.18.0 changes

- **Named-secret typing (#130):** `hyperv_console_type_text` and
  `hyperv_ui_set_value` accept `secret_ref` (`env:NAME` or an allowlisted
  `file:PATH`, resolved host-side through the `host_read_roots` policy).
  The resolved value is typed or set; only its length is reported — the
  value never appears in a response, a script, argv, or an error record.
  `secret_ref` and literal text/value are mutually exclusive. Typing
  literal text without `secret_ref` behaves exactly as before.
- **Console lock state and one-attempt unlock (#130):** new tools
  `hyperv_console_lock_state` (reports `locked`/`unlocked`/`unknown` from
  the guest's process table — a running `LogonUI.exe` is the lock evidence,
  replacing the retired screenshot-byte-size guess) and
  `hyperv_console_unlock` (refuses with `not_locked` when the console is
  already unlocked or the state is unknown — no input is sent; otherwise
  one wake press, the secret typed once, submit, and verification through
  lock state AND a frame change; a still-locked result is `unlock_failed`
  with no retry, because repeated wrong attempts lock the guest account
  out).
- **The drift-inventory gate is self-reference-safe (#143):**
  `scripts/gen_trace_drift_inventory.py` no longer counts the inventory
  document's own pinned pairs in its `--check` verdict (the quine that
  made the gate unreachable at its own fresh output and forced the
  regenerate -> re-AMEND -> regenerate ritual and a disclosed
  `--no-verify` pre-push bypass). Those pairs are reported in a labelled
  "Self-referential pairs" section, whose verdict compares the pair's
  frozen blob against the WORKING-TREE blob id (`git hash-object` — an
  identity that moves with neither the regeneration nor the commit of the
  document). `--check` now also fails when a sibling trace genuinely
  drifts even when the docs copy already matches the regeneration (an
  up-to-date record of a real drift is still a failure), and when a
  `verify-checkpoint` exits nonzero with no CHANGED lines (a broken local
  setup fails the gate instead of rendering clean). The tool inventory is
  82 tools (80 through PR #112, plus the two new console tools).
- Version bump: 0.17.0 -> 0.18.0.

## 0.17.0 changes

- **UIA state-receipt verification channel for the commit guard (#140,
  closes #126):** `hyperv_console_click` accepts
  `verified_state_receipt=<id>` as an ALTERNATIVE to `verified_frame_hash`
  when `commit_guard=true` (the two are mutually exclusive; citing both is
  a refusal naming the parameter). The id comes from any successful UIA
  read — `hyperv_ui_inspect`/`hyperv_ui_find`/`hyperv_ui_wait_for`/
  `hyperv_ui_session_state` now return `state_receipt` — letting
  accessibility-driven workflows verify a selection without a pixel capture
  (the channel #126's In-list promised). The frame-hash guard's code and
  refusal texts are untouched — but the shared ledger has one honest
  consequence to state: because UIA mutations now bump the SAME input
  ledger, a UIA write between a CAPTURE and a frame-hash-guarded click
  now stales that citation too. That is a fail-closed widening of the
  #126 channel's stale set (a UIA write can change what the pixels showed),
  disclosed here rather than buried. The receipt verifies against the SAME
  per-VM input ledger:
  its sequence must be later than the most recent input dispatch, and the
  read's observation-to-stamp window is linearized against input dispatch
  by holding the console-input exclusion on both the VM's GUID and the
  caller-name key spellings — including cold by-name inputs. UIA
  mutations (`hyperv_ui_invoke`/`hyperv_ui_set_value`/`hyperv_ui_focus`)
  now bump the same input ledger at their dispatch seam, so a UIA write
  between the read and the click stales the citation (a dispatched leg
  whose delivery is unknowable — timeout/transport error — bumps
  conservatively; pre-dispatch refusals never bump). Unknown/evicted
  citations refuse as `commit_unverified` with zero mouse input; the
  receipt path takes no live-frame capture and has no pixel-domain
  requirement, and `hyperv_console_sequence` stays frame-hash-only (a step
  carrying `verified_state_receipt` is a step-indexed refusal, never a
  silently ignored key). Per-server-process ledger scope is inherited from
  #126's owner-final decision: there is no cross-process freshness here,
  and the receipt channel has no live-state re-check leg. Internal reads
  whose receipts would be dead weight (evidence's UI-tree walk surfaces the
  read's CONTENT in `meta["ui_tree"]` but can never surface its mint) mint
  nothing citable.
- Version bump: 0.16.0 -> 0.17.0.

## 0.16.0 changes

- **Letterbox-aware console capture and click mapping (#125):** capture
  metadata gains `content_rect` — [left, top, right, bottom] (right/bottom
  exclusive) of the non-letterbox pixels, live-calibrated against the head
  resolution at capture time (key absent when the head is unknown);
  `hyperv_console_screenshot` defaults to `height=0`, which captures at the
  head's aspect for the width (1024 at a 1920x1080 head is 1024x576,
  band-free); `hyperv_console_click`/`hyperv_console_mouse_move` accept a
  `frame_hash` capture citation — the cited rect threads into the mapping
  (the Python reference `_scale_to_head` and BOTH in-script mappers gained
  the identical rect-relative arithmetic), band points are refused
  host-side pre-dispatch, a capture taken at a different head resolution
  refuses as a stale frame, and shaped (cropped/scaled) captures refuse
  pointer citations outright.
- **Opt-in commit guard on clicks (#126):** `hyperv_console_click` gains
  `commit_guard`/`verified_frame_hash` — a guarded click verifies a FRESH
  cited capture (no console input to THAT VM dispatched through this server
  process since it — the input ledger is per-VM, still per-process across
  processes) and re-hashes the live frame at the
  cited pixel domain inside the locked region before committing; refusals
  are structured errors that send no mouse input, and allowed guards are
  audited. Sequence click steps accept the same pair composed with
  `expect_frame_hash`. Captures auto-register for citation (screenshots,
  wait results, capture_sequence frames), inputs bump the ledger at
  dispatch, and the wait tools hold the per-VM console input lock for the
  whole wait so registrations order against input dispatches — console
  input to a VM with a wait in flight now raises VMBusy instead of
  interleaving. Disclosed residual: the freshness leg is per-server-process
  (the live-frame hash check is transport-fresh and catches any visible
  cross-process change); a UIA state-receipt channel is split to the
  follow-up issue #140.
- **Review-feedback hardening round (#125/#126):** sequence steps carrying
  `commit_guard` or `is_down` must be real booleans (a truthy non-bool is a
  step-indexed validation refusal — a string "false" must not silently
  enable the guard or press a button); the capture registry is per-VM,
  keyed `(vm, frame_hash)` and FIFO-capped at 512 entries (two VMs with
  pixel-identical frames keep independent citation records); positional
  mouse ops compare the cited capture's head resolution IN-SCRIPT at
  dispatch, so a head change between the host preflight and the script's
  own head read refuses instead of mapping stale geometry; the guard's
  ALLOW audit row is written only after the guarded step actually parsed
  OK (a refused precondition or a failed/skipped step writes no
  allow-shaped row); and console reads (screenshots, waits) lock on the
  hint-derived GUID when the name->GUID mapping is known, so a hinted input
  op and a whole-wait read exclude each other on the same identity.
- Version bump: 0.15.0 -> 0.16.0.

## 0.15.0 changes

- **Issue #31 supplement AC16 (live seam leg) EXECUTED**: the cleanup-provider
  seam and clone/remove lifecycle ran for real on a live Hyper-V host — two
  disposable clones completed provision→run→stop→remove with the configured
  provider refusing deletion while its fault profile was PENDING (refusal
  before any deletion work, VM + child disk intact), then CLEAN removals;
  the golden parent's SHA-256 and mtime were byte-identical across both
  lifecycles and no residual child disk or .avhdx survived. The named
  evidence file is now executed
  (docs/validation/capability-plan/test_vm_agent_isolation_host-evidence.json)
  with the new gated executor tests/host/test_vm_agent_isolation_host.py
  (skips without HYPERV_MCP_INTEGRATION + HYPERV_MCP_TEST_GOLDEN_VHD).
- **Issue #79 live confirmation (boundary result)**: a self-minted blank
  Gen1 VM (no OS, hence no integration services) on host build 10.0.26300
  STILL exposes Msvm_SyntheticMouse (count 1) alongside Msvm_Ps2Mouse, ops
  select the synthetic path and fail with ReturnValue=32768, so the
  absence-triggered PS/2 fallback's trigger condition does not arise on
  this host build; the fallback's script-structure unit pins stay green and
  the full boundary record is
  docs/validation/live-host/ps2-gen1-live-confirmation-20261108.md. The
  follow-up design question (fallback on synthetic FAILURE, not only
  absence) is recorded on #79 for the maintainer.
- New no-host unit pins: tests/unit/test_host_conftest_scope.py (the
  tests/host skip guard cannot leak onto unit items) and
  tests/unit/test_vm_agent_isolation_host_helpers.py (fail-closed absence
  probes, benign-vs-failure kept rows, cleanup-report emission).
- Version bump: 0.14.0 -> 0.15.0.

## 0.14.0 changes

- **Issue #68 supplement (classed admission fairness layer, workstream C)**:
  every tool call now passes a two-class admission layer in front of the
  thread limiter — the light/status surfaces (`hyperv_list_vms`,
  `hyperv_server_info`, `hyperv_get_vm_info`, `hyperv_guest_job_status`)
  are LIGHT with a lane reserved at the thread-limiter axis
  (`admission.light_reserve` tokens of the
  `2 x max_host_powershell` budget; omitted default `min(2, budget - 1)`,
  an explicit invalid value fails startup; the reserve is a CLASS
  reservation, not a claim that these tools never touch PowerShell),
  everything else GENERAL on a
  per-agent fair queue (no agent's backlog starves another's). Console
  raw-input tools queue actor-first: one fair queue per canonical VM
  identity (the issue-#77 hint unifies by-name and by-GUID addressing),
  capacity 1, and an actor-queued caller never holds a token — K agents
  fanning in on one VM cannot occupy the whole budget. Every wait is
  bounded (`admission.wait_s` / `admission.light_wait_s`) and
  cancellation-safe; a saturated refuse answers a retryable `busy`
  envelope whose `retry_after_ms` is the measured hint, and every audit
  row gains `admission_class` + `admission_wait_ms` (busy refusals also
  record `retry_after_ms`). Pinned by the frozen
  `tests/unit/test_admission_fairness.py` and the dispatch census
  `tests/unit/test_admission_dispatch.py`.
- **Issue #64 AC3 (amendment): the binding backoff probe.** The shipped
  slot-pool wait's exponential backoff (5 ms doubling to a 200 ms
  ceiling, each sleep capped to the remaining deadline) is now bound by
  an executed probe (`tests/unit/test_c02_backoff_probe.py`): the
  measured schedule matches the ceiling model, a 3 s window performs
  10-24 sweeps (the jitter-tolerant band; a fixed 50 ms cadence would
  sweep ~61 times), and the shipped assertions pin a >= 3x attempt
  reduction from the measured ceiling (the dev-box measurement is ~4x).
- **Issue #68 supplement AC6 (transport matrix harness + evidence)**:
  the transport-matrix harness (available from the repository at
  `tests/benchmark/test_admission_transport_matrix.py`, the HOST_ONLY
  harness — shared-VM vs independent-VM topology, p50/p95, queue wait,
  throughput, busy-refusal rate, per-VM fairness over the configured MCP
  transport), env-gated so it never presents as a live pass by default,
  with the named evidence placeholder — the repo doc artifact
  `docs/validation/capability-plan/test_admission_transport_matrix-evidence.json`
  (executed: false — the plan-critic-approved substitution).
- Version bump: 0.13.0 -> 0.14.0

## 0.13.0 changes

- **Issue #118 (vendored skill bytes pinned)**: the four vendored
  agent skills under `.agents/skills/` resynced byte-for-byte to
  `ZaxbyHub/opencode-swarm@d71e5aea` (11 drifted files restored, 11
  reference docs that were missing are now present); a checked-in
  `.agents/skills/vendored-skills.manifest` (per-file sha256 plus the
  pinned canonical commit) and `tests/unit/test_vendored_skill_manifest.py`
  now fail CI on ANY vendored drift — including same-`version:`-string
  drift, which version-line comparison is structurally blind to.
  `.gitattributes` gained `*.sh text eol=lf` and `*.manifest text eol=lf`,
  killing the CRLF materialization class at checkout.
- **Issue #67 (versioning policy + consumer build identity)**:
  `docs/versioning-policy.md` documents the release contract — a version
  bump on every behavior-changing PR, the complete bump-site
  enumeration (`pyproject.toml`, `__version__`, the frozen AC7 pin via
  the issue-16 AMEND procedure, and the README changelog section plus
  today-marker), `hyperv_server_info` as the machine-readable
  provenance surface, the call-time (not build-identity) semantics of
  `git_revision`, the historical two-0.4.0 disambiguation via
  `mcp_sdk_version`, and optional tag-at-merge provenance.
  `tests/unit/test_versioning_provenance.py` pins the whole contract so
  a consumer can distinguish installed builds without reading source.
  The shared-controller section above links the new policy doc.
- Version bump: 0.12.0 -> 0.13.0

## 0.12.0 changes

- **Issue #59 (lock-scope pins)**: a new AST guardrail freezes the
  issue-#14 VM-lock scope table; job_stop's VMBusy re-raise is pinned end
  to end (module + MCP envelope), the evidence/repair swallow paths pin
  `error_class=busy`, and the wiring tests' defaulted finding-tag
  parameters were removed.
- **Issue #64 (slot-pool identity + polite waiting)**: the slot directory
  records the pool cap in `pool.meta` (atomically published under a
  publication lock; corrupt markers are warned and republished); cap and
  directory divergence warn once per process; the effective host-wide cap
  is the RECORDED one; the acquire loop backs off exponentially from 5 ms
  to a 200 ms ceiling with every sleep capped to the remaining deadline.
- **Issue #68 (limiter restore + documented bound)**: the server lifespan
  restores the captured prior thread-limiter token count on exit; the
  PS-free admission bound under VM-lock saturation is documented in the
  concurrency section and measured by a real-lock saturation test.
- **Issue #70 (five runtime fixes)**: the stdio proxy's failure path now
  claims outstanding request ids synchronously and answers every id
  exactly once even when two failures race (emission ownership); the
  upstream-closed diagnostic names the observed cause; `--port 0` is
  refused with a clear error (valid range 1..65535); registry lookups
  return snapshots; the guest-recovery wait documents its in-guest
  interval bound and its poll-slice cancellation window.
- Version bump: 0.11.0 -> 0.12.0

## 0.11.0 changes

- Frozen-check amendments (issues #63/#66): the Workstream C/D acceptance checks now
  discriminate tree-kill (event-synchronized unwind seam), the run_ps worker-thread
  promptness bound (`elapsed < 1.0`, tightening the tool-call layer's 1.5 s cancel
  bound), slot-return capacity, same-VM poll overlap and seeded status, and a
  recorded-child precondition on the cancel path.
- Frozen-checkpoint drift re-baseline (issue #119): every drifted manifest pair
  re-baselined with original replay bases preserved; trace-74's suite-count expects moved
  to stable predicates.
- New: `docs/rebaseline-runbook.md` (the CHECK_WRONG re-baseline procedure),
  `docs/issue-trace-drift-inventory.md` (live drift state), and
  `scripts/gen_trace_drift_inventory.py` (`--check` gate with fail-closed marker,
  clean-checkout, and snapshot-refusal guards).
- Version bump: 0.10.0 -> 0.11.0 (`pyproject.toml`, package `__version__`,
  `test_c03_sdk_port.py`'s expected literal; `test_version_consistency.py` pins the sites).

## 0.10.0 changes

- **Oversized console input delivers everything (#81):** Windows caps the
  spawned command line at 32766 spawnable characters (CreateProcess's 32767
  ceiling includes the terminating null), so input that would overflow ONE
  command is split into sequential commands rather than launched into
  WinError 206 — scancode arrays beyond ~1600 codes split across consecutive
  folded `type_scancodes` processes (each carrying a contiguous slice as its
  own in-script seed, all delivered in order under one console input lock;
  the result's `chunks` stays the TOTAL 64-code window count), remote
  `type_text` beyond 100 stdin chunks composes multiple sequential
  `Invoke-Command` hops (each carrying a contiguous chunk range), and an
  oversized `run_sequence` codes step encodes its array as an in-script
  base64 seed decoded in the script. Ordinary-size inputs keep the exact
  single-process emissions the one-process pins freeze.
- **`hyperv_console_sequence` refuses over-budget plans fail-closed (#81):** a plan
  whose composed command line cannot fit the spawn budget even after the
  codes-step compaction is refused before the sequence command spawns (a
  by-id plan may already have spent one resolver spawn) with a structured
  `ConsoleError` naming the composed command-line length and the 32766-char
  budget — reduce steps or per-step payload.
- **New result fields `mouse_ps2_present` and `used_fallback` (#83):**
  `hyperv_console_get_display_info` additionally reports the PS/2 mouse
  (the non-positional input ops — button, scroll, click-at-current-position
  — fall back to it, so a PS/2-only VM no longer reads as "nothing can act
  on the console"; `mouse_present` stays the synthetic-only answer), and a
  folded screenshot response without a usable `USED=` line surfaces
  `used_fallback: true` instead of silently assuming the requested size.
- **The WMI transport probes the PS/2 mouse too (#83):** the in-process WMI
  `display_info` resolves `Msvm_Ps2Mouse` through a `SystemName`-scoped
  query mirroring the mouse-path lookup, so `mouse_ps2_present` agrees
  across transports instead of reading constant false on the default
  in-process path.
- **Console input guards (#83):** mouse coordinates, frame dimensions and
  button values are bool-rejecting integer guards (a bool must never pass as
  1) validated before any spawn, and non-ASCII `type_text` is rejected with
  a pointer to `hyperv_console_type_scancodes`.
- **Folded ops emit a validated identity (#82/#83):** every folded console
  op emits `VMID=` from the script's own resolved identity and the host
  re-validates it through the same shape gate a host-resolved GUID passes,
  so a VM deleted and recreated under the same name fails closed BEFORE any
  guest input and the name->GUID mapping self-heals.
- **Version bump:** 0.9.0 -> 0.10.0 (`pyproject.toml`, package `__version__`,
  this section; `test_version_consistency.py` pins the sites).

## 0.9.0 changes

- **The auto-started controller verifiably escapes the client's job (#71):**
  on current Windows builds the spawner's `CREATE_BREAKAWAY_FROM_JOB` is
  silently ignored, so the controller stayed inside the MCP client's
  kill-on-close job object and died with every client disconnect (the
  long-standing "flaky" b03 autostart test, and silent controller respawns in
  daily use). The spawn path now queries `IsProcessInJob` (fail-closed) and
  only claims success when the controller verifiably runs OUTSIDE any job:
  plain spawn when jobless, verified breakaway, else the WMI wrapper (which
  verifies its own child and refuses on failure). The auto-start budget is
  30 s (measured spawn-to-listening: ~1.1 s idle, 2.2-3.9 s loaded) and the
  budget-expiry diagnostic names the observed wait and the exact controller
  log path.
- **Every tool parameter is described in the schema (#86):** mcp 2.x builds
  each inputSchema from the function signature alone, so the Google-style
  `Args:` docstring sections never reached the wire (434 properties across
  78 tools published without any description). The docstring is now the
  single source of truth: registration stamps every undescribed property
  with its `Args:` text, and a suite-wide pin fails on any parameter whose
  docstring never documents it (both credential variants are covered).
- **Whole-tree pytest runs the unit suite (#115):** the integration
  conftest's collection hook scoped its skip/timeout markers to the whole
  session, so `pytest tests` reported every item skipped with exit 0 and a
  broken tree looked green. The markers now apply only to items under
  `tests/integration`; unit items always execute.
- **Failure-envelope docstrings name the busy holder (#60):** the
  `(+ holder on busy)` note now covers every lock-capable tool that
  advertises the failure envelope (the UIA family and
  `hyperv_vm_secureboot_set` had drifted). The lock-free
  `hyperv_vm_get_video` states explicitly that it takes no VM lock and never
  emits holder metadata, and `vmlocks.py` documents the queued-writer holder
  semantics (queue-time `since`/`held_ms`, refresh-only-when-queued, live
  recompute, honest no-holder case).
- **Version bump:** 0.8.0 -> 0.9.0 (`pyproject.toml`, package `__version__`,
  this section; `test_version_consistency.py` pins the sites).

## 0.8.0 changes

- **Non-loopback binds keep DNS-rebinding protection (#69):** on mcp 2.x the
  SDK auto-enables Host/Origin validation only for loopback binds, so a
  `--host 0.0.0.0` (or LAN IP) bind silently ran with the middleware
  disabled. `hyperv-mcp-http` now arms explicit protection for every
  non-loopback bind: allowed hosts/origins cover the bind address forms, and
  a new `http.allowed_hosts` config list (names only, never secrets) covers
  the LAN hostname/IP clients actually send. Loopback binds are unchanged.
  A foreign Host header is rejected (421); an uncovered Origin is rejected
  (403).
- **WMI console survives worker turnover (#95):** a cached SWbem service
  dies with the worker thread that created it (the observed
  "Object is not connected to server" storm). The backend cache now records
  each service's creator and reconnects on a live worker when the creator
  has exited. `ConsoleWMI.creator`/`creator_thread` expose query provenance,
  and every translated WMI failure names the serving worker and the concrete
  operation (input-method failures name the method; input is still never
  replayed through PowerShell).
- **Controller log lines carry timestamps (#57):** every line the controller
  writes to its redirected per-user log is prefixed `YYYY-MM-DDTHH:MM:SSZ`
  (ISO-8601 UTC), so spawn/refusal history is readable from the log alone.
  That covers the startup banner and policy lines, the token refusals, the
  audit stream and the endpoint notice — they all share one emitter
  (`hyperv_mcp.logemit`), which also prefixes every line of a multi-line
  payload. The SDK's and uvicorn's own records land in the same file, so a
  process-wide record factory stamps those too (uvicorn's access line
  carries the stamp in its client-address field). The interactive
  `--install-logon-task` prints keep their operator-shell format (they are
  written to the operator's terminal, not to the redirected log).
- **Guest-root UNC validation hardened (#37):** share-less UNC roots
  (`\\server`, `\\server\`) and the `\\?\UNC\server\share`
  device form are rejected at config load; a configured root must name its
  share. A failed `guest_get` no longer leaves empty husk directories when
  directory creation fails mid-chain (the created prefix is pruned
  leaf-first before the error re-raises).
- **Wheel ships the UIA helper — verified (#110):** a unit check builds the
  wheel via the PEP 517 backend and asserts
  `hyperv_mcp/guest/uia_helper.ps1` ships in the archive, and fails on a
  build configuration that excludes it (a packaging regression can no
  longer ship a broken wheel with CI green).
- **README connect section documents the controller token (#56):** the
  `.mcp.json` snippet and the `claude mcp add` one-liner now name
  `HYPERV_MCP_HTTP_TOKEN`, and the `setx` guidance is paste-safe.
- **Version bump:** 0.7.0 -> 0.8.0 (`pyproject.toml`, package `__version__`,
  this section; `test_version_consistency.py` pins the sites).

## 0.7.0 changes

- **`hyperv_deployment_status` result shape (richer contract, issue #32):**
  `vm{state, uptime_s}` flattens to top-level `state` / `uptime_s` with
  `vm_id` added; `heartbeat` (a bare string) becomes a struct
  `{enabled, primary_status, application_status}`; `guest` gains `fqdn` and
  `ipv6[]`; new `phase_basis` (the producing signals) and UTC `checked_at`.
  The vocabulary grows to seven phases (`off` / `suspended` /
  `heartbeat_disabled` / `no_guest_signal` / `os_ready` / `os_unresponsive`
  / `degraded` — the Running+enabled+OK-heartbeat+no-KVP row retained from
  the reviewed table). `guest.*` and `kvp.*` always read the heartbeat-gated
  view (stale pairs never surface as the guest's identity).
- **`hyperv_harvest_offline_logs` manifest (evidence contract, issue #33):**
  `files[]` rows are now `{volume, source, dest, size, sha256,
  last_write_utc}` (was `{path, bytes, sha256}`) with `source` the
  guest-relative log path; `skipped[]` rows are `{volume, reason}` (was
  `{path, reason}`); absent fixed-log entries surface under the new
  `missing[]` instead of `skipped`; per-file over-cap sources are named
  individually and in-budget glob siblings still copy; `sha256` and `size`
  are re-derived in Python from the copied bytes; new `vm_id` and
  `truncated` (any engaged per-file/total cap).
- **In-session UI Automation helper (issue #29):** eight new
  `hyperv_ui_*` tools drive the guest's interactive desktop by UI
  Automation element (inspect, find, invoke, set_value, wait_for, focus,
  session_state, helper provisioning with a full teardown). The read verbs
  need only VM policy plus guest credentials; the mutating verbs require
  the new `destructive.ui_input` category and provisioning the new
  `destructive.ui_provision` category plus `confirm`. See "In-session UI
  Automation helper" under Available Tools.
- **`hyperv_checkpoint_create` gains `checkpoint_type`** (issue #26):
  `standard`, `production`, `production_only`, or `""` (default — the VM's
  own setting, byte-identical behavior to 0.6.x). Additive; no breaking
  change. The create result gains `checkpoint_type` and `vm_checkpoint_type`
  when a type was requested; `hyperv_get_vm_info` gains `checkpoint_type`;
  the restore `note` is now state-accurate (Saved/Paused/Running restore
  states no longer claim the VM is powered off). See "Checkpoint types" under
  Checkpoints for the security and recovery notes.

## 0.6.0 breaking changes

- **`hyperv_console_click` coordinates:** `x`/`y` now default to `null`
  instead of `0`, and `(0,0)` is a real coordinate that moves the pointer to
  the frame origin. To click at the current pointer position, OMIT both
  `x` and `y` (callers that passed `x=0, y=0` to mean "here" must drop the
  arguments). Giving exactly one of `x`/`y` is now an error — the tool
  returns the standard failure envelope with `error_class: "invalid"`
  (`x and y must be given together`). There is no compatibility shim
  (issue #25); the versioning-policy follow-up is tracked as issue #67.
- **Coordinate clicks need a resolvable display head and the synthetic
  mouse.** Any click WITH `x`/`y` — now including `(0,0)` — positions the
  pointer first, which requires the VM's display head to be readable and
  an `Msvm_SyntheticMouse`; guests with only a PS/2 mouse cannot take
  coordinate clicks and support only click-at-current-position (omit
  `x`/`y`). At `0.5.x` a `(0,0)` call degraded to click-at-current-position,
  so callers that relied on that on PS/2-only guests must drop the
  coordinates.

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

Optional in-process WMI console transport (issue #45; removes the
per-call `powershell.exe` start from console tools):

```powershell
pip install -e ".[wmi]"   # adds pywin32 on Windows
```

Console scripts: `hyperv-mcp` (default: proxy to the shared controller;
`--proxy URL`, `--standalone`, `--version`, `--check-env`) and
`hyperv-mcp-http` (streamable-http controller; `--install-logon-task`,
`--uninstall-logon-task`). `python -m hyperv_mcp` also works.

---

## Credential model

All guest-facing tools authenticate to the guest via PowerShell Direct.
Resolution order:

1. **A matching credential profile** (0.7.0, issue #30) — see
   [Per-VM credential profiles](#per-vm-credential-profiles-070-issue-30)
   below. When several profiles match one VM the server refuses to start the
   leg (fail-closed); when none matches, the global variables apply.
2. `HYPERV_GUEST_USERNAME` + one of:
   - `HYPERV_GUEST_PASSWORD`
   - `HYPERV_GUEST_PASSWORD_FILE` (path to a UTF-8 file holding just the
     password; preferred — put it in a profile directory with a restrictive
     ACL)
3. `HYPERV_GUEST_VICTIM_USERNAME` + `HYPERV_GUEST_VICTIM_PASSWORD` /
   `HYPERV_GUEST_VICTIM_PASSWORD_FILE` for the Medium-IL victim tools. A
   profile may also carry the victim identity (`victim_username` plus
   `victim_password_env`/`victim_password_file`); it wins for VMs it matches.
4. Optional, remote-host mode only: `HYPERV_HOST_USERNAME` +
   `HYPERV_HOST_PASSWORD` / `HYPERV_HOST_PASSWORD_FILE` authenticates the
   WS-Man hop to the remote Hyper-V host. When unset, the hop uses the
   current user's implicit credentials (works for domain or matching local
   accounts; workgroup boxes typically need the explicit pair or
   TrustedHosts). The host password rides the same stdin channel as guest
   passwords and is redacted everywhere.

Inline `username`/`password` tool arguments (only present when
`allow_inline_credentials: true`) keep their historical precedence: they beat
profiles and global variables for that call — a per-call identity is never
replaced by the VM's profile.

### Per-VM credential profiles (0.7.0, issue #30)

A lab whose VMs use different local admin accounts (a golden image per OS
family, a domain-joined VM next to workgroup boxes) maps each VM-name pattern
to a named credential profile:

```json
{
  "credential_profiles": [
    {
      "name": "lab-a",
      "vm_patterns": ["lab-a-*", "LABA-*"],
      "username": "LabAdminA",
      "password_env": "LAB_A_PW"
    },
    {
      "name": "lab-b",
      "vm_patterns": ["lab-b-*"],
      "username": "LabAdminB",
      "password_file": "C:/lab/secrets/lab-b.txt"
    }
  ]
}
```

Rules:

- The key must carry at least one profile: an explicit empty list is a
  load error. Omit the key entirely for the zero-profile behavior.

- Matching is case-insensitive fnmatch against the target VM's canonical
  name — the same semantics as `allowed_vm_patterns`. A profile never grants
  VM access; `allowed_vm_patterns` stays the only VM gate.
- Precedence is fixed: inline arguments (policy-gated) → the single matching
  profile → the global `HYPERV_GUEST_*` variables. With zero profiles
  configured, behavior is byte-identical to pre-profile releases.
- **Secrets never live in the config.** Each profile names an environment
  variable (`password_env`) or a file path (`password_file`). A literal
  `password` key — or any unknown key, application-account-shaped or
  otherwise — is refused at load with an error naming the key, and an env
  reference that is not a valid variable name is refused without echoing the
  value. The name `default` is reserved (it is the sentinel the server
  reports for the global credential).
- Fail-closed shapes: two matching profiles → the leg refuses naming both; a
  matched profile whose secret is missing → the leg refuses naming the
  profile (no global fallback).
- GUID-only calls (`vm_id` without `vm_name`) resolve the VM's canonical
  name first so profile matching still applies. When profiles are configured
  and the name cannot be resolved, the leg refuses instead of silently using
  the global admin; with zero profiles the lookup failure falls back exactly
  as before.
- The pooled PowerShell Direct session key separates the admin and victim
  identities of one profile (a victim call can never inherit an admin
  session), and every guest session key is still redacted in errors and
  logs.
- Managed guest jobs and relays record the credential **identity** (profile
  name + username, never the secret) they started with, and a restore after
  a server restart re-resolves through that identity — a changed environment
  or a renamed profile refuses instead of silently switching accounts.

`--check-env` lists each configured profile's name, VM patterns, and secret
source (variable name or file path, plus set/missing) — never the value.

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

## Leases: multi-call exclusion with fencing tokens (0.5.0)

A test agent's unit of work spans several tool calls — restore a checkpoint,
start the VM, run a probe, collect output. Per-call locks cannot protect the
gaps between those calls, and two separate server processes never saw each
other's locks at all. Leases close both gaps.

**Workflow:** `hyperv_lease_acquire(vm_name, scopes, ttl_s)` (`ttl_s` 0 or
omitted means the configured default; above `max_ttl_s` is refused) → pass the returned
`lease_id` + `fencing_token` on every subsequent mutating call →
`hyperv_lease_renew(lease_id)` periodically (a heartbeat) →
`hyperv_lease_release(lease_id)` when done. `hyperv_lease_list` shows the
leases on a VM; holder, scopes and expiry are public, but a lease's id and
token are visible ONLY to the agent that holds it.

**Scopes:** `lifecycle` (start/stop/reset/checkpoints/KD/provisioning —
exclusive against every other scope), `guest_exec` (guest runs, victim runs,
jobs, relays, repair), `transfer` (guest put/get), `console` (keyboard/mouse
input). Two non-`lifecycle` scopes held by different agents coexist.

**Fencing:** every grant bumps a per-`(VM, scope)` counter that is persisted in
the state store, so tokens strictly increase across restarts. A call presenting
a superseded token is refused `fenced` — a paused former holder cannot resume
into a VM another agent has taken over. Hyper-V itself cannot verify the token;
the store checks it before any PowerShell runs.

**Required vs optional:** on the shared HTTP controller (`hyperv-mcp-http`)
every mutating call MUST carry a valid lease — a call without one is refused
`lease_required` before anything runs. Standalone stdio servers default to
optional: an unleased call is still refused `lease_conflict` when ANOTHER agent
holds a lease on the VM, but a single-agent deployment needs no changes. Config
override:

```jsonc
{ "leases": { "required": false, "default_ttl_s": 300, "max_ttl_s": 3600 } }
```

**Cross-process exclusion:** every mutating call also takes a short per-call
row in the state store, so two `hyperv-mcp` server processes sharing one
`HYPERV_MCP_STATE_DB` now exclude each other on the same VM — previously each
process had its own lock dict and the exclusion was invisible between them. The
per-call row is deleted when the call ends; if a process dies, its rows expire
with their TTL and no manual cleanup is needed. Concurrent read-mode legs
(guest probes, job polling) still coexist, within and across processes.

**What a lease does NOT do:** a leg already running when its lease expires is
not aborted — fencing stops the NEXT call, it cannot un-send a PowerShell
child. Cancellation is a separate workstream. Read-only tools (list, info,
screenshots, status) never require a lease and are never blocked by one.
Deny-by-default policy and `confirm` gates are unchanged: a lease never
authorizes an operation policy denies.

**Disclosed limits:**

- A lease on a VM that does not exist yet (`hyperv_vm_create`, or acquiring
  before first boot) is keyed by NAME in a distinct namespace; renaming the VM
  right after creation splits that lease. GUID-keyed leases survive renames.
- `hyperv_relay_start` / `hyperv_relay_stop` take no per-call VM lock (the
  relay transport's own design), so their lease enforcement is guard-level
  only. `relay_stop` resolves the VM from the relay's in-memory
  registry first, then the store row (both owner-filtered); if neither
  yields a VM — unknown id, foreign owner — the call is not lease-gated
  against a VM (it is still owner-scoped, so a foreign agent cannot stop
  your relay).
- The same store-row lookup covers `hyperv_guest_job_stop`; if the job row is
  pruned the call is likewise not lease-gated against the VM.
- When a caller supplies only `vm_name` and another agent's lease exists, the
  guard resolves the name to its GUID (one PowerShell spawn, paid only when
  candidate leases exist). If that resolution itself fails, the guard defers
  and the tool body raises the authoritative identity error — a resolution
  failure is never treated as "no lease held".
- A lease never bypasses policy or `confirm` gates, and read-only tools are
  never gated. Note `hyperv_guest_get` is leased (scope `transfer`) because
  the issue's scope map puts guest put/get together, even though `get` writes
  only the HOST filesystem — the guest stays read-only to it.
- Expired lease rows are retained (so a late `renew` reports `lease_expired`
  rather than `lease_unknown`) until a sweep deletes them one `max_ttl_s`
  after expiry, on the store's first open per process.

Upgrade notes: enabling `leases.required` on a shared controller is a breaking
change for clients that have not adopted leases — they will start receiving
`lease_required`. That is the intended design for a multi-agent host. An OLDER
binary cannot load a config file that contains the `leases` key at all
(unknown config key at startup) — remove the key before downgrading.
Anonymous leases (`--allow-anonymous`, or stdio where every caller is
unattributed) are a supported posture: they provide mutual exclusion between
processes but NO identity — any unattributed process that learns the lease id
can use it, and two anonymous callers are indistinguishable to the ownership
check. Attributed (bearer-token) callers get full identity binding.

## Durable state store

Job and relay handles survive a server restart. The registry lives in a SQLite
database in WAL mode, so a `job_id` or `relay_id` an agent is holding still
addresses the guest process after the server process exits, crashes, or is
restarted — a stdio client restart is enough. The store is always on; there is
no in-memory-only mode.

```jsonc
{
  "state_db_path": "C:\\ProgramData\\hyperv-mcp\\state.db"   // optional
}
```

| Setting | Default | Notes |
| --- | --- | --- |
| `state_db_path` | `%LOCALAPPDATA%\hyperv-mcp\state.db` | Where the store lives. |
| `HYPERV_MCP_STATE_DB` | — | Environment override of `state_db_path`, like `HYPERV_MCP_UNRESTRICTED`. |

The startup banner and `hyperv-mcp --check-env` print the resolved path. The
database must be on a local disk: WAL mode needs shared memory and does not
work over a network filesystem, so a UNC path is refused with a clear error.

What the store holds, and what it never holds:

- **Holds** — `job_id`, VM name and GUID, PID and its start-time identity,
  the job directory and stream paths, `started_at`, lifecycle state, the
  owning agent, and a *credential reference* (`env`, `file`, or `inline`) plus, for rows
  written since the identity binding shipped, the recorded *credential
  identity* (`cred_profile`/`cred_username` — never the secret).
- **Never holds** — no password, no password-file content, no command text,
  no argument text, and no relay capability secret. A restored job re-resolves
  its credential from the source it was started with, which registers the
  secret for redaction exactly as at start.

Lifecycle after a restart:

- A job that was running is still addressable: `hyperv_guest_job_status`,
  `_output` and `_stop` reattach to it.
- A job whose start was interrupted by the crash comes back as `orphaned`.
- A relay whose listener died with the process is reported as
  `state: "interrupted"` instead of `unknown relay_id`, and starting the same
  VM + guest port again is not refused as a duplicate. No listener is re-bound
  automatically — bringing a relay back is an explicit `hyperv_relay_start`,
  which re-checks policy.
- A job started with inline credentials cannot be re-attached: it reports a
  credential error rather than silently substituting whatever credentials the
  environment now holds.

The schema is versioned with `PRAGMA user_version` (this release sets 4; a
v1 database written by 0.4.x gains the lease tables automatically on first
open, and a v2 database written by 0.5.x gains the `ops`/`events`/`meta`
tables the same way — every migration is additive and transactional) and
migrations only go forward. A database written by a newer build is refused rather than silently
corrupted; conversely, an OLDER binary refuses any config file that contains
the `leases` key OR any `destructive` key it does not know (e.g. the #112 `vm_remove`/`offline_harvest` switches) (unknown config key) — remove the key or upgrade the binary.

## Durable operation handles: detach, idempotency, and the event cursor (issue #24)

The slow tools — start/stop/reset VM, checkpoint create/restore/remove,
wait_vm_state, wait_guest_recovery, vm_create, and guest run/run_ps/put/get —
accept two extra coordination arguments:

- `detach: true` returns an operation handle (`{op_id, status: "working",
  poll_interval_ms}`) immediately, after the policy/confirm/lease gates have
  run synchronously and the op row is durably committed. A detached runner
  thread executes the tool body holding the same VM lock and lease a
  synchronous call would; the client polls `hyperv_op_status` and reads the
  stored (redacted) result with `hyperv_op_result` (64 KiB pages,
  resumable by cursor, byte-identical across restarts).
- `idempotency_key` deduplicates retries: the same agent repeating the same
  tool with the same key and arguments gets the stored result back marked
  `replayed: true` — across server restarts too. The same key with different
  arguments is refused with `error_class: "idempotency_conflict"`. Arguments
  are stored only as an HMAC fingerprint (credential and coordination fields
  excluded), never in plaintext.

`hyperv_op_cancel` requests cooperative cancellation — the runner honours it
at its next leg boundary; a crashed runner surfaces as `failed` with
`error_class: "interrupted"` and a note that the VM-side outcome is unknown,
never as a `working` that never ends. `hyperv_op_list` lists the calling
agent's handles. Everything is scoped to the calling agent: another agent's
(or an unknown) id answers exactly like an unknown id.

Every state transition also appends to an event log read with
`hyperv_events(after=<cursor>)`: op, lease, job, and relay transitions arrive
in order with monotonic sequence numbers that survive retention pruning, so
an agent can resume an event stream across restarts. A cursor older than the
retention window answers `cursor_expired: true` with `oldest_cursor`.
`oldest_cursor` is the window-start watermark - the cursor of the oldest
event that survived retention - not a resume token: resuming from it can
skip events that landed between your cursor and the window start, so
gap-free recovery re-reads from `after=""`.

When an MCP client advertises the `io.modelcontextprotocol/tasks` capability
per request (the 2026-07-28 protocol), the same durable ops are served as
tasks: a detachable `tools/call` answers with a `CreateTaskResult`
(`resultType: "task"`), and `tasks/get` / `tasks/cancel` / `tasks/update`
drive it — `taskId` is the same id as `op_id`, so the `op_*` tools and the
tasks methods are two views of one store row. Clients that do not advertise
the capability get ordinary synchronous results.

```jsonc
{
  "operations": {
    "enabled": true,              // optional, default true
    "retention_s": 86400,         // op/result retention
    "idempotency_ttl_s": 86400,   // replay window; a later retry re-executes
    "heartbeat_ttl_s": 60,        // runner liveness; lapse -> failed/interrupted
    "runner_bound": 0,            // 0 = share max_host_powershell
    "event_retention_s": 604800,
    "event_max_rows": 10000,
    "key_env": ""                 // env var carrying the fingerprint HMAC key
  }
}
```

Excess detached calls beyond `runner_bound` are refused with a retryable busy
envelope, never queued without bound.

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
    "vm_provision": true,         // VM create/clone, disk add, firmware, TPM, SecureBoot
    "vm_remove": false,           // VM removal (+ own-disk deletion with delete_disks)
    "offline_harvest": false,     // offline log harvest from a stopped VM's disk
    "display": true,              // VM display resolution (Set-VMVideo; restart leg needs stop + confirm)
    "guest_repair": true,         // APPLY guest access repairs (dry run needs no switch)
    "relay": true,                // host->guest HTTP relay listener
    "ui_input": true,             // issue #29: UIA invoke/set_value/focus
    "ui_provision": true,         // issue #29: UIA helper install + autologon (needs confirm)
    "require_confirm": true       // tools additionally need confirm=true
  },
  "allow_inline_credentials": false,   // expose username/password tool params
  // issue #30: per-VM credential profiles — secrets from env/files only, never here.
  // See "Per-VM credential profiles" under "Credential model" for the full rules.
  "credential_profiles": [
    { "name": "lab-a", "vm_patterns": ["lab-a-*"], "username": "LabAdminA",
      "password_env": "LAB_A_PW",
      "victim_username": "LabVictimA", "victim_password_env": "LAB_A_VICTIM_PW" }
  ],
  "unrestricted": false,               // explicit research mode: allow all
  "audit_log_path": "C:\\Lab\\audit.jsonl",  // default: one line per op on stderr
  "max_output_bytes": 1048576,         // guest output cap (applied after capture; truncated flag)
  "host_powershell_path": null,        // default: Windows PowerShell 5.1
  "verify_sha256": false,              // default integrity check for transfers
  "ps_timeout_s": 120,                 // default host PowerShell timeout
  "vm_lock_wait_s": 30,                // per-VM lock bounded wait, 0..600 s (0 = fail fast; also bounds the documented PS-free admission delay, issue #68)
  "max_host_powershell": 8,            // host-wide concurrent powershell.exe cap, 1..64 (issue #15)
  "host_powershell_wait_s": 60,        // oversubscribed-leg bounded wait, 0..600 s, int or float
                                       // (0 = fail immediately with a busy error)
  "ps_slot_dir": null,                 // slot lock-file directory; ABSOLUTE path or null. Default
                                       // %ProgramData%\hyperv-mcp\ps-slots (shared per host); a shared
                                       // temp dir when ProgramData is unset (per-account on Windows).
                                       // All servers on a host must use the same value and cap
  "agent_isolation": { "cleanup_provider": "none" },  // optional per-agent cleanup seam (issue #31 supplement): a named registered provider is consulted before hyperv_vm_remove deletes (CLEAN proceeds; PENDING/UNKNOWN/FAILED refuse); "none" = default = no consult
  "psdirect_session_reuse": true,      // reuse PowerShell Direct sessions across calls (issue #21).
                                       // See "PowerShell Direct session reuse" below
 "state_db_path": null,                // durable state store location (issue #22); null = the
                                       // %LOCALAPPDATA% default. See "Durable state store" above
  // "hyperv": { "host": "nuc01" },    // remote Hyper-V host (issue #43);
  //                                    // OMIT the section entirely for local mode
  //                                    // (the section requires a non-empty host)
  "http": { "host": "127.0.0.1", "port": 8787, "token_env": "HYPERV_MCP_HTTP_TOKEN",
            "agents": { "agent-a": "HYPERV_MCP_TOKEN_AGENT_A" },
            // allowed_hosts: public host names/IPs clients send for a
            // non-loopback bind (DNS-rebinding protection, issue #69)
            "allowed_hosts": ["lab.example.com"] }
}
```

Unknown keys are rejected at startup (typos must not disable a control).
`HYPERV_MCP_UNRESTRICTED=1` is the environment equivalent of
`"unrestricted": true` for disposable labs; unrestricted mode also forces a
visible audit line per operation.

#### Audit record schema

One JSON object per audited operation, appended to `audit_log_path` (or one
line per op on stderr when unset):

```json
{
  "ts": "2026-10-17T15:25:35.721+00:00",
  "tool": "hyperv_guest_run_ps",
  "vm_name": "test-vm",
  "category": "guest_exec",
  "ok": true,
  "duration_ms": 1247,
  "exit_code": 0,
  "error_class": "",
  "agent_id": null,
  "request_id": "31ee4c18f3be4a7c843902a37fb3996d",
  "job_id": null,
  "relay_id": null,
  "timing": {
    "lock_wait_ms": 0,
    "ps_ms": 1200,
    "ps_spawns": 1,
    "total_ms": 1247,
    "ps_startup_ms": 120,
    "psdirect_session_ms": 1300,
    "guest_ms": 900
  }
}
```

`timing` is additive: `duration_ms` and every key above it keep their meaning,
so existing log consumers are unaffected. `lock_wait_ms` is how long the call
waited for the per-VM lock (0 when it never waited, and a real number on a
`busy` failure that timed out). `ps_ms`/`ps_spawns` are the total duration and
the count of `powershell.exe` children the call started. `total_ms` is the
whole operation, measured from the operation's entry, so it is never smaller
than `duration_ms` and never smaller than `ps_ms`. The three guest keys are
populated only when the guest host script emitted timing markers — null
otherwise, which is the normal answer for console-only calls and for a fake
transport. `guest_ms` is the guest-side measurement; `psdirect_session_ms` is
the PowerShell Direct **session-establishment** cost, and it is emitted only on
the call that opened the session. On the per-call path it covers the whole
session, so the setup cost is recoverable as `psdirect_session_ms - guest_ms`;
on the pooled path it is establishment only, so that subtraction does not hold
there. Values are
numeric or null; nothing in `timing` ever carries script text, arguments or
credentials.

`hyperv_console_screenshot` is the one console image tool that returns this
same object as its `timing` metadata key. `hyperv_console_wait_frame_change`,
`hyperv_console_wait_frame_stable` and `hyperv_console_capture_sequence`
still return the legacy `timings` block only, so a consumer reading `timing`
from them gets nothing — read the audit record for those three.

#### Soak benchmark

`scripts/soak_bench.py` runs 1, 4 and 8 concurrent agents against the real tool
layer and reports p50/p95/p99 plus busy and incorrect rates per agent count
and per tool, and the median guest timing breakdown for `guest_run_ps`. Only
read-only and console-input tools are used — no lifecycle or destructive call.
The harness ships in the sdist (`scripts/` at the extraction root, so the
`python scripts/soak_bench.py` invocations below work there and from a git
checkout) and in the wheel (force-included as
`<site-packages>/scripts/soak_bench.py` after `pip install`).

```bash
# CI-runnable: stubs run_ps, needs no Hyper-V
python scripts/soak_bench.py --fake --agents 1,4,8 --iterations 5 --json

# live: refuses to start unless all three variables are set and guest
# credentials resolve, and only ever touches the named disposable VM
HYPERV_MCP_INTEGRATION=1 HYPERV_MCP_SOAK=1 HYPERV_MCP_TEST_VM="Deployment Test 3" \
    python scripts/soak_bench.py --agents 1,4,8 --iterations 20 --json
```

Fake and live mode share the tool layer, the percentile helper and the audit
sink. They differ in three ways besides whether `pswindows.run_ps` is stubbed:
fake mode force-disables the in-process WMI backend so every leg takes the
PowerShell transport, it swaps in a `test-*` config with `console_input`
enabled instead of `unrestricted`, and it injects a fake guest credential pair.
Policy, credential resolution and the audit operation still behave the same way
in both, but a fake-mode run is not evidence about the production regime: live
mode is the one that measures the real backend and the real lock contention.
Percentiles reuse `hyperv_mcp.consolebench.pct` (nearest-rank), so the two
cannot drift; no new runtime dependency.

`--vm <name>` overrides the VM every agent addresses (default: the VM named by
`HYPERV_MCP_TEST_VM`). `guest_timing_median_ms` appears in the JSON row only
when at least one `guest_run_ps` row in the audit log carried a marker, so its
absence is itself the signal that no guest timing was measured.

`host_powershell_path` limitation: the child environment handed to every
spawn always carries a PowerShell 5.1-shaped `PSModulePath` (pwsh7 module
directories stripped, the 5.1 system module directory appended). Pointing
`host_powershell_path` at a `pwsh.exe` (PowerShell 7) executable is therefore
not recommended: the pwsh7 child would lose its pwsh7 module directories on
every spawn. The knob exists for exotic 5.1 layouts; leave it `null` for
PowerShell 7 hosts.

## Non-loopback binds: DNS-rebinding protection (0.8.0, issue #69)

`hyperv-mcp-http` binds loopback by default. A non-loopback bind
(`--host 0.0.0.0`, a LAN IP, or a DNS name) now arms DNS-rebinding
protection explicitly: requests whose `Host` (or `Origin`) header does not
match the bind address are rejected with 421 (host) / 403 (origin).

The allow-lists cover the bind address itself (any port, and the bracketed
IPv6 form). Clients that connect by a DIFFERENT name — the usual LAN case,
where a browser or agent dials `http://192.168.1.20:8787` while the server
binds `0.0.0.0` — must be allowed explicitly:

```jsonc
{
  "http": {
    "host": "0.0.0.0",
    "port": 8787,
    "token_env": "HYPERV_MCP_HTTP_TOKEN",
    "allowed_hosts": ["192.168.1.20", "lab.example.com"]
  }
}
```

Each entry contributes its host and host:* forms to the allowed hosts and
its `http://` / `https://` forms (any port) to the allowed origins. An
entry that already names a PORT (`lab.example.com:8787`) contributes only
its exact form — the `host:port:*` sibling could never match a Host
header. Names only — never put a secret in this list. Entries are
validated at load: a scheme, a path, a wildcard, a name with whitespace,
a malformed address or an out-of-range port is rejected at startup rather
than silently failing to match any request.

For a WILDCARD bind (`0.0.0.0`, `::`) the loopback forms
(`127.0.0.1`, `localhost`, `[::1]`) are admitted automatically — this
repo's own stdio proxy dials the controller over loopback on a wildcard
bind (so the bearer token never crosses a routable interface), and a
client dialing the machine's LAN address still needs its own entry.
Do NOT leave the list empty on a wildcard bind: the bind address itself
is not a name any client dials, so every LAN client would be refused
with 421. Either list the addresses your clients dial, or front the
endpoint with a reverse proxy that rewrites `Host`/`Origin` to the bind
address.

Loopback binds are unchanged: mcp 2.x's own auto-enable still applies, and
no allow-list is needed.

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
hyperv-mcp 0.8.0
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
  to local mode for `hyperv_vm_create`/`hyperv_vm_clone`/`hyperv_vm_disk_add`/
  `hyperv_harvest_offline_logs`/
  `hyperv_vm_media_attach`; all other media/firmware operations work
  remotely.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `hyperv.target_probe UNREACHABLE: The client cannot connect to the destination specified` | WinRM not listening on the host, or the agent box does not trust it (workgroup) | `Enable-PSRemoting -SkipNetworkProfileCheck` on the host; `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<host>' -Concatenate` on the agent box; retest with `Test-WSMan -ComputerName <host>` |
| `hyperv.target_probe POOL_BUSY: host PowerShell pool saturated: ...` | The host-wide PowerShell slot pool is full (`max_host_powershell` children already running) and the bounded wait expired. With session reuse on (the default), an **idle** pooled worker holds its slot for its whole lifetime — up to 300 s with no call in flight — so the pool can be saturated with no tool leg running at all | Retry (the envelope is `busy`, retryable); reduce concurrency or raise `max_host_powershell` (1..64) if the host has headroom; when the slots are held by idle pooled workers, set `psdirect_session_reuse: false` or lower `max_host_powershell` |
| Legs fail as `error_class: "transport"` with `cannot open PowerShell slot file pool.meta.lock` (the pool-cap marker's publication lock is opened before the slot files; a `slot-NN.lock` name in this message indicates the same ACL problem) | The slot directory's ACLs do not include the running account (e.g. a second non-admin account against the hardened default directory) | Set `ps_slot_dir` to a directory both accounts can use, or grant the account access to `%ProgramData%\hyperv-mcp\ps-slots`; `--check-env` prints the effective `max_host_powershell`, `host_powershell_wait_s` and `ps_slot_dir` |
| `Access is denied` (or 0x80070005) on every remote tool | Wrong `HYPERV_HOST_*` credentials, or the account lacks remote VM rights | Check the credential env vars are in the **server's** environment (restart the MCP client after editing `.mcp.json`); put the account in the host's `Hyper-V Administrators` group |
| Tools worked locally; after adding `hyperv.host` every call fails | Server process started before the env/config landed | Config is read at server start; env per call but from the server's process — restart the MCP client and re-check the banner line |
| `CONFIG ERROR: hyperv.host must be a hostname or IP literal` | Metacharacters in the configured host | Use the bare hostname/IP; quoting is applied by the server |
| Transfers of large files are much slower than local mode | Remote put/get cross the hop in bounded base64 chunks (192 KiB of file data per hop, sized under the WS-Man envelope limit) | Expected; for bulk transfers run the server on the Hyper-V host (local mode) instead |
| A tool reported timeout but the VM state kept changing | The local kill does not reach a command already running on the remote host | Inherent to WS-Man remoting; re-check state with `hyperv_get_vm_info` before retrying |
| `hyperv_vm_create`/`hyperv_vm_clone`/`hyperv_vm_disk_add`/`hyperv_vm_media_attach`/`hyperv_harvest_offline_logs` fail with "does not support ... in this release" | File-backed media ops and the offline harvest mount host-local disks: paths are validated on the agent box but consumed on the remote host — unsupported remotely in this release | Pre-place the file on the remote host / run the harvest on the host itself, in local mode; path-free operations (`hyperv_media_detach`, `hyperv_vm_disk_list`, firmware/TPM/SecureBoot) work remotely |
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
| `hyperv_vm_clone` | `vm_provision` + `confirm` (creates a VM on a differencing disk over a read-only golden image) |
| `hyperv_vm_remove` | `vm_remove` + `confirm` (removes the stopped VM's registration; `delete_disks=true` additionally deletes only its own disk files). Issue #31 supplement: consults the configured `agent_isolation.cleanup_provider` before deletion (CLEAN proceeds; PENDING/UNKNOWN/FAILED refuse; `none` = default = no consult) |
| `hyperv_harvest_offline_logs` | `offline_harvest` (read-only, no confirm — mounts the guest disk read-only and copies the fixed log set) |
| `hyperv_vm_set_resolution` | `display` (reversible, no confirm; applies at next start) — its `restart=true` stop/start additionally needs `stop` + `confirm` |
| `hyperv_ui_invoke` / `hyperv_ui_set_value` / `hyperv_ui_focus` | `ui_input` (no confirm — element-level interactive input; the lease gate runs first) |
| `hyperv_ui_helper_provision` | `ui_provision` + `confirm` (installs the in-session helper and configures autologon; `teardown=true` runs the same gate) |
| `hyperv_repair_guest_access` with `apply=true` | `guest_repair` + `confirm` (dry run is read-only) |
| `hyperv_relay_start` | `relay` (standing loopback listener, no confirm) |
| `hyperv_repair_guest_access` (dry run) | none (read-only) |

Denials return a structured `policy` error (no secrets, no speculative paths).
Concurrency is also guarded per VM with scoped read/write locks: read
legs — job start/status/output/stop, guest script execution, guest file
transfers, diagnostics probes, evidence capture — share the VM with each
other, while VM-state mutations (power, checkpoints, media, firmware) and
repair apply exclude everything. A conflicting call waits up to
`vm_lock_wait_s` (default 30 s, `0` = fail fast) and then returns a `busy`
error whose payload carries `holder` — `{tool, mode, since, held_ms}` — so
the caller can see what holds the VM and for how long. Waiting writers are
admitted before newly arriving readers, so polling reads cannot starve a
checkpoint restore. Documented admission bound (issue #68): the tool-limiter
resize (2x `max_host_powershell`) reserves no class for PS-free tools, so
lock-queued calls occupying every limiter token delay PS-free admission up to the `vm_lock_wait_s` bound
(measured worst case: 1 lock holder + 15 lock-queued calls); the classed
admission layer below is the issue-#68-supplement fairness reserve that
closes it for the LIGHT class only — the reserved lane the admission
section below calls the closed half of this bound (GENERAL admission
keeps the documented bounded wait). The limiter
bound is restored on server-lifespan exit, so co-tenant `to_thread` users
keep their own token count; in-process embedders driving `call_tool` never
enter the lifespan and keep anyio's 40-token default. Console input runs under a read lock on the VM key
(guest work proceeds during typing) plus a write lock on a second per-VM
key, so two agents cannot interleave keystrokes. Both keys derive from the
resolved GUID on every transport since issue #77: operations whose stdout
carries the resolved identity (`VMID=` — screenshot, display info, capture,
sequences) plus the identity guard's own report teach the host-side
name-to-GUID mapping, a by-name console call whose name is known locks on
the canonical GUID (the same key a by-id caller takes) and carries an
in-script identity guard that fails closed before any input when the mapping
is stale (see "Canonical console identity" below). The one residual: a
by-name console call whose name has no learned mapping yet (an input-only
caller on a fresh process — waits, by-id input, and WMI-transport
operations neither feed nor need the mapping) stays keyed on the
caller-supplied name until a feeding operation supplies one — disclosed in
the console-identity section, not tracked as an open defect.

Classed admission (issue #68 supplement, workstream C) sits in front of the
thread limiter on every tool call. Two classes: LIGHT — the
status/readiness/list/info/jobs-status surfaces (`hyperv_list_vms`,
`hyperv_server_info`, `hyperv_get_vm_info`, `hyperv_guest_job_status`) —
and GENERAL (everything else). The LIGHT set is a lane reserved at the
THREAD-LIMITER axis, not a claim of PowerShell-freeness: the registry is a
fixed class list, and the reserve keeps that class admitted even while
GENERAL callers saturate the budget. The budget mirrors the limiter sizing
(`2 x max_host_powershell` tokens); GENERAL callers may occupy at most
`total - admission.light_reserve` of them (and in-flight GENERAL + LIGHT
together never exceed the total), so the reserved lane keeps
LIGHT admission flowing even while GENERAL callers saturate the budget —
the closed half of the documented `vm_lock_wait_s` admission bound above.
`admission.light_reserve` omitted (the default) resolves to
`min(2, budget - 1)` — valid at every host cap including 1; an explicitly
configured value is validated `0 <= light_reserve < budget` at startup and
a violation fails loudly (never clamped; `0` is the explicit disable,
accepting the documented bound). GENERAL waiters queue per-agent
round-robin (`admission.wait_s` bounds the park, default 30 s; LIGHT parks
are bounded by `admission.light_wait_s`, default 10 s), so one agent's
backlog can never starve another's. The console raw-input tools
(`type_text`, `press_key`, `key_combo`, `type_scancodes`, `mouse_move`,
`click`, `button`, `scroll`, `sequence`) queue ACTOR-FIRST: one fair queue
per canonical VM identity (the issue-#77 hint map unifies the by-name and
by-GUID spellings onto the GUID), capacity 1, and the actor-eligible
caller only then acquires a token — K agents fanning in on one VM hold no
token while queued and enter one at a time, so they cannot occupy every
token and starve unrelated light/status traffic. Every wait observes
cancellation each tick; a saturated or timed-out refuse answers the
ordinary retryable `busy` envelope with a measured `retry_after_ms`, and
the detached-operation runner admits through the same core
synchronously before the tool body. Every audit row records
`admission_class` (LIGHT/GENERAL) and `admission_wait_ms` (the measured
park wait; null when no admit was in flight), and busy refusals also
record their `retry_after_ms`.

Host PowerShell itself is bounded host-wide (issue #15): every tool leg,
every relay request, every server process that shares the slot directory, and
— with `psdirect_session_reuse` on (the default) — every **idle pooled worker**
draws from a pool of `max_host_powershell` (default 8) slot lock files, so
the number of simultaneous `powershell.exe` children stays at or below the
cap for the whole host. A pooled worker holds its slot for its whole LIFETIME
rather than for the duration of a call, which is why the pool reserves two
slots of headroom (`max_host_powershell - 2`) and installs no pool at all
below a host cap of 3: see the session-reuse section below. When the
recorded `pool.meta` cap differs from this process's configured cap, the
headroom arithmetic no longer lines up (the pool still sizes from the
CONFIGURED cap while the slot sweep honors the RECORDED one) - the
documented mitigation is to keep one slot directory and one cap per host,
which the divergence warning also names. The cap is only as wide as the slot directory:
servers configured with different `ps_slot_dir` values run separate pools
(each divergence is warned once per process, naming both directories), and
the slot directory records the pool's cap in a `pool.meta` marker (published
atomically under a publication lock; a corrupt marker is repaired loudly on
first read). A process whose configured `max_host_powershell` differs from
the recorded cap is warned once, naming both values, and honors the
RECORDED cap — a cap-64 process cannot exceed a recorded cap-8 pool (issue
#64) — so keep one slot directory and one cap per host. The inter-attempt
wait backs off exponentially from 5 ms to a 200 ms ceiling (each sleep
capped to the remaining deadline), so a saturated wait performs far fewer
lock attempts than the previous fixed 50 ms cadence; cancellation is still
observed on every retry tick. The wait does not
consume the leg's own timeout: a caller that queues gets its full
`timeout_s` budget once it holds a slot. A caller that cannot get a slot
within `host_powershell_wait_s` (default 60 s) gets a retryable `busy`
envelope (`retryable: true`, `retry_after_ms: 2000`; unlike the per-VM busy
envelope it carries no `holder` block, because the pool is host-wide rather
than a specific VM's holder); relay requests surface it as their existing
HTTP 502 transport reply. Slots are OS file locks, so a server process that
dies has its slots released by the OS. The default slot directory
(`%ProgramData%\hyperv-mcp\ps-slots`) is hardened, best effort, to
Administrators, Hyper-V Administrators, and the running account — once per
process, whether or not this process created the directory, so a
pre-existing directory is not adopted unhardened. Hosts running servers
under several non-administrative accounts should set `ps_slot_dir`
explicitly with suitable ACLs (a second account cannot open slots in a
directory hardened for the first; every leg then fails as a non-retryable
`transport` error naming the lock file). If the ACL hardening step fails,
the server continues and logs a warning — but a partially applied `icacls`
can strip inheritance without granting, after which legs fail until the
directory's ACLs are fixed by hand; the derived directory is never
re-hardened for the life of the process. When `ProgramData` is unset (or on
non-Windows hosts) the pool falls back to a shared temp directory, which is
per-account on Windows and is not ACL-hardened.

Cancellation is leg-safe now: if a leg unwinds for any reason other than a
normal completion or its own timeout, `run_ps` kills the whole host
PowerShell process tree for that leg before returning, releases the slot,
and closes the Job Object handle — previously the child kept running and
kept the caller's VM lock held until it finished on its own (the VM lock
itself is released by the caller as the exception unwinds). When the leg
runs in an anyio worker thread — where every tool body runs since 0.4.0
(mcp 2.x dispatches sync handlers through `anyio.to_thread.run_sync`) —
`run_ps` also observes host-task cancellation between 0.2 s polling slices
and kills promptly instead of running the leg out. MCP request cancellation
is therefore wired end to end: a client cancelling a call (over
streamable-http, by closing its response stream) settles the call within
about a second, kills the host PowerShell tree, and releases the VM lock.
The guest-side process of a PowerShell Direct leg may
still be running after such a kill; that is the documented timeout
semantics (see "Timeout semantics") and applies to cancellation the same
way.

---

## Connecting to MCP clients

```powershell
$env:HYPERV_MCP_HTTP_TOKEN = [convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
claude mcp add hyperv -- hyperv-mcp
```

The stdio client inherits `HYPERV_MCP_HTTP_TOKEN` from this shell, so the
merged auto-start fail-fast (which names that variable) is satisfied; the
token value stays in your environment and out of argv.

`.mcp.json` (a persistent client configuration — the token is stored there
IN PLAINTEXT, so keep the file out of version control, and replace the
placeholder below with your generated secret: the controller accepts ANY
non-empty value as the bearer token, so an unreplaced placeholder would
become a published credential):

```json
{
  "mcpServers": {
    "hyperv": {
      "command": "hyperv-mcp",
      "env": {
        "HYPERV_MCP_CONFIG": "C:\\Lab\\hyperv-mcp.json",
        "HYPERV_MCP_HTTP_TOKEN": "REPLACE_WITH_YOUR_GENERATED_TOKEN",
        "HYPERV_GUEST_USERNAME": "Administrator",
        "HYPERV_GUEST_PASSWORD_FILE": "C:\\Lab\\secrets\\guest.pw"
      }
    }
  }
}
```

---

## Available Tools (80 total)

Every registered tool in the tables below returns failures the same way:
the one-envelope contract (`ok/error/error_class/retryable/retry_after_ms`,
delivered with `isError: true`) applies to ALL of them — lifecycle,
checkpoints, guest, console, VM/media, and orchestration alike. The
detailed contract is documented under "Behavior changes" below.

### VM identity: `vm_name` and `vm_id` (0.4.0)

Every tool that takes `vm_name` also takes an optional `vm_id` (the VM's CIM
GUID); at least one of `vm_name`/`vm_id` is required (both may be given when
they refer to the same VM). VMs are resolved by GUID end to
end: operations lock on the resolved GUID (stable across renames;
a by-name console call whose name carries a learned mapping locks on the
same canonical GUID with an in-script identity guard — see "Canonical
console identity" below and the concurrency note; the unhinted residual is
disclosed there),
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
| `hyperv_get_vm_info` | `vm_name` or `vm_id` | `{id, name, state, generation, memory_mb, cpu_count, checkpoint_count, checkpoint_type, com_ports, network_adapters, hard_drives, ...}` |
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
| `hyperv_checkpoint_create` | `vm_name` or `vm_id`, `checkpoint_name?`, `checkpoint_type?` | `{status, vm_name, checkpoint_name}` (+ `checkpoint_type`, `vm_checkpoint_type` when a type is requested) |
| `hyperv_checkpoint_list` | `vm_name` or `vm_id` | `[{name, type, created, parent_name}]` |
| `hyperv_checkpoint_restore` | `vm_name` or `vm_id`, `checkpoint_name`, `confirm` | `{status, vm_name, checkpoint_name, state, note}` |
| `hyperv_checkpoint_remove` | `vm_name` or `vm_id`, `checkpoint_name`, `include_subtree`, `confirm` | `{status, vm_name, checkpoint_name}` |

`checkpoint_name` auto-generates (`MCP-YYYYMMDD-HHMMSS`) only on **create**;
restore/remove require it.

**Checkpoint types (0.7.0).** `hyperv_checkpoint_create` accepts
`checkpoint_type`: `standard`, `production`, `production_only`, or empty
(default: the VM's own `CheckpointType` setting, unchanged behavior).
`Checkpoint-VM` has no per-call type parameter, so a requested type is
applied to the VM-level setting for that one call and restored afterwards —
the result reports the requested type and the VM's pre-call type
(`checkpoint_type`, `vm_checkpoint_type`).

- **Standard** captures guest memory: applying it returns the VM to the exact
  saved moment (a `hyperv_checkpoint_restore` then reports `Saved` or
  `Running`, with a note saying so, instead of claiming the VM is powered
  off). A Standard-typed checkpoint captured while the VM was off restores
  to `Off` like any other; a Production checkpoint that fell back to Standard
  restores `Saved`/`Running` too — the reported state is what the checkpoint
  captured, never an assumption from the requested type.
- **Production** takes no memory snapshot (restores to `Off`) and falls back
  to Standard when the guest cannot take a production checkpoint.
- **ProductionOnly** fails instead of falling back.

**Security note.** A memory-bearing checkpoint (explicit Standard, or a
Production fallback) writes guest RAM — potentially including secrets such as
an autologon password — to the host checkpoint store. The same applies to
every later **default (no-type) create** if a previous typed call was killed
mid-flight and stranded the VM's `CheckpointType` at Standard (see Recovery):
the default path uses the VM's own setting, whatever it now is. Microsoft
also warns that standard snapshots can cause data-consistency issues for
systems that replicate data between nodes (for example Active Directory).

**Recovery.** The VM-level `CheckpointType` is visibly changed during the
whole create call (a concurrent `hyperv_get_vm_info` or Hyper-V Manager read
sees the temporary value, and an external change made inside the window is
overwritten by the restore), and a forced termination (timeout, client
cancellation, hard kill, dropped host connection) can leave it stranded at
the requested value — both create paths share a 600 s budget, but a
large-VM checkpoint can still exceed it. Inspect with `Get-VM "<name>"` and
repair with `Get-VM "<name>" | Set-VM -CheckpointType <original>`. After a
kill the pre-call original is unrecoverable from the tool result (the value
is captured inside the killed script) — restore it from your own run records
or set it deliberately.

Restore waits up to 600 s for Off/Saved/Paused/Running while any checkpoint
merge completes. Removal merges disks; it cannot be undone.

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
  guest | lease_conflict | lease_required | lease_unknown | lease_expired |
  fenced | lease_not_owned`. `lease_conflict` is retryable with
  `retry_after_ms` = milliseconds to the holder's expiry; the other lease
  classes are not retryable. Every registered tool returns this envelope on failure (0.4.0
  documented breaking change: host-side tools no longer raise through the
  protocol), delivered with `isError: true` so failures are visible at the
  MCP protocol level — the envelope rides as the text content AND as
  `structuredContent`. The five keys are the minimum set; module-level
  diagnostics (`timed_out`, `stopped`, `alive_pids`, ...) ride alongside,
  and per-VM `busy` failures additionally carry `holder`
  (`{tool, mode, since, held_ms}` — see the Concurrency section above; the
  host-wide PowerShell-pool `busy` is a capacity condition and carries no
  `holder`).
  The envelope and the audit log share one isinstance-based taxonomy, so a
  record's `error_class` always equals the envelope's.

#### PowerShell Direct session reuse (0.4.0, issue #21)

`psdirect_session_reuse` (default **true**) keeps one long-lived host
`powershell.exe` worker per **session key** instead of starting a fresh process
and opening a fresh PowerShell Direct session on every guest call. The key is

```
(VM GUID, credential profile, agent id, boot epoch)
```

and each component is load-bearing, with one caveat on the fourth:

- **VM GUID** — the identity the caller already resolved, so a renamed VM can
  never silently re-target a pooled session.
- **credential profile** — the credential identity the call resolved (issue
  #30). A named credential profile contributes its NAME; the admin and
  victim identities of one profile never share a session (the victim role
  widens the component to `<profile>#victim`); a global (unprofiled)
  credential keeps the pre-#30 identity derivation (username plus an HMAC of
  the password under a per-process random key), so two credentials that
  share a username but differ by password still never share a session and a
  rotated password cannot inherit a session opened under the old one. The
  component is never shown verbatim in an error, log, or audit row.
- **agent id** — the authenticated bearer-token `client_id`. Microsoft documents
  that persistent PowerShell Direct sessions retain state (variables, imported
  modules, location), so a session is never handed to a caller that is not the
  one it was opened for. On the paths that carry no identity — plain stdio,
  `--standalone`, `--allow-anonymous` — all callers form one local principal
  (see the relay ownership section), so they form one key bucket.
- **boot epoch** — read from the guest at session open and re-read on every
  request. The worker compares the two and refuses to run the inner script
  when they differ, reporting a session-phase failure, so a guest reboot
  under a live session is detected rather than assumed away. The POOL does
  not close a session on an epoch change: the key carries no epoch today, so
  the worker's per-request guard is the whole of that protection.

What the pool does and does not touch:

| | |
|---|---|
| **Pooled** | `hyperv_guest_run`, `hyperv_guest_run_ps`, `hyperv_victim_run`, `hyperv_victim_run_ps`, `hyperv_guest_read_file`, `hyperv_guest_list_dir`, the diagnose/repair/evidence guest legs, and every guest-job leg including `hyperv_guest_job_start` (they share `diagnostics.run_guest_inner`) |
| **Not pooled (yet)** | `hyperv_guest_put` and `hyperv_guest_get`. A transfer rides `Copy-Item -ToSession`, which needs the session object in the guest scriptblock's own scope; routing that through a pooled worker needs a second worker mode this change does not add. They keep the per-call path. |
| **Not pooled, by design** | `hyperv_wait_guest_recovery` (it exists to detect a guest coming back, so it must open fresh sessions and observe a real failure) and the relay's per-request legs (they deliberately skip `vm_lock`) |
| **Never pooled** | remote Hyper-V host mode (`hyperv.host`, issue #43) — a pooled worker would have to be spawned on the remote host through a second transport this does not add. Remote mode takes the per-call path unchanged |

Invalidation. A session is closed when the VM is
checkpoint-restored, checkpoint-removed, stopped, reset or started, when a
debugging configuration reboots the guest, and when the credential behind a
profiled session changes (a rotated password or changed username under the
same profile name is detected by the session pool's in-memory credential
fingerprint and the stale session is retired; across a server restart the
restore-time identity binding refuses instead). Each lifecycle tool invalidates
after the action **succeeds** — a failed action leaves the guest as it was and
invalidates nothing. A session is also closed when it reports itself Broken or
Closed, and on a transport error during use. The next call then retries once on a fresh session, but only
when the failure happened before any guest-side effect — the worker reports
that in its own response frame, which is the only signal the host has. A
script that breaks its own session part-way through (a `Restart-Computer`,
say) is a guest-phase failure and is never retried.

Bounds. Every worker holds one host-wide PowerShell slot
(`max_host_powershell`) for its whole lifetime, so the session cap is derived as
`max_host_powershell - 2`: two slots of headroom is what keeps the
per-call legs — the identity-resolution leg on every guest call, every lifecycle
action, `hyperv_wait_guest_recovery` — able to run instead of queueing for
`host_powershell_wait_s`. At a host cap of 1 or 2 there is no headroom to
reserve, so no pool is installed at all and every guest call takes the
per-call path. Workers are also closed after 300 s idle, at the cap
(least-recently-used **idle** session first; in-use sessions are never evicted),
and at server exit by the lifespan teardown, so the host `powershell.exe` count
returns to zero without waiting out the idle TTL.

Secrets. The password reaches a worker only on its stdin, once, as base64 —
never in argv, never in the script text, never in the worker command line, and
never inside a request frame. All worker output passes the redaction filter.

Honest limits, stated rather than hidden:

- A reboot started **from inside the guest** has no host-side hook, so nothing
  on the host notices it as it happens. The worker's per-request epoch guard
  catches it on the next call: the guard reports a session-phase failure, the
  worker is discarded, and the call is retried once on a fresh session. That
  guard is one extra guest round trip per call, which is the price of
  detecting it at all.
- The audit record's `ps_spawns` is **not** zero for a pooled guest call: every
  guest call still pays the identity-resolution leg, which is a real process
  spawn. Pooling removes the session establishment, not the resolution. The
  timing trio's `psdirect_session_ms` therefore appears only on the call that
  opened each session.
- Setting `"psdirect_session_reuse": false` restores the exact per-call path.
  Note that once the key is present in the config file, that file is no longer
  loadable by any pre-0.4.0 binary: the older `from_dict` hard-aborts on an
  unknown key rather than ignoring it, so removing the key again is required
  before an older binary can read the file.

`scripts/soak_bench.py --session-reuse off,on` runs each agent count once with
reuse off and once with it on, so the before/after latency comparison is one
command (live mode). Both legs are labelled `session_reuse=off` /
`session_reuse=on` in the output, so the rows are distinguishable without
`--json`.

- (0.4.0) **Retry guidance:** `busy` is the only retryable class
  (`retry_after_ms` is a fixed ~2s hint; the holder data an FND-14
  derivation will consume now ships on busy envelopes — the derivation
  itself remains with Workstream A PR 5); every
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
only (RunAs cannot redirect streams). The registry is capped at
128 active jobs (oldest stopped entries are evicted first; new starts are
rejected once the cap is reached) and holds the start-time credentials until
a successful stop or cap eviction. Every job belongs to the agent that started it: a
status/output/stop call from a different agent gets the same `unknown
job_id` error as an absent id (a foreign caller's id is never distinguishable
from a made-up one, and no guest leg runs for it). `exiting` is not a
terminal state: if the guest wrapper dies
before writing its exit-code file, status stays `exiting` until you call
`hyperv_guest_job_stop`. Every job/relay tool call writes an audit row
naming the caller's agent id (null for `--standalone`/in-process stdio or
`--allow-anonymous`; the default proxy mode authenticates, so its rows
carry `local-cli` or the configured agent) and a
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
| `hyperv_relay_status` | `relay_id?` | `{ok, relays[{relay_id, url, counters, latency, stopped, ...}]}` |
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
id, so ids cannot be probed through the tools. Without an identity (`--standalone` in-process,
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

**Per-request latency.** Each successful request's guest-leg elapsed time is
recorded in a per-relay ring of the last 1024 samples, and `relay_status`
returns a `latency` summary beside the unchanged `counters`:
`{cap, samples, p50_ms, p95_ms, p99_ms}`. An empty store reports null
percentiles rather than zeros, so "no requests yet" is distinguishable from
"requests were instantaneous". Percentiles are nearest-rank, reusing
`consolebench.pct` so the relay and the soak benchmark cannot drift. The ring
is bounded structurally (`deque(maxlen=...)`), so a long-lived relay cannot
grow it. The relay's per-request legs run outside any `auditlog.operation`,
which is why this store exists at all: issue #20's per-call `timing` object
reaches every tool's audit row but never the relay path.

### Evidence Capture (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_capture_evidence` | `vm_name` or `vm_id`, `width=1024`, `height=768`, `save_path?`, `ui_tree=false`, `ui_tree_depth=3` (clamped 1..6), `ui_tree_max_elements=200` (clamped 1..500), `format?` (png\|jpeg/jpg\|webp), `quality?` (1..100), `scale?` (0,1], `crop?` ([left,top,right,bottom]), `if_changed_from?` (frame_hash) | `[ImageContent, TextContent(meta)]` — metadata alone when `if_changed_from` matches (the UI-tree leg is skipped too, and `meta.ui_tree` says why) |

One call pairing the console screenshot with `captured_at` (UTC ISO-8601),
`vm_id`, capture dimensions, `frame_hash`, and — when `ui_tree=true` — a
bounded UIAutomation element tree from the guest (depth/element caps;
requires guest credentials, which the screenshot alone does not). The UI
tree is session-honest (issue #29): the walk records the session it ran in,
a walk whose session does not own the input desktop is refused as
`ui_tree.ok=false` with `error_class: "no_interactive_session"` and the
walked session identity in `ui_tree.session`, and when the in-session UIA
helper is running the tree comes from the helper and `ui_tree.source` is
"helper". On an `unchanged: true` result the tree leg is
skipped entirely (it is a credentialed 60 s PowerShell Direct session whose
only purpose is to describe the frame just captured), and `ui_tree` reports
`{requested: true, skipped: true, reason}`; a call with `ui_tree=false`
still reports exactly `{requested: false}` whatever the frame did.

**Output dimensions.** With no `scale` or `crop`, `width`/`height` in the
metadata are the captured dimensions. With either applied they become the
OUTPUT dimensions — post-crop, post-scale — which is what mouse tools need
when they are given `frame_width`/`frame_height`. On an `unchanged: true`
result they are the CAPTURED dimensions, because no output image exists to
measure; `crop`, `scale`, `format` and `quality` are echoed there too, so an
unchanged result is exactly as informative about the request as a changed one.

---

### In-session UI Automation helper (0.7.0, issue #29)

Eight `hyperv_ui_*` tools drive the guest's interactive desktop BY ELEMENT
instead of by screen coordinates. They require guest credentials (like every
PowerShell Direct tool) and the `hyperv-mcp-uia-helper` PowerShell process
running inside the guest's interactive session; it serves UI Automation
requests on a local named pipe that the host reaches through PowerShell
Direct.

| Tool | Policy | Purpose |
| --- | --- | --- |
| `hyperv_ui_inspect` | vm policy + credentials | bounded UIA element tree (depth <= 8, 2000 elements) |
| `hyperv_ui_find` | vm policy + credentials | resolve elements by selector or element_id |
| `hyperv_ui_wait_for` | vm policy + credentials | wait for a selector to appear / disappear |
| `hyperv_ui_session_state` | vm policy + credentials | active session, interactive user, locked, foreground window, helper version |
| `hyperv_ui_invoke` | `ui_input` | Invoke/Toggle/SelectionItem/ExpandCollapse on an element |
| `hyperv_ui_set_value` | `ui_input` | set a Value-pattern property (result reports the length, never the value) |
| `hyperv_ui_focus` | `ui_input` | focus an element (locked sessions refuse: `no_interactive_desktop` — as do invoke and set_value) |
| `hyperv_ui_helper_provision` | `ui_provision` + confirm | install + start the helper (`teardown=true` removes it); optional autologon |

Provisioning (`hyperv_ui_helper_provision(autologon=true, confirm=true)`)
configures automatic logon for the test account: the password is stored ONLY
as the LSA secret `DefaultPassword` (never a plain-text registry value) and a
per-user AtLogOn scheduled task (Interactive, RunLevel Highest, restart 3x/1m)
starts the helper at logon. This is for DISPOSABLE TEST IMAGES; the server is
a lab tool. `teardown=true` is provisioning's inverse: it stops the task,
removes every helper directory, deletes the LSA secret and restores the
Winlogon values.

Session honesty: every request carries its target VM identity (the guest
SMBIOS UUID recorded at provision time), user SID, and interactive session;
the helper refuses a session-less or mismatched SESSION as
`session_unverified`, and a VM/user mismatch as `target_mismatch`. Element
operations the target does not support return `unsupported_capability`
(naming every pattern tried) rather than a coordinate fallback; ambiguous
selectors fail with `ambiguous_selector` and up to 20 candidates.

### VM Console (WMI — works from firmware through WinPE)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_console_screenshot` | `vm_name` or `vm_id`, `width=1024`, `height=0` (0.16.0: derive the head's aspect for the width — requires a readable display head and refuses without one, so on a host whose head never reports pass an explicit height, e.g. 768, to restore the pre-0.16.0 fallback-chain behavior; the derived height clamps to the 160..4096 window, so a very small width is NOT captured at the head's aspect; an explicit 160..4096 height is also accepted), `save_path?`, `format?` (png\|jpeg/jpg\|webp), `quality?` (1..100), `scale?` (0,1], `crop?` ([left,top,right,bottom]), `if_changed_from?` (frame_hash) | MCP ImageContent + metadata text (`vm_id`, `frame_hash`, `head_resolution`, `content_rect` (issue #125: [left, top, right, bottom] of the non-letterbox pixels, right/bottom exclusive, from the RAW pre-shaping dimensions against the head at capture; key absent when the head is unknown), `scale_note`, `fallback_used`, `used_fallback`, `capture_method`, `captured_at`, `timings`, `width`, `height`, `vm_name`, `prefix_hex`, plus `format`/`quality`/`scale`/`crop`/`saved_format` only when those options were supplied) — metadata alone when `if_changed_from` matches. `used_fallback` (issue #83, PowerShell transport) is true exactly when the response's `USED=` line was absent or malformed, i.e. the reported dimensions are the REQUESTED size by assumption rather than the chain's own report; false when `USED=` was present and parseable (`fallback_used` remains the separate human-readable note about which chain size actually captured) |
| `hyperv_console_get_display_info` | `vm_name` or `vm_id` | `{ok, enabled_state, head_horizontal, head_vertical, keyboard_present, keyboard_enabled, mouse_present, mouse_enabled, mouse_ps2_present, boot_epoch, guest_channel, guest_channel_note, vm_id}` — `mouse_present` reports the SYNTHETIC mouse only (absolute positioning); `mouse_ps2_present` (issue #83) additionally reports the PS/2 mouse the non-positional input ops (button, scroll, click-at-current-position) fall back to, so a PS/2-only VM no longer reads as "nothing can act on the console" — the field is always present, false meaning no PS/2 mouse was reported, and it is measured per transport: the in-process WMI transport probes it via a `SystemName`-scoped `Msvm_Ps2Mouse` query, the PowerShell transport via the folded script's own PS/2 query. NOTE: `guest_channel` is per-tool vocabulary; this tool still reports the constant `ps_direct_unverified` (Workstream D owns its rework), while `hyperv_wait_vm_state` derives `os_heartbeat_ok`/`no_guest_signal` from the Heartbeat service and `hyperv_deployment_status` reports the richer seven-phase `phase` vocabulary (`off`/`suspended`/`heartbeat_disabled`/`no_guest_signal`/`os_ready`/`os_unresponsive`/`degraded`) instead |
| `hyperv_console_type_text` | `vm_name` or `vm_id`, `text` (ASCII), `secret_ref?` (0.18.0: `env:NAME` or an allowlisted `file:PATH` resolved host-side through `host_read_roots`; mutually exclusive with `text`; the resolved value is typed, only its length is reported) | `{ok, chunks, chars}` (+ `secret_typed` when `secret_ref` was given) |
| `hyperv_console_lock_state` | `vm_name` or `vm_id` | `{ok, state: locked\|unlocked\|unknown, evidence, vm_name}` — locked = `LogonUI.exe` running in the guest's session (process-table check via PowerShell Direct; needs guest credentials and a running supported guest OS); `unknown` names why the leg failed |
| `hyperv_console_unlock` | `vm_name` or `vm_id`, `secret_ref` (required) | `{ok, state: unlocked, attempts: 1, evidence, vm_name}` or the `not_locked` refusal (console already unlocked or state unknown — no input sent) or `unlock_failed` after ONE attempt (no retry) |
| `hyperv_console_press_key` | `vm_name` or `vm_id`, `key`, `modifiers[]` (ctrl/alt/shift incl. right- variants, win/leftwin/rightwin — held while key taps) — keys: enter, escape (esc), tab, backspace, space, capslock, up/down/left/right, delete, home, end, pageup, pagedown, insert, f1-f12, a-z, 0-9, punctuation (minus/equals/leftbracket/rightbracket/semicolon/apostrophe/grave/backslash/comma/period/slash, single-char aliases `-` `=` `[` `]` `\` `;` `'` `` ` `` `,` `.` `/`), numpad (num0-num9, numdecimal, nummultiply, numsubtract, numadd, numlock, numdivide, numenter), win (alias leftwin), rightwin, menu (alias apps); modifier-named keys are also valid bare presses | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_key_combo` | `vm_name` or `vm_id`, `keys[]` — modifiers ctrl/alt/shift (incl. right- variants) and win/leftwin/rightwin; every other key name taps in order, e.g. `["win","r"]` | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_type_scancodes` | `vm_name` or `vm_id`, `scancodes[]` (0..255) | `{ok, scancodes_sent, chunks}` |
| `hyperv_console_mouse_move` | `vm_name` or `vm_id`, `x`, `y`, `frame_width?`, `frame_height?` (both MAY be omitted when `frame_hash` is cited — they then default from the cited record's registered `frame_size`, and a record without one refuses naming the requirement), `frame_hash?` (issue #125 capture citation — see the mapping contract below) | `{ok, operation, head_x, head_y}` |
| `hyperv_console_click` | `vm_name` or `vm_id`, `x?`/`y?` (null default — omit both to click at the current position; (0,0) is a real coordinate; x/y are REQUIRED when `commit_guard` is true), `frame_width?=0`, `frame_height?=0` (both MAY be omitted when a `frame_hash` citation or the commit guard's `verified_frame_hash` is given — they then default from the cited record's registered `frame_size`, and a record without one refuses naming the requirement), `button=1`, `frame_hash?` (issue #125 capture citation), `commit_guard=false`, `verified_frame_hash?` (issue #126 commit guard — both below), `verified_state_receipt?` (issue #140 receipt channel — mutually exclusive with `verified_frame_hash`; see the receipt channel below) | `{ok, operation, head_x?, head_y?}` |
| `hyperv_console_button` | `vm_name` or `vm_id`, `button`, `is_down` | `{ok, operation}` |
| `hyperv_console_scroll` | `vm_name` or `vm_id`, `delta` | `{ok, operation}` |
| `hyperv_console_wait_frame_change` | `vm_name` or `vm_id`, `baseline_hash=""`, `width=640`, `height=480`, `timeout_s=60`, `interval_s=2` | list[ImageContent(image/png), TextContent({stop_reason: changed\|deadline, polls, elapsed_ms, frame_hash, head_resolution, content_rect, hash_domain})] — `head_resolution`/`content_rect` (issue #125) join a returned hash from the poll that produced it (keys absent when the head is unknown) — or deadline dict |
| `hyperv_console_wait_frame_stable` | `vm_name` or `vm_id`, `stable_ms=1500` (>= 1 and < timeout_s*1000), `timeout_s=30` (>= 1), `interval_ms=250` (>= 100), `width=640`, `height=480`, `baseline_hash=""` | [ImageContent(image/png), TextContent({stop_reason: stable\|unchanged\|deadline, stable, polls, elapsed_ms, frame_hash, head_resolution, content_rect, stable_ms_measured, hash_domain})] — `head_resolution`/`content_rect` (issue #125) join a returned hash from the poll that produced it (keys absent when the head is unknown) — or meta-only dict with `stable=false` |
| `hyperv_console_capture_sequence` | `vm_name` or `vm_id`, `count=3`, `interval_s=2`, `width=640`, `height=480` | [first Image, last Image (a single Image when count==1), meta_text(frames[] with per-frame vm_id + hash + changed_bytes_vs_previous + head_resolution/content_rect — issue #125 per-frame head provenance, keys absent when the head is unknown)] |
| `hyperv_console_sequence` | `steps` (1..50 step dicts; grammar below), `vm_name` or `vm_id`, `expect_frame_hash=""`, `expect_boot_epoch=None`, `timeout_s=60`, `request_key=""`, `width=640`, `height=480` | {ok: true, vm_name, boot_epoch, steps: [{index, ok, stop_reason?, error?, skipped?}]} or {ok: false, error_class: "precondition"\|"unknown", ...} |

Console notes: text rides the stdin channel (never in argv/script/errors); non-ASCII input must use type_scancodes; mouse coordinates are in the space of the observed image — pass `frame_width`/`frame_height` matching your screenshot dimensions to scale to head space, or omit them to use head coordinates directly; `wait_frame_change` with `baseline_hash=""` treats the first polled frame as the baseline, and a returned `frame_hash` can be passed back as `baseline_hash` to detect changes across calls (both are the full lowercase-hex sha256 of the PIXEL payload, i.e. the thumbnail bytes after the 4-byte opaque prefix — see the 0.4.0 breaking change above; the tool also returns `hash_domain` so a client can refuse a baseline recorded in a different domain — the same applies to `wait_frame_stable`, whose `baseline_hash` and returned `frame_hash` live in the identical domain and whose result also carries `hash_domain`); `capture_sequence`'s `changed_bytes_vs_previous` counts PIXEL bytes, the same domain `frame_hash` covers (an idle console costs one C-level comparison rather than a per-byte walk, and a change confined to one 64 KiB chunk costs that chunk rather than the whole payload — a change in EVERY chunk walks those chunks, but with `sum(map(operator.ne, ...))` the per-byte work is C-level and executes no Python line events at all, so the cost is a single C walk rather than a Python loop); `capture_sequence`'s `frames[]` entries report `vm_id` — on the PowerShell transport, the GUID that frame's own process actually resolved; on the in-process WMI transport, the GUID the sequence resolved once (`null` means the frame carried no identity metadata, which is legal). Issue #82: a mid-sequence identity change — a delete+recreate under the same name — aborts the sequence with a structured error naming both GUIDs instead of returning a spliced diff); a returned `console.Frame` holds only its encoding until something reads a pixel — the raster is derived from the encoding on first pixel access and cached from then on, so an untouched frame retains no `width*height*3` buffer, and a mutation made after the first access survives; WinPE errors and wizard screens are returned as images for visual interpretation (no OCR is performed).

#### Letterbox-aware mapping, capture citations, and the commit guard (0.16.0, issues #125/#126)

**Mapping contract.** A capture whose aspect differs from the display head's
is LETTERBOXED — the host scales the head into the frame and pads the
remainder with black bands. Capture metadata therefore carries
`content_rect` ([left, top, right, bottom], right/bottom exclusive) of the
non-letterbox pixels, derived from the capture geometry against the head
resolution at capture time (live-calibrated model: floor on the constrained
dimension, bands split floor/ceil; absent when the head is unknown).
`height=0` (the new default on `hyperv_console_screenshot`) captures at the
head's aspect for the given width — e.g. width=1024 at a 1920x1080 head is
1024x576, which is band-free. Deriving requires a READABLE display head and
refuses without one ("display head resolution unavailable"); on a host whose
head never reports, pass an explicit height (e.g. 768) to restore the
pre-0.16.0 fallback-chain behavior. The derived height clamps to the
160..4096 window every capture dimension obeys, so a very small width is NOT
captured at the head's aspect. Without a citation, frame coordinates scale
per-axis over the whole frame (the pre-0.16.0 behavior, unchanged for
same-aspect frames); WITH a citation (below) they map through the rect —
offset into it, scaled by head/content size, rounded and clamped — so the
first content row maps to head row 0 instead of landing ~15% short.

**Capture citations (`frame_hash=`).** `hyperv_console_click` and
`hyperv_console_mouse_move` accept the `frame_hash` of a capture this
server process returned (screenshots, wait results, capture_sequence frames
auto-register). Citing resolves the capture's `content_rect` and
`head_resolution` and fixes the citation's pixel domain: when
`frame_width`/`frame_height` are omitted they DEFAULT from the record's
registered `frame_size` (the coordinates were observed on THAT frame), and
a record registered without a `frame_size` refuses asking for explicit
dimensions. A capture taken at a DIFFERENT head resolution refuses
with a "stale frame" error before any input script exists, and the
positional mouse ops re-check the cited head IN-SCRIPT at dispatch so a
resolution change between the host preflight and the script's own head read
cannot map the cited rect onto the wrong head; a point inside a
letterbox band refuses ("letterbox band point … no head-space meaning");
and a shaped (cropped/scaled) capture refuses outright ("shaped frame has
no head-space mapping; cite an unshaped capture").

**The commit guard (`commit_guard`/`verified_frame_hash`, opt-in).** A
guarded click requires `x`/`y` coordinates (a click-at-current-position has
no point to verify and is refused) and refuses to commit on a stale
verification: `verified_frame_hash` must cite a capture taken AFTER the
most recent console input to that VM, and the guard re-captures the live
frame at the cited pixel domain inside the locked region and refuses on any
hash mismatch (the refusal names the live hash). The guard's
`frame_width`/`frame_height` may be omitted when the cited record carries a
`frame_size` — they default from it exactly like a `frame_hash` citation,
and a size-less record refuses (the live verification hashes that pixel
domain, so the dims must be within 160..4096). Refusals are structured
errors (`commit_unverified` / `stale …`) and send no mouse input; an
allowed guard is recorded in the audit log. Scope disclosure: the freshness
leg counts console inputs to THAT VM dispatched through THIS SERVER PROCESS
only (a per-VM, per-process in-process ledger) — a cross-process input that
changed the pixels is still caught by
the live-frame hash check, but a cross-process input that left the pixels
unchanged is a residual window; the shared-state (statestore) follow-up is
tracked on #126. Sequence click steps accept the same
`commit_guard`/`verified_frame_hash` pair, composed with
`expect_frame_hash` (they must be equal — the precondition capture IS the
live verification); a guarded click must be the plan's FIRST step (no wait
steps before it), and the step's `frame_width`/`frame_height` must equal
the sequence call's `width`/`height` — the cited verification's registered
`frame_size` must match that pair when it was recorded (a size-less
citation falls through to the precondition capture, which hashes the
sequence size).

**The receipt channel (`verified_state_receipt`, issue #140).** A guarded
click may instead cite a UIA state-read receipt: `hyperv_ui_inspect`,
`hyperv_ui_find`, `hyperv_ui_wait_for`, and `hyperv_ui_session_state`
return a `state_receipt` id on every successful read, and a
`commit_guard=true` click accepts `verified_state_receipt=<id>` in place
of `verified_frame_hash` — exactly one channel per click (citing both is a
refusal naming the parameter; citing neither keeps the classic
`commit_unverified` refusal). The receipt's freshness rule is the same
input ledger: the receipt's sequence must postdate the VM's most recent
input dispatch, so the read that saw the selection provably happened after
the click that made it. That comparison reads the MAX input-dispatch
sequence across every ledger key under which an input to the VM could have
been recorded (the caller name, the explicit id, and the hint-resolved
GUID), because an input already in flight on a cold name-keyed ref records
its bump under the name key while the receipt is keyed by GUID — taking the
max closes that split fail-closed (it can only ever add a stale refusal).
A successful UIA read holds the per-VM
console-input exclusion across its helper leg, its parse, and its receipt
stamp — on both the GUID and the caller-name key spellings — so no console
input can dispatch between the observation and the stamp, and the UIA
mutating tools (`hyperv_ui_invoke`/`hyperv_ui_set_value`/`hyperv_ui_focus`)
bump the same ledger at their dispatch seam (dispatched legs bump even when
the result is unknowable — timeout/transport error — while pre-dispatch
refusals never bump; a UIA write after the read therefore stales the
citation exactly like a console write). Cost (accepted + disclosed): the
read's console-key hold is shared with console INPUT dispatch AND with
capture/wait ops (`#125` whole-wait hold) — contention runs BOTH
directions: a UIA read issued concurrently with a console input op, a
screenshot, or a `wait_frame_*` on the same VM queues behind the holder,
and equally a console input op dispatched while a read holds the key waits
for the stamp to land — either waiter times out after
`Config.vm_lock_wait_s` (default 30s) raising the retryable `VMBusy`, the
same retryable signal the multi-agent guard family already uses. The hold
spans the whole verb request for the NON-POLLING reads (inspect/find/
session_state, including their front-door discovery legs — install-facts,
SID lookup, session bootstrap, each bounded by its own timeout and cached
after first success), so a slow-guest read widens the contention window
beyond the helper round trip itself. `hyperv_ui_wait_for` is the exception,
not a whole-wait holder: `_verb_request` re-acquires and releases the
console key PER poll slice (the bounded guest-side slices), so console
inputs interleave freely BETWEEN slices and only queue behind a single
in-flight slice — the receipt's observation-to-stamp atomicity is preserved
per minted slice, while the wait as a whole does not monopolize the key.
Single-operator flows alternate capture->read->click and are unaffected. Unlike the frame-hash channel the
receipt verifies ledger ordering ONLY: there is no live-frame re-check leg,
no pixel-domain requirement (`frame_width`/`frame_height` are not needed
for the verification itself, only for coordinate mapping), and the
per-server-process scope limitation from #126 applies with no pixels
backstop. Unknown, never-minted, or FIFO-evicted citations refuse through
the structured `commit_unverified` family with zero mouse input — the
receipt registry's 512-entry cap is PROCESS-GLOBAL (shared across all VMs):
heavy read churn on one VM (e.g. a long `hyperv_ui_wait_for`, which mints
per helper slice and returns only the last receipt) can evict another VM's
still-citable receipt; eviction fails closed and a re-read re-mints. Every
refusal dispatches zero mouse input; allowed decisions are audited like the
frame-hash channel's.
`hyperv_console_sequence` remains frame-hash-only: a step carrying
`verified_state_receipt` is a step-indexed refusal (never a silently
ignored key) — use `hyperv_console_click` for receipt-verified commits.

**Whole-wait lock holding.** Because captures now auto-register for
citation, `wait_frame_change`/`wait_frame_stable` hold the per-VM console
input lock for the WHOLE wait (both transports), so the registration is
ordered against input dispatches: console input to that VM blocks until the
wait returns (a concurrent input raises `VMBusy` instead of queueing).
Screenshots likewise hold the input lock for the whole capture-and-register
region — up to the ~6-minute chain timeout the folded screenshot script
allows, so console input during a long capture raises `VMBusy` too. Each
wait poll also re-reads the display head (issue #125 provenance — the WMI
loop queries `Msvm_VideoHead` per poll, the folded script emits `HEAD=` on
every poll) so a returned hash's `head_resolution`/`content_rect` come from
the poll that produced it; that extra provider round trip per poll means
sampling density is slightly lower than the raw poll budget.

#### Batched console sequences (issue #28)

`hyperv_console_sequence` composes up to 50 console actions into ONE plan that
holds the per-VM console lock for its whole duration — no raw input from any
agent can interleave between its steps, and one audit record replaces the N
single-step calls. Step grammar (mirrors the single-step tools):
`{"action": "press_key", "key", "modifiers"?}`, `{"action": "key_combo",
"keys"}`, `{"action": "type_text", "text"}` (ASCII; rides stdin base64, never
the script), `{"action": "type_scancodes", "scancodes"}`,
`{"action": "mouse_move", "x", "y", "frame_width"?, "frame_height"?}`,
`{"action": "click", "x"?, "y"?, "frame_width"?, "frame_height"?, "button"?,
"commit_guard"?, "verified_frame_hash"?}` (the issue #126 guard pair on a
click step: `x`/`y` are REQUIRED when `commit_guard=true`, the step must be
the plan's FIRST step, its `frame_width`/`frame_height` must equal the
sequence call's `width`/`height`, and `verified_frame_hash` must equal the
call's `expect_frame_hash`; `commit_guard` and `is_down` must be real
booleans — a truthy non-bool is a step-indexed validation refusal),
`{"action": "mouse_button", "button", "is_down"}`,
`{"action": "scroll", "delta"}`, `{"action": "wait_frame_stable",
"stable_ms", "timeout_s"?, "interval_ms"?, "baseline_hash"?}` (the in-sequence
grammar mirrors the single-step tools except that wait steps accept
`interval_ms >= 1` — the call `timeout_s` bounds the whole plan, so the
standalone tool's >= 100 floor does not apply). Every step is
validated BEFORE anything spawns (a rejection names `step <i>`); at most 50
steps; every wait budget is capped by the call `timeout_s`, the SUMMED wait
budgets must fit the call `timeout_s` (a plan whose worst case exceeds it is
rejected before anything spawns), and the PowerShell
child deadline sits at `timeout_s + 15`. Preconditions run inside the locked
region BEFORE the first input: `expect_frame_hash` (capture a screenshot at
the same `width`/`height` first and pass its `frame_hash`) and
`expect_boot_epoch` (pass `boot_epoch` from `hyperv_console_get_display_info`;
±5 s tolerance) each return `{ok: false, error_class: "precondition",
steps: []}` with the actual observed value and send nothing on a mismatch.
`boot_epoch` is derived from host WMI (`Msvm_ComputerSystem.
OnTimeInMilliseconds` against the host clock), so it needs no guest
credentials and is meaningful in firmware and WinPE; pausing the VM shifts it,
and a mismatch fails closed. With `request_key`, an uncertain post-dispatch
outcome (a timed-out leg) is recorded once as UNKNOWN with whatever
executed-step prefix the leg reported, is never automatically replayed, and a
retry carrying the same key returns the recorded result instead of
re-driving the guest; a NEW plan requires a fresh explicit request and
precondition. `request_key` is a CALLER-MANAGED namespace: keys are not
validated against VM or plan, so keep them unique per plan — a colliding key
returns the recorded result for that key (the lookup happens before the
addressing/policy checks). The UNKNOWN record and the deadline enforcement are
PowerShell-transport behaviors; the WMI transport carries no per-call timeout
and completes or raises without an UNKNOWN record. Admission note (see issue #68): a sequence holds one tool
thread for the by-id resolve leg (one spawn, 60 s), the bounded lock wait
(`vm_lock_wait_s`), and the folded child (`timeout_s + 15`); on the in-process
WMI transport the provider calls carry no per-call timeout.

Canonical console identity (issue #77): operations whose stdout carries the
resolved identity (`VMID=` — screenshot, display info, capture, sequences)
plus the identity guard's own report teach the host-side name→GUID pair, and
a by-name console input whose name is known locks and acts on the canonical
GUID — the same key a by-id caller takes — with an in-script identity guard
that fails closed BEFORE any input when the VM was deleted and recreated
under the same name (the call returns a structured identity error and the
mapping self-heals from the guard's own report). A by-name console input
with NO learned mapping yet stays keyed on the caller-supplied name until a
feeding operation supplies one; that residual window is disclosed here
rather than fixed with an extra resolve spawn, which would break the
one-PowerShell-process-per-call contract (ordinary inputs compose exactly
one process; oversized inputs split into sequential processes and
over-budget `hyperv_console_sequence` plans are refused before the sequence
command spawns (a by-id plan may already have spent one resolver spawn) —
see the oversized-input delivery paragraph below).

#### Console transport: in-process WMI or PowerShell (issue #45)

Every console tool call runs over one of two transports, selected
automatically per call:

- **In-process WMI** (`pip install ".[wmi]"` adds pywin32): the
  `root\virtualization\v2` operations execute in-process over COM with
  zero `powershell.exe` spawns per call — per-VM object paths are cached
  and re-bound each call, and the cached devices are dropped when the VM's
  `EnabledState` changes (head resolution is re-read every call, so a
  `Set-VMVideo` change is picked up immediately). On a remote Hyper-V host
  (`hyperv.host` configured), the backend connects over DCOM using the
  `HYPERV_HOST_*` credentials.
- **Generated PowerShell** (the original transport, always available):
  used automatically when pywin32 is absent, the WMI namespace cannot be
  reached (including a remote host whose DCOM endpoint is unavailable —
  the WS-Man hop then composes exactly as before), or the target VM is not
  present in the WMI plane. Each call folds every leg into one script: the
  prelude binds `$vmTarget` (the fail-closed name resolver embedded for
  by-name callers, the validated GUID preamble for by-id callers), and the
  script then looks up the devices/head and runs the operation. Chunked
  keyboard input keeps its chunks and pacing inside that process (typed text
  rides stdin as base64 lines), the screenshot fallback chain loops its
  de-duplicated size list inside it, and the mouse is selected with a
  `SystemName` key filter — with an `Msvm_Ps2Mouse` fallback for button,
  scroll and click-at-current-position on VMs that expose no synthetic mouse
  (positional ops report the structured error: absolute positioning has no
  PS/2 equivalent).

Oversized input delivery (issue #81): Windows caps the spawned command line
at 32766 spawnable characters (CreateProcess's 32767 ceiling includes the
terminating null) and a folded script costs roughly 8/3 command-line
characters per script character after `-EncodedCommand` base64, so input that
would overflow ONE command is split into sequential commands rather than
failing — scancode arrays beyond ~1600 codes split across consecutive folded
`type_scancodes` processes (each carrying a contiguous slice as its own
in-script seed, all delivered in order under one console input lock; the
result's `chunks` stays the TOTAL 64-code window count), remote `type_text`
beyond 100 stdin chunks composes multiple sequential `Invoke-Command` hops
(each carrying a contiguous chunk range), and an oversized `run_sequence`
codes step encodes its array as an in-script base64 seed decoded in the
script — ordinary-size inputs keep the exact single-process emissions the
one-process pins freeze. The screenshot chain additionally refuses a
`ReturnValue=0` capture whose payload has the wrong length IN-SCRIPT, so a
corrupt payload advances the chain to the next size instead of committing.

Fallback happens only at connect/selection time: a WMI **method** failure
(non-zero `ReturnValue`, bad payload, raw COM failure) — or a backend
unavailability raised mid-operation — is a structured error and is never
retried through PowerShell, so console input can never double-send. Every
SUCCESSFUL result carries a per-call `timings` breakdown (failure
envelopes carry the standard error shape without timings):
`{"transport": "powershell", "spawn_ms": [402.6]}` (one float per
`powershell.exe` spawn — since issue #18 each ORDINARY call is ONE process
whose script resolves the VM, looks up the devices/head and runs the
operation, with the 0.16.0 accuracy additions as named exceptions: a
`height=0` screenshot runs a head-preflight process before the capture
process, a `frame_hash`-cited or commit-guarded positional mouse op adds
the same head preflight, and a guarded click adds the guard's live-capture
process as well — 2-3 spawns instead of the ordinary one. Of these, the
head preflight runs BEFORE the console input lock is taken (its refusal
records zero positional scripts), while the capture, mapping and input
legs stay under the one console input lock; oversized inputs instead split
into sequential
processes (see
the oversized-input delivery paragraph above) and `hyperv_console_sequence`
refuses an over-budget plan before the sequence command spawns (a by-id plan
may already have spent one resolver spawn); a call
addressed by `vm_id` keeps a separate resolution leg first, because policy must
run on the GUID's resolved name before any guest mutation. `capture_sequence`
is the exception: it carries no payload between frames, so each frame is its
own folded process — `count` floats by name, `count + 1` by `vm_id`) or
`{"transport": "wmi", "connect_ms": 0.0, "rebind_ms": 0.8,
"method_ms": 31.2}`.

`spawn_ms` entries are recorded on two bases (issue #83, documented contract —
the field is NOT re-plumbed to one basis): the resolve-leg entry is host-side
wall-clock around `vmident.resolve` — it INCLUDES the policy check, the remote
composition and the PowerShell slot wait — while every op-leg entry is the
child's `duration_ms`, measured AFTER the slot wait (the bounded
`host_powershell_wait_s` slot wait is its own budget and must not consume the
caller's script timeout, which is also why `run_ps` starts the leg clock after
slot acquisition). Both bases are numeric milliseconds in call order, so the
entry count is exactly the spawn count on every path.

On the WMI path `connect_ms` is the measured
backend lookup (near-zero on a warm cache — one real DCOM connect per host
per process, shared by concurrent callers),
`rebind_ms` the cached-identity re-bind and state check, and `method_ms`
the operation's WMI work; chunked and polling operations (type_text,
type_scancodes, wait_frame_change, wait_frame_stable, capture_sequence)
SUM these phases across their iterations — for wait_frame_stable one
`method_ms` entry lands per poll, so the value is the SUM of every
thumbnail call the settle window took, not one capture. In-process COM calls have no per-call timeout: a
hung WMI provider blocks that VM's operations until the provider returns,
where the PowerShell transport's child process is killed at its timeout.
The screenshot metadata's `capture_method` field names the serving
transport ("... in-process WMI ..." vs "... WMI root\virtualization\v2").

Benchmark the two transports on a real host with a disposable VM:

```powershell
python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --n 15                # after (auto)
python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --n 15 --transport powershell   # before
python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --n 15 --transport powershell --baseline before.json  # before/after table
python -m hyperv_mcp.consolebench --vm "Deployment Test 3" --agents 4            # multi-agent soak
python -m hyperv_mcp.consolebench --selftest                                     # offline selftest
```

The benchmark CLI runs with an UNRESTRICTED in-process config (it is an
operator tool driving the host directly, not the policy-gated MCP
server): `--vm` is not subject to `allowed_vm_patterns` and input ops are
not gated by the console_input category — only point it at disposable
VMs. Failed soak ops are counted and excluded from the percentiles, and
the run exits non-zero when any op failed; `--transport wmi` verifies the
served transport and exits non-zero if the WMI plane could not serve.

### VM & Media Preparation (deployment testing)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_vm_create` | `name`, `vhd_path`, `memory_mb=2048`, `cpu_count=1` (applied to the new VM via `Set-VMProcessor`), `generation=2`, `vhd_size_gb=64`, `switch_name?`, `confirm` | `{ok, id, name, state, generation}` |
| `hyperv_vm_clone` | `name`, `parent_vhd_path`, `vhd_path`, `memory_mb=2048`, `cpu_count=1` (applied), `generation=2`, `switch_name?`, `confirm` | `{ok, id, name, state, generation, vhd_path, parent_vhd_path, parent_made_read_only}` |
| `hyperv_vm_remove` | `vm_name` or `vm_id`, `delete_disks=false`, `confirm` | `{ok, status, vm_name, deleted[], kept[{path, reason}]}` — refuses non-Off (use `hyperv_stop_vm`); with `delete_disks=true` deletes only the VM's own disks (never differencing ancestors, never outside `host_write_roots`), waiting out the post-removal checkpoint merge (bounded). `deleted[]` is present only with `delete_disks=true`; `kept` reasons: `not_owned_ancestor` (a differencing ancestor — never deleted), `in_use_by_other_vm`, `outside_host_write_roots`, `merge_pending` (retry the removal later), `already_gone` (the merge consumed it), `cleanup_leg_failed: …`, `delete_failed: …`. Issue #31 supplement: when `agent_isolation.cleanup_provider` names a registered provider, the removal consults it BEFORE any deletion work (CLEAN proceeds; PENDING/UNKNOWN/FAILED or a raising provider refuse fail-closed; only the literal `none` — the default — skips the consult) |
| `hyperv_deployment_status` | `vm_name` or `vm_id` | `{ok, phase, phase_basis, vm_id, state, uptime_s, heartbeat{enabled, primary_status, application_status}, guest{os_name, os_build, fqdn, ipv4[], ipv6[]}, kvp{available, items}, checked_at, vm_name}` — credential-free readiness from the Heartbeat integration service + KVP (issue #32 AC4/AC5 richer contract); phases: `off` / `suspended` / `heartbeat_disabled` / `no_guest_signal` / `os_ready` / `os_unresponsive` / `degraded` (a Running+OK-heartbeat+no-KVP row retained from the reviewed PR #112 table; `guest.*` and `kvp.*` always read the heartbeat-gated view so stale pairs never surface as the guest's identity); `phase_basis` names the producing signals; `checked_at` is UTC ISO-8601 |
| `hyperv_harvest_offline_logs` | `vm_name` or `vm_id`, `dest_dir` | `{ok, vm_id, vm_name, dest_dir, files[{volume, source, dest, size, sha256, last_write_utc}], missing[], skipped[{volume, reason}], truncated}` — requires state Off + SeBackupPrivilege (elevated); mounts the disk read-only and copies the fixed documented log set (Panther/MDT/SMSTS); `offline_harvest` category (issue #33 AC7 evidence manifest: sha256 recomputed in Python over the copied host files, not trusted from PowerShell). `missing[]` lists fixed log entries absent from the volume; `skipped` reasons (volume-shaped): `volume_locked` (partition not mountable, e.g. BitLocker), `cap_exceeded: <source>` (per-file/total byte budget — screened before copy AND rechecked in Python; `truncated` reports any engaged cap), `copy_failed: …` (robocopy failed), `unreadable_copy: <source>` (a copy that could not be re-read) |
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
| `hyperv_vm_get_video` | `vm_name` or `vm_id` | `{ok, resolution_type, horizontal, vertical, observed_horizontal, observed_vertical, vm_name}` |
| `hyperv_vm_set_resolution` | `vm_name` or `vm_id`, `width`, `height`, `resolution_type=single`, `restart=false`, `confirm` | `{ok, resolution_type, horizontal, vertical, observed_horizontal, observed_vertical, effective_after_restart, vm_name}` (`state` added on the restart path) |

Display notes (issue #44): `single` forces exactly width x height (160..4096);
`maximum` allows that size and smaller standard modes; `default` reverts and
ignores the dimensions (the returned `resolution_type` is Title-case:
Single/Maximum/Default). The host REFUSES Set-VMVideo on a running VM:
without `restart=true` the VM must be stopped, and the mode applies at its
next start (`effective_after_restart: true`); `restart=true` stops the VM
first (hard power-off via TurnOff — not a graceful shutdown; an
already-stopped VM is simply started), sets the mode while off, then starts
it — behind the destructive `stop` category + `confirm`; a mid-leg failure
compensates with a best-effort start so the tool never strands a confirmed
restart powered off. `observed_*` always come from `Msvm_VideoHead`, never from
the request — and they are guest-dependent: the guest's display driver may
keep its own mode, so observed_* can differ from the configured values (and
is null while the VM is off or the head cannot be read). Gen1 VMs are unverified; unsupported modes are refused by the
host. Enhanced Session Mode is out of scope (it renders over RDP, invisible
to the WMI thumbnail and synthetic input). Snapshot-scale defaults elsewhere
(1024x768 screenshots, 640x480 frame waits) are deliberate: a 1920x1080 RGB565
frame is about 4 MB before encoding, and the screenshot fallback chain already
prefers the head-native mode as its second tier — pass explicit
width/height/frame dimensions when you need head-sized captures.

### Orchestration

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_wait_vm_state` | `vm_name` or `vm_id`, `states[]` (Off/Running/Saved/Paused/...), `timeout_s=300` | `{ok, final_state, guest_channel, [heartbeat]}` — `guest_channel` is derived from the Heartbeat integration service on Running finals (`os_heartbeat_ok` / `no_guest_signal`); non-Running finals run no heartbeat query |

### Server Provenance (0.3.0)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `hyperv_server_info` | — | `{version, git_revision, powershell: {path, edition, version, psmodulepath}, config_path, config_sha256, mcp_sdk_version, protocol_version, feature_flags}` — read-only; never contains secrets |

### MDT Deployment Playbook (agent-driven)

1. **Identify** — `hyperv_list_vms`; pick a disposable VM matching allowed_vm_patterns.
2. **Verify media** — `hyperv_vm_media_list` on the VM or known-good ISO path; confirm freshness.
3. **Checkpoint/clone/recreate** — `hyperv_checkpoint_create` (restore later), `hyperv_vm_clone` + `hyperv_vm_disk_add` (golden-image differencing clone: fast, parent stays pristine), or `hyperv_vm_create` for a blank disk; finish with `hyperv_vm_remove` (`delete_disks=true` cleans up the clone's own disks, never the golden parent).
4. **Attach media** — `hyperv_vm_media_attach` with the LiteTouch ISO.
5. **Boot** — `hyperv_vm_firmware_set_boot_order` (Drive for blank-disk fallthrough, or Network for PXE) then `hyperv_start_vm`.
6. **Observe** — `hyperv_console_screenshot` then `hyperv_console_wait_frame_change` (chain via `frame_hash`). WinPE errors appear as images — interpret visually, never answer blindly.
7. **Answer wizard** — `hyperv_console_click` (coordinates from the screenshot) then `hyperv_console_type_text` for harmless fields. For the disk-selection step: verify which disk you are targeting against `hyperv_vm_disk_list` — an early cleanup prompt and the later "Select OS Disk" step are DIFFERENT stages; never target the deployment-media disk.
8. **Monitor** — repeated `wait_frame_change` (static frame = no progress, not success), or after any console input call `hyperv_console_wait_frame_stable` — it returns once the screen has been UNCHANGED for `stable_ms` (default 1500, `interval_ms` floor 100, bounded by `timeout_s`), so an animation or wizard repaint is allowed to finish before the next step instead of guessing a sleep length. With `baseline_hash` from before the input, "the input did nothing" reports `stop_reason: unchanged` rather than `stable`.
9. **Switch channels** — poll `hyperv_deployment_status` until `phase: "os_ready"` (credential-free: heartbeat + KVP; `hyperv_wait_vm_state` also reports the real heartbeat on Running finals). Once an admin account exists, switch to `hyperv_guest_run_ps` / `filetransfer` tools. PS Direct failures during WinPE are expected, not evidence the VM is down. Report the switch explicitly.
10. **Collect** — guest logs: `C:\Windows\Temp\DeploymentLogs\SMSTS.log`, `...\BDD.log`. Results.xml lives on the deployment share (host-side) — inspect via host_read_roots, not guest_get. RetVal=0 does not mean zero errors. If the deployment died before Windows booted (WinPE crash, specialize-pass failure), `hyperv_stop_vm(method=turnoff)` then `hyperv_harvest_offline_logs` reads Panther setupact/setuperr, BDD.log and smsts.log straight from the stopped VM's disk — no guest credentials needed.
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
- `pytest tests/host` (0.15.0) runs the VM-agent-isolation live seam leg on
  a dedicated disposable lab: it skips unless `HYPERV_MCP_INTEGRATION=1` and
  `HYPERV_MCP_TEST_GOLDEN_VHD=<path>` name an existing READ-ONLY golden
  `.vhdx` (mint one: `New-VHD -Dynamic`, then
  `Set-ItemProperty IsReadOnly $true`); no guest credentials are needed.
  See `docs/validation/capability-plan/test_vm_agent_isolation_host-evidence.json`
  for the recorded procedure. CI does not collect this suite.

```powershell
$env:HYPERV_MCP_INTEGRATION = "1"
$env:HYPERV_MCP_TEST_VM     = "lab-vm-01"
$env:HYPERV_GUEST_USERNAME  = "Administrator"
$env:HYPERV_GUEST_PASSWORD_FILE = "C:\Lab\secrets\guest.pw"
pytest tests/integration
```

CI (`.github/workflows/ci.yml`) runs ruff + mypy + unit tests on
`windows-latest`; it does **not** validate real Hyper-V behavior.

Two run-lifecycle behaviours worth knowing before reading a check run:

- **Pushing again to an open PR cancels the earlier run.** The workflow's
  `concurrency` group is the PR's merge ref, so a new member of the group
  cancels whatever is in flight. The trade-off is that this is ordered by
  *arrival*, not by commit recency: re-running an older commit's run also
  cancels the newer head run, which then has to be re-run. Runs on `main`
  are never cancelled and never replaced — each push gets its own group.
- **A job fails at 15 minutes.** The longest successful job observed over
  261 runs was 5.8 minutes, so 15 minutes is roughly 2.5x headroom. A
  per-test `pytest-timeout` of 120 s already bounds a single hung test well
  inside that, so the job timeout is a backstop rather than the first line
  of defence.

---

## Security limitations

- In default proxy mode the stdio client holds no Hyper-V rights of its
  own: the trust boundary is the shared controller process plus the bearer
  token(s) — anyone presenting a configured token gets full tool authority
  through the controller, and `--standalone` still trusts the client's
  process token directly. Policy allowlists and confirm gates remain the
  mitigation — keep `unrestricted` off on shared hosts.
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

**Dependency pin** — this fork pins `mcp>=2.3,<3`; the server uses the mcp
2.x `MCPServer` API (the v1 `FastMCP` name was removed in 2.x) and relies on
CallToolResult passthrough behavior. See the 0.4.0 breaking-changes section
for the in-process embedder surface.

---

## Contributing

Issues and PRs welcome. This is a research tool, not a product — expect rough
edges and breaking changes between versions.

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Built by [Origin](https://originhq.com) for security research and red team
operations; hardened fork maintained at
[zaxbysauce/zaxby-hyperv-mcp](https://github.com/zaxbysauce/zaxby-hyperv-mcp).
