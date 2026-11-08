# Issue-trace checkpoint inventory

<!-- regenerated-state-begin -->

Live verify-checkpoint state of every local trace (regenerate with
`python scripts/gen_trace_drift_inventory.py`; gate with `--check`; runbook:
docs/rebaseline-runbook.md).

| trace | pairs | OK | CHANGED | verify-checkpoint |
|---|---:|---:|---:|---|
| 10-agent-identity-audit-correlation | 12 | 12 | 0 | clean |
| 11-job-relay-ownership | 12 | 12 | 0 | clean |
| 115-86-71-60-collated | 9 | 9 | 0 | clean |
| 12-remote-hyperv-host | 7 | 7 | 0 | clean |
| 13-stdio-proxy | 10 | 10 | 0 | clean |
| 17-rgb565-native-decode | 12 | 12 | 0 | clean |
| 18-console-one-ps-process-per-call | 17 | 17 | 0 | clean |
| 19-screenshot-output-options | 23 | 23 | 0 | clean |
| 20-per-call-timing-soak-benchmark | 17 | 17 | 0 | clean |
| 21-psdirect-session-reuse | 31 | 31 | 0 | clean |
| 22-durable-state-store | 15 | 15 | 0 | clean |
| 23-leases-with-fencing-tokens | 16 | 16 | 0 | clean |
| 24-durable-operation-handles | 19 | 19 | 0 | clean |
| 25-f1-console-keyboard-click-origin | 11 | 11 | 0 | clean |
| 26-checkpoint-type-standard | 11 | 11 | 0 | clean |
| 27-frame-stable-wait | 14 | 14 | 0 | clean |
| 29-uia-helper-element-desktop | 19 | 19 | 0 | clean |
| 30-per-vm-credential-profiles | 30 | 30 | 0 | clean |
| 31-32-33-94-workstream-g-deployment | 18 | 18 | 0 | clean |
| 44-vm-display-resolution | 8 | 8 | 0 | clean |
| 45-console-direct-wmi | 8 | 8 | 0 | clean |
| 5-ps51-sanitized-env | 8 | 8 | 0 | clean |
| 55-108-31-32-33-collated | 14 | 14 | 0 | clean |
| 59-64-68-70-hardening-wave | 15 | 15 | 0 | clean |
| 6-guest-put-get-policy | 13 | 13 | 0 | clean |
| 63-66-119-collated | 12 | 12 | 0 | clean |
| 64-68-collated | 11 | 11 | 0 | clean |
| 67-118-release-vendor-provenance | 10 | 10 | 0 | clean |
| 7-guest-jobs-truthful-reporting | 13 | 13 | 0 | clean |
| 74-72-88-cost-latency-accounting | 17 | 17 | 0 | clean |
| 75-76-78-81-83-84-collated | 26 | 26 | 0 | clean |
| 77-28-console-actor-batched-sequences | 18 | 18 | 0 | clean |
| 8-vm-guid-identity | 11 | 11 | 0 | clean |
| 9-error-envelope | 13 | 13 | 0 | clean |
| 95-69-37-57-56-110-collated | 20 | 20 | 0 | clean |
| gpt6sol-guest-access-tools | 22 | 22 | 0 | clean |
| issue-14-vm-rw-locks | 11 | 11 | 0 | clean |
| issue-15-ps-cap-cancel | 9 | 9 | 0 | clean |
| issue-16-tool-concurrency | 13 | 13 | 0 | clean |

## Drift detail (CHANGED pairs)

None — every frozen pair verifies OK at the current tree.
<!-- regenerated-state-end -->

## Discovery snapshot (recorded 2026-11-05, base 8bc60cb7196ae128231c25a15881cded26b0afda)

Verbatim verify-checkpoint output per drifted trace at the recorded state.

### 10-agent-identity-audit-correlation

```

CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C1)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C2)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C3)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C4)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C5)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C6)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C7)
CHANGED tests/unit/test_b01_agent_identity.py 3008efa110ea709232f18424ed6d7707203fab9d 8cccd750c1a1c691f2493cb938dd668d9dbd4fad (C8)
CHANGED tests/unit/test_http_entry.py 44556c8e67c4c1473b2f26ab4c3329d8aa816fd3 2373f94fbd6b97281d645a21136f4021ad67df16 (C9)
CHANGED tests/unit/test_http_entry.py 44556c8e67c4c1473b2f26ab4c3329d8aa816fd3 2373f94fbd6b97281d645a21136f4021ad67df16 (C10)
OK tests/unit/test_ops.py (C11)
CHANGED tests/unit/test_server.py 28cd281c3d25e6876e9317f7128f772d40d40d39 929155739290772e3ea1380c216b3a79694524c9 (C12)
```

### 11-job-relay-ownership

```

OK tests/unit/test_b02_ownership_relay.py (C1)
OK tests/unit/test_b02_ownership_relay.py (C2)
OK tests/unit/test_b02_ownership_relay.py (C3)
OK tests/unit/test_b02_ownership_relay.py (C4)
OK tests/unit/test_b02_ownership_relay.py (C5)
OK tests/unit/test_b02_ownership_relay.py (C6)
OK tests/unit/test_b02_ownership_relay.py (C7)
OK tests/unit/test_b02_ownership_relay.py (C8)
OK tests/unit/test_b02_ownership_relay.py (C9)
CHANGED tests/unit/test_relay.py d10ceacf8e2549bfbcd02d2f8ddfbb9897ee9d7b b3b9a1965c10ef85f39296b44cd1afeea56a3e25 (C10)
CHANGED tests/unit/test_relay.py d10ceacf8e2549bfbcd02d2f8ddfbb9897ee9d7b b3b9a1965c10ef85f39296b44cd1afeea56a3e25 (C11)
CHANGED tests/unit/test_guestjobs.py 7d978e1a137d22e5a06316e4e17c42069f578b1a 159af076b7cb047e6c1541acf1bb141e2a05a3aa (C12)
```

### 12-remote-hyperv-host

```

OK tests/unit/test_remote_host_config.py (C1)
CHANGED tests/unit/test_remote_host_wiring.py fb99ada860d7a7eb5c15b7fa4ba2c1cdfc2d3d9f 321c97c10f33b2c85a60ba8a55fbd4d285d66069 (C2)
OK tests/unit/test_remote_psdirect_hop.py (C3)
OK tests/unit/test_remote_host_credentials.py (C4)
OK tests/unit/test_remote_server_info.py (C5)
OK tests/unit/test_remote_readme.py (C6)
CHANGED tests/unit/test_remote_host_wiring.py fb99ada860d7a7eb5c15b7fa4ba2c1cdfc2d3d9f 321c97c10f33b2c85a60ba8a55fbd4d285d66069 (C7)
```

### 13-stdio-proxy

```

CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C1)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C2)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C3)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C4)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C5)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C6)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C7)
CHANGED tests/unit/test_b03_stdio_proxy.py d814a06f86abc935f377a7ac3032dbbdf32fec9b 37796356f59f15b5418d3a3043ad901eae451ee8 (C8)
OK tests/unit/test_server.py (C11)
OK tests/unit/test_server.py (C12)
```

### 19-screenshot-output-options

```

CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C1)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C2)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C3)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C4)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C5)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C6)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C8)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C10)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C11)
OK tests/unit/test_image_content.py (C13)
CHANGED tests/unit/test_console.py 33b9914d6552821edae007fa8d7c008591ec8ea5 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C14)
CHANGED tests/unit/test_server.py 64f10595af0e6a05e9c3f8dc665a8869ad01f696 929155739290772e3ea1380c216b3a79694524c9 (C15)
CHANGED tests/unit/test_console.py 33b9914d6552821edae007fa8d7c008591ec8ea5 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C16)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C17)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C18)
OK tests/unit/test_console_decode.py (C19)
CHANGED tests/unit/test_d03_screenshot_options.py 9c34b9632ab6858f09849bf53bcefba12a4ac8d4 2c68a8feb768f50660e64dedf690cca4906a02d4 (C7)
CHANGED tests/integration/test_d03_frame_prefix_live.py a2c7564520a207679ce0c3833605b30a82a74668 123fe08d414392498d7f3006995bc03df737e896 (C20)
OK tests/unit/test_d03_prefix_stability.py (C9)
OK tests/unit/test_d03_evidence_and_order.py (C21)
OK tests/unit/test_d03_evidence_and_order.py (C22)
OK tests/unit/test_d03_evidence_and_order.py (C23)
OK tests/unit/test_d03_evidence_and_order.py (C24)
```

### 20-per-call-timing-soak-benchmark

```

CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C1)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C2)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C3)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C4)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C5)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C6)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C7)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C8)
OK tests/unit/test_ops.py (C9)
OK tests/unit/test_ops.py (C10)
OK tests/unit/test_ops.py (C11)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C12)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C13)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C14)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C15)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C16)
CHANGED tests/unit/test_d04_timing.py 4854538ece1e5ec859ebbbb79c85586da271e6d9 f1325550c390760ebbd2f28601d6a4e2b7c94872 (C17)
```

### 21-psdirect-session-reuse

```

OK tests/unit/test_guestexec.py (C11)
OK tests/unit/test_guestexec.py (C12)
CHANGED tests/unit/test_lifecycle.py 72e5789555f9332ad2ef5d904aa2bb1921de213f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C13)
CHANGED tests/unit/test_d05_soak_session_reuse.py 1088785e3c26cf2dc370aa5f23d363ff3eb878f0 ef2c05d635ccd3dbd8569770798ad559f04665c4 (C20)
OK tests/integration/test_d05_psdirect_sessions_live.py (C21)
CHANGED tests/unit/test_d05_pool_census.py 06afb6d206a8baa8bdc48a65feb9808bfe1ea3b9 3ead63d4d2b451e50c4a79d604098caedeaa1d64 (C28)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C1)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C2)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C3)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C4)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C5)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C6)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C7)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C8)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C9)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C10)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C14)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C15)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C16)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C17)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C18)
CHANGED tests/unit/test_d05_psdirect_sessions.py f12c4afeb392c210aab6ea06c21e9881f9d908f4 ec5b6c6c1485a87f984137be4989afc4997b8f9d (C19)
CHANGED tests/unit/test_d05_worker_execution.py 43030b2e0b2657fd38a623fd20da17df5e749650 db11052c8a7a6477d83539b566be552faca4ddd6 (C29)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C30)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C22)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C23)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C24)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C25)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C26)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C27)
CHANGED tests/unit/test_d05_pool_edges.py cd4d03248794f9da787bf4539e75bf31798ae3b3 0b55391ded5b7c0db4006f3cf400726950880c37 (C31)
```

### 22-durable-state-store

```

OK tests/unit/_e01_multi_child.py (C7)
OK tests/unit/_e01_multi_child.py (C8)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C1)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C2)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C3)
OK tests/unit/_e01_crash_child.py (C3)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C4)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C5)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C6)
CHANGED tests/unit/test_e01_durable_state.py 41c175ff175aa4484f55939443d0c2f710183784 78f403383f62ea1753afb5795a2fd7f881189437 (C9)
CHANGED tests/unit/test_e01_state_store.py b96061163768050c34595b9783d043f96f4ae81b 67c528603dd4c0873abe5f53603b108bbe08ff24 (C7)
CHANGED tests/unit/test_e01_state_store.py b96061163768050c34595b9783d043f96f4ae81b 67c528603dd4c0873abe5f53603b108bbe08ff24 (C8)
OK tests/unit/test_guestjobs.py (C11)
OK tests/unit/test_guestjobs.py (C12)
OK tests/unit/test_relay.py (C13)
```

### 23-leases-with-fencing-tokens

```

CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C1)
OK tests/unit/_e02_lease_child.py (C1)
CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C2)
CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C3)
OK tests/unit/test_e02_lease_store.py (C4)
OK tests/unit/test_e02_lease_store.py (C5)
OK tests/unit/test_e02_lease_store.py (C6)
OK tests/unit/test_e02_lease_store.py (C7)
OK tests/unit/test_e02_lease_store.py (C8)
OK tests/unit/test_e02_lease_store.py (C9)
OK tests/unit/test_e02_lease_store.py (C10)
OK tests/unit/_e02_lease_child.py (C10)
OK tests/unit/test_e02_lease_store.py (C11)
CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C12)
CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C13)
CHANGED tests/unit/test_e02_leases.py 53f8a8b2b724d8a0aca485c593810369d3f0a277 416df77b04d061aed4a4c12c6d81a05fd61d83ac (C14)
```

### 24-durable-operation-handles

```

CHANGED tests/unit/test_e03_operations.py 8d5e01d74bddd340afdba37635ef77f354eb42e4 03f8247346cd17d842ddcf88832077b6964893bc (C1)
CHANGED tests/unit/test_e03_operations.py 8d5e01d74bddd340afdba37635ef77f354eb42e4 03f8247346cd17d842ddcf88832077b6964893bc (C2)
CHANGED tests/unit/test_e03_operations.py 8d5e01d74bddd340afdba37635ef77f354eb42e4 03f8247346cd17d842ddcf88832077b6964893bc (C3)
CHANGED tests/unit/test_e03_operations.py 8d5e01d74bddd340afdba37635ef77f354eb42e4 03f8247346cd17d842ddcf88832077b6964893bc (C4)
CHANGED tests/unit/test_server.py 8455156c6c5d868f203d7050d89145bf91e2a558 929155739290772e3ea1380c216b3a79694524c9 (C4)
CHANGED tests/unit/test_c03_tool_surface.py b20eccd2bfedabacd1a15f50906d69107744bb94 4c1d1a79edd1f49b86969d204302f5af11b198a5 (C4)
OK tests/unit/test_e03_tasks_bridge.py (C12)
OK tests/unit/test_e03_tasks_bridge.py (C13)
OK tests/unit/test_e03_tasks_bridge.py (C14)
OK tests/unit/test_e03_tasks_bridge.py (C15)
CHANGED tests/unit/test_lifecycle.py 72e5789555f9332ad2ef5d904aa2bb1921de213f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C17)
CHANGED tests/unit/test_lifecycle.py 72e5789555f9332ad2ef5d904aa2bb1921de213f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C18)
OK tests/unit/test_e03_operation_store.py (C5)
OK tests/unit/test_e03_operation_store.py (C6)
OK tests/unit/test_e03_operation_store.py (C7)
OK tests/unit/test_e03_operation_store.py (C8)
OK tests/unit/test_e03_operation_store.py (C10)
OK tests/unit/test_e03_operation_store.py (C11)
OK tests/unit/test_e03_operation_store.py (C9)
```

### 25-f1-console-keyboard-click-origin

```

CHANGED tests/unit/test_console.py 0d68a3b3ea0e5258f6d88171a5852067cd1465ab 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C8)
CHANGED tests/unit/test_console.py 0d68a3b3ea0e5258f6d88171a5852067cd1465ab 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C9)
CHANGED tests/unit/test_console.py 0d68a3b3ea0e5258f6d88171a5852067cd1465ab 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C10)
CHANGED tests/unit/test_console.py 0d68a3b3ea0e5258f6d88171a5852067cd1465ab 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C11)
OK tests/unit/test_f01_console_keys.py (C1)
OK tests/unit/test_f01_console_keys.py (C2)
OK tests/unit/test_f01_console_keys.py (C3)
OK tests/unit/test_f01_console_keys.py (C4)
OK tests/unit/test_f01_console_keys.py (C5)
OK tests/unit/test_f01_console_keys.py (C6)
OK tests/unit/test_f01_console_keys.py (C7)
```

### 26-checkpoint-type-standard

```

OK tests/unit/test_f02_checkpoint_type.py (C1)
OK tests/unit/test_f02_checkpoint_type.py (C2)
OK tests/unit/test_f02_checkpoint_type.py (C3)
OK tests/unit/test_f02_checkpoint_type.py (C4)
OK tests/unit/test_f02_checkpoint_type.py (C5)
OK tests/unit/test_f02_checkpoint_type.py (C6)
OK tests/unit/test_lifecycle.py (C7)
OK tests/unit/test_lifecycle.py (C8)
CHANGED tests/unit/test_server.py 8455156c6c5d868f203d7050d89145bf91e2a558 929155739290772e3ea1380c216b3a79694524c9 (C9)
OK tests/unit/test_lifecycle.py (C9)
CHANGED tests/unit/test_script_parse.py e226e879ea57373f9a4b889eae1ec94d163d1a74 54afd64be5b70fca9a18b31ca3b013f4a72f0104 (C10)
```

### 27-frame-stable-wait

```

OK .agents/issue-traces/27-frame-stable-wait/repro/check-C6.sh (C6)
OK .agents/issue-traces/27-frame-stable-wait/repro/check-C7.sh (C7)
OK .agents/issue-traces/27-frame-stable-wait/repro/check-C8.sh (C8)
OK .agents/issue-traces/27-frame-stable-wait/repro/check-C9.sh (C9)
OK tests/unit/test_d18_capture_sequence_identity.py (C10)
CHANGED tests/unit/test_d02_console_spawns.py 8c9e8288bdd70f057a6659a7a4876c0a953cfde8 218b1404769c71b831b0e737cd71d61c95ff6958 (C11)
OK tests/unit/test_d18_capture_sequence_identity.py (C12)
OK tests/unit/test_wmiconsole.py (C13)
OK tests/unit/test_console_folded_protocol.py (C11)
OK tests/unit/test_f03_frame_stable.py (C1)
OK tests/unit/test_f03_frame_stable.py (C2)
OK tests/unit/test_f03_frame_stable.py (C3)
OK tests/unit/test_f03_frame_stable.py (C4)
OK tests/unit/test_f03_frame_stable.py (C5)
```

### 29-uia-helper-element-desktop

```

CHANGED tests/integration/test_hyperv_real.py 6bce342a71fec1f8b5139ca547b999d20ace91d1 93d0f163278655ceebbd390ee5699531c0049eb6 (C18)
OK tests/unit/test_evidence.py (C14)
OK tests/unit/test_f05_interactive_helper.py (C19)
OK tests/unit/test_f05_interactive_helper.py (C20)
OK tests/unit/test_f05_interactive_helper.py (C21)
OK tests/unit/test_f05_uia_helper.py (C1)
OK tests/unit/test_f05_uia_helper.py (C10)
OK tests/unit/test_f05_uia_helper.py (C11)
OK tests/unit/test_f05_uia_helper.py (C12)
OK tests/unit/test_f05_uia_helper.py (C2)
OK tests/unit/test_f05_uia_helper.py (C3)
OK tests/unit/test_f05_uia_helper.py (C4)
OK tests/unit/test_f05_uia_helper.py (C5)
OK tests/unit/test_f05_uia_helper.py (C6)
OK tests/unit/test_f05_uia_helper.py (C7)
OK tests/unit/test_f05_uia_helper.py (C8)
OK tests/unit/test_f05_uia_helper.py (C9)
OK tests/unit/test_script_parse_new.py (C13)
CHANGED tests/unit/test_server.py 935066ed34ef7af5d2665597b2ff3087a4b3056c 929155739290772e3ea1380c216b3a79694524c9 (C15)
```

### 30-per-vm-credential-profiles

```

OK tests/unit/test_g01_credential_profiles.py (C1)
OK tests/unit/test_g01_credential_profiles.py (C2)
OK tests/unit/test_g01_credential_profiles.py (C3)
OK tests/unit/test_g01_credential_profiles.py (C4)
OK tests/unit/test_g01_credential_profiles.py (C5)
OK tests/unit/test_g01_credential_profiles.py (C6)
OK tests/unit/test_g01_credential_profiles.py (C7)
OK tests/unit/test_g01_credential_profiles.py (C8)
OK tests/unit/test_g01_credential_profiles.py (C9)
OK tests/unit/test_g01_credential_profiles.py (C10)
OK tests/unit/test_g01_credential_profiles.py (C11)
OK tests/unit/test_g01_credential_profiles.py (C15)
OK tests/unit/test_g01_credential_profiles.py (C16)
OK tests/unit/test_g01_credential_profiles.py (C17)
OK tests/unit/test_g01_credential_profiles.py (C18)
OK tests/unit/test_credentials.py (C12)
CHANGED tests/unit/test_server.py 935066ed34ef7af5d2665597b2ff3087a4b3056c 929155739290772e3ea1380c216b3a79694524c9 (C13)
OK tests/unit/test_guestexec.py (C13)
CHANGED tests/unit/test_config.py 665d75d4945991e1d273b8831464dd19f2952aa8 ee2f1fd3b3b96ccba7f44b6c8566dffa5690ea57 (C13)
OK tests/unit/test_g01_pool_edges.py (C19)
OK tests/unit/test_g01_pool_edges.py (C20)
OK tests/unit/test_g01_pool_edges.py (C21)
OK tests/unit/test_g01_pool_edges.py (C22)
OK tests/unit/test_g01_pool_edges.py (C23)
OK tests/unit/test_g01_restore_edges.py (C24)
OK tests/unit/test_g01_restore_edges.py (C25)
OK tests/unit/test_g01_restore_edges.py (C26)
OK tests/unit/test_g01_restore_edges.py (C27)
OK tests/unit/test_g01_inline_precedence.py (C28)
OK tests/integration/test_hyperv_real.py (C14)
```

### 31-32-33-94-workstream-g-deployment

```

OK tests/unit/test_g02_clone_remove.py (C1)
OK tests/unit/test_g02_clone_remove.py (C2)
OK .agents/issue-traces/31-32-33-94-workstream-g-deployment/repro/check-g.sh (C3)
OK tests/unit/test_g02_clone_remove.py (C4)
OK tests/unit/test_g02_clone_remove.py (C5)
OK .agents/issue-traces/31-32-33-94-workstream-g-deployment/repro/check-g.sh (C6)
CHANGED tests/unit/test_g03_readiness.py 7b30bdad68ae216dab64686b3578d7da6f2c1b27 95f94900e4f11797479cba5cc7682b5972cf2610 (C7)
CHANGED tests/unit/test_g03_readiness.py 7b30bdad68ae216dab64686b3578d7da6f2c1b27 95f94900e4f11797479cba5cc7682b5972cf2610 (C8)
CHANGED tests/unit/test_g03_readiness.py 7b30bdad68ae216dab64686b3578d7da6f2c1b27 95f94900e4f11797479cba5cc7682b5972cf2610 (C9)
CHANGED tests/unit/test_g03_readiness.py 7b30bdad68ae216dab64686b3578d7da6f2c1b27 95f94900e4f11797479cba5cc7682b5972cf2610 (C10)
OK .agents/issue-traces/31-32-33-94-workstream-g-deployment/repro/check-g.sh (C11)
CHANGED tests/unit/test_g04_offline_harvest.py 787c43e76460ad68031e74262ca0df288752d060 f34151f49753ac4eeec69882affa276da4d99f69 (C12)
CHANGED tests/unit/test_g04_offline_harvest.py 787c43e76460ad68031e74262ca0df288752d060 f34151f49753ac4eeec69882affa276da4d99f69 (C13)
CHANGED tests/unit/test_g04_offline_harvest.py 787c43e76460ad68031e74262ca0df288752d060 f34151f49753ac4eeec69882affa276da4d99f69 (C14)
CHANGED tests/unit/test_g04_offline_harvest.py 787c43e76460ad68031e74262ca0df288752d060 f34151f49753ac4eeec69882affa276da4d99f69 (C15)
OK .agents/issue-traces/31-32-33-94-workstream-g-deployment/repro/check-g.sh (C16)
OK tests/unit/test_g05_vm_create_cpu.py (C17)
OK tests/unit/test_g05_vm_create_cpu.py (C18)
```

### 44-vm-display-resolution

```

CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C1)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C2)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C3)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C4)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C5)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C6)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C7)
CHANGED tests/unit/test_vm_video.py 4995d35c55d0750923487a8a0a74c80086272a69 4f62257380b88732b1fca0177d2358ec160ede98 (C8)
```

### 45-console-direct-wmi

```

CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C1)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C2)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C3)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C5)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C6)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C8)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C9)
CHANGED tests/unit/test_wmiconsole.py 638f10c477479c0aae8b6577541730244eb070c3 f005643343016fc3b0165a98d4f402d23c7e5bf1 (C7)
```

### 5-ps51-sanitized-env

```

CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C1)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C2)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C3)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C4)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C6)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C7)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C8)
CHANGED tests/unit/test_a01_ps_environment.py 190a99b60a7a862d4648d4faeb0cdb3ecbb0fd69 009ded260d32a28b2aaf80fc7e24503c2252a450 (C9)
```

### 55-108-31-32-33-collated

```

OK tests/unit/test_b03_feedback_fixes.py (C1)
CHANGED tests/unit/test_version_consistency.py 76f3a1def766c83ee691db939a4af38385a7df1c a6e9bc494b03e3bc113380a64c1e99f77dadfd93 (C4)
CHANGED tests/unit/test_version_consistency.py 76f3a1def766c83ee691db939a4af38385a7df1c a6e9bc494b03e3bc113380a64c1e99f77dadfd93 (C5)
CHANGED tests/unit/test_version_consistency.py 76f3a1def766c83ee691db939a4af38385a7df1c a6e9bc494b03e3bc113380a64c1e99f77dadfd93 (C6)
OK .agents/issue-traces/55-108-31-32-33-collated/repro/check-g.sh (C12)
OK .agents/issue-traces/55-108-31-32-33-collated/repro/check-g.sh (C13)
OK .agents/issue-traces/55-108-31-32-33-collated/repro/check-g.sh (C2)
OK .agents/issue-traces/55-108-31-32-33-collated/repro/check-g.sh (C3)
OK tests/unit/test_g03_readiness.py (C9)
OK tests/unit/test_g03_readiness.py (C10)
OK tests/unit/test_g04_offline_harvest.py (C11)
OK tests/unit/test_vm_agent_isolation.py (C7)
OK tests/unit/test_vm_agent_isolation.py (C8)
OK tests/unit/test_vm_agent_isolation.py (C14)
```

### 6-guest-put-get-policy

```

CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C1)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C2)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C3)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C4)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C5)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C6)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C7)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C9)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C10)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C11)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C12)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C13)
CHANGED tests/unit/test_a02_guest_transfer.py 362bbfb4b53fb82b35920b1411989e00110a5f91 f89e843e643a492bd9707e3227a2541bda9a3f54 (C14)
```

### 7-guest-jobs-truthful-reporting

```

CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C1)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C2)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C3)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C4)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C5)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C6)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C7)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C10)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C11)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C12)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C13)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C14)
CHANGED tests/unit/test_a03_guest_jobs.py eeac553769501b3b009421988b05ddcdf2952de4 9199c93332d0514db0f1cdbc0361e872c4068587 (C15)
```

### 74-72-88-cost-latency-accounting

```

OK tests/unit/test_d01_ps_encode.py (C3)
CHANGED tests/unit/test_console.py 33b9914d6552821edae007fa8d7c008591ec8ea5 0a1bb3e616d57174f1a09e7001ef4dcf6343eab5 (C4)
OK .agents/issue-traces/74-72-88-cost-latency-accounting/repro/check_c10.sh (C10)
CHANGED tests/unit/test_relay.py d10ceacf8e2549bfbcd02d2f8ddfbb9897ee9d7b b3b9a1965c10ef85f39296b44cd1afeea56a3e25 (C8)
CHANGED src/hyperv_mcp/relay.py 6d7c5d6525af1300952662fbf4785c1e96be369f 2ee098fff0550b50db983932bd61ca26467ebc77 (C6)
CHANGED src/hyperv_mcp/relay.py 6d7c5d6525af1300952662fbf4785c1e96be369f 2ee098fff0550b50db983932bd61ca26467ebc77 (C7)
CHANGED src/hyperv_mcp/relay.py 6d7c5d6525af1300952662fbf4785c1e96be369f 2ee098fff0550b50db983932bd61ca26467ebc77 (C9)
CHANGED src/hyperv_mcp/server.py 0a8c1000811f70616cfc03c2677c6e7b435442a8 0c90918f7e2df5b8f3907642dc1d8037c13d9d98 (C10)
CHANGED tests/unit/test_e01_frame_lazy.py 95d829dfec706086426700fad59cc9760e30ce17 a07f7f3d22e3f0771e589eb660710e10c66a004f (C2)
CHANGED tests/unit/test_e01_frame_lazy.py 95d829dfec706086426700fad59cc9760e30ce17 a07f7f3d22e3f0771e589eb660710e10c66a004f (C1)
CHANGED tests/unit/test_e01_relay_latency.py 6cd7f6a8445ecce26d6784d0cea0235729b6aa3b fa3333e8e93fc4ceab0345e14e3982752b298885 (C6)
CHANGED tests/unit/test_e01_relay_latency.py 6cd7f6a8445ecce26d6784d0cea0235729b6aa3b fa3333e8e93fc4ceab0345e14e3982752b298885 (C7)
CHANGED tests/unit/test_e01_relay_latency.py 6cd7f6a8445ecce26d6784d0cea0235729b6aa3b fa3333e8e93fc4ceab0345e14e3982752b298885 (C9)
OK tests/unit/test_e01_capture_diff.py (C5)
OK src/hyperv_mcp/console.py (C1)
OK src/hyperv_mcp/console.py (C5)
OK README.md (C10)
```

### 77-28-console-actor-batched-sequences

```

OK tests/unit/test_c01_console_cross_form_lock.py (C771)
OK tests/unit/test_c01_console_cross_form_lock.py (C772)
OK .agents/issue-traces/77-28-console-actor-batched-sequences/repro/check_C77_3.sh (C773)
OK tests/unit/test_c01_console_cross_form_lock.py (C774)
OK tests/unit/test_c01_console_cross_form_lock.py (C775)
OK tests/unit/test_f04_sequences.py (C281)
OK tests/unit/test_f04_sequences.py (C282)
OK tests/unit/test_f04_sequences.py (C283)
OK tests/unit/test_f04_sequences.py (C284)
OK tests/unit/test_f04_sequences.py (C285)
OK tests/unit/test_f04_sequences.py (C286)
OK tests/unit/test_f04_sequences.py (C287)
OK .agents/issue-traces/77-28-console-actor-batched-sequences/repro/check_C28_8.sh (C288)
OK .agents/issue-traces/77-28-console-actor-batched-sequences/repro/check_C28_9.sh (C289)
CHANGED tests/unit/test_script_parse.py a774dabba764fda6679c4294fa35c5b14f94c5ed 54afd64be5b70fca9a18b31ca3b013f4a72f0104 (C2810)
OK tests/unit/test_f04_sequences.py (C2813)
OK tests/unit/test_f04_sequences.py (C2814)
OK tests/unit/test_f04_sequences.py (C2815)
```

### 8-vm-guid-identity

```

OK tests/unit/test_ops.py (C10)
OK tests/unit/test_ops.py (C11)
OK tests/integration/test_a04_vm_identity_real.py (C7)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C1)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C2)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C3)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C4)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C5)
CHANGED tests/unit/test_a04_vm_identity.py 4575e9beba52be18a9baf21a3c7030d6ce8771ce cf3c4899989fb77c4065b520be43ad1a3415844e (C6)
CHANGED tests/unit/test_lifecycle.py 931b3fe28e658d9b40282ff267494a84e9a9296f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C8)
CHANGED tests/unit/test_lifecycle.py 931b3fe28e658d9b40282ff267494a84e9a9296f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C9)
```

### 9-error-envelope

```

CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C1)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C2)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C3)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C4)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C5)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C6)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C7)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C8)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C9)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C10)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C11)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C12)
CHANGED tests/unit/test_a05_error_envelope.py aaaed669b1647ae949c4fdfa388f4a7303216c8a 0ff69e005980665142313a2dfd2f85d8192f4671 (C13)
```

### issue-14-vm-rw-locks

```

OK tests/unit/test_c01_vm_locks.py (C1)
OK tests/unit/test_c01_vm_locks.py (C2)
OK tests/unit/test_c01_vm_locks.py (C3)
OK tests/unit/test_c01_vm_locks.py (C4)
OK tests/unit/test_c01_vm_locks.py (C5)
OK tests/unit/test_c01_vm_locks.py (C6)
OK tests/unit/test_ops.py (C7)
OK tests/unit/test_ops.py (C8)
OK tests/unit/test_ops.py (C9)
OK tests/unit/test_media.py (C10)
CHANGED tests/unit/test_guestjobs.py 7d978e1a137d22e5a06316e4e17c42069f578b1a 159af076b7cb047e6c1541acf1bb141e2a05a3aa (C11)
```

### issue-15-ps-cap-cancel

```

OK tests/unit/test_c02_ps_cap.py (C1)
OK tests/unit/test_c02_ps_cap.py (C2)
OK tests/unit/test_c02_ps_cap.py (C3)
OK tests/unit/test_c02_ps_cap.py (C4)
OK tests/unit/test_c02_ps_cap.py (C5)
OK tests/unit/test_pswindows.py (C6)
OK tests/unit/test_pswindows.py (C7)
CHANGED tests/unit/test_lifecycle.py 72e5789555f9332ad2ef5d904aa2bb1921de213f 0e187cd56cda54f46753e33b9583c3ab6852ede8 (C8)
CHANGED tests/unit/test_guestjobs.py 7d978e1a137d22e5a06316e4e17c42069f578b1a 159af076b7cb047e6c1541acf1bb141e2a05a3aa (C9)
```
