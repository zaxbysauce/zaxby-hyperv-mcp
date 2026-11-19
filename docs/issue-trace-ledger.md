# Issue-trace ledger

Append-only register of every trace slug ever rendered into
docs/issue-trace-drift-inventory.md (issue #148, plan F7). Machine rows
live between the markers, one per slug:

- <slug> | <active|retired> | <first-rendered commit> | <retirement date+reason or ->

Regeneration (python scripts/gen_trace_drift_inventory.py) appends newly
rendered slugs automatically; retiring a trace — flip its row to
`retired` with a date and reason — is the only manual edit. The ledger
carries no inventory-derived value (no blobs, counts, or verdicts), so
it adds no self-referential hash surface to the inventory document.

<!-- ledger-rows-begin -->
- 10-agent-identity-audit-correlation | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 11-job-relay-ownership | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 115-86-71-60-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 12-remote-hyperv-host | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 125-126-console-accuracy-commit-guard | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 128-129-134-gui-drivability | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 13-stdio-proxy | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 135-127-138-gui-electron-drivability | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 136-137-uia-element-contract | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 140-126-uia-state-receipt | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 143-130-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 147-trace-drift-repair | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 148-151-153-followup-hygiene-triad | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 17-rgb565-native-decode | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 18-console-one-ps-process-per-call | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 19-screenshot-output-options | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 20-per-call-timing-soak-benchmark | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 21-psdirect-session-reuse | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 22-durable-state-store | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 23-leases-with-fencing-tokens | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 24-durable-operation-handles | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 25-f1-console-keyboard-click-origin | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 26-checkpoint-type-standard | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 27-frame-stable-wait | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 29-uia-helper-element-desktop | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 30-per-vm-credential-profiles | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 31-32-33-94-workstream-g-deployment | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 31-79-live-host-confirmation | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 44-vm-display-resolution | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 45-console-direct-wmi | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 5-ps51-sanitized-env | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 55-108-31-32-33-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 59-64-68-70-hardening-wave | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 6-guest-put-get-policy | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 63-66-119-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 64-68-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 67-118-release-vendor-provenance | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 7-guest-jobs-truthful-reporting | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 74-72-88-cost-latency-accounting | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 75-76-78-81-83-84-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 77-28-console-actor-batched-sequences | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 8-vm-guid-identity | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 9-error-envelope | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- 95-69-37-57-56-110-collated | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- gpt6sol-guest-access-tools | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- issue-14-vm-rw-locks | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- issue-15-ps-cap-cancel | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
- issue-16-tool-concurrency | active | c3a9f8d0241faeb4e3656e097e7855fb855f11aa | -
<!-- ledger-rows-end -->
