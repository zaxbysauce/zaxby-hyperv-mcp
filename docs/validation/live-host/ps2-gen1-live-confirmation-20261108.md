# Live confirmation — #79 AC1 Gen1 PS/2 fallback (trace 31-79-live-host-confirmation)

Record type: boundary evidence (premise falsified live). This transcript
records the FINAL gate invocation and its observed results only.

tree-id: 96b4917761a76882ee37ce32383a5088f92bcf6f
- head at run time: 250003bd8073719fd58f2d6d8260a8b97d0c26dd (main; the wave
  ships docs/tests/version only)
- host build: Windows host 10.0.26300 x64 (Hyper-V), 2026-11-08
- lab: self-minted disposable Gen1 VM host-ac79-gen1-f73242ef
  (guid e0825eed-7971-4be1-b3af-092d50e51be1), blank 8 GiB VHDX, 512 MB,
  no NIC, minted + STARTED + waited Running via the trace harness
  (repro/infra_leg.py) under the least-privilege lab config; teardown
  verified (VM gone, disks deleted, scratch removed).

## Pre-operation device probe (GUID-scoped, exact queries run via pswindows)

```
Msvm_SyntheticMouse count: 1
Msvm_Ps2Mouse count: 1
```

The #79/#18 premise (a Gen1 VM without integration services exposes NO
Msvm_SyntheticMouse) is FALSIFIED on this host build: the blank Gen1 VM
(no OS, therefore no integration services) still exposes the synthetic
mouse WMI object. The AC1 trigger condition (no synthetic mouse + PS/2
present) does not arise here; the PS/2 fallback is unreachable on this
host build.

## Gated live run (the final gate invocation)

```
$ HYPERV_MCP_INTEGRATION=1 HYPERV_MCP_TEST_VM=host-ac79-gen1-f73242ef \
    HYPERV_MCP_TEST_VM_GEN1=host-ac79-gen1-f73242ef \
    HYPERV_GUEST_USERNAME=unused-synthetic \
    HYPERV_GUEST_PASSWORD=unused-synthetic-not-a-real-secret \
    python -m pytest tests/integration/test_d02_console_live.py::test_ps2_mouse_fallback_live \
    -p no:cacheprovider -o addopts=
...
E           + FullyQualifiedErrorId : SetButtonState failed with ReturnValue=32768
...
FAILED tests/integration/test_d02_console_live.py::test_ps2_mouse_fallback_live
============================== 1 failed in 4.32s ==============================
```

With the synthetic device present, the ops select the SYNTHETIC path
(absence-triggered fallback), which fails with ReturnValue=32768 (0x8000,
"failed") because a guest-less Gen1 VM's synthetic mouse has no guest
cursor to drive. The fallback is absence-triggered by #18's shipped
contract and is therefore unreachable on this host build.

## Direct probes (the structured-error observation, executed live)

```
mouse_button -> RAISED: ConsoleError SetButtonState failed with ReturnValue=32768
mouse_move   -> RAISED: ConsoleError SetAbsolutePosition failed with ReturnValue=32768
```

Both op classes fail the same way: the synthetic device is selected
(present in WMI) and fails with ReturnValue=32768 without a guest; the
"no synthetic mouse" structured error is not produced because the device
IS present.

## Conclusion: premise unreachable on this host build

1. Gen1 without a guest on host build 10.0.26300: synthetic=1, ps2=1.
2. The absence-triggered PS/2 fallback (#18's shipped contract) cannot be
   selected here; the premise-unreachable outcome is the leg's honest
   completion under the re-planned objective (premise unreachable, fully
   characterized).
3. The unit pins for the fallback's script structure stay green
   (C04 GREEN at base and head; the fallback is correct-by-construction
   and remains valuable for host builds where the condition can arise).
4. Downstream design question (out of wave scope, routed via closeout):
   should console ops fall back to PS/2 when the synthetic op FAILS
   (ReturnValue=32768), not only when the device is absent? Recorded on
   the trace and routed to the maintainer decision at closeout.
