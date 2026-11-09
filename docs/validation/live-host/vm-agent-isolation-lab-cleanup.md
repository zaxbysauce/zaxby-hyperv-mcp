# Operator sweep — orphaned VM-agent-isolation lab objects

The tests/host live seam legs self-clean on every path EXCEPT a
pytest-timeout kill: this repo's `timeout_method = "thread"` ends in
`os._exit(1)` (pytest-timeout), which does not run `finally` blocks. If a
tests/host leg times out despite the derived 5400s budget, any tracked
clone may remain. Sweep:

```powershell
Get-VM | Where-Object { $_.Name -like 'host-iso-*' }
# inspect, then per VM:
Stop-VM -Name <name> -Force
Remove-VM -Name <name> -Force
# delete the child disk recorded in the test output (under the golden's
# clone-disks subdirectory), then the golden itself if it is disposable
```

The minted lab (golden + Gen1 probe VM) is cleaned by the trace harness
(repro/infra_leg.py down), which removes the two VHDs and its state file —
NOT the scratch directory (review PRR-004); remove that directory manually.
