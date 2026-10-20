"""Frozen acceptance check for issue #21, AC30 — the recurrence guardrail.

The defect class this PR closes is "per-call connection setup with no pooling":
a guest leg that opens its own PowerShell Direct session inside a freshly
spawned host process, when the same session could have been reused. The 27
behavioural checks prove the three named chokes are pooled; this census is what
stops the class coming back. It enumerates every place in `src/hyperv_mcp/`
that EMITS a session-establishing command and requires each one to be either

  * the pool's own establishment (`psdsessions._worker_loop`), or
  * an explicitly enumerated per-call-by-design site, with the reason recorded
    beside it.

A new, unlisted emission fails the suite, so a future contributor cannot add a
fourth unpooled per-call session without either pooling it or amending this
allow-list with a reason.

RED at base 9434636cb035ebdb91415c5e4809ba6db20b05c5 (the module does not exist,
so `psdsessions._worker_loop` is absent from the census and the guardrail's own
allow-list is unsatisfiable); GREEN after the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "hyperv_mcp"

#: Every emission that is deliberately NOT pooled, with the reason. The pool's
#: own establishment is added separately because it is the fix, not an exemption.
PER_CALL_BY_DESIGN: dict[tuple[str, str], str] = {
    # The per-call wrapper. Still the path of record for flag-off, no-pool,
    # remote-host mode and every direct module call in unit tests.
    ("guestexec.py", "_host_script"): "the per-call path the pooled branch falls back to",
    # The per-call leg wrapper, reached through build_guest_script by the relay,
    # which deliberately skips vm_lock and must not borrow tool-call sessions.
    ("diagnostics.py", "_guest_leg_script"): "the relay's per-request legs, excluded by the issue",
    # wait_guest_recovery exists to detect a guest coming back, so it must open
    # fresh sessions and observe a real failure.
    ("diagnostics.py", "_recovery_script"): "wait_guest_recovery must observe a fresh session",
    # The local per-call transfer wrapper, plus the remote-mode session legs,
    # which run inside the -ComputerName hop and are never pooled.
    ("filetransfer.py", "_session_body"): "the per-call transfer wrapper",
    ("filetransfer.py", "_remote_put_script"): "remote-host mode is never pooled",
    ("filetransfer.py", "_remote_get_script"): "remote-host mode is never pooled",
    # The per-call bodies for read_file/list_dir, kept for the fallback path.
    ("filetransfer.py", "guest_read_file"): "the per-call body the pooled branch falls back to",
    ("filetransfer.py", "guest_list_dir"): "the per-call body the pooled branch falls back to",
    # The KD tools configure kernel debugging and then REBOOT the guest, which
    # invalidates the session they would have opened. One-shot, so pooling buys
    # nothing and the reboot leg needs a fresh session anyway.
    ("lifecycle.py", "configure_kdnet"): "a one-shot operation that ends in a guest reboot",
    ("lifecycle.py", "configure_kdcom"): "a one-shot operation that ends in a guest reboot",
}

#: The pool's own establishment — the fix, not an exemption.
POOLED_SITE = ("psdsessions.py", "_worker_loop")

#: A session-establishing emission, not a prose mention of one. Requiring the
#: bound variable is what keeps docstrings ("... Invoke-Command -VMId after CIM
#: GUID resolution ...") out of the census: every real emission binds
#: `-VMId $vmTarget`.
_EMISSION_RE = re.compile(r"(?:Invoke-Command|New-PSSession) -VMId \$")


def _enclosing_function(lines: list[str], index: int) -> str:
    for j in range(index, -1, -1):
        m = re.match(r"^(?:async )?def (\w+)", lines[j])
        if m:
            return m.group(1)
    return "<module>"


def census() -> list[tuple[str, str, int]]:
    """Every session-establishing emission in src/hyperv_mcp, as
    (file, enclosing function, line)."""
    out: list[tuple[str, str, int]] = []
    for py in sorted(SRC.glob("*.py")):
        lines = py.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if _EMISSION_RE.search(line):
                out.append((py.name, _enclosing_function(lines, i), i + 1))
    return out


def test_every_session_establishment_site_is_dispositioned():
    """AC30: every emission of a PS Direct session-establishing command is
    either the pool's own establishment or an enumerated per-call-by-design
    site. A new unlisted site fails."""
    hits = census()
    assert hits, "the census found no session-establishing emissions at all"
    allowed = set(PER_CALL_BY_DESIGN) | {POOLED_SITE}
    unlisted = [h for h in hits if (h[0], h[1]) not in allowed]
    assert unlisted == [], (
        "a PS Direct session-establishing command is emitted outside the pool "
        f"and outside the per-call-by-design allow-list: {unlisted}. Either "
        "route it through psdsessions or add it to PER_CALL_BY_DESIGN with a "
        "reason."
    )


def test_the_pooled_establishment_site_exists():
    """AC30: the pool's own establishment is present, so the guardrail is not
    vacuously satisfied by an empty allow-list."""
    sites = {(f, fn) for f, fn, _ in census()}
    assert POOLED_SITE in sites, (
        f"the pooled worker's establishment site {POOLED_SITE} is gone; the "
        "guardrail would then be checking a codebase with no session reuse"
    )


def test_every_per_call_by_design_site_is_real():
    """AC30: the allow-list names sites that actually exist. An entry that
    rotted away is a lie in the guardrail, and a guardrail that over-states its
    exemptions hides exactly the regression it exists to catch."""
    sites = {(f, fn) for f, fn, _ in census()}
    stale = sorted(set(PER_CALL_BY_DESIGN) - sites)
    assert stale == [], (
        f"PER_CALL_BY_DESIGN names site(s) that emit nothing any more: {stale}. "
        "Remove them, or the exemption outlives the code it excused."
    )
