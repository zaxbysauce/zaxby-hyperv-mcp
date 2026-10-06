"""Pin the `guest_run` cwd assembly: the exit tail belongs INSIDE the try.

Round-1 implementation review of issue #7 (trace 7-guest-jobs-truthful-reporting,
mutation M3) proved that moving `_EXIT_PROPAGATION` back to its pre-fix place -
after `} finally { Pop-Location }` - leaves every other shipped check green:
the frozen AC7 check exercises the NON-cwd path, the integration module has no
cwd case, and the PS 5. probe builds its cwd script from its own template
instead of reading what `guest_run` emits. With the tail outside the try,
`$ok = $?` captures `Pop-Location`'s success and a failing command exits 0 -
exactly the defect the plan critic caught in round 1.

These tests read the script `guest_run` really emits and pin that ordering, so
the regression turns the suite red instead of shipping silently. They are
additive: no existing test file is modified.
"""

import base64
import json

import pytest

from hyperv_mcp import guestexec, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet

CRED = CredentialSet("Administrator", "placeholder-pass")
CWD = r"C:\work dir"


def _inner_script(host_script: str) -> str:
    """The guest-visible inner script rides in the host script as b64."""
    marker = "$enc = '"
    start = host_script.index(marker) + len(marker)
    end = host_script.index("'", start)
    return base64.b64decode(host_script[start:end]).decode("utf-8")


class FakePS:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        item = self.responses.pop(0) if self.responses else pswindows.PSResult(returncode=0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


def _emit_inner(monkeypatch, unrestricted, cwd):
    """Capture the inner script guest_run actually hands to the guest."""
    fake = FakePS([pswindows.PSResult(
        stdout=json.dumps({"exit_code": 0, "stdout": "", "stderr": ""}), returncode=0)])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    guestexec.guest_run(
        unrestricted, "vm1", r"C:\tool.exe", ["arg"], cwd=cwd, cred=CRED,
    )
    return _inner_script(fake.scripts[0])


def test_cwd_exit_tail_is_emitted_inside_the_try(monkeypatch, unrestricted):
    """`$ok = $?` must read the invoke, not Pop-Location's success."""
    inner = _emit_inner(monkeypatch, unrestricted, CWD)
    capture = inner.index("$ok = $?")
    finally_at = inner.index("finally")
    assert capture < finally_at, (
        "the exit tail must be emitted INSIDE the try block (before "
        f"`}} finally {{ Pop-Location }}`); found $ok at {capture} and finally "
        f"at {finally_at} in:\n{inner}"
    )


def test_cwd_tail_is_the_three_branch_tail_inside_the_try(monkeypatch, unrestricted):
    """The guarded tail (not just a capture) must sit inside the try."""
    inner = _emit_inner(monkeypatch, unrestricted, CWD)
    assert guestexec._EXIT_PROPAGATION in inner
    capture = inner.index("$ok = $?")
    finally_at = inner.index("finally")
    assert capture < finally_at
    assert "exit 0" in inner[capture:finally_at], (
        "the exit-0 branch belongs to the tail inside the try; "
        "it must not be reachable only after the finally block"
    )
    assert inner.rstrip().endswith("} finally { Pop-Location }"), (
        "the cwd variant must still restore the location in a finally block"
    )


def test_cwd_pins_the_location_and_still_uses_terminating_setlocation(monkeypatch, unrestricted):
    """The pinned construction the existing suite relies on must survive."""
    inner = _emit_inner(monkeypatch, unrestricted, CWD)
    assert f"Set-Location -LiteralPath '{CWD}' -ErrorAction Stop" in inner
    assert "} finally { Pop-Location }" in inner


def test_non_cwd_tail_is_appended_after_the_invoke(monkeypatch, unrestricted):
    """Without cwd there is no try block; the tail is simply appended."""
    inner = _emit_inner(monkeypatch, unrestricted, "")
    assert "Push-Location" not in inner
    assert guestexec._EXIT_PROPAGATION in inner
    assert inner.index("$ok = $?") > inner.index("& 'C:\\tool.exe'")
