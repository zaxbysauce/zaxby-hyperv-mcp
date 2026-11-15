"""Falsification pins for the swarm-pr-review findings on PR #146.

Every node here kills a mutant that survived the shipped suite at
``e82d79e4f58f2aaed76c948e9db9e6a7fb060ee0``. Each docstring names the finding
it closes and the mutant it is designed to kill.
"""
from __future__ import annotations

import subprocess

import pytest

from hyperv_mcp import guestexec, uia

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _script(**kw) -> str:
    args = kw.pop("args", None)
    cwd = kw.pop("cwd", None)
    command = kw.pop("command", "notepad")
    return guestexec._interactive_launch_script(
        "hyperv-mcp-interactive-" + "a" * 32, command, args, cwd, 60)


def _between(text: str, head: str, tail: str) -> str:
    i = text.index(head) + len(head)
    j = text.index(tail, i)
    return text[i:j]


def _observer_payload(text: str) -> str:
    """The here-string the launch script writes into the observer .ps1."""
    return _between(
        text,
        "Set-Content -LiteralPath $ObserverPath -Value @'" + chr(10),
        chr(10) + "'@ -Encoding UTF8")


# --------------------------------------------------------------------------
# FB-002 / RC-01 — the observer payload is the observer BODY
# --------------------------------------------------------------------------

def test_observer_payload_is_the_observer_body():
    """RC-01: the re.subn replacement re-introduced the literal ``__OBSERVER__``
    as the Set-Content payload AFTER the only ``.replace("__OBSERVER__", ...)``
    had already run, so the guest wrote a .ps1 whose entire body was that token
    and every launch answered ``not_started`` after the full timeout while the
    application had actually started. Mutant: revert to the two-pass
    substitution (or re-introduce the token in the replacement string) — the
    payload becomes the 12-character token and this node fails."""
    text = _script()
    payload = _observer_payload(text)
    assert payload == guestexec._INTERACTIVE_OBSERVER.strip(chr(10)), (
        "the observer .ps1 the guest writes must contain the observer body, "
        f"not a placeholder; got {payload[:60]!r}")


def test_observer_payload_runs_under_powershell():
    """RC-01 (execution half): the payload the guest writes is executable
    PowerShell that decodes the base64 input and writes a status file. Mutant:
    substitute the token instead of the body — the child exits with
    CommandNotFound and no status file is written."""
    text = _script()
    payload = _observer_payload(text)
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "[System.Management.Automation.Language.Parser]::ParseInput("
         "[Console]::In.ReadToEnd(), [ref]$null, [ref]$e) | Out-Null; "
         "'ERRORS=' + $e.Count"],
        input=payload, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "ERRORS=0" in proc.stdout, (
        f"the observer payload must be valid PowerShell: {proc.stdout}")


# --------------------------------------------------------------------------
# FB-002 / RC-10 — caller text is never rewritten by a later pass
# --------------------------------------------------------------------------

def test_cwd_containing_a_placeholder_is_inserted_verbatim():
    """RC-10: the caller-supplied cwd was embedded at :882, BEFORE
    ``__EXE__``/``__COMMAND__`` (:887-888) and ``__ARGCLAUSE__`` (:922) were
    substituted, so a cwd containing ``__COMMAND__`` was rewritten after
    ``ps_quote`` had already closed its literal — putting the command text
    OUTSIDE the quoting as a second top-level statement in the guest script.
    Mutant: substitute the cwd before the command, or substitute
    ``__ARGCLAUSE__`` last — the cwd is rewritten and this node fails."""
    text = _script(cwd="C:\\Work\\__COMMAND__", command="notepad.exe")
    assert "C:\\Work\\__COMMAND__" in text, (
        "a cwd containing a placeholder token must be inserted verbatim")
    # the emitted script must still be a single New-ScheduledTaskAction
    # statement plus the intended ones -- no extra top-level command.
    _assert_no_injected_statement(text, "notepad.exe")


def test_command_containing_a_placeholder_is_inserted_verbatim():
    """RC-10 (sibling): a command containing ``__ARGCLAUSE__`` used to be
    rewritten by the last substitution pass. Mutant: substitute
    ``__ARGCLAUSE__`` after the command — the command is rewritten."""
    text = _script(command="C:/w__ARGCLAUSE__.exe", args=["a b"])
    assert "C:/w__ARGCLAUSE__.exe" in text, (
        "a command containing a placeholder token must be inserted verbatim")
    assert "-Argument" in text, "the real argument clause must still land"


def _assert_no_injected_statement(text: str, command: str) -> None:
    """The generated script must not contain a second top-level statement
    carrying the caller's command text.

    Uses the REAL PowerShell 5.1 parser through the same census harness the
    frozen acceptance checks use (``_ps_ast``), so a comment cannot satisfy
    the assertion.
    """
    from test_guest_start_interactive import _ps_ast

    ast = _ps_ast(text)
    cmds = ast["commands"]
    assert cmds, "the AST census returned no commands"
    actions = [c for c in cmds if c.get("n") == "New-ScheduledTaskAction"]
    assert len(actions) == 1, (
        f"exactly one New-ScheduledTaskAction command is expected; got "
        f"{[c.get('n') for c in cmds]}")
    action_text = actions[0]["x"]
    assert "notepad.exe" in action_text, (
        "the task action must carry the real command")
    # No OTHER executable command may carry the caller's command text: that is
    # what an injected second top-level statement looks like.
    others = [c["x"] for c in cmds if c is not actions[0]]
    leaked = [t for t in others if command.rsplit("/", 1)[-1] in t]
    assert not leaked, (
        f"the caller's command text appears in another executable command: "
        f"{leaked}")


# --------------------------------------------------------------------------
# FB-010 / RC-11 — the -File path is pre-quoted
# --------------------------------------------------------------------------

def test_observer_file_path_is_pre_quoted():
    """RC-11: ``Start-Process -ArgumentList`` joins its elements with spaces
    WITHOUT quoting, so a guest TEMP path containing a space split into two
    tokens and the observer never started (live: exit -196608, no status file).
    Mutant: pass ``$ObserverPath`` bare — this node fails."""
    text = _script()
    assert "'-File', ('\"' + $ObserverPath + '\"'), $observerArgs)" in text, (
        "the observer .ps1 path must be pre-quoted inside -ArgumentList, "
        "because -ArgumentList joins its elements with spaces without quoting")


# --------------------------------------------------------------------------
# FB-010 / RC-12 — the WQL filter carries only the numeric session id
# --------------------------------------------------------------------------

def test_observer_wql_filter_is_numeric_only():
    """RC-12: the observer built ``"Name='" + $Exe + "'"`` by concatenation;
    ``ps_quote`` doubles quotes for a PowerShell literal, not for WQL, so a
    quote in the exe name is invalid WQL (swallowed -> false ``not_started``)
    and a crafted name steers the filter at another process. Mutant: put the
    name back into the WQL filter — this node fails."""
    obs = guestexec._INTERACTIVE_OBSERVER
    assert 'Filter ("SessionId=" + $SessionId)' in obs, (
        "the observer's WQL filter must carry only the NUMERIC session id")
    assert "Name='\" +" not in obs, (
        "no caller-derived text may be concatenated into the WQL filter")
    # the name match runs client-side instead
    assert "$_.Name -eq $Exe" in obs, (
        "the executable name must be matched client-side, not in WQL")
    assert "$_.CommandLine -like" in obs, (
        "a .bat/.cmd or pre-quoted path must still be matched, through the "
        "command line")


def test_observer_selects_the_earliest_match_not_the_latest():
    """RC-12 (sibling): ``Sort-Object CreationDate -Descending`` picked the
    NEWEST same-named process, which for an Electron app is a renderer or GPU
    child rather than the process the task started. Mutant: restore
    ``-Descending`` — this node fails."""
    obs = guestexec._INTERACTIVE_OBSERVER
    assert "Sort-Object CreationDate" in obs
    assert "Sort-Object CreationDate -Descending" not in obs, (
        "the observer must take the EARLIEST process created at or after the "
        "launch began, which is the process the task itself started")


def test_exe_name_strips_surrounding_quotes():
    """RC-12 (sibling): a caller passing a pre-quoted path synthesized
    ``Name='myapp.exe"'``, which no Win32_Process row can match. Mutant: take
    the basename without stripping quotes — this node fails."""
    quoted = '"C:\\Program Files\\App\\myapp.exe"'
    bare = "C:\\Program Files\\App\\myapp.exe"
    assert _exe_of(quoted) == _exe_of(bare) == "myapp.exe"


def _exe_of(command: str) -> str:
    exe = command.strip().strip('"').replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in exe:
        exe += ".exe"
    return exe


# --------------------------------------------------------------------------
# FB-007 / RC-06 + RC-07 — the quser discovery
# --------------------------------------------------------------------------

def _quser_fragment() -> str:
    """The discovery block the PRODUCTION launch template actually runs,
    sliced out of guestexec.LAUNCH_TEMPLATE at test time.

    It used to be a hand-copied fragment, which meant a mutant applied to the
    template could never reach it -- three pins that claimed to bite RC-06 and
    RC-07 did not. Slicing the real block makes them bite.
    """
    from hyperv_mcp import guestexec

    text = guestexec.LAUNCH_TEMPLATE
    start = text.index("$Active = @()")
    end = text.index("$InteractiveSession = $Active[0].Session") + len(
        "$InteractiveSession = $Active[0].Session")
    # The slice runs THROUGH both production refusals and their returns, so a
    # mutant that guts either emit is visible. Only the success case needs a
    # visible answer, and appending it must not duplicate a refusal (that would
    # mask a mutant which removes the refusal itself).
    return text[start:end] + chr(10) + (
        "'user=' + $InteractiveUser + ' session=' + $InteractiveSession")


def _run_quser(rows: str, stderr: bool = False) -> str:
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        shim = os.path.join(tmp, "quser.cmd")
        if stderr:
            body = "@echo off\r\necho No User exists for * 1>&2\r\nexit /b 1\r\n"
        else:
            # '^>' escapes the caret in cmd, otherwise echo reads the row's
            # leading '>' as an output redirection and emits nothing.
            lines = ["@echo off",
                     "echo USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME"]
            for row in rows.splitlines():
                if row.strip():
                    lines.append("echo " + row.replace(">", "^>"))
            lines.append("exit /b 0")
            body = "\r\n".join(lines) + "\r\n"
        with open(shim, "w", newline="") as fh:
            fh.write(body)
        env = dict(os.environ)
        env["PATH"] = tmp + os.pathsep + env.get("PATH", "")
        # cwd=tmp: the shim's echo lines are the only thing that can write, and
        # a stray redirection must land in the temp dir, never in the repo.
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             _quser_fragment()],
            capture_output=True, text=True, timeout=120, env=env, cwd=tmp)
        return (proc.stdout + proc.stderr).strip()


def test_quser_marker_is_stripped_from_the_username():
    """RC-06: the regex ``^\\s*(\\S+)\\s+\\S+\\s+(\\d+)\\s+Active`` captured the
    ``>`` current-session marker into the username, so
    ``New-ScheduledTaskPrincipal -UserId '>brett'`` built and
    ``Register-ScheduledTask`` then failed with 0x80070534. The sibling
    ``uia._parse_quser`` strips it for exactly this reason. Mutant: drop the
    ``StartsWith('>')`` strip — the captured user gains the marker."""
    out = _run_quser(">brett                 console  1  Active  none  30  "
                     "11/14/2026 10:00 AM")
    assert out == "user=brett session=1", out


def test_quser_multiple_active_sessions_are_refused():
    """RC-06 (the other half): the loop took the FIRST Active row of ANY user,
    so on a multi-user guest the command ran at the highest run level on a
    desktop the caller did not name. Mutant: ``break`` on the first match —
    this node fails."""
    out = _run_quser("alice                  console  1  Active  none  30  "
                     "11/14/2026 10:00 AM" + "\r\n" +
                     "svc                    rdp-tcp#2 2  Active  none  30  "
                     "11/14/2026 10:00 AM")
    assert "ambiguous_session" in out, (
        f"more than one Active session must be refused, not guessed; got {out!r}")
    assert "alice" in out and "svc" in out, out


def test_quser_stderr_reaches_the_no_interactive_session_refusal():
    """RC-07: with ``$ErrorActionPreference = 'Stop'`` a native ``quser`` that
    writes to stderr raises a terminating NativeCommandError, so the script
    aborted BEFORE the ``no_interactive_session`` emit and the host reported
    ``not_started`` with the guest's real cause discarded. Mutant: remove the
    try/catch — the fragment terminates and this node fails."""
    out = _run_quser("", stderr=True)
    assert "no_interactive_session" in out, (
        f"a stderr-writing quser must reach the refusal, got: {out!r}")


def test_no_interactive_session_precedes_the_executable_register():
    """RC-06 (ordering): the refusal must still be emitted before the first
    executable ``Register-ScheduledTask`` statement. Mutant: move the
    registration above the discovery — this node fails."""
    text = _script()
    assert text.index("no_interactive_session") < text.index(
        "Register-ScheduledTask"), (
        "the no_interactive_session refusal must precede registration")


# --------------------------------------------------------------------------
# FB-009 / RC-38 + RC-15 — the task lifecycle
# --------------------------------------------------------------------------

def test_launch_registers_no_future_dated_trigger():
    """RC-38: the task was registered with ``New-ScheduledTaskTrigger -Once -At
    (Get-Date).AddMinutes(10)``, so a host death between registration and the
    cleanup leg stranded an armed task that re-fired the caller's command ten
    minutes later at the interactive user's highest run level (verified live on
    10.0.26300). A triggerless task still runs from an explicit on-demand start
    (verified live). Mutant: restore the ``-Once`` trigger — this node fails."""
    text = _script()
    assert "New-ScheduledTaskTrigger" not in text, (
        "the one-shot task must carry NO trigger: a future-dated -Once "
        "trigger re-fires the command if the host dies before cleanup")


def test_launch_has_a_guest_side_finally_unregister():
    """RC-14: the host's cleanup is a SEPARATE leg, so on a launch-leg timeout
    it can run before the guest script reaches ``Register-ScheduledTask`` and
    leave the task stranded. A guest-side ``finally`` closes that race. Mutant:
    remove the finally — this node fails."""
    text = _script()
    i = text.index("Register-ScheduledTask")
    j = text.rindex("Unregister-ScheduledTask")
    assert i < j, "the guest-side unregister must follow the registration"
    assert "finally {" in text[i:], (
        "the launch script must unregister from a guest-side finally")


def test_unregister_template_verifies_the_removal():
    """RC-15: ``UNREGISTER_TEMPLATE`` ran ``Unregister-ScheduledTask
    -ErrorAction SilentlyContinue`` and then unconditionally emitted
    ``ok=true; unregistered=true``, so a task that survived was reported as a
    successful cleanup and the documented ``unregistered:false`` +
    ``cleanup_error`` contract was unreachable. Mutant: drop the
    ``Get-ScheduledTask`` verification — this node fails."""
    text = guestexec._interactive_unregister_script("hyperv-mcp-interactive-x")
    assert "Get-ScheduledTask" in text, (
        "the cleanup leg must verify the task is really gone")
    assert "unregistered = $false" in text, (
        "the cleanup leg must be able to report a task that survived")


def test_cleanup_leg_has_its_own_budget():
    """RC-13: the cleanup leg re-used the caller's full ``timeout_ms``, so one
    call could occupy twice the documented per-call timeout. Mutant: pass
    ``timeout_ms`` again — this node fails."""
    src = _source()
    assert "_CLEANUP_TIMEOUT_MS" in src, (
        "the cleanup leg must use a fixed budget of its own")
    assert "cfg, ref.id, unregister_inner, cred, timeout_ms, False" not in src, (
        "the cleanup leg must not re-use the caller's timeout_ms")


def test_cleanup_error_is_redacted():
    """RC-37: ``cleanup_error`` was the only new error string that did not pass
    through ``pswindows.redact``, and it rides the SUCCESS envelope. Mutant:
    drop the redact call — this node fails."""
    src = _source()
    i = src.index("out[\"cleanup_error\"]")
    assert "pswindows.redact" in src[i:i + 400], (
        "cleanup_error must pass through pswindows.redact")


# --------------------------------------------------------------------------
# FB-016 / RC-26 — the pid shape check
# --------------------------------------------------------------------------

def test_pid_less_ok_protocol_returns_an_envelope():
    """RC-26: ``int(str(protocol.get("pid")))`` raised ValueError out of
    ``start_interactive`` for an ok protocol carrying no pid, losing the
    ``unregistered``/``cleanup_error`` fields the finally had already
    assembled. Mutant: restore the bare coercion — this node fails."""
    src = _source()
    assert "answered no usable pid" in src, (
        "a pid-less ok protocol must be converted to a not_started envelope, "
        "never raised out of start_interactive")


# --------------------------------------------------------------------------
# FB-028 / RC-25 — merge_glyph_runs degrades on a malformed rect
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rect", ["1,2,3", "1,2", "5"])
def test_merge_glyph_runs_degrades_on_a_short_rect(rect):
    """RC-25: ``_spanning_rect`` caught only (TypeError, ValueError) and then
    indexed ``r[2]``/``r[3]`` unguarded, so a numeric-but-short rect raised
    IndexError out of ``merge_glyph_runs`` and therefore out of the verb layer.
    Mutant: remove the length guard — this node fails."""
    nodes = [
        {"name": "a", "control_type": "Text", "rect": rect,
         "element_id": "1:1"},
        {"name": "b", "control_type": "Text", "rect": "0,10,5,5",
         "element_id": "1:2"},
    ]
    out = uia.merge_glyph_runs(nodes)  # must not raise
    assert isinstance(out, list)


def test_merge_glyph_runs_still_merges_a_valid_run():
    """Control for RC-25: the guard must not disable the merge."""
    nodes = [
        {"name": "W", "control_type": "Text", "rect": "0,10,5,5",
         "element_id": "1:1"},
        {"name": "o", "control_type": "Text", "rect": "5,10,5,5",
         "element_id": "1:2"},
    ]
    out = uia.merge_glyph_runs(nodes)
    assert [n["name"] for n in out] == ["Wo"], out


# --------------------------------------------------------------------------
# FB-001 / RC-02 — the tool is callable through the real MCP surface
# --------------------------------------------------------------------------

def test_new_tool_does_not_forward_lease_kwargs():
    """RC-02: both registrations forwarded ``lease_id``/``fencing_token`` into
    ``guestexec.start_interactive``, which accepts neither, so every call
    raised TypeError before any leg ran. The lease gate reads the raw
    arguments itself, and no sibling guest tool forwards them. Mutant: add the
    kwargs back — this node fails."""
    import inspect

    params = inspect.signature(guestexec.start_interactive).parameters
    assert "lease_id" not in params and "fencing_token" not in params
    src = _server_source()
    i = src.index('"hyperv_guest_start_interactive", vm_name, "exec"')
    j = src.index(")", src.index("cred_factory", i))
    body = src[i:j]
    assert "lease_id=lease_id" not in body and (
        "fencing_token=fencing_token" not in body), (
        "the new tool must not forward the lease kwargs into start_interactive")


def _source() -> str:
    import pathlib

    return pathlib.Path(guestexec.__file__).read_text(encoding="utf-8")


def _server_source() -> str:
    import pathlib

    from hyperv_mcp import server
    return pathlib.Path(server.__file__).read_text(encoding="utf-8")
