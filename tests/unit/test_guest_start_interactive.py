"""Issue #128 acceptance checks (trace 128-129-134-gui-drivability):
hyperv_guest_start_interactive -- launching a process into the guest's
INTERACTIVE session through a one-shot scheduled task, so a GUI application
lands on the logged-on user's desktop (where console input and the UIA
helper can reach it) instead of in the PowerShell Direct remoting session.

AC map (issue #128 body):
  AC1  test_launch_returns_pid_and_session   NEW-SURFACE
  AC2  test_no_logged_on_user_is_refused     NEW-SURFACE
  AC3  test_task_is_always_unregistered      NEW-SURFACE
  AC4  test_refused_without_policy           NEW-SURFACE
  (AC5 is the live-host leg: a GUI window in a console screenshot.)

Every check is RED at base ea5fac5 (this spec file is absent; with the file
present each test fails on the missing ``guestexec.start_interactive``
surface) and GREEN after the fix. No real PowerShell and no live VM: the
host transport is the tests/unit/test_guestexec.py idiom -- ``FakePS`` on
``pswindows.run_ps`` records every host script and serves canned legs.

Frozen surface contract this file pins (the issue names the tool and the
error classes; the remaining shapes are underdetermined by the issue text,
so this file IS the spec the fix implements against):

  module hyperv_mcp.guestexec gains:

    start_interactive(cfg, vm_name="", command="", args=None, cwd=None, *,
                      timeout_ms=60000, confirm=False, cred=None, vm_id="")
        -> dict

    Order of operations:

    1. POLICY FIRST. The launch registers a scheduled task that runs the
       command with the interactive user's highest run level, so it sits
       behind the SAME destructive category and confirmation semantics as
       the other process-starting tools' elevated path:
       ``policy.require_destructive(cfg, "elevated_exec", confirm, ...)``.
       A refusal raises ``PolicyDenied`` BEFORE the VM is resolved -- zero
       host PowerShell legs of any kind (issue #128 AC4: "refuse before
       contacting the guest"). No new policy category is introduced.
    2. The target is resolved once (``vmident.resolve`` -- one host leg).
    3. ONE launch leg through the module's shared runner (``_run_inner``,
       so the guest-visible script rides the host script base64-encoded as
       ``$enc`` exactly like guest_run/guest_run_ps). The guest script:
         - discovers the interactively logged-on user with ``quser``;
         - with NO interactive session it emits the refusal and registers
           NOTHING: the ``no_interactive_session`` emit precedes the first
           ``Register-ScheduledTask`` statement in the script text;
         - otherwise builds ``New-ScheduledTaskAction`` for the command and
           its arguments (arguments QUOTED on the action statement; the
           working directory set on the action when a cwd was supplied),
           a ``New-ScheduledTaskPrincipal -UserId <user> -LogonType
           Interactive`` principal statement (the uia.py helper-task
           precedent, generalized), ``Register-ScheduledTask``,
           ``Start-ScheduledTask``, and reads back the started process id
           and the session id it runs in;
         - names the one-shot task ``hyperv-mcp-interactive-<uuid>`` -- a
           FRESH uuid per call, so every leg below can pin the EXACT name
           the unregister leg must target (TASK_NAME_RE below).
       The launch protocol is the guest script's own stdout, one JSON
       object:
         {"ok": true,  "pid": <int>, "session_id": <int>}
         {"ok": false, "error_class": "no_interactive_session", "error": ...}
         {"ok": false, "error_class": "not_started", "error": ...}
    4. CLEANUP ON EVERY PATH. Whenever the launch leg was driven and did
       not answer ``no_interactive_session`` (the one outcome that proves
       nothing was registered), the host drives a SECOND guest leg whose
       script runs ``Unregister-ScheduledTask`` against the SAME
       ``hyperv-mcp-interactive-<uuid>`` name the launch registered -- from
       a host-side ``finally``, so it also fires when the launch leg itself
       raised (including an exception that escapes ``_run_inner`` outright,
       not just transport errors ``_run_inner`` converts to dicts at
       guestexec.py:668-675) or reported ``not_started``/a failure. A
       guest-side ``finally`` alone is not enough: a launch leg that dies
       in transport would strand the task.

    Result envelopes:
      success  {"ok": True, "pid": <int>, "session_id": <int>,
                "vm_name": <resolved name>, ...}
      refusal  {"ok": False, "error_class": "no_interactive_session",
                "error": <text>}
      failure  {"ok": False, "error_class": <class>, "error": <text>}
               -- also the envelope for a launch leg whose exception
               ESCAPED ``_run_inner``: converted host-side, never raised
               out of start_interactive, and never carrying a pid.
      launch ok + cleanup failed
               {"ok": True, "pid": <int>, "unregistered": False,
                "cleanup_error": <text>} -- the pid the caller already
               owns is never hidden, the stranded task is named, and
               nothing raises out of start_interactive.

Leg accounting the tests rely on (``FakePS.scripts``, in order):
  success / failure / not_started:  [resolve, launch, unregister] -> 3
  launch escaped _run_inner:        [resolve, unregister]         -> 2
      (the launch raised before reaching pswindows.run_ps)
  launch torn down by a non-Exception
  BaseException (the finally
  discriminator, S2 leg 3b):        [resolve, unregister]         -> 2
  no session:                       [resolve, launch]             -> 2
  policy refusal:                   []                            -> 0

Wave-3 strengthening (survivors S1/S2): every launch/registration/start/
read-back/unregister pin is additionally verified against the REAL
PowerShell parser's CommandAst census of the generated guest script
(the tests/unit/test_script_parse_new.py ParseInput idiom, driven as a
direct subprocess because run_ps is monkeypatched here). A '#'
PowerShell comment cannot produce a CommandAst, so a comment-only
launch script or a comment-only cleanup leg fails; the tokenizer's
comment spans also blank comments out of every textual pin (the
emit-before-register ordering, the task-name tokens). The AST lane
skips LOUDLY only when powershell.exe is genuinely absent.
"""

import base64
import json
import re
import subprocess

import pytest

from hyperv_mcp import guestexec, pswindows
from hyperv_mcp.config import Config
from hyperv_mcp.credentials import CredentialSet
from hyperv_mcp.policy import PolicyDenied

CRED = CredentialSet("Administrator", "placeholder-pass")

VM_GUID = "e953c649-1234-5678-9abc-def012345678"

#: The launch protocol objects the guest script reports on its own stdout.
LAUNCH_OK = {"ok": True, "pid": 4242, "session_id": 2}
NO_SESSION = {
    "ok": False,
    "error_class": "no_interactive_session",
    "error": "no user is logged on interactively",
}
NOT_STARTED = {
    "ok": False,
    "error_class": "not_started",
    "error": "the task ran but no process id came back",
}
UNREGISTER_OK = {"ok": True, "unregistered": True}
UNREGISTER_FAILED = {"ok": False, "error_class": "guest",
                     "error": "Unregister-ScheduledTask refused"}

#: The one-shot task's unique name (strengthened AC3/AC1 pin): every launch
#: registers a task named ``hyperv-mcp-interactive-<uuid>`` -- a FRESH uuid
#: per call (both the dashed str(uuid4) and the 32-hex uuid4().hex
#: spellings accepted) -- and the cleanup leg must target that EXACT name,
#: not merely mention Unregister-ScheduledTask somewhere.
TASK_NAME_RE = re.compile(
    r"hyperv-mcp-interactive-(?:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{32})")


# ---------------------------------------------------------------------------
# shared harness (the tests/unit/test_guestexec.py idiom; no real PowerShell)
# ---------------------------------------------------------------------------

def _guid_result():
    """Canned by-name resolution leg response (stdout = the VM GUID)."""
    return pswindows.PSResult(stdout=VM_GUID, returncode=0)


def _inner_script(host_script: str) -> str:
    """The guest-visible inner script rides in the host script as b64."""
    marker = "$enc = '"
    start = host_script.index(marker) + len(marker)
    end = host_script.index("'", start)
    return base64.b64decode(host_script[start:end]).decode("utf-8")


def _leg_text(host_script: str) -> str:
    """The guest-visible text of one host leg: the decoded inner script
    when the leg carries one (the shared-runner shape), else the script."""
    if "$enc = '" in host_script:
        return _inner_script(host_script)
    return host_script


def _guest_leg(payload: dict) -> pswindows.PSResult:
    """One guest leg as the shared runner sees it: the capture wrapper
    {exit_code, stdout, stderr} whose stdout is the guest script's own
    output -- here the launch protocol's JSON object."""
    wrapper = {"exit_code": 0, "stdout": json.dumps(payload), "stderr": ""}
    return pswindows.PSResult(stdout=json.dumps(wrapper), returncode=0)


class FakePS:
    """pswindows.run_ps stand-in: records every host script and serves the
    canned responses in order (an Exception entry is raised)."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.scripts = []
        self.kwargs = []

    def __call__(self, script, **kwargs):
        self.scripts.append(script)
        self.kwargs.append(kwargs)
        item = (
            self.responses.pop(0)
            if self.responses
            else pswindows.PSResult(returncode=0)
        )
        if isinstance(item, Exception):
            raise item
        return item


def _task_names(text: str) -> set:
    """Every distinct hyperv-mcp-interactive-<uuid> token in `text`."""
    return {m.group(0) for m in TASK_NAME_RE.finditer(text)}


def _single_task_name(text: str, what: str) -> str:
    """The ONE unique task name `what` must target: exactly one distinct
    hyperv-mcp-interactive-<uuid>-shaped token, or the check fails."""
    names = _task_names(text)
    assert names, (
        f"{what} must name the one-shot task with the frozen unique shape "
        f"hyperv-mcp-interactive-<uuid> (fresh uuid per call); no such "
        f"token found")
    assert len(names) == 1, (
        f"{what} must target exactly ONE hyperv-mcp-interactive-<uuid> task "
        f"name; found {len(names)} distinct tokens: {sorted(names)!r}")
    return names.pop()


# ---------------------------------------------------------------------------
# PowerShell AST lane (wave-3 strengthening, survivors S1/S2): validate
# EXECUTABLE PowerShell, not token-bearing lines. The real parser
# ([System.Management.Automation.Language.Parser]::ParseInput -- the
# tests/unit/test_script_parse_new.py idiom, here run through a direct
# subprocess instead of pswindows.run_ps because every test in this file
# monkeypatches run_ps) yields one CommandAst per executable command; a
# '#' comment can NEVER produce one. The tokenizer's comment spans also
# give a comment-blanked rendering of the script (each comment byte
# replaced by a space, positions preserved), so the textual pins
# (emit-before-register ordering, task-name tokens) run on EXECUTABLE
# code only. Skips loudly when powershell.exe is genuinely absent.
# ---------------------------------------------------------------------------

_PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

#: One-shot parser probe: reads the script text from stdin (base64 -- it
#: never rides argv), reports parse errors, then emits the CommandAst /
#: simple-AssignmentStatementAst censuses and the comment token spans as
#: one JSON object per line.
_PS_AST_DUMPER = "\n".join([
    "$text = [System.Text.Encoding]::UTF8.GetString("
    "[Convert]::FromBase64String([Console]::In.ReadLine()))",
    "$tokens = $null",
    "$errs = $null",
    "$ast = [System.Management.Automation.Language.Parser]::ParseInput("
    "$text, [ref]$tokens, [ref]$errs)",
    "if ($errs.Count -gt 0) {",
    "  foreach ($e in $errs) { Write-Output ('PARSE-ERR ' + "
    "$e.Extent.StartLineNumber + ': ' + $e.Message) }",
    "  exit 1",
    "}",
    "$rows = @()",
    "foreach ($c in $ast.FindAll({ param($n) $n -is "
    "[System.Management.Automation.Language.CommandAst] }, $true)) {",
    "  $params = [ordered]@{}",
    "  for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {",
    "    $el = $c.CommandElements[$i]",
    "    if ($el -is "
    "[System.Management.Automation.Language.CommandParameterAst]) {",
    "      $val = $null",
    "      if (($i + 1) -lt $c.CommandElements.Count -and -not "
    "($c.CommandElements[$i+1] -is "
    "[System.Management.Automation.Language.CommandParameterAst])) {",
    "        $val = [string]$c.CommandElements[$i+1].Extent.Text",
    "        $i++",
    "      }",
    "      $params[[string]$el.ParameterName] = $val",
    "    }",
    "  }",
    "  $rows += [pscustomobject]@{ k = 'cmd'; n = [string]$c.GetCommandName();"
    " p = $params; x = [string]$c.Extent.Text; o = [int]$c.Extent.StartOffset }",
    "}",
    "foreach ($a in $ast.FindAll({ param($n) $n -is "
    "[System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {",
    "  $var = $null",
    "  if ($a.Left -is "
    "[System.Management.Automation.Language.VariableExpressionAst]) "
    "{ $var = $a.Left.VariablePath.UserPath }",
    "  if ($null -ne $var) {",
    "    $rows += [pscustomobject]@{ k = 'assign'; var = [string]$var; "
    "x = [string]$a.Right.Extent.Text }",
    "  }",
    "}",
    "$spans = @()",
    "foreach ($t in $tokens) {",
    "  if ($t.Kind -eq 'Comment') { $spans += ,@([int]$t.Extent.StartOffset, "
    "[int]$t.Extent.EndOffset) }",
    "}",
    "Write-Output ([pscustomobject]@{ k = 'meta'; comments = $spans; "
    "len = $text.Length } | ConvertTo-Json -Compress -Depth 6)",
    "foreach ($r in $rows) { Write-Output ($r | ConvertTo-Json -Compress "
    "-Depth 6) }",
])

_AST_CACHE: dict[str, dict] = {}


def _ps_available() -> bool:
    import os

    return os.path.isfile(_PS_EXE)


def _ps_ast(text: str) -> dict:
    """Parse one guest script with the REAL PowerShell parser; returns
    {commands, assignments, stripped} -- `stripped` being the script with
    every comment byte blanked to a space (positions preserved), so
    textual pins see EXECUTABLE code only. A parse failure is an
    assertion: the generated guest script must be valid PowerShell."""
    cached = _AST_CACHE.get(text)
    if cached is not None:
        return cached
    if not _ps_available():
        pytest.skip(
            "Windows PowerShell 5.1 is genuinely absent -- the AST command "
            "census (S1/S2) cannot run")
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    proc = subprocess.run(
        [_PS_EXE, "-NoProfile", "-NonInteractive", "-Command",
         _PS_AST_DUMPER],
        input=b64, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"the generated guest script must be VALID PowerShell; parser "
        f"output: {proc.stdout!r} stderr: {proc.stderr[-2000:]!r}")
    rows = [json.loads(line) for line in proc.stdout.splitlines()
            if line.startswith("{")]
    assert rows and rows[0].get("k") == "meta", (
        f"the AST census harness answered nothing parseable: "
        f"{proc.stdout!r}")
    meta = rows[0]
    stripped = text
    spans = [tuple(span) for span in (meta.get("comments") or [])]
    if spans:
        # Offsets are UTF-16 code-unit positions; for any script containing
        # astral characters they would not map 1:1 onto Python characters --
        # refuse loudly rather than blank the wrong bytes.
        assert meta.get("len") == len(text), (
            "the AST census's comment spans do not map onto the script's "
            "characters (astral content?); refusing to strip comments "
            "unsoundly")
        chars = list(text)
        for start, end in spans:
            for i in range(start, min(end, len(chars))):
                chars[i] = " "
        stripped = "".join(chars)
    out = {
        "commands": [r for r in rows if r.get("k") == "cmd"],
        "assignments": [r for r in rows if r.get("k") == "assign"],
        "stripped": stripped,
    }
    _AST_CACHE[text] = out
    return out


def _cmd_matches(cmd: dict, name: str) -> bool:
    """CommandAst `cmd` invokes the command `name` (bare or .exe)."""
    got = str(cmd.get("n") or "").lower()
    return got == name.lower() or got == name.lower() + ".exe"


def _literals_for(value, assignments: list) -> list[str]:
    """The literal texts a parameter value can resolve to: the value's own
    extent, plus the assigned values when it is a plain $variable (one
    level of indirection -- `$TaskName $t` with `$t = '<name>'`)."""
    out: list[str] = []
    if value:
        out.append(value)
    m = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)", value or "")
    if m:
        for a in assignments:
            if a.get("var") == m.group(1) and a.get("x"):
                out.append(a["x"])
    return out


def _carries(literals: list, token: str) -> bool:
    return any(token in lit for lit in literals)


def _assert_launch_ast(launch: str, *, command: str, args, cwd,
                       what: str) -> None:
    """The launch script's EXECUTABLE command census (S1): every
    launch/registration/start/read-back pin below is satisfied by a
    CommandAst the real parser found -- a script whose tokens all sit in
    '#' comments produces no CommandAst and fails at the first pin."""
    ast = _ps_ast(launch)
    commands, assignments, stripped = (
        ast["commands"], ast["assignments"], ast["stripped"])

    # the interactive user is discovered by an EXECUTABLE quser command
    assert any(_cmd_matches(c, "quser") for c in commands), (
        f"{what} must discover the interactive user with an executable "
        f"quser COMMAND (a '#' comment cannot discover anyone); commands "
        f"found: {[c.get('n') for c in commands]!r}")

    # 1. the task ACTION command carries the command, the QUOTED arguments
    #    and the working directory as ITS parameters
    actions = [c for c in commands if _cmd_matches(c, "New-ScheduledTaskAction")]
    assert actions, (
        f"{what} must build the task action with an EXECUTABLE "
        f"New-ScheduledTaskAction command (AST-verified); commands found: "
        f"{[c.get('n') for c in commands]!r}")
    action_params = actions[0].get("p") or {}
    assert _carries(
        _literals_for(action_params.get("Execute"), assignments),
        command), (
        f"the New-ScheduledTaskAction command's -Execute parameter must "
        f"carry the command {command!r}; command text: {actions[0].get('x')!r}")
    if args:
        arg_literals = _literals_for(action_params.get("Argument"),
                                     assignments)
        for arg in args:
            assert (f"'{arg}'" in " ".join(arg_literals)
                    or f'"{arg}"' in " ".join(arg_literals)), (
                f"the New-ScheduledTaskAction command's -Argument parameter "
                f"must carry {arg!r} in QUOTED form (an argument list, not "
                f"bare prose); command text: {actions[0].get('x')!r}")
    if cwd:
        assert "WorkingDirectory" in action_params and _carries(
            _literals_for(action_params.get("WorkingDirectory"),
                          assignments), cwd), (
            f"a supplied cwd must be set on the task action via the "
            f"New-ScheduledTaskAction command's -WorkingDirectory parameter "
            f"carrying {cwd!r}; command text: {actions[0].get('x')!r}")

    # 2. ONE executable principal command carrying -LogonType Interactive
    #    AND -UserId
    principals = [c for c in commands
                  if _cmd_matches(c, "New-ScheduledTaskPrincipal")]
    assert principals, (
        f"{what} must build the task principal with an EXECUTABLE "
        f"New-ScheduledTaskPrincipal command; commands found: "
        f"{[c.get('n') for c in commands]!r}")
    principal_params = principals[0].get("p") or {}
    assert "UserId" in principal_params, (
        f"the New-ScheduledTaskPrincipal command must name the discovered "
        f"user via -UserId; command text: {principals[0].get('x')!r}")
    assert any(
        lit.strip("'\" ") == "Interactive"
        for lit in _literals_for(principal_params.get("LogonType"),
                                 assignments)), (
        f"the New-ScheduledTaskPrincipal command must carry "
        f"-LogonType Interactive (exactly Interactive -- not S4U, not "
        f"Service); command text: {principals[0].get('x')!r}")

    # 3. Register-ScheduledTask and Start-ScheduledTask as EXECUTABLE
    #    commands, in that order, carrying the SAME unique task name
    registers = [c for c in commands
                 if _cmd_matches(c, "Register-ScheduledTask")]
    starters = [c for c in commands if _cmd_matches(c, "Start-ScheduledTask")]
    assert registers and starters, (
        f"{what} must BOTH register and run the task with EXECUTABLE "
        f"Register-ScheduledTask and Start-ScheduledTask commands; "
        f"commands found: {[c.get('n') for c in commands]!r}")
    task_name = _single_task_name(stripped, what + " (executable text)")
    for label, cmd in (("Register-ScheduledTask", registers[0]),
                       ("Start-ScheduledTask", starters[0])):
        literals = _literals_for((cmd.get("p") or {}).get("TaskName"),
                                 assignments)
        literals.append(cmd.get("x") or "")
        assert _carries(literals, task_name), (
            f"the EXECUTABLE {label} command must carry the SAME task name "
            f"{task_name!r} (its -TaskName value or the command's own "
            f"extent); command text: {cmd.get('x')!r}")
    assert (registers[0].get("o", 0)) < (starters[0].get("o", 0)), (
        f"Register-ScheduledTask must precede Start-ScheduledTask in the "
        f"script (register offsets {registers[0].get('o')} / "
        f"{starters[0].get('o')})")

    # 4. Start-Process -PassThru: the pid/session read-back's engine
    starters_ps = [c for c in commands if _cmd_matches(c, "Start-Process")]
    assert starters_ps, (
        f"{what} must read back the started process with an EXECUTABLE "
        f"Start-Process command; commands found: "
        f"{[c.get('n') for c in commands]!r}")
    assert "PassThru" in (starters_ps[0].get("p") or {}), (
        f"the Start-Process command must pass -PassThru, or no process "
        f"object comes back to read the pid from; command text: "
        f"{starters_ps[0].get('x')!r}")

    # the read-back keys live in EXECUTABLE code (not comments)
    assert "pid" in stripped and "session_id" in stripped, (
        f"{what} must report the started pid and session_id from EXECUTABLE "
        f"code; both tokens must survive comment-stripping")


def _assert_unregister_ast(unregister: str, expected_name: str,
                           what: str) -> None:
    """The cleanup leg's EXECUTABLE Unregister-ScheduledTask command naming
    the EXACT task name the launch registered (S2): a cleanup leg whose
    tokens sit only in '#' comments leaves the task registered and fails
    here."""
    ast = _ps_ast(unregister)
    commands = ast["commands"]
    unregisters = [c for c in commands
                   if _cmd_matches(c, "Unregister-ScheduledTask")]
    assert unregisters, (
        f"{what} must contain an EXECUTABLE Unregister-ScheduledTask "
        f"command (AST-verified -- a '#' comment unregisters nothing); "
        f"commands found: {[c.get('n') for c in commands]!r}")
    cmd = unregisters[0]
    literals = _literals_for((cmd.get("p") or {}).get("TaskName"),
                             ast["assignments"])
    literals.append(cmd.get("x") or "")
    assert _carries(literals, expected_name), (
        f"{what}: the EXECUTABLE Unregister-ScheduledTask command must name "
        f"the EXACT task name {expected_name!r} (its -TaskName value or the "
        f"command's own extent); command text: {cmd.get('x')!r}")


def _start_interactive():
    """The #128 surface, resolved inside each test so a missing function
    fails as an assertion naming the surface (never a collection error)."""
    fn = getattr(guestexec, "start_interactive", None)
    assert fn is not None, (
        "guestexec.start_interactive (tool hyperv_guest_start_interactive) "
        "is missing (issue #128)"
    )
    return fn


@pytest.fixture()
def unrestricted():
    return Config(unrestricted=True)


# ---------------------------------------------------------------------------
# AC1: an interactive principal for the logged-on user; pid + session back
# ---------------------------------------------------------------------------

def test_launch_returns_pid_and_session(monkeypatch, unrestricted):
    """AC1: WHEN an interactive launch is requested and a user is logged
    on, the launch registers a task with an INTERACTIVE principal for that
    user, runs it, and returns the started process id and session id. The
    action/principal pins are LINE-BOUND (the statement lines must carry
    the command, the QUOTED arguments, the working directory and the
    -UserId + -LogonType Interactive pair), so a script that merely
    CONTAINS the tokens in comments or prose cannot pass.
    RED at base (guestexec.start_interactive is missing), GREEN after the
    fix."""
    start_interactive = _start_interactive()
    fake = FakePS([
        _guid_result(),
        _guest_leg(LAUNCH_OK),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    out = start_interactive(
        unrestricted, "vm1", "notepad.exe", ["notes.txt"], cwd="C:\\Work",
        cred=CRED, confirm=True,
    )

    assert out.get("ok") is True, out
    assert out.get("pid") == 4242, (
        f"the started process id must be returned top-level: {out!r}")
    assert out.get("session_id") == 2, (
        f"the started process's session id must be returned top-level: "
        f"{out!r}")
    assert isinstance(out["pid"], int) and not isinstance(out["pid"], bool)
    assert isinstance(out["session_id"], int)
    assert out.get("vm_name") == "vm1", (
        "the envelope carries the resolved VM name like every guest tool")

    assert len(fake.scripts) >= 2, (
        "the launch must reach the guest (resolve leg + launch leg)")
    launch = _leg_text(fake.scripts[1])
    # the logged-on user is discovered in the guest, not assumed by the host
    assert "quser" in launch, (
        "the launch script must discover the interactive user with quser")
    # the command and its arguments ride the task ACTION
    assert "New-ScheduledTaskAction" in launch
    assert "notepad.exe" in launch, "the task action must run the command"
    assert "notes.txt" in launch, "the task action must carry the arguments"
    # LINE-BOUND action pins: the New-ScheduledTaskAction statement itself
    # carries the command, the arguments in QUOTED form (an argument list,
    # not bare prose), and the supplied working directory -- tokens in
    # comments or surrounding prose cannot satisfy these.
    action_lines = [ln for ln in launch.splitlines()
                    if "New-ScheduledTaskAction" in ln]
    assert action_lines, (
        "the launch script must build the task action on a "
        "New-ScheduledTaskAction statement line")
    action = "\n".join(action_lines)
    assert "notepad.exe" in action, (
        f"the task ACTION statement must carry the command itself: "
        f"{action!r}")
    assert "'notes.txt'" in action or '"notes.txt"' in action, (
        f"the task ACTION statement must carry the arguments in QUOTED "
        f"form (an argument list), not as bare prose: {action!r}")
    assert "C:\\Work" in action and "-WorkingDirectory" in action, (
        f"a supplied cwd must be set on the task action via "
        f"-WorkingDirectory: {action!r}")
    # the INTERACTIVE principal for that user -- the whole point of #128: a
    # task without it starts the process in a non-interactive session.
    # LINE-BOUND: -LogonType Interactive must sit on a statement line that
    # also carries -UserId (the principal naming the discovered user).
    assert "New-ScheduledTaskPrincipal" in launch
    assert "-LogonType Interactive" in launch, (
        "the task principal must use the Interactive logon type, or the "
        "process never appears on the user's desktop")
    assert "-UserId" in launch, (
        "the principal must name the discovered interactive user")
    logon_lines = [ln for ln in launch.splitlines()
                   if "-LogonType Interactive" in ln]
    assert logon_lines, (
        "-LogonType Interactive must appear on a statement line, not only "
        "in comments or prose")
    assert any("-UserId" in ln for ln in logon_lines), (
        f"-LogonType Interactive must appear on the principal line "
        f"TOGETHER WITH -UserId (one principal statement for the "
        f"discovered user); lines carrying -LogonType: {logon_lines!r}")
    # the launch registers the task under the frozen unique name
    _single_task_name(launch, "the launch script")
    # registered, then run
    assert "Register-ScheduledTask" in launch
    assert "Start-ScheduledTask" in launch
    assert launch.index("Register-ScheduledTask") < launch.index(
        "Start-ScheduledTask"), "the task is registered before it is run"
    # the read-back the envelope is built from
    assert "pid" in launch and "session_id" in launch, (
        "the launch script must report the started process id and the "
        "session it runs in")

    # S1 AST lane: the EXECUTABLE command census of the launch script --
    # quser, the action's -Execute/-Argument/-WorkingDirectory parameters,
    # the principal's -LogonType Interactive + -UserId pair, Register-
    # ScheduledTask before Start-ScheduledTask carrying the SAME unique
    # task name, and Start-Process -PassThru. A script whose tokens all
    # sit in '#' comments produces no CommandAst and fails here.
    _assert_launch_ast(launch, command="notepad.exe", args=["notes.txt"],
                       cwd="C:\\Work", what="the launch script")
    # and the cleanup leg this flow drove carries an EXECUTABLE
    # Unregister-ScheduledTask naming that EXACT task name
    _assert_unregister_ast(
        _leg_text(fake.scripts[2]),
        _single_task_name(_ps_ast(launch)["stripped"], "the launch script"),
        "the unregister script after the AC1 launch")


# ---------------------------------------------------------------------------
# AC2: nobody logged on -> no_interactive_session, and nothing registered
# ---------------------------------------------------------------------------

def test_no_logged_on_user_is_refused(monkeypatch, unrestricted):
    """AC2: IF no user is logged on interactively, the launch returns
    no_interactive_session and registers no task.
    RED at base (guestexec.start_interactive is missing), GREEN after the
    fix."""
    start_interactive = _start_interactive()
    fake = FakePS([_guid_result(), _guest_leg(NO_SESSION)])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    out = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)

    assert out.get("ok") is False, (
        f"a launch with nobody logged on must not report success: {out!r}")
    assert out.get("error_class") == "no_interactive_session", (
        f"the refusal must be the structured no_interactive_session class, "
        f"got {out.get('error_class')!r}")
    assert out.get("error"), "the refusal carries a human-readable error"
    assert "pid" not in out and "session_id" not in out, (
        "a refused launch started nothing, so it reports no process")

    # Nothing was registered, so there is nothing to clean up: the refusal
    # completes in the launch leg (resolve + launch, no further leg).
    assert len(fake.scripts) == 2, (
        f"a no-session refusal must drive exactly the resolve leg and the "
        f"launch leg, got {len(fake.scripts)} host scripts")

    # ...and the guest script proves it statically: the refusal is emitted
    # BEFORE the first registration statement, so the no-session path can
    # never reach Register-ScheduledTask. (S1 strengthening: the ordering
    # runs on the comment-STRIPPED script and the registration side is an
    # EXECUTABLE Register-ScheduledTask CommandAst, so a comment-only
    # script cannot satisfy the pair.)
    launch = _leg_text(fake.scripts[1])
    assert "no_interactive_session" in launch, (
        "the guest script itself must emit the no_interactive_session "
        "refusal (the host cannot assume who is logged on)")
    assert "Register-ScheduledTask" in launch
    assert launch.index("no_interactive_session") < launch.index(
        "Register-ScheduledTask"), (
        "the no-session refusal must precede task registration in the "
        "guest script -- registering first and checking afterwards would "
        "leave a task behind for a session that does not exist")
    launch_ast = _ps_ast(launch)
    registers = [c for c in launch_ast["commands"]
                 if _cmd_matches(c, "Register-ScheduledTask")]
    assert registers, (
        "the no-session launch script must still contain an EXECUTABLE "
        "Register-ScheduledTask command (AST-verified) for the "
        "emit-before-register ordering to mean anything; commands found: "
        f"{[c.get('n') for c in launch_ast['commands']]!r}")
    stripped = launch_ast["stripped"]
    assert "no_interactive_session" in stripped, (
        "the no_interactive_session refusal must live in EXECUTABLE code "
        "(a '#' comment refuses nothing)")
    assert stripped.index("no_interactive_session") < registers[0].get(
        "o", 0), (
        "the no_interactive_session emission must precede the EXECUTABLE "
        "Register-ScheduledTask command in the guest script -- registering "
        "first and checking afterwards would leave a task behind for a "
        "session that does not exist")


# ---------------------------------------------------------------------------
# AC3: the one-shot task is unregistered on success AND on failure
# ---------------------------------------------------------------------------

def test_task_is_always_unregistered(monkeypatch, unrestricted):
    """AC3: WHEN an interactive launch completes or fails, the one-shot
    task is unregistered. FIVE legs are driven, and every cleanup
    assertion targets the EXACT hyperv-mcp-interactive-<uuid> name the
    launch registered (never a bare Unregister-ScheduledTask substring):

      1. completes          -- resolve + launch + unregister
      2. transport failure  -- the launch leg raises inside
                               pswindows.run_ps (converted to a dict by
                               _run_inner's except at guestexec.py:668-675)
      3. escapes            -- _run_inner ITSELF raises, so the exception
                               escapes the shared runner outright; the
                               host-side cleanup must STILL fire
      4. not_started        -- the launch leg answers ok:false
                               not_started; no pid, cleanup still runs
      5. cleanup failure    -- the unregister leg fails (a refusal frame,
                               and a transport raise): the pid already
                               returned is not hidden, the failure is
                               surfaced, nothing raises

    S2 strengthening -- the finally-proof: the cleanup leg is driven on
    ALL THREE launch outcomes (legs 1/2/3: success, launch-leg raise,
    _run_inner escape) AND leg 4, and each cleanup leg now carries an
    AST-verified EXECUTABLE Unregister-ScheduledTask command naming the
    EXACT task name -- a catch-all post-call cleanup whose leg holds the
    tokens only in '#' comments fails every one of those pins. Leg 3b is
    the finally DISCRIMINATOR: a launch torn down by a non-Exception
    BaseException still gets its cleanup leg (a catch-all `except
    Exception` with post-call cleanup strands the task there), whether or
    not the signal itself propagates out of start_interactive.

    RED at base (guestexec.start_interactive is missing), GREEN after the
    fix."""
    start_interactive = _start_interactive()
    observed_names: list[str] = []

    # -- 1. completes: launch ok, then the cleanup leg
    fake = FakePS([
        _guid_result(),
        _guest_leg(LAUNCH_OK),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)
    out = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    assert out.get("ok") is True, out
    assert len(fake.scripts) == 3, (
        f"a completed launch must be followed by exactly one cleanup leg "
        f"(resolve + launch + unregister), got {len(fake.scripts)}")
    assert "Unregister-ScheduledTask" in _leg_text(fake.scripts[2]), (
        "the leg after a completed launch must unregister the one-shot task")
    ok_launch = _single_task_name(_leg_text(fake.scripts[1]),
                                  "the completed launch script")
    ok_unregister = _single_task_name(_leg_text(fake.scripts[2]),
                                      "the unregister script after a "
                                      "completed launch")
    assert ok_unregister == ok_launch, (
        f"the cleanup leg must target the EXACT task name the launch "
        f"registered ({ok_launch!r}), got {ok_unregister!r}")
    _assert_unregister_ast(
        _leg_text(fake.scripts[2]), ok_launch,
        "the unregister script after a completed launch (S2 AST pin)")
    observed_names.append(ok_launch)

    # -- 2. fails: the launch leg itself raises (inside pswindows.run_ps,
    #    so _run_inner converts it); the task may already be registered in
    #    the guest, so the cleanup leg must STILL run
    failing = FakePS([
        _guid_result(),
        pswindows.PowerShellTransportError("the launch leg died mid-run"),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", failing)
    failed = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    assert failed.get("ok") is False, (
        f"a launch whose guest leg raised must not report success: "
        f"{failed!r}")
    assert "pid" not in failed, "a failed launch reports no process"
    assert len(failing.scripts) == 3, (
        f"the cleanup leg must run even when the launch leg raised "
        f"(resolve + launch + unregister), got {len(failing.scripts)} host "
        f"scripts -- the one-shot task would be left behind")
    assert "Unregister-ScheduledTask" in _leg_text(failing.scripts[2]), (
        "the leg after a FAILED launch must unregister the one-shot task")
    fail_launch = _single_task_name(_leg_text(failing.scripts[1]),
                                    "the failed launch script")
    fail_unregister = _single_task_name(_leg_text(failing.scripts[2]),
                                        "the unregister script after a "
                                        "failed launch")
    assert fail_unregister == fail_launch, (
        f"the cleanup leg must target the EXACT task name the failed "
        f"launch registered ({fail_launch!r}), got {fail_unregister!r}")
    _assert_unregister_ast(
        _leg_text(failing.scripts[2]), fail_launch,
        "the unregister script after a failed launch (S2 AST pin)")
    observed_names.append(fail_launch)

    # -- 3. escapes: _run_inner ITSELF raises, so the exception ESCAPES the
    #    shared runner instead of being converted to a dict by its internal
    #    except at guestexec.py:668-675. The injected PowerShellTransportError
    #    of leg 2 cannot prove finally-unwind (it is caught INSIDE
    #    _run_inner); this leg can. The launch inner script is captured on
    #    its way into _run_inner (the module's shared-runner call shape:
    #    positional (cfg, vm_id, inner_script, ...) -- guestexec.py:628-642)
    #    so the exact-name pin still applies even though the launch host
    #    script never reaches pswindows.run_ps.
    real_run_inner = guestexec._run_inner
    captured: dict = {}

    def _raise_then_real(*a, **k):
        if "inner" not in captured:
            captured["inner"] = a[2] if len(a) > 2 else k.get("inner_script")
            raise RuntimeError(
                "the launch leg died before any guest answer (escaping "
                "leg -- issue #128 AC3)")
        return real_run_inner(*a, **k)

    monkeypatch.setattr(guestexec, "_run_inner", _raise_then_real)
    escaped = FakePS([
        _guid_result(),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", escaped)
    raised = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    monkeypatch.setattr(guestexec, "_run_inner", real_run_inner)
    assert isinstance(raised, dict), (
        "an exception escaping _run_inner must be converted host-side to an "
        "envelope, never raised out of start_interactive")
    assert raised.get("ok") is False, (
        f"a launch whose leg escaped the shared runner must not report "
        f"success: {raised!r}")
    assert isinstance(raised.get("error_class"), str) and (
        raised.get("error_class")), (
        f"the escaping-leg envelope must carry a structured error_class: "
        f"{raised!r}")
    assert "pid" not in raised, "an escaped launch reports no process"
    assert len(escaped.scripts) == 2, (
        f"the cleanup leg must run even when the launch leg ESCAPED "
        f"_run_inner (resolve + unregister; the launch never reached "
        f"pswindows.run_ps), got {len(escaped.scripts)} host scripts -- "
        f"the one-shot task would be left behind")
    escaped_unregister_text = _leg_text(escaped.scripts[1])
    assert "Unregister-ScheduledTask" in escaped_unregister_text, (
        "the leg after an ESCAPED launch must unregister the one-shot task")
    escaped_name = _single_task_name(escaped_unregister_text,
                                     "the unregister script after an "
                                     "escaping launch leg")
    _assert_unregister_ast(
        escaped_unregister_text, escaped_name,
        "the unregister script after an escaping launch leg (S2 AST pin -- "
        "the finally-proof's hardest leg: the launch exception escaped "
        "_run_inner outright, and the cleanup STILL ran with the EXACT "
        "name)")
    if captured.get("inner"):
        assert "Register-ScheduledTask" in captured["inner"], (
            "the captured launch inner script must be the launch script "
            "(it registers the task)")
        assert escaped_name == _single_task_name(
            captured["inner"], "the escaped launch script"), (
            "the cleanup leg after an escaping launch must target the "
            "EXACT task name that launch was about to register")
        observed_names.append(escaped_name)
    else:  # unexpected call shape: still require a fresh unique name
        observed_names.append(escaped_name)

    # -- 3b. the FINALLY discriminator (S2): the launch leg is torn down by
    #    a BaseException that is NOT an Exception, so a catch-all
    #    `except Exception` followed by POST-CALL cleanup never sees it and
    #    strands the task; only a host-side `finally` (or an equally wide
    #    guard) still drives the cleanup leg. Legs 1-3 cannot tell those
    #    two shapes apart -- every Exception-typed raise is converted by
    #    either -- so this is the leg that makes "driven from a finally"
    #    observable. Whether the signal then propagates out of
    #    start_interactive or is converted to an envelope is deliberately
    #    NOT pinned: only that the one-shot task is never left behind.
    class _EscapeSignal(BaseException):
        """Not an Exception: invisible to `except Exception`."""

    captured_signal: dict = {}

    def _signal_then_real(*a, **k):
        if "inner" not in captured_signal:
            captured_signal["inner"] = (
                a[2] if len(a) > 2 else k.get("inner_script"))
            raise _EscapeSignal(
                "the launch leg was torn down mid-flight (finally "
                "discriminator -- issue #128 AC3)")
        return real_run_inner(*a, **k)

    monkeypatch.setattr(guestexec, "_run_inner", _signal_then_real)
    torn = FakePS([
        _guid_result(),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", torn)
    try:
        start_interactive(
            unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    except _EscapeSignal:
        pass  # propagating the signal is fine; stranding the task is not
    finally:
        monkeypatch.setattr(guestexec, "_run_inner", real_run_inner)
    assert captured_signal.get("inner"), (
        "sanity: the torn-down leg must have been the launch leg (its "
        "inner script reached the shared runner)")
    assert len(torn.scripts) == 2, (
        f"the cleanup leg must be driven from a host-side FINALLY: a launch "
        f"leg torn down by a non-Exception BaseException must STILL be "
        f"followed by the unregister leg (resolve + unregister), got "
        f"{len(torn.scripts)} host scripts -- a catch-all `except "
        f"Exception` with post-call cleanup strands the one-shot task")
    torn_unregister_text = _leg_text(torn.scripts[1])
    torn_name = _single_task_name(
        torn_unregister_text,
        "the unregister script after a torn-down launch leg")
    _assert_unregister_ast(
        torn_unregister_text, torn_name,
        "the unregister script after a torn-down launch leg (S2 finally "
        "discriminator)")
    assert torn_name == _single_task_name(
        captured_signal["inner"], "the torn-down launch script"), (
        "the finally-driven cleanup must target the EXACT task name the "
        "torn-down launch was about to register")
    observed_names.append(torn_name)

    # -- 4. not_started: the launch leg answers ok:false not_started. The
    #    task MAY have been registered (the guest refuses to guess), so the
    #    cleanup leg must run, and the envelope reports no pid.
    ns = FakePS([
        _guid_result(),
        _guest_leg(NOT_STARTED),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", ns)
    refused = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    assert refused.get("ok") is False, (
        f"a not_started launch must not report success: {refused!r}")
    assert refused.get("error_class") == "not_started", (
        f"the not_started answer must surface as the structured "
        f"not_started class, got {refused.get('error_class')!r}")
    assert refused.get("error"), (
        "the not_started envelope carries a human-readable error")
    assert "pid" not in refused, (
        "a not_started launch owns no process, so it reports no pid")
    assert len(ns.scripts) == 3, (
        f"a not_started launch must still drive the cleanup leg (resolve + "
        f"launch + unregister -- the task may already be registered), got "
        f"{len(ns.scripts)} host scripts")
    ns_launch = _single_task_name(_leg_text(ns.scripts[1]),
                                  "the not_started launch script")
    ns_unregister = _single_task_name(_leg_text(ns.scripts[2]),
                                      "the unregister script after a "
                                      "not_started launch")
    assert ns_unregister == ns_launch, (
        f"the cleanup leg must target the EXACT task name the not_started "
        f"launch registered ({ns_launch!r}), got {ns_unregister!r}")
    _assert_unregister_ast(
        _leg_text(ns.scripts[2]), ns_launch,
        "the unregister script after a not_started launch (S2 AST pin)")
    observed_names.append(ns_launch)

    # -- 5. cleanup failure: the launch SUCCEEDED but the unregister leg
    #    fails. The pid already returned must not be hidden, the failure
    #    must be surfaced, and nothing may raise out of start_interactive.
    #    5a: the unregister leg answers an ok:false frame.
    cf = FakePS([
        _guid_result(),
        _guest_leg(LAUNCH_OK),
        _guest_leg(UNREGISTER_FAILED),
    ])
    monkeypatch.setattr(pswindows, "run_ps", cf)
    out5a = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    assert out5a.get("ok") is True, (
        f"a successful launch stays successful when the CLEANUP fails (the "
        f"process is running): {out5a!r}")
    assert out5a.get("pid") == 4242, (
        f"an already-returned pid must not be hidden by a cleanup "
        f"failure: {out5a!r}")
    assert out5a.get("unregistered") is False, (
        f"a failed cleanup must be reported as such (unregistered false): "
        f"{out5a!r}")
    assert str(out5a.get("cleanup_error") or ""), (
        f"the cleanup failure must be surfaced in the envelope "
        f"(cleanup_error): {out5a!r}")
    #    5b: the unregister leg itself dies in transport (raises inside
    #    pswindows.run_ps) -- same surface, still nothing raises.
    cf2 = FakePS([
        _guid_result(),
        _guest_leg(LAUNCH_OK),
        pswindows.PowerShellTransportError("the cleanup leg died mid-run"),
    ])
    monkeypatch.setattr(pswindows, "run_ps", cf2)
    out5b = start_interactive(
        unrestricted, "vm1", "notepad.exe", cred=CRED, confirm=True)
    assert out5b.get("ok") is True, (
        f"a successful launch stays successful when the CLEANUP dies in "
        f"transport: {out5b!r}")
    assert out5b.get("pid") == 4242, (
        f"an already-returned pid must not be hidden by a dying cleanup "
        f"leg: {out5b!r}")
    assert out5b.get("unregistered") is False, (
        f"a dying cleanup must be reported as such (unregistered false): "
        f"{out5b!r}")
    assert str(out5b.get("cleanup_error") or ""), (
        f"the dying cleanup leg must be surfaced in the envelope "
        f"(cleanup_error): {out5b!r}")

    # every independent launch named its task with a FRESH uuid: a fixed
    # or counter-colliding name fails here even when it matches the shape
    assert len(observed_names) == len(set(observed_names)), (
        f"each launch must register a task under a FRESH unique name; "
        f"observed repeated name(s): "
        f"{sorted(n for n in observed_names if observed_names.count(n) > 1)}")


# ---------------------------------------------------------------------------
# AC4: the policy gate fires before anything reaches the guest
# ---------------------------------------------------------------------------

def test_refused_without_policy(monkeypatch):
    """AC4: IF the interactive launch is requested without the
    guest-execution policy category enabled, it is refused BEFORE
    contacting the guest -- zero host PowerShell legs, not even the VM
    resolution leg. The category is the existing destructive
    ``elevated_exec`` switch with the usual confirm leg (the same gate as
    the other process-starting tools). A positive control proves the gate,
    not a blanket refusal, is what stopped the call.
    RED at base (guestexec.start_interactive is missing), GREEN after the
    fix."""
    start_interactive = _start_interactive()
    # A restrictive lab config: the VM is allowed, the category is not.
    cfg = Config(allowed_vm_patterns=["test-*"])
    assert cfg.destructive.elevated_exec is False
    fake = FakePS([
        _guid_result(),
        _guest_leg(LAUNCH_OK),
        _guest_leg(UNREGISTER_OK),
    ])
    monkeypatch.setattr(pswindows, "run_ps", fake)

    with pytest.raises(PolicyDenied, match="elevated_exec"):
        start_interactive(
            cfg, "test-vm", "notepad.exe", cred=CRED, confirm=True)
    assert fake.scripts == [], (
        f"the category refusal must fire before ANY host PowerShell leg "
        f"(no resolution, no guest contact); {len(fake.scripts)} leg(s) ran")

    # the confirmation leg of the same gate: category on, no confirm
    cfg.destructive.elevated_exec = True
    with pytest.raises(PolicyDenied, match="confirm"):
        start_interactive(
            cfg, "test-vm", "notepad.exe", cred=CRED, confirm=False)
    assert fake.scripts == [], (
        "the confirm refusal must also fire before any host PowerShell leg")

    # positive control: category enabled + confirmed -> the launch proceeds
    # and reaches the guest, so the zero-leg pins above are not vacuous.
    # S1: the positive control's launch script is also AST-verified (a
    # comment-only launch script would satisfy the canned-leg counts but
    # not the executable-command census).
    out = start_interactive(
        cfg, "test-vm", "notepad.exe", cred=CRED, confirm=True)
    assert out.get("ok") is True, out
    assert out.get("pid") == 4242
    assert len(fake.scripts) == 3, (
        "with the category enabled and confirmed the launch must reach the "
        "guest (resolve + launch + unregister)")
    _assert_launch_ast(_leg_text(fake.scripts[1]), command="notepad.exe",
                       args=None, cwd=None,
                       what="the positive-control launch script")
