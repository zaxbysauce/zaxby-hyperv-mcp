"""Frozen acceptance checks for issue #57: every line the http controller
emits on its serve path must carry an ISO-8601 UTC timestamp prefix, and
no emitted line may ever contain the token value.

Token -> AC map:
  test_log_lines_carry_iso8601_timestamps
      AC1: the controller's line-emission helper prefixes each emitted
      line with YYYY-MM-DDTHH:MM:SSZ (ISO-8601 UTC).
  test_log_lines_never_carry_the_token_value
      AC2: with a non-blank token value in the environment, two
      refusal-style emissions never echo that value into the output.

The seam is probed arm's-length because the issue binds the OUTPUT shape,
not the implementation: the fix may name its helper controller_log, _log
or _emit (probed in that order via getattr on hyperv_mcp.http_entry; the
helper may print and/or return the formatted line — both are captured).
At base none of those names exists, so both checks fail by naming the
missing seam — the intended red while the timestamping work is
unimplemented.
"""

import ast
import re
from pathlib import Path

from hyperv_mcp import http_entry

SEAM_NAMES = ("controller_log", "_log", "_emit")
TIMESTAMP_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

HTTP_ENTRY_SOURCE = Path(http_entry.__file__).read_text(encoding="utf-8")


def _emission_seam():
    for name in SEAM_NAMES:
        seam = getattr(http_entry, name, None)
        if callable(seam):
            return seam
    raise AssertionError(
        "hyperv_mcp.http_entry exposes no controller log-line emission seam "
        f"(probed {', '.join(SEAM_NAMES)}); issue #57 requires the "
        "controller's serve-path lines to be emitted through a helper that "
        "prefixes ISO-8601 UTC timestamps"
    )


def _assert_serve_path_routes_through_seam(seam_name: str) -> None:
    """Plan-critic round-1 blocker 3 + round-2 blocker 3 (wiring): the serve
    entry point and EVERY module function it transitively calls must emit
    through the timestamped seam — a bare `print()` in any serve-path
    helper (e.g. the per-agent token resolver) would bypass the prefix on
    exactly the lines the issue binds. Structural pin via AST call-graph
    walk (driving a real uvicorn serve needs a live host)."""
    tree = ast.parse(HTTP_ENTRY_SOURCE)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "main" in functions, "http_entry.main not found"

    def _called_names(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Name):
                    yield sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    yield sub.func.attr

    # Transitive closure over same-module calls, starting at main().
    # Plan-critic round-3 blocker: the interactive --install-logon-task path
    # (its own helper subtree) prints to the OPERATOR'S SHELL, not the
    # redirected per-user log, and the issue's scope explicitly leaves those
    # lines unprefixed (05-fix-plan Fix 5). Exclude that subtree from the
    # serve-path closure: reachable-from-main MINUS everything reachable
    # only through the install helper.
    INSTALL_ONLY = {"_handle_logon_task"}

    def _reachable(skip: set) -> set:
        seen_local = {"main"}
        frontier_local = ["main"]
        while frontier_local:
            current = frontier_local.pop()
            for name in _called_names(functions[current]):
                if name in functions and name not in seen_local and name not in skip:
                    seen_local.add(name)
                    frontier_local.append(name)
        return seen_local

    seen = _reachable(set())
    serve_only = _reachable(INSTALL_ONLY)
    seen = serve_only

    bare_prints = []
    for fname in sorted(seen):
        if fname == seam_name:
            # The seam itself is the sanctioned emitter (plan-critic round-4
            # follow-up: its own print() IS the timestamped mechanism the
            # issue binds; scanning it is self-referential).
            continue
        for sub in ast.walk(functions[fname]):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "print"
            ):
                bare_prints.append((fname, sub.lineno))
    assert not bare_prints, (
        f"serve-path functions still make direct print() call(s): "
        f"{bare_prints!r}; serve-path output must route through {seam_name} "
        "so every emitted line carries the ISO-8601 UTC prefix"
    )
    seam_refs = [
        fname
        for fname in sorted(seen)
        for sub in ast.walk(functions[fname])
        if isinstance(sub, ast.Name) and sub.id == seam_name
    ]
    assert seam_refs, (
        f"the serve path (main + {len(seen) - 1} transitive callees) never "
        f"references the emission seam {seam_name!r}; it is not wired through"
    )


def test_log_lines_carry_iso8601_timestamps(capsys):
    seam = _emission_seam()
    seam_name = next(
        name for name in SEAM_NAMES if getattr(http_entry, name, None) is seam
    )
    _assert_serve_path_routes_through_seam(seam_name)
    returned = seam("controller refused to start: no token is set")
    captured = capsys.readouterr()
    # BOTH output sources are validated: a seam that returns a string AND
    # prints must not let the printed (possibly unprefixed) line escape
    # the check (implementation-review).
    chunks = [captured.out, captured.err]
    if isinstance(returned, str):
        chunks.append(returned)
    lines = [
        line for chunk in chunks for line in chunk.splitlines() if line.strip()
    ]
    assert lines, "emission seam produced no observable line"
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        "controller log lines carry no ISO-8601 UTC timestamp prefix: "
        f"{unprefixed!r}"
    )
    # Implementation-review round 1: the PREFIX SHAPE alone is not UTC --
    # a local-time stamp suffixed "Z" matches the same regex. Parse the
    # emitted stamp as UTC and compare it with the real UTC clock.
    from datetime import datetime, timezone

    stamp = lines[0].split(" ", 1)[0]
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    now = datetime.now(timezone.utc)
    drift = abs((now - parsed).total_seconds())
    assert drift <= 120, (
        f"controller log timestamp {stamp!r} is not UTC (drift {drift:.0f}s "
        f"from {now.isoformat()}); local time suffixed 'Z' matches the shape "
        "but is the wrong clock"
    )


def test_log_lines_never_carry_the_token_value(monkeypatch, capsys):
    monkeypatch.setenv("HYPERV_MCP_HTTP_TOKEN", "sup3rs3cret-sentinel-value")
    seam = _emission_seam()
    seam_name = next(
        name for name in SEAM_NAMES if getattr(http_entry, name, None) is seam
    )
    _assert_serve_path_routes_through_seam(seam_name)
    returned: list = []
    for _ in range(2):
        out = seam("ERROR: HYPERV_MCP_HTTP_TOKEN is not set (refusal)")
        if isinstance(out, str):
            returned.append(out)
    captured = capsys.readouterr()
    blob = "".join(returned) + captured.out + captured.err
    assert "sup3rs3cret-sentinel-value" not in blob, (
        "controller log output leaked the token value"
    )


def test_main_output_is_fully_timestamped(monkeypatch, capsys):
    """Implementation-review round 3: the per-file AST walk could not see
    the modules main() IMPORTS — the server bootstrap banner and the audit
    stream reached the redirected per-user log UNPREFIXED while every
    seam-level assertion passed. This leg captures what main() actually
    writes and requires EVERY non-empty line to carry the prefix."""
    import importlib

    import hyperv_mcp.server as srv

    importlib.reload(srv)
    real_get_mcp = http_entry.get_mcp

    def wrap_get_mcp():
        mcp = real_get_mcp()
        mcp.run = lambda *a, **k: 0
        return mcp

    monkeypatch.setattr(http_entry, "get_mcp", wrap_get_mcp)
    monkeypatch.setattr(http_entry, "configure_http_auth", lambda v: None)
    rc = http_entry.main(["--host", "127.0.0.1", "--allow-anonymous"])
    assert rc == 0, f"http_entry.main returned {rc}"
    captured = capsys.readouterr()
    lines = [
        line
        for line in (captured.out + captured.err).splitlines()
        if line.strip()
    ]
    assert lines, "main() produced no observable output to check"
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        "controller output reached the redirected log without the ISO-8601 "
        f"UTC prefix: {unprefixed!r}"
    )


def test_sdk_and_uvicorn_records_are_prefixed_too(capsys):
    """PRR-009: the SDK's own records ("mcp.*") and uvicorn's records land
    in the SAME redirected per-user log, so they must carry the prefix as
    well.

    A filter attached to a LOGGER does not see the records of its
    CHILDREN, and a filter attached to a HANDLER is lost when the SDK's
    configure_logging() replaces the root handlers - so this leg pins the
    hook that actually covers every record (the global record factory).

    The uvicorn ACCESS record is the delicate one: uvicorn composes that
    line from a FIVE-element args tuple (its own AccessFormatter), so the
    stamp must not reshape that tuple - doing so would make uvicorn raise
    "not enough values to unpack" and print a logging error INTO the
    controller log.
    """
    import logging
    import sys

    from hyperv_mcp import logemit

    # The record factory is process-global: install it, observe, and put
    # the previous one back so this leg cannot leak into later tests.
    previous_factory = logging.getLogRecordFactory()
    name = "mcp.server.lowlevel.server"
    logger = logging.getLogger(name)
    saved = (logger.level, list(logger.handlers), logger.propagate)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logemit.install_log_prefix()
        logger.info("sdk record %s", name)
        captured = capsys.readouterr()
    finally:
        logger.handlers = saved[1]
        logger.setLevel(saved[0])
        logger.propagate = saved[2]
        logging.setLogRecordFactory(previous_factory)
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1, f"expected one logged record, got {lines!r}"
    assert TIMESTAMP_PREFIX.match(lines[0]), (
        "a third-party log record reached the redirected log without the "
        f"ISO-8601 UTC prefix: {lines[0]!r}"
    )


def test_uvicorn_access_records_keep_their_args_contract():
    """PRR-009 follow-up (closeout-review finding 8): uvicorn's access
    line is composed by uvicorn's own AccessFormatter from a five-element
    args tuple. The stamp must reach that line WITHOUT breaking the tuple
    (a broken tuple makes uvicorn's formatter raise and print a logging
    error into the controller log).

    The client address uvicorn really passes is a STRING ("host:port",
    from uvicorn/protocols/utils.py get_client_addr) - so that is the
    shape the leg drives; the tuple form is kept as a compatibility leg
    because the stamp handles both.
    """
    import logging

    from hyperv_mcp import logemit

    previous_factory = logging.getLogRecordFactory()
    try:
        logemit.install_log_prefix()
        record = logging.getLogger("uvicorn.access").makeRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:54321", "GET", "/mcp", "1.1", 200),
            None,
        )
        tuple_record = logging.getLogger("uvicorn.access").makeRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            (("127.0.0.1", 54321), "GET", "/mcp", "1.1", 200),
            None,
        )
    finally:
        logging.setLogRecordFactory(previous_factory)

    for rec in (record, tuple_record):
        assert len(rec.args) == 5, (
            f"the access record's args tuple was reshaped: {rec.args!r}"
        )
        client = rec.args[0]
        assert isinstance(client, str), client
        assert TIMESTAMP_PREFIX.match(client), (
            f"the access record carries no timestamp: {client!r}"
        )
        # The REAL uvicorn formatter must still be able to render it.
        from uvicorn.logging import AccessFormatter

        rendered = AccessFormatter(
            fmt="%(client_addr)s - %(request_line)s %(status_code)s"
        ).format(rec)
        assert TIMESTAMP_PREFIX.search(rendered), (
            f"the rendered access line carries no timestamp: {rendered!r}"
        )
        assert "GET /mcp HTTP/1.1" in rendered, (
            f"the access line lost its request text: {rendered!r}"
        )


def test_log_line_prefixes_every_physical_line(capsys):
    """PRR-003 (closeout-review finding 13): a payload with an embedded
    newline must not leak an unprefixed continuation line - the log is
    read line by line, so EVERY physical line must carry the prefix."""
    from hyperv_mcp import logemit

    logemit.log_line("first line", "second\nthird line")
    captured = capsys.readouterr()
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 2, f"expected two physical lines, got {lines!r}"
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        f"a continuation line reached the log without the prefix: {unprefixed!r}"
    )


def test_unrenderable_records_are_still_stamped(capsys):
    """A record whose message cannot be rendered (a stray "%" with no
    args) must still be stamped - and must not raise into the caller."""
    import logging
    import sys

    from hyperv_mcp import logemit

    previous_factory = logging.getLogRecordFactory()
    logger = logging.getLogger("mcp.unrenderable")
    saved = (logger.level, list(logger.handlers), logger.propagate)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logemit.install_log_prefix()
        logger.info("100%% done")          # a stray percent, no args
        logger.info("%s and %s", "one")     # too few args
        captured = capsys.readouterr()
    finally:
        logger.handlers = saved[1]
        logger.setLevel(saved[0])
        logger.propagate = saved[2]
        logging.setLogRecordFactory(previous_factory)
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 2, f"expected two logged records, got {lines!r}"
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        "an unrenderable record reached the log without the prefix: "
        f"{unprefixed!r}"
    )


def test_controller_streams_are_pinned_to_utf8(monkeypatch):
    """PRR-018 (closeout-review finding 13): the controller's stdout and
    stderr are redirected into a UTF-8 log file, but the child's streams
    otherwise follow the Windows locale encoding - a non-ASCII line would
    be written in the wrong encoding. The entry point must pin both
    streams to UTF-8."""
    import sys

    import hyperv_mcp.http_entry as http_entry_mod

    class _Stream:
        """A text stream that records the reconfigure() call."""

        def __init__(self) -> None:
            self.calls: list = []
            self.encoding = "cp1252"

        def reconfigure(self, **kwargs) -> None:
            self.calls.append(kwargs)
            self.encoding = kwargs.get("encoding", self.encoding)

        def write(self, _text: str) -> int:
            return 0

        def flush(self) -> None:
            return None

    out, err = _Stream(), _Stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    # main() must not need a real config for this leg: it fails early and
    # returns, and the reconfiguration happens BEFORE the config load.
    monkeypatch.setattr(
        http_entry_mod, "load_controller_config", lambda: (_ for _ in ()).throw(RuntimeError("stop"))
    )
    try:
        http_entry_mod.main(["--host", "127.0.0.1"])
    except Exception:
        pass
    for stream, name in ((out, "stdout"), (err, "stderr")):
        assert stream.calls, f"{name} was never reconfigured"
        assert stream.calls[0].get("encoding") == "utf-8", stream.calls
        assert stream.encoding == "utf-8", stream.encoding


def test_audit_stream_lines_carry_the_timestamp(monkeypatch, capsys):
    """Implementation-review round 3 follow-up: the audit stream also
    reaches the redirected per-user log (auditlog._emit writes to stderr
    when no audit file is configured), so its lines carry the prefix too.
    The end-to-end main() leg does NOT cover this: a controller that never
    runs a tool emits no audit line at all — the mutant M14 (audit stream
    unprefixed) survived until this leg existed."""
    from hyperv_mcp import auditlog
    from hyperv_mcp.config import Config

    auditlog.init(Config())
    auditlog.log_operation(tool="hyperv_test", category="lifecycle", ok=True)
    captured = capsys.readouterr()
    lines = [
        line
        for line in (captured.out + captured.err).splitlines()
        if line.strip()
    ]
    assert lines, "the audit stream produced no observable line"
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        "audit stream line reached the redirected log without the ISO-8601 "
        f"UTC prefix: {unprefixed!r}"
    )


def test_log_exception_prefixes_every_traceback_line(capsys):
    """Implementation-review round 6: the crash-log emitter's traceback
    prefix had NO shipped pin (mutating logemit's per-line prefix left the
    suite green). Drive the emitter inside a real except block and require
    EVERY emitted line - message AND traceback - to carry the prefix."""
    from hyperv_mcp import logemit

    try:
        raise ValueError("deliberate probe failure")
    except ValueError:
        logemit.log_exception("tool probe raised an unexpected exception\nsecond line")
    captured = capsys.readouterr()
    lines = [
        line
        for line in (captured.out + captured.err).splitlines()
        if line.strip()
    ]
    assert len(lines) >= 3, (
        "the exception emission produced no traceback lines: " + repr(lines)
    )
    unprefixed = [line for line in lines if not TIMESTAMP_PREFIX.match(line)]
    assert not unprefixed, (
        "a traceback line reached the log without the ISO-8601 UTC prefix: "
        f"{unprefixed!r}"
    )


def _is_logger_receiver(value) -> bool:
    """Is this expression a logger?

    Three shapes reach the redirected log unprefixed: a NAME that names
    a logger ("logger", "_audit_log", "log"), an ATTRIBUTE chain on such
    a name ("self.logger"), and a CALL to logging.getLogger(...)
    ("logging.getLogger('x').warning(...)") - the last one is the shape
    the round-1 finding named, and a name-only test could not see it.
    """
    if isinstance(value, ast.Name):
        name = value.id
        return (
            name == "logger"
            or name.lstrip("_").endswith("log")
            or name.lstrip("_").endswith("logger")
        )
    if isinstance(value, ast.Attribute):
        # "self.logger" - the attribute's own name is the logger name.
        attr = value.attr
        if (
            attr == "logger"
            or attr.lstrip("_").endswith("log")
            or attr.lstrip("_").endswith("logger")
        ):
            return True
        return _is_logger_receiver(value.value)
    if isinstance(value, ast.Call):
        # A LOGGER FACTORY call: logging.getLogger("mcp") or
        # get_logger() - the expression IS the logger.
        func = value.func
        if isinstance(func, ast.Attribute) and func.attr in ("getLogger", "get_logger"):
            return True
        if isinstance(func, ast.Name) and func.id in ("getLogger", "get_logger"):
            return True
    return False


def test_logger_guardrail_covers_every_logger_shape():
    """PRR-013 (closeout-review finding 11): the package guardrail must
    see EVERY shape a logger call can take. A receiver that is a CALL
    ("logging.getLogger('x').warning(...)") is not an ast.Name, so a
    name-only test could not see it - and the shape the finding named
    would have slipped through the guardrail."""
    import ast

    cases = {
        "logger.warning('x')": True,
        "_audit_log.warning('x')": True,
        "log.info('x')": True,
        "self.logger.error('x')": True,
        "logging.getLogger('mcp').warning('x')": True,
        "get_logger().warning('x')": True,
        "print('x')": False,
        "sys.stderr.write('x')": False,
        "some_object.helper('x')": False,
    }
    for source, expected in cases.items():
        call = ast.parse(source).body[0].value
        assert isinstance(call, ast.Call), source
        if isinstance(call.func, ast.Attribute):
            got = _is_logger_receiver(call.func.value)
        else:
            # print(...) and friends are not logger calls at all.
            got = False
        assert got is expected, source


def _scan_unprefixed_writers(package, emitter, excluded_modules, excluded_functions):
    """Scan a package directory for writers that can reach the controller's
    redirected log UNPREFIXED.

    Split out of the guardrail test so a SYNTHETIC package can be fed to
    it: the shapes the scan must recognise (a logger-factory call, an
    attribute receiver) do not occur in the shipped package, so the scan's
    own branches would otherwise never be exercised.
    """
    offenders = []
    for module in sorted(package.glob("*.py")):
        if module == emitter or module.name in excluded_modules:
            continue
        skip_funcs = excluded_functions.get(module.name, set())
        tree = ast.parse(module.read_text(encoding="utf-8"))
        # Module-level emissions are scanned too (a module-level print() is
        # not inside any FunctionDef - implementation-review round 6 nit).
        scopes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        module_scope = ast.Module(
            body=[
                node
                for node in tree.body
                if not isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                )
            ],
            type_ignores=[],
        )
        scopes.append(module_scope)
        for func in scopes:
            fname = getattr(func, "name", "<module level>")
            if fname in skip_funcs:
                continue
            for node in ast.walk(func):
                is_print = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"
                )
                # A logger call reaches stderr through the root handler
                # (the SDK installs one) just as a print does, and its
                # handler prints the message - and any traceback - WITHOUT
                # a timestamp (implementation-review round 5).
                is_logger = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr
                    in ("exception", "error", "warning", "info", "critical")
                    and _is_logger_receiver(node.func.value)
                )
                # A direct stream write (sys.stdout.write / sys.stderr.write)
                # lands in the redirected log exactly like a print does
                # (implementation-review round 7).
                is_write = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "write"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr in ("stdout", "stderr")
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "sys"
                )
                if not (is_print or is_logger or is_write):
                    continue
                # The controller is spawned with stdout=log and
                # stderr=STDOUT (stdio_proxy), so BOTH streams reach the
                # same log file: an explicit file=sys.stdout is in scope
                # too (implementation-review round 7).
                to_stream = False
                for kw in node.keywords:
                    if kw.arg == "file":
                        to_stream = isinstance(kw.value, ast.Attribute) and (
                            kw.value.attr in ("stderr", "stdout")
                        )
                # A print with ANY keyword other than file= (flush=,
                # sep=, end=) still writes to stdout - which IS the
                # redirected log - so it counts as an unprefixed writer
                # (implementation-review). A logger named anything other
                # than "logger" (_log, audit) counts too.
                other_kwargs = [
                    kw for kw in node.keywords if kw.arg != "file"
                ]
                if (
                    is_logger
                    or is_write
                    or to_stream
                    or not node.keywords
                    or other_kwargs
                ):
                    offenders.append(
                        f"{module.name}:{fname}:{node.lineno}"
                    )
    return offenders


def test_no_unprefixed_stderr_writers_in_the_package():
    """Package-wide guardrail (the general form of the #57 requirement).

    Every print() that can reach the CONTROLLER's redirected per-user log
    must go through the shared timestamped emitter. The controller process
    is the `hyperv-mcp-http` entry point (http_entry.main) plus everything
    it calls (server.bootstrap -> _startup_banner, the audit sink, the
    PowerShell slot pool).

    Documented exclusions (each writes to a DIFFERENT stream):
      - http_entry._handle_logon_task: the interactive install path, whose
        output goes to the operator's terminal;
      - server.main: the STDIO server CLI, whose stderr is the MCP
        CLIENT's stderr;
      - stdio_proxy: the client-side proxy, whose stderr is the operator's
        terminal;
      - consolebench: a development benchmark tool.

    A NEW module (or a new function in an in-scope module) that prints to
    stderr would fail here - the round-3 gap (server banner / audit
    stream) was exactly that shape, and a per-module check could not see
    it."""
    from pathlib import Path

    package = Path(http_entry.__file__).resolve().parent
    emitter = package / "logemit.py"
    # module -> fully excluded function names
    excluded_functions = {
        "http_entry.py": {"_handle_logon_task"},
        "server.py": {"main"},
    }
    # modules whose stderr never reaches the controller log
    excluded_modules = {"stdio_proxy.py", "consolebench.py"}
    offenders = _scan_unprefixed_writers(
        package, emitter, excluded_modules, excluded_functions
    )
    assert not offenders, (
        "these print() calls can reach the controller's redirected log "
        f"unprefixed: {offenders}"
    )


def test_the_guardrail_reports_every_writer_shape(tmp_path):
    """The scan must REPORT the shapes it claims to know: a print, a
    logger by name, a logger reached through a factory call
    ("logging.getLogger('mcp').warning(...)") and a logger reached
    through an attribute ("self.logger.error(...)").

    The shipped package contains none of the latter two, so without a
    synthetic package the scan's own branches would never run (and a
    revert of the receiver handling would stay green).
    """
    from pathlib import Path

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "logemit.py").write_text("# the emitter itself\n", encoding="utf-8")
    (package / "offender.py").write_text(
        "import logging\n"
        "\n"
        "def a():\n"
        "    print('x')\n"
        "\n"
        "def b():\n"
        "    logger.warning('x')\n"
        "\n"
        "def c():\n"
        "    logging.getLogger('mcp').warning('x')\n"
        "\n"
        "def d():\n"
        "    self.logger.error('x')\n",
        encoding="utf-8",
    )
    offenders = _scan_unprefixed_writers(
        Path(package), Path(package) / "logemit.py", set(), {}
    )
    # EVERY shape must be reported - not merely "some offender": the
    # synthetic module holds four writers, and a scan that only sees the
    # first one would still report an offender.
    for shape in ("a", "b", "c", "d"):
        assert any(
            o.startswith(f"offender.py:{shape}:") for o in offenders
        ), f"the scan did not report the {shape}() writer: {offenders}"
    assert len(offenders) == 4, offenders


def test_refusal_paths_never_carry_the_token_value(monkeypatch, capsys):
    """Implementation-review round 1+2: the seam-level no-leak floor does
    not prove the REAL refusal sites are safe. Drive the serve-path
    refusals that could echo a value and assert EVERY involved token
    value is absent — the reviewer's falsifier (the refusal echoing
    {value!r}) must be caught, so each value in the refusal's scope is
    asserted absent, not just the first one."""
    sentinel_a = "sup3rs3cret-refusal-sentinel-a"
    sentinel_b = "sup3rs3cret-refusal-sentinel-b"
    non_ascii = "not-ascii-\u00e9"
    # (a) a RESOLVED agent emits nothing; its value must not appear.
    monkeypatch.setenv("HYPERV_MCP_TOKEN_AGENT_A", sentinel_a)
    rc, pairs = http_entry._resolve_agent_tokens(
        {"agent-a": "HYPERV_MCP_TOKEN_AGENT_A"}, ""
    )
    assert rc == 0 and pairs, pairs
    captured = capsys.readouterr()
    assert sentinel_a not in (captured.out + captured.err), (
        "the agent-token resolver echoed the token value"
    )
    # (b) the non-ASCII refusal: the REFUSED value (non_ascii) AND EVERY
    # already-resolved sibling value must be absent — asserting only the
    # first sibling's absence left the falsifier alive.
    monkeypatch.setenv("HYPERV_MCP_TOKEN_AGENT_B", sentinel_b)
    monkeypatch.setenv("HYPERV_MCP_TOKEN_AGENT_C", non_ascii)
    rc, _ = http_entry._resolve_agent_tokens(
        {
            "agent-a": "HYPERV_MCP_TOKEN_AGENT_A",
            "agent-b": "HYPERV_MCP_TOKEN_AGENT_B",
            "agent-c": "HYPERV_MCP_TOKEN_AGENT_C",
        },
        "",
    )
    assert rc == 2, rc
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert non_ascii not in blob, (
        "the refusal echoed the refused token value"
    )
    assert sentinel_a not in blob, (
        "the refusal echoed another agent's token value"
    )
    assert sentinel_b not in blob, (
        "the refusal echoed a second resolved agent's token value"
    )
    assert "agent-c" in blob, (
        f"the refusal must name the offending agent, not its value: {blob!r}"
    )
    assert "never printed" in blob, (
        f"the refusal must state that values are never printed: {blob!r}"
    )
    # (c) the MISSING-variable refusal names the variable, never a value.
    monkeypatch.delenv("HYPERV_MCP_TOKEN_AGENT_B", raising=False)
    rc, _ = http_entry._resolve_agent_tokens(
        {
            "agent-a": "HYPERV_MCP_TOKEN_AGENT_A",
            "agent-b": "HYPERV_MCP_TOKEN_AGENT_B",
        },
        "",
    )
    assert rc == 2, rc
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert sentinel_a not in blob, "the missing-variable refusal echoed a value"
    assert "HYPERV_MCP_TOKEN_AGENT_B" in blob, (
        f"the missing-variable refusal must name the variable: {blob!r}"
    )
