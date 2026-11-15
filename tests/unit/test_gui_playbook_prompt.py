"""Issue #134 acceptance checks (trace 128-129-134-gui-drivability): the
built-in GUI-testing playbook prompt and see-also links from the console
input tools to the UI Automation element tools, so a client that knows only
"click at coordinates" can discover the element-level alternative.

AC map (issue #134 body):
  AC1  test_playbook_prompt_is_listed       NEW-SURFACE
  AC2  test_playbook_has_required_sections  NEW-SURFACE
  AC3  test_console_click_points_to_uia     NEW-SURFACE
  AC4  test_tool_schemas_unchanged          PRESERVING
  AC5  test_paths_are_ordered_by_surface    NEW-SURFACE
       test_reversed_path_guidance_is_rejected  NEW-SURFACE (AC5's negative
       fixture: reversed guidance in the REAL path-selection section must
       be rejected even when a correctly ordered decoy table appears
       elsewhere in the prompt)

Every check is RED at base ea5fac5 (this spec file is absent; with the file
present each test fails on the missing prompt / see-also text) and GREEN
after the fix. The server-level checks read the PUBLISHED surface --
``asyncio.run(mcp.list_prompts())`` / ``get_prompt()`` / ``list_tools()``
on the bootstrapped server -- never raw docstrings, so what is asserted is
what a client sees.

Frozen surface contract this file pins (the issue names the prompt and the
link targets; the text shape is underdetermined by the issue text, so this
file IS the spec the fix implements against):

  THE PROMPT: the server registers exactly one prompt named
  ``gui-testing-playbook`` (a no-argument prompt; listed with a non-empty
  description). Fetching it returns text containing, case-insensitively,
  the five section markers, each as a markdown heading so the section
  under it is extractable:

      "path selection"   -- which interaction path to take, as a table
      "verification"     -- observe/verify before and after acting
      "commit-click"     -- the commit-guarded click discipline
      "transient"        -- transient-vs-absent error handling (the word
      "absent"              "absent" distinguishes the two)
      "evidence"         -- capturing screenshots/results as evidence

  THE SECTIONS' OPERATIONAL SEQUENCES (AC2, strengthened): the assertions
  bind to the text UNDER each heading, not the whole prompt:

    - the transient-error section states its operational sequence IN
      ORDER: retry FIRST, then the tools to reach for (a hyperv_ tool
      name), then reporting the target unavailable;
    - the verification section requires verification after EVERY action
      (the phrase "every action");
    - the commit-click section names the commit guard (the phrase
      "commit guard" / "commit_guard" / "commit-guard");
    - the transient-vs-absent distinction ("absent") lives in the
      transient section itself.

  THE PATH-SELECTION TABLE (AC5): a markdown table (rows beginning with
  ``|``) INSIDE the Path selection section, with one row per surface and
  the surface name in the FIRST column; the paths are read from the
  CHOICE COLUMNS (every cell after the first), in priority order:

      the row mentioning "web"    names the DevTools path BEFORE the UI
                                  Automation path (DevTools is the first
                                  path for web content)
      the row mentioning "native" names the UI Automation path FIRST --
                                  before any DevTools mention on that row
                                  (UI Automation is the first path for
                                  native windows)

  "UI Automation" is recognized as either the phrase "ui automation" or a
  "hyperv_ui_" tool name; "DevTools" as the word "devtools". A prompt
  whose real path-selection section carries reversed guidance fails even
  when a correctly ordered table appears elsewhere (the section, not the
  whole prompt, is what is parsed).

  THE SEE-ALSO LINK (AC3, strengthened): the PUBLISHED description of
  ``hyperv_console_click``, ``hyperv_console_type_text`` AND
  ``hyperv_console_screenshot`` names BOTH ``hyperv_ui_find`` and
  ``hyperv_ui_invoke`` (the find + invoke pair) with POSITIVE wording (a
  phrase like "see also" / "prefer" / "recommended") in BOTH credential
  registration variants -- a description that mentions the tools only to
  forbid them ("Never use hyperv_ui_find ...") fails. Wave-3 S7: ANY
  forbidding construction in the same description as the tool names is
  rejected (the substrings "forbidden", "never use", "do not use",
  "avoid", "must not", "not recommended"), even when a recommending
  phrase also appears -- "See also: docs. hyperv_ui_find and
  hyperv_ui_invoke are forbidden" fails. The link text lives
  OUTSIDE the docstring's ``Args:`` block (a "See also:" line at the
  parameter indent would close the block and strip trailing parameter
  descriptions -- the toolschema.py parser and
  tests/unit/test_d04_tool_param_descriptions.py).

  THE OPERATIONAL SECTIONS' POLARITY (AC2, wave-3 S6): the three
  operational sections state their guidance with the RIGHT polarity --
  the transient-error section must not say "never retry" / "do not
  retry", the verification section must not say "do not verify" /
  "skip verification", and the commit-click section must not say "do not
  use the commit guard" / "skip the commit guard". Positive form present
  AND negated form absent, per section
  (test_negated_guidance_sections_are_rejected is the negative fixture:
  negated guidance injected into the REAL prompt must FAIL).

  THE INVENTORY (AC4, preserving): the DEFAULT registration publishes
  exactly 85 tools -- the 84 frozen below plus
  ``hyperv_guest_start_interactive`` (#128) -- and every PRE-EXISTING tool
  keeps its FULL ``inputSchema`` object DEEP-EQUAL to the frozen literal
  below (types, defaults, descriptions, titles, required lists,
  additionalProperties -- not just the property-name set), in BOTH
  credential variants (default and ``allow_inline_credentials=True``).
  The frozen maps below were generated from the base registration; any
  schema drift fails on the first differing path. Wave-3 S5: the NEW
  tool's COMPLETE ``inputSchema`` is frozen DEEPLY in BOTH variants
  (NEW_TOOL_SCHEMA_DEFAULT_JSON / NEW_TOOL_SCHEMA_INLINE_JSON) -- the
  full exact property set, types, defaults, descriptions, titles,
  ``additionalProperties: false``, the
  ``hyperv_guest_start_interactiveArguments`` title and NO ``required``
  key (every parameter defaults); a registration omitting ``command``,
  ``args``, ``timeout_ms``, ``vm_name`` or ``vm_id`` fails on the exact
  differing path. The property-set pins are retained alongside: it
  carries ``cwd``, ``lease_id``, ``fencing_token`` and ``confirm``; it
  carries ``username``/``password`` ONLY in the inline-credentials
  variant; and it does NOT carry ``detach`` or ``idempotency_key``.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import re

import pytest

import hyperv_mcp.server as server_module
from hyperv_mcp.config import Config

PROMPT_NAME = "gui-testing-playbook"

#: The section markers the fetched playbook text must carry (AC2), lower-
#: cased; "transient" + "absent" together pin the transient-vs-absent
#: errors section, the others pin one section each.
REQUIRED_SECTION_MARKERS = (
    "path selection",
    "verification",
    "commit-click",
    "transient",
    "absent",
    "evidence",
)

#: #128's tool joins the inventory; every other name is pre-existing and
#: frozen. 84 at base + 1 = 85.
NEW_TOOL_NAMES = {"hyperv_guest_start_interactive"}

#: The console-input tools whose PUBLISHED descriptions must positively
#: see-also the UI Automation find + invoke pair (AC3).
SEE_ALSO_TOOLS = (
    "hyperv_console_click",
    "hyperv_console_type_text",
    "hyperv_console_screenshot",
)
SEE_ALSO_LINK_TARGETS = ("hyperv_ui_find", "hyperv_ui_invoke")
#: The see-also wording must RECOMMEND the element-level tools; a phrase
#: from this set (case-insensitive) proves positive wording.
SEE_ALSO_PHRASES = ("see also", "prefer", "recommended")
#: Wording that mentions the UIA tools only to forbid them -- the negative
#: shape AC3's positive-wording pin exists to reject.
SEE_ALSO_NEGATIVE_RE = re.compile(
    r"(never|don't|do not|avoid)\s+(use|using|call|calling)\s+`?hyperv_ui_")
#: Wave-3 S7: ANY forbidding construction in the same description as the
#: tool names is rejected, even when a recommending phrase also appears --
#: "See also: docs. hyperv_ui_find and hyperv_ui_invoke are forbidden"
#: survived the wave-2 pin. The whole description counts as "near" the
#: tool names.
SEE_ALSO_FORBIDDEN_SUBSTRINGS = (
    "forbidden",
    "never use",
    "do not use",
    "avoid",
    "must not",
    "not recommended",
)

#: Wave-3 S6: the negated guidance shapes the three operational sections
#: must NOT carry -- polarity, not token presence (sections saying "Never
#: retry" / "Do not verify after every action" / "Do not use the commit
#: guard" survived the wave-2 token pins).
_NEGATED_TRANSIENT_RE = re.compile(
    r"(never|do\s+not|don't)\s+retry", re.IGNORECASE)
_NEGATED_VERIFICATION_RE = re.compile(
    r"((never|do\s+not|don't)\s+verif(?:y|ication|ying)"
    r"|skips?\s+verification)", re.IGNORECASE)
_NEGATED_COMMIT_RE = re.compile(
    r"((do\s+not|don't|never)\s+use\s+the\s+commit[ _-]?guard"
    r"|skips?\s+the\s+commit[ _-]?guard)", re.IGNORECASE)

#: A markdown heading line: 0-3 leading spaces, 1-6 '#', then the text.
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s*(.*)$")

#: The path tokens recognized inside table cells (case-insensitive): the
#: UI Automation phrase or a hyperv_ui_ tool name; the DevTools word.
_UIA_TOKEN_RE = re.compile(r"ui automation|hyperv_ui_\w+", re.IGNORECASE)
_DEVTOOLS_TOKEN_RE = re.compile(r"devtools", re.IGNORECASE)

# ---------------------------------------------------------------------------
# shared harness
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_server():
    """The test_server.py idiom: reload the server module, bootstrap it,
    yield it; reload again afterwards so later tests see a clean module."""
    def make(environ: dict | None = None):
        mod = importlib.reload(server_module)
        mod.bootstrap(environ or {})
        return mod
    yield make
    importlib.reload(server_module)


def _prompt_text(result) -> str:
    """All text of a get_prompt() result: every message's text blocks
    joined (the prompt may return one string or several messages)."""
    chunks: list[str] = []
    for message in getattr(result, "messages", None) or []:
        content = (
            message.get("content")
            if isinstance(message, dict)
            else getattr(message, "content", None)
        )
        blocks = content if isinstance(content, list) else [content]
        for block in blocks:
            if isinstance(block, str):
                chunks.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                chunks.append(block["text"])
            else:
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    chunks.append(text)
    return "\n".join(chunks)


def _tool_description(mcp, name: str) -> str:
    """The PUBLISHED description of one tool, read from list_tools()."""
    for tool in asyncio.run(mcp.list_tools()):
        if tool.name == name:
            return tool.description or ""
    raise AssertionError(f"tool {name!r} is not registered on this server")


def _schema_of(tool) -> dict:
    return getattr(tool, "input_schema", None) or tool.inputSchema


def _extract_section(text: str, marker: str) -> str:
    """The text under the first markdown heading containing `marker`
    (case-insensitive), up to the next heading of the same or higher
    level -- the strengthened AC2/AC5 assertions bind to SECTIONS, not to
    the whole prompt."""
    lines = text.splitlines()
    start = None
    level = 0
    for i, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if m and marker in m.group(2).lower():
            start, level = i + 1, len(m.group(1))
            break
    assert start is not None, (
        f"the playbook must carry a markdown heading containing {marker!r} "
        f"so the section under it is extractable (issue #134)")
    out: list[str] = []
    for line in lines[start:]:
        m = _HEADING_RE.match(line)
        if m and len(m.group(1)) <= level:
            break
        out.append(line)
    return "\n".join(out)


def _row_cells(row: str) -> list[str]:
    """One markdown table row -> its stripped cells (bars dropped)."""
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def _first_in_cells(pattern: re.Pattern, cells: list[str]):
    """(cell_index, position_in_cell) of the first `pattern` match among
    the cells, in cell order -- None when absent. AC5's ordering is read
    from the CHOICE COLUMNS, never from substring positions across the
    whole row (a surface cell mentioning a path cannot skew the order)."""
    for idx, cell in enumerate(cells):
        m = pattern.search(cell)
        if m:
            return (idx, m.start())
    return None


def _path_order_violations(text: str) -> list[str]:
    """Every way `text`'s Path selection section violates the by-surface
    path ordering. The section under the first heading containing
    "path selection" is extracted (a decoy table elsewhere in the prompt
    is never read), its table rows are parsed into cells, and the web /
    native rows' CHOICE COLUMNS (cells after the surface column) must
    carry the paths in priority order."""
    section = _extract_section(text, "path selection")
    rows = [ln for ln in section.splitlines() if ln.strip().startswith("|")]
    violations: list[str] = []
    if not rows:
        violations.append(
            "the path-selection section must be a markdown table (rows "
            "beginning with '|') so the per-surface ordering is parseable")
        return violations

    web_rows = [r for r in rows if "web" in r.lower()]
    if not web_rows:
        violations.append(
            "the path table must carry a web-content row (a row mentioning "
            "'web')")
    else:
        cells = _row_cells(web_rows[0])
        if len(cells) < 2:
            violations.append(
                f"the web-content row needs a surface cell plus at least "
                f"one choice cell: {web_rows[0]!r}")
        else:
            choice = cells[1:]
            devtools = _first_in_cells(_DEVTOOLS_TOKEN_RE, choice)
            uia = _first_in_cells(_UIA_TOKEN_RE, choice)
            if devtools is None:
                violations.append(
                    f"the web-content row's choice columns must name the "
                    f"DevTools path: {web_rows[0]!r}")
            if uia is None:
                violations.append(
                    f"the web-content row's choice columns must also name "
                    f"the UI Automation fallback: {web_rows[0]!r}")
            if devtools is not None and uia is not None \
                    and not devtools < uia:
                violations.append(
                    f"for web content the DevTools tools are the FIRST "
                    f"path -- in the web row's choice columns the DevTools "
                    f"mention must precede the UI Automation mention: "
                    f"{web_rows[0]!r}")

    native_rows = [r for r in rows if "native" in r.lower()]
    if not native_rows:
        violations.append(
            "the path table must carry a native-windows row (a row "
            "mentioning 'native')")
    else:
        cells = _row_cells(native_rows[0])
        if len(cells) < 2:
            violations.append(
                f"the native-windows row needs a surface cell plus at least "
                f"one choice cell: {native_rows[0]!r}")
        else:
            choice = cells[1:]
            devtools = _first_in_cells(_DEVTOOLS_TOKEN_RE, choice)
            uia = _first_in_cells(_UIA_TOKEN_RE, choice)
            if uia is None:
                violations.append(
                    f"the native-windows row's choice columns must name the "
                    f"UI Automation tools: {native_rows[0]!r}")
            if uia is not None and devtools is not None \
                    and not uia < devtools:
                violations.append(
                    f"for native windows the UI Automation tools are the "
                    f"FIRST path -- in the native row's choice columns the "
                    f"UI Automation mention must precede any DevTools "
                    f"mention: {native_rows[0]!r}")
    return violations


#: A correctly ordered path-selection table (the checker must ACCEPT it --
#: the non-vacuity companion of the reversed-guidance negative fixture).
CORRECT_PATH_TABLE = "\n".join([
    "| Surface | Paths in priority order |",
    "| --- | --- |",
    "| web content | 1. DevTools relay  2. UI Automation (hyperv_ui_find) |",
    "| native windows | 1. UI Automation (hyperv_ui_find, hyperv_ui_invoke) |",
])


def _swap_first_tokens(joined_cells: str) -> str:
    """Swap the first UI-Automation token and the first DevTools token in
    a '|'-joined cell run -- the mutation that reverses a row's path
    guidance while keeping the table structure intact."""
    uia = _UIA_TOKEN_RE.search(joined_cells)
    devtools = _DEVTOOLS_TOKEN_RE.search(joined_cells)
    assert uia is not None and devtools is not None, (
        "the reversed-guidance mutation needs both path mentions in the "
        "row's choice cells")
    first, second = sorted((uia, devtools), key=lambda m: m.start())
    return (joined_cells[:first.start()] + second.group(0)
            + joined_cells[first.end():second.start()]
            + first.group(0) + joined_cells[second.end():])


def _assert_see_also(description: str, tool: str) -> None:
    """One console tool's PUBLISHED description must positively see-also
    the UI Automation find + invoke pair: BOTH tool names present, a
    recommending phrase present, and no forbidding wording (S7: no
    forbidding SUBSTRING anywhere in the same description as the tool
    names)."""
    low = description.lower()
    for target in SEE_ALSO_LINK_TARGETS:
        assert target in description, (
            f"the PUBLISHED description of {tool} must see-also {target} "
            f"(the element-level alternative to blind console input)")
    assert any(phrase in low for phrase in SEE_ALSO_PHRASES), (
        f"the PUBLISHED description of {tool} must RECOMMEND the UI "
        f"Automation tools with positive wording (a phrase like 'see also' "
        f"or 'prefer') -- naming the tools alone is not a link a client "
        f"can follow: {description!r}")
    assert not SEE_ALSO_NEGATIVE_RE.search(low), (
        f"the PUBLISHED description of {tool} must not forbid the UI "
        f"Automation tools ('Never use hyperv_ui_find ...' is not a "
        f"see-also link): {description!r}")
    for bad in SEE_ALSO_FORBIDDEN_SUBSTRINGS:
        assert bad not in low, (
            f"the PUBLISHED description of {tool} must not carry FORBIDDING "
            f"wording near the UI Automation tools ({bad!r} appears in the "
            f"same description as {SEE_ALSO_LINK_TARGETS} -- 'See also: "
            f"... hyperv_ui_find and hyperv_ui_invoke are forbidden' is "
            f"not a see-also link): {description!r}")


def _section_polarity_violations(text: str) -> list[str]:
    """Every way `text`'s three OPERATIONAL sections carry NEGATED guidance
    (wave-3 S6 -- polarity, not token presence): the transient-error
    section must not say never/do-not retry, the verification section must
    not say do-not/don't/never verify or skip verification, and the
    commit-click section must not say do-not/don't/never use the commit
    guard or skip the commit guard. The POSITIVE forms are pinned in
    test_playbook_has_required_sections; this checker is their polarity
    mirror, and test_negated_guidance_sections_are_rejected proves it has
    teeth against a mutated real prompt."""
    violations: list[str] = []

    transient = _extract_section(text, "transient").lower()
    m = _NEGATED_TRANSIENT_RE.search(transient)
    if m:
        violations.append(
            f"transient section: negated retry guidance {m.group(0)!r} -- "
            f"the section must tell the caller TO retry transient errors")

    verification = _extract_section(text, "verification").lower()
    m = _NEGATED_VERIFICATION_RE.search(verification)
    if m:
        violations.append(
            f"verification section: negated verification guidance "
            f"{m.group(0)!r} -- the section must require verification "
            f"after every action")

    commit = _extract_section(text, "commit-click").lower()
    m = _NEGATED_COMMIT_RE.search(commit)
    if m:
        violations.append(
            f"commit-click section: negated commit-guard guidance "
            f"{m.group(0)!r} -- the section must recommend the commit "
            f"guard")

    return violations


#: The negated-guidance sentences the S6 negative fixture injects under
#: each operational heading of the REAL prompt (one per section).
_NEGATED_INJECTIONS = [
    ("transient", "Never retry a transient error; treat it as absent."),
    ("verification",
     "Do not verify after every action on repeated steps."),
    ("commit-click",
     "Do not use the commit guard for trusted flows."),
]


def _inject_after_heading(text: str, marker: str, sentence: str) -> str:
    """`text` with `sentence` inserted directly under the first heading
    containing `marker` (the reversed-guidance mutation's injector
    idiom)."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if m and marker in m.group(2).lower():
            lines.insert(i + 1, sentence)
            lines.insert(i + 1, "")
            return "\n".join(lines)
    raise AssertionError(
        f"no markdown heading carrying {marker!r} to inject into")


#: The exact inputSchema of every tool registered by the DEFAULT variant
#: at trace base ea5fac5 (84 tools), as canonical JSON (sorted keys,
#: compact). Frozen verbatim -- these literals ARE the AC4 deep-equality
#: pin: the WHOLE schema object (property names, types, defaults,
#: descriptions, titles, required, additionalProperties) must match
#: exactly; the first differing path is reported on drift.
FROZEN_SCHEMAS_DEFAULT_JSON: dict[str, str] = {
    'hyperv_capture_evidence': '{"additionalProperties":false,"properties":{"crop":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"[left, top, right, bottom] in captured-frame pixels","title":"Crop"},"format":{"default":"","description":"png (default), jpeg/jpg, or webp; an unsupported format is refused as an invalid-input error","title":"Format","type":"string"},"height":{"default":768,"description":"requested screenshot height in pixels (160..4096)","title":"Height","type":"integer"},"if_changed_from":{"default":"","description":"a frame_hash from a previous capture, as 64 lowercase hex characters; when it equals the current capture\'s hash the tool returns metadata only and skips decode, encode, the file write AND the UI-tree leg (meta[\\"ui_tree\\"] then reports why it was skipped)","title":"If Changed From","type":"string"},"quality":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"1..100; applies to jpeg/webp only. An out-of-range value is refused whatever the format, including png — png has no quality axis, so an in-range value there is accepted and has no effect","title":"Quality"},"save_path":{"default":"","description":"optional host path to also write the encoded image","title":"Save Path","type":"string"},"scale":{"anyOf":[{"type":"number"},{"type":"null"}],"default":null,"description":"downscale factor in (0, 1] applied after crop","title":"Scale"},"ui_tree":{"default":false,"description":"also fetch a bounded guest UI element tree (needs credentials)","title":"Ui Tree","type":"boolean"},"ui_tree_depth":{"default":3,"description":"tree walk depth, clamped to 1..32","title":"Ui Tree Depth","type":"integer"},"ui_tree_max_elements":{"default":200,"description":"element cap, clamped to 1..500","title":"Ui Tree Max Elements","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"},"width":{"default":1024,"description":"requested screenshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_capture_evidenceArguments","type":"object"}',
    'hyperv_checkpoint_create': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Label (auto timestamp if omitted)","title":"Checkpoint Name","type":"string"},"checkpoint_type":{"default":"","description":"\\"standard\\", \\"production\\", \\"production_only\\", or \\"\\" (default: the VM\'s own setting). Production falls back to Standard on guests without production-checkpoint support, and ProductionOnly fails instead. A Standard checkpoint — including a Production fallback — writes guest memory to the host checkpoint store: it can persist secrets held in guest memory (for example an autologon password).","title":"Checkpoint Type","type":"string"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_createArguments","type":"object"}',
    'hyperv_checkpoint_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_listArguments","type":"object"}',
    'hyperv_checkpoint_remove': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Name of the checkpoint to remove","title":"Checkpoint Name","type":"string"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"include_subtree":{"default":false,"description":"Also remove all child checkpoints","title":"Include Subtree","type":"boolean"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_removeArguments","type":"object"}',
    'hyperv_checkpoint_restore': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Name of the checkpoint to restore","title":"Checkpoint Name","type":"string"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_restoreArguments","type":"object"}',
    'hyperv_configure_kdcom': '{"additionalProperties":false,"properties":{"com_port":{"default":1,"description":"1 or 2 (default 1)","title":"Com Port","type":"integer"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"pipe_name":{"default":"","description":"Named pipe path — auto-generated if omitted","title":"Pipe Name","type":"string"},"reboot":{"default":false,"description":"Reboot the guest after configuring","title":"Reboot","type":"boolean"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_configure_kdcomArguments","type":"object"}',
    'hyperv_configure_kdnet': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"host_ip":{"default":"","description":"Debugger host IP on the VM\'s vSwitch (IPv4/IPv6)","title":"Host Ip","type":"string"},"key":{"default":"","description":"kdnet key a.b.c.d hex — auto-generated if omitted","title":"Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"port":{"default":50000,"description":"UDP port (1024-65535)","title":"Port","type":"integer"},"reboot":{"default":false,"description":"Reboot the guest after configuring","title":"Reboot","type":"boolean"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_configure_kdnetArguments","type":"object"}',
    'hyperv_console_button': '{"additionalProperties":false,"properties":{"button":{"default":1,"description":"Button number (1=left, 2=right)","title":"Button","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"is_down":{"default":false,"description":"True presses the button, False releases it","title":"Is Down","type":"boolean"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_buttonArguments","type":"object"}',
    'hyperv_console_capture_sequence': '{"additionalProperties":false,"properties":{"count":{"default":3,"description":"Number of console frames to capture","title":"Count","type":"integer"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_s":{"default":2,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_capture_sequenceArguments","type":"object"}',
    'hyperv_console_click': '{"additionalProperties":false,"properties":{"button":{"default":1,"description":"Button number (1=left, 2=right)","title":"Button","type":"integer"},"commit_guard":{"default":false,"description":"Opt-in commit guard (issue #126): the click verifies a cited FRESH capture before committing — no console input to THAT VM dispatched through this server process since the capture (a per-VM ledger, still per-process across processes), and the live frame hash at the cited pixel domain still matches (the domain defaults from the cited record\'s frame_size like frame_hash above). Requires x/y coordinates — a click-at-current-position has no point to verify and is refused. Refusals are structured errors and send no mouse input; an allowed guard is audited","title":"Commit Guard","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"frame_hash":{"default":"","description":"Optional frame_hash of the capture the coordinates were observed on (issue #125): resolves against the server\'s capture registry, refuses when the capture was taken at a different head resolution (\\"stale frame\\"), maps through the capture\'s content_rect (a point inside a letterbox band is refused), and refuses shaped (cropped/scaled) captures. When frame_width/frame_height are omitted they default from the cited record\'s frame_size (a record without one refuses naming the requirement)","title":"Frame Hash","type":"string"},"frame_height":{"default":0,"description":"Frame height the coordinates were observed at (scales them)","title":"Frame Height","type":"integer"},"frame_width":{"default":0,"description":"Frame width the coordinates were observed at (scales them)","title":"Frame Width","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"verified_frame_hash":{"default":"","description":"The commit guard\'s verification: the frame_hash of a capture taken AFTER the most recent input (e.g. the selection screenshot), required when commit_guard is true","title":"Verified Frame Hash","type":"string"},"verified_state_receipt":{"default":"","description":"The commit guard\'s SECOND verification channel (issue #140): a state_receipt id minted by a UIA read tool (hyperv_ui_inspect/find/wait_for/ session_state) AFTER the most recent input — cite it INSTEAD of (mutually exclusive with) verified_frame_hash when the selection was verified by an accessibility read rather than a pixel capture. The receipt verifies by the per-VM input ledger only (per-server-process; no live-frame re-check leg, and no frame_width/frame_height pixel-domain requirement). Unknown/evicted citations refuse as unverified with no mouse input; an allowed guard is audited","title":"Verified State Receipt","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"x":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click X in the coordinate space of the observed frame (optional)","title":"X"},"y":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click Y in the coordinate space of the observed frame (optional)","title":"Y"}},"title":"hyperv_console_clickArguments","type":"object"}',
    'hyperv_console_get_display_info': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_get_display_infoArguments","type":"object"}',
    'hyperv_console_key_combo': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"keys":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Key combination as an ordered name list (modifiers make/break)","title":"Keys"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_key_comboArguments","type":"object"}',
    'hyperv_console_lock_state': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_lock_stateArguments","type":"object"}',
    'hyperv_console_mouse_move': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"frame_hash":{"default":"","description":"Optional frame_hash of the capture the coordinates were observed on (issue #125): resolves against the server\'s capture registry, refuses when the capture was taken at a different head resolution (\\"stale frame\\"), maps through the capture\'s content_rect (a point inside a letterbox band is refused), and refuses shaped (cropped/scaled) captures. When frame_width/frame_height are omitted they default from the cited record\'s frame_size (a record without one refuses naming the requirement)","title":"Frame Hash","type":"string"},"frame_height":{"default":0,"description":"Frame height the coordinates were observed at (scales them)","title":"Frame Height","type":"integer"},"frame_width":{"default":0,"description":"Frame width the coordinates were observed at (scales them)","title":"Frame Width","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"x":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click X in the coordinate space of the observed frame (optional)","title":"X"},"y":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click Y in the coordinate space of the observed frame (optional)","title":"Y"}},"title":"hyperv_console_mouse_moveArguments","type":"object"}',
    'hyperv_console_press_key': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"key":{"default":"","description":"A key name to press","title":"Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"modifiers":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Modifier key names held while the key is tapped","title":"Modifiers"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_press_keyArguments","type":"object"}',
    'hyperv_console_screenshot': '{"additionalProperties":false,"properties":{"crop":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"[left, top, right, bottom] in captured-frame pixels","title":"Crop"},"format":{"default":"","description":"png (default), jpeg/jpg, or webp; an unsupported format is refused as an invalid-input error, never silently ignored","title":"Format","type":"string"},"height":{"default":0,"description":"requested snapshot height (160..4096), or 0 (the default) to capture at the head\'s aspect for the width (issue #125; e.g. width=1024 at a 1920x1080 head captures 1024x576, which is band-free)","title":"Height","type":"integer"},"if_changed_from":{"default":"","description":"a frame_hash from a previous capture, as 64 lowercase hex characters; when it equals the current capture\'s hash the tool returns metadata only (no image) and skips decode, encode and the file write — but still applies the save_path policy check, so an out-of-roots path is denied on both paths","title":"If Changed From","type":"string"},"quality":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"1..100; applies to jpeg/webp only. An out-of-range value is refused whatever the format, including png — png has no quality axis, so an in-range value there is accepted and has no effect (it is echoed in the metadata as `quality`)","title":"Quality"},"save_path":{"default":"","description":"optional host path to also save the image (host_write policy); the bytes written are exactly the bytes returned","title":"Save Path","type":"string"},"scale":{"anyOf":[{"type":"number"},{"type":"null"}],"default":null,"description":"downscale factor in (0, 1] applied after crop; 1.0 is a no-op and leaves the frame byte-identical","title":"Scale"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":1024,"description":"requested snapshot width (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_screenshotArguments","type":"object"}',
    'hyperv_console_scroll': '{"additionalProperties":false,"properties":{"delta":{"default":0,"description":"Wheel delta (positive = down)","title":"Delta","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_scrollArguments","type":"object"}',
    'hyperv_console_sequence': '{"additionalProperties":false,"properties":{"expect_boot_epoch":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"integer from hyperv_console_get_display_info, or None","title":"Expect Boot Epoch"},"expect_frame_hash":{"default":"","description":"\\"\\" or 64-char hex sha256 captured at width x height","title":"Expect Frame Hash","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"height":{"default":480,"description":"Capture geometry shared by preconditions and wait steps","title":"Height","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"request_key":{"default":"","description":"Optional correlation key for the UNKNOWN no-replay contract","title":"Request Key","type":"string"},"steps":{"description":"1..50 step dicts (grammar above); invalid steps raise ValueError naming the step index before any PowerShell runs","items":{"additionalProperties":true,"type":"object"},"title":"Steps","type":"array"},"timeout_s":{"default":60,"description":"Overall deadline (>= 1); child bound is timeout_s + 15","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Capture geometry shared by preconditions and wait steps","title":"Width","type":"integer"}},"required":["steps"],"title":"hyperv_console_sequenceArguments","type":"object"}',
    'hyperv_console_type_scancodes': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"scancodes":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"PS/2 scan-code sequence (make/break pairs included)","title":"Scancodes"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_type_scancodesArguments","type":"object"}',
    'hyperv_console_type_text': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; the value is typed, only its length is reported (mutually exclusive with text)","title":"Secret Ref","type":"string"},"text":{"default":"","description":"Text to type into the guest console","title":"Text","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_type_textArguments","type":"object"}',
    'hyperv_console_unlock': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; required","title":"Secret Ref","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_unlockArguments","type":"object"}',
    'hyperv_console_wait_frame_change': '{"additionalProperties":false,"properties":{"baseline_hash":{"default":"","description":"frame_hash from a previous capture (\\"\\" compares against nothing — first poll\'s frame is baseline)","title":"Baseline Hash","type":"string"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_s":{"default":2,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"timeout_s":{"default":60,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_wait_frame_changeArguments","type":"object"}',
    'hyperv_console_wait_frame_stable': '{"additionalProperties":false,"properties":{"baseline_hash":{"default":"","description":"frame_hash from before the input (\\"\\" settles on the current screen — first poll starts the quiet window)","title":"Baseline Hash","type":"string"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_ms":{"default":250,"description":"Poll interval in milliseconds","title":"Interval Ms","type":"integer"},"stable_ms":{"default":1500,"description":"Required quiet window (>= 1 and < timeout_s*1000)","title":"Stable Ms","type":"integer"},"timeout_s":{"default":30,"description":"Overall deadline (>= 1); the host-side child bound is timeout_s + 15","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_wait_frame_stableArguments","type":"object"}',
    'hyperv_deployment_status': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_deployment_statusArguments","type":"object"}',
    'hyperv_diagnose_vm_access': '{"additionalProperties":false,"properties":{"timeout_ms":{"default":90000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_diagnose_vm_accessArguments","type":"object"}',
    'hyperv_events': '{"additionalProperties":false,"properties":{"after":{"default":"","description":"Resume cursor from a previous read","title":"After","type":"string"},"limit":{"default":100,"description":"Maximum events to return","title":"Limit","type":"integer"}},"title":"hyperv_eventsArguments","type":"object"}',
    'hyperv_get_vm_info': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_get_vm_infoArguments","type":"object"}',
    'hyperv_guest_get': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"local_path":{"default":"","description":"Path on the host (policy-checked against host roots)","title":"Local Path","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"verify":{"anyOf":[{"type":"boolean"},{"type":"null"}],"default":null,"description":"Verify the transferred bytes with SHA-256 after the copy","title":"Verify"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_getArguments","type":"object"}',
    'hyperv_guest_job_output': '{"additionalProperties":false,"properties":{"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"},"tail_bytes":{"default":65536,"description":"Read the last N bytes of each stream","title":"Tail Bytes","type":"integer"}},"required":["job_id"],"title":"hyperv_guest_job_outputArguments","type":"object"}',
    'hyperv_guest_job_start': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"cwd":{"default":"","description":"Working directory for the guest command","title":"Cwd","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_job_startArguments","type":"object"}',
    'hyperv_guest_job_status': '{"additionalProperties":false,"properties":{"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"}},"required":["job_id"],"title":"hyperv_guest_job_statusArguments","type":"object"}',
    'hyperv_guest_job_stop': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"}},"required":["job_id"],"title":"hyperv_guest_job_stopArguments","type":"object"}',
    'hyperv_guest_list_dir': '{"additionalProperties":false,"properties":{"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_list_dirArguments","type":"object"}',
    'hyperv_guest_put': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"local_path":{"default":"","description":"Path on the host (policy-checked against host roots)","title":"Local Path","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"verify":{"anyOf":[{"type":"boolean"},{"type":"null"}],"default":null,"description":"Verify the transferred bytes with SHA-256 after the copy","title":"Verify"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_putArguments","type":"object"}',
    'hyperv_guest_read_file': '{"additionalProperties":false,"properties":{"max_bytes":{"default":262144,"description":"Read cap in bytes (bounded stream read)","title":"Max Bytes","type":"integer"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_read_fileArguments","type":"object"}',
    'hyperv_guest_run': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the guest command","title":"Cwd"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"elevated":{"default":false,"description":"Run elevated in the guest (destructive.elevated_exec + confirm)","title":"Elevated","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_runArguments","type":"object"}',
    'hyperv_guest_run_ps': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"elevated":{"default":false,"description":"Run elevated in the guest (destructive.elevated_exec + confirm)","title":"Elevated","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"script":{"default":"","description":"PowerShell script text to run in the guest","title":"Script","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_run_psArguments","type":"object"}',
    'hyperv_harvest_offline_logs': '{"additionalProperties":false,"properties":{"dest_dir":{"default":"","description":"Directory on the host to copy the harvested logs into","title":"Dest Dir","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_harvest_offline_logsArguments","type":"object"}',
    'hyperv_lease_acquire': '{"additionalProperties":false,"properties":{"scopes":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Lease scopes to acquire (e.g. lifecycle, guest_exec, transfer)","title":"Scopes"},"ttl_s":{"default":0,"description":"Lease time-to-live in seconds","title":"Ttl S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_lease_acquireArguments","type":"object"}',
    'hyperv_lease_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_lease_listArguments","type":"object"}',
    'hyperv_lease_release': '{"additionalProperties":false,"properties":{"lease_id":{"description":"REQUIRED - the id of the lease being released","title":"Lease Id","type":"string"}},"required":["lease_id"],"title":"hyperv_lease_releaseArguments","type":"object"}',
    'hyperv_lease_renew': '{"additionalProperties":false,"properties":{"lease_id":{"description":"REQUIRED - the id of the lease being renewed","title":"Lease Id","type":"string"}},"required":["lease_id"],"title":"hyperv_lease_renewArguments","type":"object"}',
    'hyperv_list_vms': '{"additionalProperties":false,"properties":{},"title":"hyperv_list_vmsArguments","type":"object"}',
    'hyperv_op_cancel': '{"additionalProperties":false,"properties":{"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_cancelArguments","type":"object"}',
    'hyperv_op_list': '{"additionalProperties":false,"properties":{"include_terminal":{"default":false,"description":"Also list finished operations","title":"Include Terminal","type":"boolean"}},"title":"hyperv_op_listArguments","type":"object"}',
    'hyperv_op_result': '{"additionalProperties":false,"properties":{"cursor":{"default":"","description":"Continuation cursor from a previous paged result","title":"Cursor","type":"string"},"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_resultArguments","type":"object"}',
    'hyperv_op_status': '{"additionalProperties":false,"properties":{"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_statusArguments","type":"object"}',
    'hyperv_relay_start': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"guest_port":{"default":0,"description":"Guest-local port to relay to (loopback)","title":"Guest Port","type":"integer"},"host_port":{"default":0,"description":"Host-side loopback listener port","title":"Host Port","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_relay_startArguments","type":"object"}',
    'hyperv_relay_status': '{"additionalProperties":false,"properties":{"relay_id":{"default":"","description":"Relay id returned by relay_start","title":"Relay Id","type":"string"}},"title":"hyperv_relay_statusArguments","type":"object"}',
    'hyperv_relay_stop': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"relay_id":{"description":"Relay id returned by relay_start","title":"Relay Id","type":"string"}},"required":["relay_id"],"title":"hyperv_relay_stopArguments","type":"object"}',
    'hyperv_repair_guest_access': '{"additionalProperties":false,"properties":{"apply":{"default":false,"description":"Propose only by default; pass true with confirm to apply repairs","title":"Apply","type":"boolean"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_repair_guest_accessArguments","type":"object"}',
    'hyperv_reset_vm': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_reset_vmArguments","type":"object"}',
    'hyperv_server_info': '{"additionalProperties":false,"properties":{},"title":"hyperv_server_infoArguments","type":"object"}',
    'hyperv_start_vm': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_start_vmArguments","type":"object"}',
    'hyperv_stop_vm': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"method":{"default":"shutdown","description":"\\"shutdown\\" — graceful guest shutdown via Integration Services, then waits for Off (default) \\"shutdown-force\\" — force shutdown (data-loss risk) \\"save\\" — suspend to disk (final state Saved) \\"turnoff\\" — hard power-off","title":"Method","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_stop_vmArguments","type":"object"}',
    'hyperv_ui_act': '{"additionalProperties":false,"properties":{"action":{"default":"","description":"one of invoke, toggle_on, toggle_off, select, expand, collapse, set_value, focus, scroll_into_view, click","title":"Action","type":"string"},"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried — take a fresh hyperv_ui_snapshot","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"value":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"the text to set (set_value only, <= 64 KiB; rides the framed payload, never script text; the result reports the length only)","title":"Value"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_actArguments","type":"object"}',
    'hyperv_ui_find': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — refused adapter_unapproved unless the registration carries the adapter:electron capability","title":"Adapter","type":"string"},"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect (\\"42:1024\\" form) — resolves the live element by id","title":"Element Id","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137; the snapshot id may be hex, the index decimal) — resolves the element captured by that hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref pointing at a fresh snapshot, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector (accepted keys: automation_id, name, name_contains, control_type, class_name, window_title, window_title_contains, process_name, hwnd, index, scope); a selector with no window scope searches the FOREGROUND window (scope: foreground default / window / all_windows)","title":"Selector"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_findArguments","type":"object"}',
    'hyperv_ui_focus': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_focusArguments","type":"object"}',
    'hyperv_ui_helper_provision': '{"additionalProperties":false,"properties":{"autologon":{"default":true,"description":"configure automatic logon for the guest account (default true; ignored by teardown)","title":"Autologon","type":"boolean"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"teardown":{"default":false,"description":"true removes the helper instead of installing it","title":"Teardown","type":"boolean"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_helper_provisionArguments","type":"object"}',
    'hyperv_ui_inspect': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — an Electron adapter request is refused adapter_unapproved unless the helper registration carries the adapter:electron capability","title":"Adapter","type":"string"},"depth":{"default":3,"description":"Walk depth (1..32, default 3; one clamp shared with evidence\'s PS Direct walk and the helper)","title":"Depth","type":"integer"},"max_elements":{"default":200,"description":"Element cap (1..500, default 200; the same clamp as evidence\'s walk)","title":"Max Elements","type":"integer"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector scoping the walk (accepted keys: automation_id, name, name_contains, control_type, class_name, window_title, window_title_contains, process_name, hwnd, index, scope); with a selector the walk starts at the matched element, without it at the FOREGROUND window (the scope key picks the breadth: foreground default / window / all_windows)","title":"Selector"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_inspectArguments","type":"object"}',
    'hyperv_ui_invoke': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_invokeArguments","type":"object"}',
    'hyperv_ui_session_state': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_session_stateArguments","type":"object"}',
    'hyperv_ui_set_value': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; the resolved value is set, only the length is reported (mutually exclusive with value)","title":"Secret Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"value":{"default":"","description":"the text to set (<= 64 KiB)","title":"Value","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_set_valueArguments","type":"object"}',
    'hyperv_ui_snapshot': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — an Electron adapter request is refused adapter_unapproved unless the helper registration carries the adapter:electron capability","title":"Adapter","type":"string"},"max_elements":{"default":250,"description":"element cap (1..500, default 250)","title":"Max Elements","type":"integer"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"optional UIA selector picking the window (accepted keys: hwnd, window_title, window_title_contains, process_name, scope; a selector with no window scope searches the FOREGROUND window)","title":"Selector"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_snapshotArguments","type":"object"}',
    'hyperv_ui_wait_for': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect — address the target by exactly one of selector=, element_id= or ref=","title":"Element Id","type":"string"},"gone":{"default":false,"description":"true waits for DISAPPEARANCE instead of appearance","title":"Gone","type":"boolean"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector waited for (accepted keys as find; a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"state":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"wait until every given element/state property matches (a non-empty dict; matching spans element-level properties and the nested state block)","title":"State"},"timeout_s":{"default":30,"description":"wait budget in seconds (1..120, default 30)","title":"Timeout S","type":"integer"},"value":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"wait until the element\'s state.value equals this (empty string is a legitimate predicate; omit for none)","title":"Value"},"value_contains":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"wait until the element\'s state.value contains this substring","title":"Value Contains"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_wait_forArguments","type":"object"}',
    'hyperv_victim_run': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the guest command","title":"Cwd"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_victim_runArguments","type":"object"}',
    'hyperv_victim_run_ps': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"script":{"default":"","description":"PowerShell script text to run in the guest","title":"Script","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_victim_run_psArguments","type":"object"}',
    'hyperv_vm_clone': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cpu_count":{"default":1,"description":"Virtual processor count","title":"Cpu Count","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"generation":{"default":2,"description":"VM generation (1 or 2)","title":"Generation","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"memory_mb":{"default":2048,"description":"Startup memory in MB","title":"Memory Mb","type":"integer"},"name":{"description":"New VM name (must match allowed_vm_patterns)","title":"Name","type":"string"},"parent_vhd_path":{"description":"Read-only golden parent VHDX path (host_read_roots)","title":"Parent Vhd Path","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vhd_path":{"description":"Path for the new VHDX (policy-checked against host_write_roots)","title":"Vhd Path","type":"string"}},"required":["name","parent_vhd_path","vhd_path"],"title":"hyperv_vm_cloneArguments","type":"object"}',
    'hyperv_vm_create': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cpu_count":{"default":1,"description":"Virtual processor count","title":"Cpu Count","type":"integer"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"generation":{"default":2,"description":"VM generation (1 or 2)","title":"Generation","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"memory_mb":{"default":2048,"description":"Startup memory in MB","title":"Memory Mb","type":"integer"},"name":{"description":"New VM name (must match allowed_vm_patterns)","title":"Name","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vhd_path":{"description":"Path for the new VHDX (policy-checked against host_write_roots)","title":"Vhd Path","type":"string"},"vhd_size_gb":{"default":64,"description":"VHDX size in GB","title":"Vhd Size Gb","type":"integer"}},"required":["name","vhd_path"],"title":"hyperv_vm_createArguments","type":"object"}',
    'hyperv_vm_disk_add': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"controller_type":{"default":"SCSI","description":"Disk controller type (default SCSI)","title":"Controller Type","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"path":{"default":"","description":"Path of the VHDX to attach","title":"Path","type":"string"},"size_gb":{"default":0,"description":"Size in GB for the new VHDX","title":"Size Gb","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_disk_addArguments","type":"object"}',
    'hyperv_vm_disk_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_disk_listArguments","type":"object"}',
    'hyperv_vm_firmware_get': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_firmware_getArguments","type":"object"}',
    'hyperv_vm_firmware_set_boot_order': '{"additionalProperties":false,"properties":{"boot_type":{"default":"Drive","description":"First boot device type: Drive | Network | File","title":"Boot Type","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_firmware_set_boot_orderArguments","type":"object"}',
    'hyperv_vm_get_video': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_get_videoArguments","type":"object"}',
    'hyperv_vm_media_attach': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"iso_path":{"default":"","description":"Path of the ISO to attach (host_read policy)","title":"Iso Path","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_attachArguments","type":"object"}',
    'hyperv_vm_media_detach': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_detachArguments","type":"object"}',
    'hyperv_vm_media_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_listArguments","type":"object"}',
    'hyperv_vm_network_set': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_network_setArguments","type":"object"}',
    'hyperv_vm_remove': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"delete_disks":{"default":false,"description":"Also delete this VM\'s own disk files (never the parent)","title":"Delete Disks","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_removeArguments","type":"object"}',
    'hyperv_vm_secureboot_set': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"enabled":{"description":"REQUIRED — true to enable, false to disable (omission is a schema error; it never silently defaults to disable)","title":"Enabled","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"template":{"default":"","description":"Secure Boot template (e.g. MicrosoftWindows)","title":"Template","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"required":["enabled"],"title":"hyperv_vm_secureboot_setArguments","type":"object"}',
    'hyperv_vm_set_resolution': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"required for the stop/start when restart=true","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"height":{"default":0,"description":"Vertical resolution in pixels (160..4096; required unless resolution_type is \\"default\\")","title":"Height","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"resolution_type":{"default":"single","description":"single | maximum | default","title":"Resolution Type","type":"string"},"restart":{"default":false,"description":"stop/start the VM now so the mode applies immediately","title":"Restart","type":"boolean"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"},"width":{"default":0,"description":"Horizontal resolution in pixels (160..4096; required unless resolution_type is \\"default\\")","title":"Width","type":"integer"}},"title":"hyperv_vm_set_resolutionArguments","type":"object"}',
    'hyperv_vm_tpm_set': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"enabled":{"description":"REQUIRED — true to enable, false to disable (omission is a schema error; it never silently defaults to disable)","title":"Enabled","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"required":["enabled"],"title":"hyperv_vm_tpm_setArguments","type":"object"}',
    'hyperv_wait_guest_recovery': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"interval_s":{"default":3,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"processes":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Guest process names to verify present after restart","title":"Processes"},"services":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Guest service names to verify Running after restart","title":"Services"},"timeout_s":{"default":300,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_wait_guest_recoveryArguments","type":"object"}',
    'hyperv_wait_vm_state': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"states":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"States to wait for (Off/Running/Saved/Paused/Starting/Stopping/Resuming/Pausing)","title":"States"},"timeout_s":{"default":300,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_wait_vm_stateArguments","type":"object"}',
}


#: The same freeze under ``allow_inline_credentials=True``: the guest and
#: UIA tools that accept inline credentials publish their username /
#: password parameters (and the docstring lines describing them); every
#: other tool is identical to the default variant's entry.
FROZEN_SCHEMAS_INLINE_JSON: dict[str, str] = {
    'hyperv_capture_evidence': '{"additionalProperties":false,"properties":{"crop":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"[left, top, right, bottom] in captured-frame pixels","title":"Crop"},"format":{"default":"","description":"png (default), jpeg/jpg, or webp; an unsupported format is refused as an invalid-input error","title":"Format","type":"string"},"height":{"default":768,"description":"requested screenshot height in pixels (160..4096)","title":"Height","type":"integer"},"if_changed_from":{"default":"","description":"a frame_hash from a previous capture, as 64 lowercase hex characters; when it equals the current capture\'s hash the tool returns metadata only and skips decode, encode, the file write AND the UI-tree leg (meta[\\"ui_tree\\"] then reports why it was skipped)","title":"If Changed From","type":"string"},"password":{"default":"","description":"guest password for the UI-tree leg (or set HYPERV_GUEST_PASSWORD)","title":"Password","type":"string"},"quality":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"1..100; applies to jpeg/webp only. An out-of-range value is refused whatever the format, including png — png has no quality axis, so an in-range value there is accepted and has no effect","title":"Quality"},"save_path":{"default":"","description":"optional host path to also write the PNG/encoded image","title":"Save Path","type":"string"},"scale":{"anyOf":[{"type":"number"},{"type":"null"}],"default":null,"description":"downscale factor in (0, 1] applied after crop","title":"Scale"},"ui_tree":{"default":false,"description":"also fetch a bounded guest UI element tree (needs credentials)","title":"Ui Tree","type":"boolean"},"ui_tree_depth":{"default":3,"description":"tree walk depth, clamped to 1..32","title":"Ui Tree Depth","type":"integer"},"ui_tree_max_elements":{"default":200,"description":"element cap, clamped to 1..500","title":"Ui Tree Max Elements","type":"integer"},"username":{"default":"","description":"guest username for the UI-tree leg (or set HYPERV_GUEST_USERNAME)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"},"width":{"default":1024,"description":"requested screenshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_capture_evidenceArguments","type":"object"}',
    'hyperv_checkpoint_create': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Label (auto timestamp if omitted)","title":"Checkpoint Name","type":"string"},"checkpoint_type":{"default":"","description":"\\"standard\\", \\"production\\", \\"production_only\\", or \\"\\" (default: the VM\'s own setting). Production falls back to Standard on guests without production-checkpoint support, and ProductionOnly fails instead. A Standard checkpoint — including a Production fallback — writes guest memory to the host checkpoint store: it can persist secrets held in guest memory (for example an autologon password).","title":"Checkpoint Type","type":"string"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_createArguments","type":"object"}',
    'hyperv_checkpoint_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_listArguments","type":"object"}',
    'hyperv_checkpoint_remove': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Name of the checkpoint to remove","title":"Checkpoint Name","type":"string"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"include_subtree":{"default":false,"description":"Also remove all child checkpoints","title":"Include Subtree","type":"boolean"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_removeArguments","type":"object"}',
    'hyperv_checkpoint_restore': '{"additionalProperties":false,"properties":{"checkpoint_name":{"default":"","description":"Name of the checkpoint to restore","title":"Checkpoint Name","type":"string"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_checkpoint_restoreArguments","type":"object"}',
    'hyperv_configure_kdcom': '{"additionalProperties":false,"properties":{"com_port":{"default":1,"description":"1 or 2 (default 1)","title":"Com Port","type":"integer"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"pipe_name":{"default":"","description":"Named pipe path — auto-generated if omitted","title":"Pipe Name","type":"string"},"reboot":{"default":false,"description":"Reboot the guest after configuring","title":"Reboot","type":"boolean"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_configure_kdcomArguments","type":"object"}',
    'hyperv_configure_kdnet': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"host_ip":{"default":"","description":"Debugger host IP on the VM\'s vSwitch (IPv4/IPv6)","title":"Host Ip","type":"string"},"key":{"default":"","description":"kdnet key a.b.c.d hex — auto-generated if omitted","title":"Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"port":{"default":50000,"description":"UDP port (1024-65535)","title":"Port","type":"integer"},"reboot":{"default":false,"description":"Reboot the guest after configuring","title":"Reboot","type":"boolean"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_configure_kdnetArguments","type":"object"}',
    'hyperv_console_button': '{"additionalProperties":false,"properties":{"button":{"default":1,"description":"Button number (1=left, 2=right)","title":"Button","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"is_down":{"default":false,"description":"True presses the button, False releases it","title":"Is Down","type":"boolean"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_buttonArguments","type":"object"}',
    'hyperv_console_capture_sequence': '{"additionalProperties":false,"properties":{"count":{"default":3,"description":"Number of console frames to capture","title":"Count","type":"integer"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_s":{"default":2,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_capture_sequenceArguments","type":"object"}',
    'hyperv_console_click': '{"additionalProperties":false,"properties":{"button":{"default":1,"description":"Button number (1=left, 2=right)","title":"Button","type":"integer"},"commit_guard":{"default":false,"description":"Opt-in commit guard (issue #126): the click verifies a cited FRESH capture before committing — no console input to THAT VM dispatched through this server process since the capture (a per-VM ledger, still per-process across processes), and the live frame hash at the cited pixel domain still matches (the domain defaults from the cited record\'s frame_size like frame_hash above). Requires x/y coordinates — a click-at-current-position has no point to verify and is refused. Refusals are structured errors and send no mouse input; an allowed guard is audited","title":"Commit Guard","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"frame_hash":{"default":"","description":"Optional frame_hash of the capture the coordinates were observed on (issue #125): resolves against the server\'s capture registry, refuses when the capture was taken at a different head resolution (\\"stale frame\\"), maps through the capture\'s content_rect (a point inside a letterbox band is refused), and refuses shaped (cropped/scaled) captures. When frame_width/frame_height are omitted they default from the cited record\'s frame_size (a record without one refuses naming the requirement)","title":"Frame Hash","type":"string"},"frame_height":{"default":0,"description":"Frame height the coordinates were observed at (scales them)","title":"Frame Height","type":"integer"},"frame_width":{"default":0,"description":"Frame width the coordinates were observed at (scales them)","title":"Frame Width","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"verified_frame_hash":{"default":"","description":"The commit guard\'s verification: the frame_hash of a capture taken AFTER the most recent input (e.g. the selection screenshot), required when commit_guard is true","title":"Verified Frame Hash","type":"string"},"verified_state_receipt":{"default":"","description":"The commit guard\'s SECOND verification channel (issue #140): a state_receipt id minted by a UIA read tool (hyperv_ui_inspect/find/wait_for/ session_state) AFTER the most recent input — cite it INSTEAD of (mutually exclusive with) verified_frame_hash when the selection was verified by an accessibility read rather than a pixel capture. The receipt verifies by the per-VM input ledger only (per-server-process; no live-frame re-check leg, and no frame_width/frame_height pixel-domain requirement). Unknown/evicted citations refuse as unverified with no mouse input; an allowed guard is audited","title":"Verified State Receipt","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"x":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click X in the coordinate space of the observed frame (optional)","title":"X"},"y":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click Y in the coordinate space of the observed frame (optional)","title":"Y"}},"title":"hyperv_console_clickArguments","type":"object"}',
    'hyperv_console_get_display_info': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_get_display_infoArguments","type":"object"}',
    'hyperv_console_key_combo': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"keys":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Key combination as an ordered name list (modifiers make/break)","title":"Keys"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_key_comboArguments","type":"object"}',
    'hyperv_console_lock_state': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_lock_stateArguments","type":"object"}',
    'hyperv_console_mouse_move': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"frame_hash":{"default":"","description":"Optional frame_hash of the capture the coordinates were observed on (issue #125): resolves against the server\'s capture registry, refuses when the capture was taken at a different head resolution (\\"stale frame\\"), maps through the capture\'s content_rect (a point inside a letterbox band is refused), and refuses shaped (cropped/scaled) captures. When frame_width/frame_height are omitted they default from the cited record\'s frame_size (a record without one refuses naming the requirement)","title":"Frame Hash","type":"string"},"frame_height":{"default":0,"description":"Frame height the coordinates were observed at (scales them)","title":"Frame Height","type":"integer"},"frame_width":{"default":0,"description":"Frame width the coordinates were observed at (scales them)","title":"Frame Width","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"x":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click X in the coordinate space of the observed frame (optional)","title":"X"},"y":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"Click Y in the coordinate space of the observed frame (optional)","title":"Y"}},"title":"hyperv_console_mouse_moveArguments","type":"object"}',
    'hyperv_console_press_key': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"key":{"default":"","description":"A key name to press","title":"Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"modifiers":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Modifier key names held while the key is tapped","title":"Modifiers"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_press_keyArguments","type":"object"}',
    'hyperv_console_screenshot': '{"additionalProperties":false,"properties":{"crop":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"[left, top, right, bottom] in captured-frame pixels","title":"Crop"},"format":{"default":"","description":"png (default), jpeg/jpg, or webp; an unsupported format is refused as an invalid-input error, never silently ignored","title":"Format","type":"string"},"height":{"default":0,"description":"requested snapshot height (160..4096), or 0 (the default) to capture at the head\'s aspect for the width (issue #125; e.g. width=1024 at a 1920x1080 head captures 1024x576, which is band-free)","title":"Height","type":"integer"},"if_changed_from":{"default":"","description":"a frame_hash from a previous capture, as 64 lowercase hex characters; when it equals the current capture\'s hash the tool returns metadata only (no image) and skips decode, encode and the file write — but still applies the save_path policy check, so an out-of-roots path is denied on both paths","title":"If Changed From","type":"string"},"quality":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"1..100; applies to jpeg/webp only. An out-of-range value is refused whatever the format, including png — png has no quality axis, so an in-range value there is accepted and has no effect (it is echoed in the metadata as `quality`)","title":"Quality"},"save_path":{"default":"","description":"optional host path to also save the image (host_write policy); the bytes written are exactly the bytes returned","title":"Save Path","type":"string"},"scale":{"anyOf":[{"type":"number"},{"type":"null"}],"default":null,"description":"downscale factor in (0, 1] applied after crop; 1.0 is a no-op and leaves the frame byte-identical","title":"Scale"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":1024,"description":"requested snapshot width (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_screenshotArguments","type":"object"}',
    'hyperv_console_scroll': '{"additionalProperties":false,"properties":{"delta":{"default":0,"description":"Wheel delta (positive = down)","title":"Delta","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_scrollArguments","type":"object"}',
    'hyperv_console_sequence': '{"additionalProperties":false,"properties":{"expect_boot_epoch":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null,"description":"integer from hyperv_console_get_display_info, or None","title":"Expect Boot Epoch"},"expect_frame_hash":{"default":"","description":"\\"\\" or 64-char hex sha256 captured at width x height","title":"Expect Frame Hash","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"height":{"default":480,"description":"Capture geometry shared by preconditions and wait steps","title":"Height","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"request_key":{"default":"","description":"Optional correlation key for the UNKNOWN no-replay contract","title":"Request Key","type":"string"},"steps":{"description":"1..50 step dicts (grammar above); invalid steps raise ValueError naming the step index before any PowerShell runs","items":{"additionalProperties":true,"type":"object"},"title":"Steps","type":"array"},"timeout_s":{"default":60,"description":"Overall deadline (>= 1); child bound is timeout_s + 15","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Capture geometry shared by preconditions and wait steps","title":"Width","type":"integer"}},"required":["steps"],"title":"hyperv_console_sequenceArguments","type":"object"}',
    'hyperv_console_type_scancodes': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"scancodes":{"anyOf":[{"items":{"type":"integer"},"type":"array"},{"type":"null"}],"default":null,"description":"PS/2 scan-code sequence (make/break pairs included)","title":"Scancodes"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_type_scancodesArguments","type":"object"}',
    'hyperv_console_type_text': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; the value is typed, only its length is reported (mutually exclusive with text)","title":"Secret Ref","type":"string"},"text":{"default":"","description":"Text to type into the guest console","title":"Text","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_type_textArguments","type":"object"}',
    'hyperv_console_unlock': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; required","title":"Secret Ref","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_console_unlockArguments","type":"object"}',
    'hyperv_console_wait_frame_change': '{"additionalProperties":false,"properties":{"baseline_hash":{"default":"","description":"frame_hash from a previous capture (\\"\\" compares against nothing — first poll\'s frame is baseline)","title":"Baseline Hash","type":"string"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_s":{"default":2,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"timeout_s":{"default":60,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_wait_frame_changeArguments","type":"object"}',
    'hyperv_console_wait_frame_stable': '{"additionalProperties":false,"properties":{"baseline_hash":{"default":"","description":"frame_hash from before the input (\\"\\" settles on the current screen — first poll starts the quiet window)","title":"Baseline Hash","type":"string"},"height":{"default":480,"description":"Requested snapshot height in pixels (160..4096)","title":"Height","type":"integer"},"interval_ms":{"default":250,"description":"Poll interval in milliseconds","title":"Interval Ms","type":"integer"},"stable_ms":{"default":1500,"description":"Required quiet window (>= 1 and < timeout_s*1000)","title":"Stable Ms","type":"integer"},"timeout_s":{"default":30,"description":"Overall deadline (>= 1); the host-side child bound is timeout_s + 15","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"VM name (must match allowed_vm_patterns)","title":"Vm Name","type":"string"},"width":{"default":640,"description":"Requested snapshot width in pixels (160..4096)","title":"Width","type":"integer"}},"title":"hyperv_console_wait_frame_stableArguments","type":"object"}',
    'hyperv_deployment_status': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_deployment_statusArguments","type":"object"}',
    'hyperv_diagnose_vm_access': '{"additionalProperties":false,"properties":{"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"timeout_ms":{"default":90000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_diagnose_vm_accessArguments","type":"object"}',
    'hyperv_events': '{"additionalProperties":false,"properties":{"after":{"default":"","description":"Resume cursor from a previous read","title":"After","type":"string"},"limit":{"default":100,"description":"Maximum events to return","title":"Limit","type":"integer"}},"title":"hyperv_eventsArguments","type":"object"}',
    'hyperv_get_vm_info': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_get_vm_infoArguments","type":"object"}',
    'hyperv_guest_get': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"local_path":{"default":"","description":"Path on the host (policy-checked against host roots)","title":"Local Path","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"verify":{"anyOf":[{"type":"boolean"},{"type":"null"}],"default":null,"description":"Verify the transferred bytes with SHA-256 after the copy","title":"Verify"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_getArguments","type":"object"}',
    'hyperv_guest_job_output': '{"additionalProperties":false,"properties":{"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"},"tail_bytes":{"default":65536,"description":"Read the last N bytes of each stream","title":"Tail Bytes","type":"integer"}},"required":["job_id"],"title":"hyperv_guest_job_outputArguments","type":"object"}',
    'hyperv_guest_job_start': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"cwd":{"default":"","description":"Working directory for the guest command","title":"Cwd","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_job_startArguments","type":"object"}',
    'hyperv_guest_job_status': '{"additionalProperties":false,"properties":{"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"}},"required":["job_id"],"title":"hyperv_guest_job_statusArguments","type":"object"}',
    'hyperv_guest_job_stop': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"job_id":{"description":"Job id returned by job_start","title":"Job Id","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"}},"required":["job_id"],"title":"hyperv_guest_job_stopArguments","type":"object"}',
    'hyperv_guest_list_dir': '{"additionalProperties":false,"properties":{"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_list_dirArguments","type":"object"}',
    'hyperv_guest_put': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"local_path":{"default":"","description":"Path on the host (policy-checked against host roots)","title":"Local Path","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"verify":{"anyOf":[{"type":"boolean"},{"type":"null"}],"default":null,"description":"Verify the transferred bytes with SHA-256 after the copy","title":"Verify"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_putArguments","type":"object"}',
    'hyperv_guest_read_file': '{"additionalProperties":false,"properties":{"max_bytes":{"default":262144,"description":"Read cap in bytes (bounded stream read)","title":"Max Bytes","type":"integer"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"remote_path":{"default":"","description":"Path in the guest filesystem","title":"Remote Path","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_read_fileArguments","type":"object"}',
    'hyperv_guest_run': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the guest command","title":"Cwd"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"elevated":{"default":false,"description":"Run elevated in the guest (destructive.elevated_exec + confirm)","title":"Elevated","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_runArguments","type":"object"}',
    'hyperv_guest_run_ps': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"elevated":{"default":false,"description":"Run elevated in the guest (destructive.elevated_exec + confirm)","title":"Elevated","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"script":{"default":"","description":"PowerShell script text to run in the guest","title":"Script","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_run_psArguments","type":"object"}',
    'hyperv_harvest_offline_logs': '{"additionalProperties":false,"properties":{"dest_dir":{"default":"","description":"Directory on the host to copy the harvested logs into","title":"Dest Dir","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_harvest_offline_logsArguments","type":"object"}',
    'hyperv_lease_acquire': '{"additionalProperties":false,"properties":{"scopes":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Lease scopes to acquire (e.g. lifecycle, guest_exec, transfer)","title":"Scopes"},"ttl_s":{"default":0,"description":"Lease time-to-live in seconds","title":"Ttl S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_lease_acquireArguments","type":"object"}',
    'hyperv_lease_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_lease_listArguments","type":"object"}',
    'hyperv_lease_release': '{"additionalProperties":false,"properties":{"lease_id":{"description":"REQUIRED - the id of the lease being released","title":"Lease Id","type":"string"}},"required":["lease_id"],"title":"hyperv_lease_releaseArguments","type":"object"}',
    'hyperv_lease_renew': '{"additionalProperties":false,"properties":{"lease_id":{"description":"REQUIRED - the id of the lease being renewed","title":"Lease Id","type":"string"}},"required":["lease_id"],"title":"hyperv_lease_renewArguments","type":"object"}',
    'hyperv_list_vms': '{"additionalProperties":false,"properties":{},"title":"hyperv_list_vmsArguments","type":"object"}',
    'hyperv_op_cancel': '{"additionalProperties":false,"properties":{"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_cancelArguments","type":"object"}',
    'hyperv_op_list': '{"additionalProperties":false,"properties":{"include_terminal":{"default":false,"description":"Also list finished operations","title":"Include Terminal","type":"boolean"}},"title":"hyperv_op_listArguments","type":"object"}',
    'hyperv_op_result': '{"additionalProperties":false,"properties":{"cursor":{"default":"","description":"Continuation cursor from a previous paged result","title":"Cursor","type":"string"},"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_resultArguments","type":"object"}',
    'hyperv_op_status': '{"additionalProperties":false,"properties":{"op_id":{"description":"Operation handle id returned by the starting tool","title":"Op Id","type":"string"}},"required":["op_id"],"title":"hyperv_op_statusArguments","type":"object"}',
    'hyperv_relay_start': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"guest_port":{"default":0,"description":"Guest-local port to relay to (loopback)","title":"Guest Port","type":"integer"},"host_port":{"default":0,"description":"Host-side loopback listener port","title":"Host Port","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_relay_startArguments","type":"object"}',
    'hyperv_relay_status': '{"additionalProperties":false,"properties":{"relay_id":{"default":"","description":"Relay id returned by relay_start","title":"Relay Id","type":"string"}},"title":"hyperv_relay_statusArguments","type":"object"}',
    'hyperv_relay_stop': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"relay_id":{"description":"Relay id returned by relay_start","title":"Relay Id","type":"string"}},"required":["relay_id"],"title":"hyperv_relay_stopArguments","type":"object"}',
    'hyperv_repair_guest_access': '{"additionalProperties":false,"properties":{"apply":{"default":false,"description":"Propose only by default; pass true with confirm to apply repairs","title":"Apply","type":"boolean"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_repair_guest_accessArguments","type":"object"}',
    'hyperv_reset_vm': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_reset_vmArguments","type":"object"}',
    'hyperv_server_info': '{"additionalProperties":false,"properties":{},"title":"hyperv_server_infoArguments","type":"object"}',
    'hyperv_start_vm': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_start_vmArguments","type":"object"}',
    'hyperv_stop_vm': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"method":{"default":"shutdown","description":"\\"shutdown\\" — graceful guest shutdown via Integration Services, then waits for Off (default) \\"shutdown-force\\" — force shutdown (data-loss risk) \\"save\\" — suspend to disk (final state Saved) \\"turnoff\\" — hard power-off","title":"Method","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_stop_vmArguments","type":"object"}',
    'hyperv_ui_act': '{"additionalProperties":false,"properties":{"action":{"default":"","description":"one of invoke, toggle_on, toggle_off, select, expand, collapse, set_value, focus, scroll_into_view, click","title":"Action","type":"string"},"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried — take a fresh hyperv_ui_snapshot","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"value":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"the text to set (set_value only, <= 64 KiB; rides the framed payload, never script text; the result reports the length only)","title":"Value"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_actArguments","type":"object"}',
    'hyperv_ui_find': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — refused adapter_unapproved unless the registration carries the adapter:electron capability","title":"Adapter","type":"string"},"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect (\\"42:1024\\" form) — resolves the live element by id","title":"Element Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137; the snapshot id may be hex, the index decimal) — resolves the element captured by that hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref pointing at a fresh snapshot, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector (accepted keys: automation_id, name, name_contains, control_type, class_name, window_title, window_title_contains, process_name, hwnd, index, scope); a selector with no window scope searches the FOREGROUND window (scope: foreground default / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_findArguments","type":"object"}',
    'hyperv_ui_focus': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_focusArguments","type":"object"}',
    'hyperv_ui_helper_provision': '{"additionalProperties":false,"properties":{"autologon":{"default":true,"description":"configure automatic logon for the guest account (default true; ignored by teardown)","title":"Autologon","type":"boolean"},"confirm":{"default":false,"description":"Must be true (destructive.require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"teardown":{"default":false,"description":"true removes the helper instead of installing it","title":"Teardown","type":"boolean"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_helper_provisionArguments","type":"object"}',
    'hyperv_ui_inspect': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — an Electron adapter request is refused adapter_unapproved unless the helper registration carries the adapter:electron capability","title":"Adapter","type":"string"},"depth":{"default":3,"description":"Walk depth (1..32, default 3; one clamp shared with evidence\'s PS Direct walk and the helper)","title":"Depth","type":"integer"},"max_elements":{"default":200,"description":"Element cap (1..500, default 200; the same clamp as evidence\'s walk)","title":"Max Elements","type":"integer"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector scoping the walk (accepted keys: automation_id, name, name_contains, control_type, class_name, window_title, window_title_contains, process_name, hwnd, index, scope); with a selector the walk starts at the matched element, without it at the FOREGROUND window (the scope key picks the breadth: foreground default / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_inspectArguments","type":"object"}',
    'hyperv_ui_invoke': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_invokeArguments","type":"object"}',
    'hyperv_ui_session_state': '{"additionalProperties":false,"properties":{"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_session_stateArguments","type":"object"}',
    'hyperv_ui_set_value': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect","title":"Element Id","type":"string"},"fencing_token":{"default":0,"description":"the lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"optional lease citation (issue #23) — the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"secret_ref":{"default":"","description":"env:NAME or allowlisted file:PATH resolved host-side; the resolved value is set, only the length is reported (mutually exclusive with value)","title":"Secret Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector — address the target by exactly one of selector=, element_id= or ref= (a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"value":{"default":"","description":"the text to set (<= 64 KiB)","title":"Value","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_set_valueArguments","type":"object"}',
    'hyperv_ui_snapshot': '{"additionalProperties":false,"properties":{"adapter":{"default":"","description":"\\"\\" (default) or \\"electron\\" — an Electron adapter request is refused adapter_unapproved unless the helper registration carries the adapter:electron capability","title":"Adapter","type":"string"},"max_elements":{"default":250,"description":"element cap (1..500, default 250)","title":"Max Elements","type":"integer"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"optional UIA selector picking the window (accepted keys: hwnd, window_title, window_title_contains, process_name, scope; a selector with no window scope searches the FOREGROUND window)","title":"Selector"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_snapshotArguments","type":"object"}',
    'hyperv_ui_wait_for': '{"additionalProperties":false,"properties":{"element_id":{"default":"","description":"a RuntimeId from a previous find/inspect — address the target by exactly one of selector=, element_id= or ref=","title":"Element Id","type":"string"},"gone":{"default":false,"description":"true waits for DISAPPEARANCE instead of appearance","title":"Gone","type":"boolean"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"ref":{"default":"","description":"a snapshot element ref, s<snapshot>:<index> (issue #137), as rendered by hyperv_ui_snapshot; a stale or unknown ref passes through as error_class stale_ref/unknown_ref, never retried","title":"Ref","type":"string"},"selector":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"UIA selector waited for (accepted keys as find; a selector with no window scope searches the FOREGROUND window; scope: foreground / window / all_windows)","title":"Selector"},"state":{"anyOf":[{"additionalProperties":true,"type":"object"},{"type":"null"}],"default":null,"description":"wait until every given element/state property matches (a non-empty dict; matching spans element-level properties and the nested state block)","title":"State"},"timeout_s":{"default":30,"description":"wait budget in seconds (1..120, default 30)","title":"Timeout S","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"value":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"wait until the element\'s state.value equals this (empty string is a legitimate predicate; omit for none)","title":"Value"},"value_contains":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"wait until the element\'s state.value contains this substring","title":"Value Contains"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_ui_wait_forArguments","type":"object"}',
    'hyperv_victim_run': '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The executable or shell command to run in the guest","title":"Command","type":"string"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the guest command","title":"Cwd"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_victim_runArguments","type":"object"}',
    'hyperv_victim_run_ps': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"script":{"default":"","description":"PowerShell script text to run in the guest","title":"Script","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_victim_run_psArguments","type":"object"}',
    'hyperv_vm_clone': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cpu_count":{"default":1,"description":"Virtual processor count","title":"Cpu Count","type":"integer"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"generation":{"default":2,"description":"VM generation (1 or 2)","title":"Generation","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"memory_mb":{"default":2048,"description":"Startup memory in MB","title":"Memory Mb","type":"integer"},"name":{"description":"New VM name (must match allowed_vm_patterns)","title":"Name","type":"string"},"parent_vhd_path":{"description":"Read-only golden parent VHDX path (host_read_roots)","title":"Parent Vhd Path","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vhd_path":{"description":"Path for the new VHDX (policy-checked against host_write_roots)","title":"Vhd Path","type":"string"}},"required":["name","parent_vhd_path","vhd_path"],"title":"hyperv_vm_cloneArguments","type":"object"}',
    'hyperv_vm_create': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cpu_count":{"default":1,"description":"Virtual processor count","title":"Cpu Count","type":"integer"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"generation":{"default":2,"description":"VM generation (1 or 2)","title":"Generation","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"memory_mb":{"default":2048,"description":"Startup memory in MB","title":"Memory Mb","type":"integer"},"name":{"description":"New VM name (must match allowed_vm_patterns)","title":"Name","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vhd_path":{"description":"Path for the new VHDX (policy-checked against host_write_roots)","title":"Vhd Path","type":"string"},"vhd_size_gb":{"default":64,"description":"VHDX size in GB","title":"Vhd Size Gb","type":"integer"}},"required":["name","vhd_path"],"title":"hyperv_vm_createArguments","type":"object"}',
    'hyperv_vm_disk_add': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"controller_type":{"default":"SCSI","description":"Disk controller type (default SCSI)","title":"Controller Type","type":"string"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"path":{"default":"","description":"Path of the VHDX to attach","title":"Path","type":"string"},"size_gb":{"default":0,"description":"Size in GB for the new VHDX","title":"Size Gb","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_disk_addArguments","type":"object"}',
    'hyperv_vm_disk_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_disk_listArguments","type":"object"}',
    'hyperv_vm_firmware_get': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_firmware_getArguments","type":"object"}',
    'hyperv_vm_firmware_set_boot_order': '{"additionalProperties":false,"properties":{"boot_type":{"default":"Drive","description":"First boot device type: Drive | Network | File","title":"Boot Type","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_firmware_set_boot_orderArguments","type":"object"}',
    'hyperv_vm_get_video': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_get_videoArguments","type":"object"}',
    'hyperv_vm_media_attach': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"iso_path":{"default":"","description":"Path of the ISO to attach (host_read policy)","title":"Iso Path","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_attachArguments","type":"object"}',
    'hyperv_vm_media_detach': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_detachArguments","type":"object"}',
    'hyperv_vm_media_list': '{"additionalProperties":false,"properties":{"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_media_listArguments","type":"object"}',
    'hyperv_vm_network_set': '{"additionalProperties":false,"properties":{"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"switch_name":{"default":"","description":"Virtual switch name to connect the adapter to","title":"Switch Name","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_vm_network_setArguments","type":"object"}',
    'hyperv_vm_remove': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"delete_disks":{"default":false,"description":"Also delete this VM\'s own disk files (never the parent)","title":"Delete Disks","type":"boolean"},"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_vm_removeArguments","type":"object"}',
    'hyperv_vm_secureboot_set': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"enabled":{"description":"REQUIRED — true to enable, false to disable (omission is a schema error; it never silently defaults to disable)","title":"Enabled","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"template":{"default":"","description":"Secure Boot template (e.g. MicrosoftWindows)","title":"Template","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"required":["enabled"],"title":"hyperv_vm_secureboot_setArguments","type":"object"}',
    'hyperv_vm_set_resolution': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"required for the stop/start when restart=true","title":"Confirm","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"height":{"default":0,"description":"Vertical resolution in pixels (160..4096; required unless resolution_type is \\"default\\")","title":"Height","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"resolution_type":{"default":"single","description":"single | maximum | default","title":"Resolution Type","type":"string"},"restart":{"default":false,"description":"stop/start the VM now so the mode applies immediately","title":"Restart","type":"boolean"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"},"width":{"default":0,"description":"Horizontal resolution in pixels (160..4096; required unless resolution_type is \\"default\\")","title":"Width","type":"integer"}},"title":"hyperv_vm_set_resolutionArguments","type":"object"}',
    'hyperv_vm_tpm_set': '{"additionalProperties":false,"properties":{"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"enabled":{"description":"REQUIRED — true to enable, false to disable (omission is a schema error; it never silently defaults to disable)","title":"Enabled","type":"boolean"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"required":["enabled"],"title":"hyperv_vm_tpm_setArguments","type":"object"}',
    'hyperv_wait_guest_recovery': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"interval_s":{"default":3,"description":"Poll interval in seconds","title":"Interval S","type":"integer"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"processes":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Guest process names to verify present after restart","title":"Processes"},"services":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Guest service names to verify Running after restart","title":"Services"},"timeout_s":{"default":300,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_wait_guest_recoveryArguments","type":"object"}',
    'hyperv_wait_vm_state': '{"additionalProperties":false,"properties":{"detach":{"default":false,"description":"Detach: report the accepted operation and finish in background","title":"Detach","type":"boolean"},"idempotency_key":{"default":"","description":"Optional caller-managed key for idempotent retries","title":"Idempotency Key","type":"string"},"states":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"States to wait for (Off/Running/Saved/Paused/Starting/Stopping/Resuming/Pausing)","title":"States"},"timeout_s":{"default":300,"description":"Overall deadline in seconds","title":"Timeout S","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_wait_vm_stateArguments","type":"object"}',
}

assert len(FROZEN_SCHEMAS_DEFAULT_JSON) == 84, (
    "the frozen default-variant schema inventory is exactly the 84 "
    "pre-existing tools")
assert len(FROZEN_SCHEMAS_INLINE_JSON) == 84, (
    "the frozen inline-variant schema inventory is exactly the 84 "
    "pre-existing tools")


#: Wave-3 S5: the COMPLETE inputSchema of the NEW #128 tool, frozen
#: DEEPLY in BOTH credential variants (canonical JSON, sorted keys,
#: compact) -- the FULL object: the exact property set, every type,
#: default, description, title, additionalProperties:false, the
#: "hyperv_guest_start_interactiveArguments" title, and NO required key
#: (every parameter defaults). A registration that omits command, args,
#: timeout_ms, vm_name or vm_id -- or drifts on any default, description
#: or title -- fails the deep-equality pins in test_tool_schemas_unchanged
#: on the exact differing path. username/password exist ONLY in the
#: inline variant (the guest-tool convention).
NEW_TOOL_SCHEMA_DEFAULT_JSON = (
    '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The GUI executable to launch in the guest\'s interactive session","title":"Command","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the launched process","title":"Cwd"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM (must match allowed_vm_patterns)","title":"Vm Name","type":"string"}},"title":"hyperv_guest_start_interactiveArguments","type":"object"}'
)
NEW_TOOL_SCHEMA_INLINE_JSON = (
    '{"additionalProperties":false,"properties":{"args":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],"default":null,"description":"Argument list passed to the command","title":"Args"},"command":{"default":"","description":"The GUI executable to launch in the guest\'s interactive session","title":"Command","type":"string"},"confirm":{"default":false,"description":"Must be true (the tool\'s destructive category + require_confirm)","title":"Confirm","type":"boolean"},"cwd":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null,"description":"Working directory for the launched process","title":"Cwd"},"fencing_token":{"default":0,"description":"The lease\'s fencing token, with lease_id","title":"Fencing Token","type":"integer"},"lease_id":{"default":"","description":"Optional lease citation - the lease gate runs before the body","title":"Lease Id","type":"string"},"password":{"default":"","description":"Inline guest password (requires allow_inline_credentials=true)","title":"Password","type":"string"},"timeout_ms":{"default":60000,"description":"Per-call timeout in milliseconds","title":"Timeout Ms","type":"integer"},"username":{"default":"","description":"Inline guest username (requires allow_inline_credentials=true)","title":"Username","type":"string"},"vm_id":{"default":"","description":"Optional VM GUID; exactly one of vm_name/vm_id must be given","title":"Vm Id","type":"string"},"vm_name":{"default":"","description":"Name of the VM","title":"Vm Name","type":"string"}},"title":"hyperv_guest_start_interactiveArguments","type":"object"}'
)


def _first_schema_diff(want, got, path: str = "schema") -> str:
    """The first differing path between two JSON schema objects ('' when
    deep-equal) -- the drift report for the AC4 freeze."""
    if isinstance(want, dict) and isinstance(got, dict):
        for key in sorted(set(want) | set(got)):
            if key not in want:
                return f"{path}.{key}: unexpected key (value {got[key]!r})"
            if key not in got:
                return f"{path}.{key}: missing key (expected {want[key]!r})"
            sub = _first_schema_diff(want[key], got[key], f"{path}.{key}")
            if sub:
                return sub
        return ""
    if isinstance(want, list) and isinstance(got, list):
        if len(want) != len(got):
            return f"{path}: expected {want!r}, got {got!r}"
        for i, (w, g) in enumerate(zip(want, got, strict=True)):
            sub = _first_schema_diff(w, g, f"{path}[{i}]")
            if sub:
                return sub
        return ""
    if isinstance(want, (dict, list)) != isinstance(got, (dict, list)):
        return f"{path}: expected {want!r}, got {got!r}"
    return "" if want == got else f"{path}: expected {want!r}, got {got!r}"


def _schema_drift(schemas: dict, frozen: dict[str, str]) -> list[str]:
    """Per-tool drift of the live schemas against a frozen variant map:
    canonical-JSON equality, first differing path in the message."""
    drift: list[str] = []
    for name, frozen_json in sorted(frozen.items()):
        live = schemas.get(name)
        if live is None:
            drift.append(f"  {name}: tool is not registered")
            continue
        live_json = json.dumps(live, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
        if live_json != frozen_json:
            drift.append(f"  {name}: {_first_schema_diff(json.loads(frozen_json), live)}")
    return drift


# ---------------------------------------------------------------------------
# AC1: the playbook prompt is listed
# ---------------------------------------------------------------------------

def test_playbook_prompt_is_listed(fresh_server):
    """AC1: WHEN a client lists prompts, the server includes
    gui-testing-playbook, listed with a non-empty description.
    RED at base (no prompt exists anywhere in src/), GREEN after the fix."""
    mod = fresh_server({})
    prompts = asyncio.run(mod.get_mcp().list_prompts())
    names = [p.name for p in prompts]
    assert PROMPT_NAME in names, (
        f"the gui-testing-playbook prompt must be listed alongside the "
        f"tools; prompts listed: {names!r}")
    listed = next(p for p in prompts if p.name == PROMPT_NAME)
    assert (listed.description or "").strip(), (
        "the listed prompt carries a description so a client knows what it "
        "is for before fetching it")


# ---------------------------------------------------------------------------
# AC2: the fetched playbook carries the five required sections
# ---------------------------------------------------------------------------

def test_playbook_has_required_sections(fresh_server):
    """AC2: WHEN the playbook prompt is fetched, the returned text contains
    the path-selection, verification, commit-click, transient-vs-absent
    errors and evidence sections -- each bound to the text UNDER its own
    heading, with the sections' operational sequences pinned: the
    transient-error section states retry BEFORE the tools BEFORE reporting
    unavailable, the verification section requires verification after
    every action, and the commit-click section names the commit guard.
    RED at base (get_prompt raises for the unknown name), GREEN after the
    fix."""
    mod = fresh_server({})
    result = asyncio.run(mod.get_mcp().get_prompt(PROMPT_NAME))
    text = _prompt_text(result)
    assert text.strip(), "the fetched prompt must return non-empty text"
    low = text.lower()
    missing = [m for m in REQUIRED_SECTION_MARKERS if m not in low]
    assert missing == [], (
        f"the playbook text is missing required section marker(s) "
        f"{missing!r} (path selection, verification, commit-click, "
        f"transient-vs-absent errors, evidence)")

    # the Path selection SECTION carries the table (not just the marker
    # somewhere in the prompt)
    path_section = _extract_section(text, "path selection")
    assert any(ln.strip().startswith("|")
               for ln in path_section.splitlines()), (
        "the Path selection section must carry the path-selection markdown "
        "table under its own heading")

    # the transient-error section orders its operational sequence: retry
    # FIRST, then the tools to reach for, then reporting unavailable
    transient = _extract_section(text, "transient").lower()
    retry_at = transient.find("retry")
    tool_at = transient.find("hyperv_")
    unavailable_at = transient.find("unavailable")
    for what, pos in (("retry", retry_at),
                      ("a hyperv_ tool name", tool_at),
                      ("unavailable", unavailable_at)):
        assert pos != -1, (
            f"the transient-error section must state {what} (under the "
            f"transient heading): {transient!r}")
    assert retry_at < tool_at < unavailable_at, (
        "the transient-error section must state its operational sequence "
        "IN ORDER: retry FIRST, then the tools to reach for, then "
        f"reporting the target unavailable: {transient!r}")
    # the transient-vs-absent distinction lives in THAT section
    assert "absent" in transient, (
        "the transient-vs-absent distinction (the word 'absent') must live "
        f"in the transient-error section: {transient!r}")

    # the verification section requires verification after every action
    verification = _extract_section(text, "verification").lower()
    assert "verif" in verification, (
        "the verification section must speak of verifying")
    assert "every action" in verification, (
        "the verification section must require verification after EVERY "
        f"action: {verification!r}")

    # the commit-click section names the commit guard
    commit = _extract_section(text, "commit-click").lower()
    assert ("commit guard" in commit or "commit_guard" in commit
            or "commit-guard" in commit), (
        "the commit-click section must name the commit guard (the "
        f"hyperv_console_click commit_guard discipline): {commit!r}")

    # the evidence section speaks of capturing evidence
    evidence = _extract_section(text, "evidence").lower()
    assert "screenshot" in evidence or "evidence" in evidence, (
        "the evidence section must speak of capturing screenshots/results "
        f"as evidence: {evidence!r}")

    # S6 polarity: the three operational sections carry NO negated
    # guidance -- the positive pins above must not be satisfiable by a
    # section that also says "never retry" / "do not verify" / "do not
    # use the commit guard"
    polarity = _section_polarity_violations(text)
    assert polarity == [], (
        "the operational sections must state their guidance with the RIGHT "
        "POLARITY -- negated guidance (never retry / do not verify / do "
        "not use the commit guard) must be ABSENT from the transient, "
        "verification and commit-click sections:\n  - "
        + "\n  - ".join(polarity))


def test_negated_guidance_sections_are_rejected(fresh_server):
    """AC2's polarity negative fixture (S6): a prompt whose REAL
    operational sections carry NEGATED guidance ("Never retry ...",
    "Do not verify after every action", "Do not use the commit guard")
    must FAIL the polarity checker -- for each of the three sections, and
    independently (each injection alone trips its own section's pin).
    The mutant is built from the REAL published prompt, and the real
    prompt itself must be clean (the checker is not a blanket rejection:
    it accepts the genuine guidance).
    RED at base (get_prompt raises for the unknown name -- the real
    prompt must exist to be mutated), GREEN after the fix."""
    mod = fresh_server({})
    real = _prompt_text(asyncio.run(mod.get_mcp().get_prompt(PROMPT_NAME)))

    # non-vacuity / no-blanket-rejection: the REAL prompt is clean
    assert _section_polarity_violations(real) == [], (
        "the real playbook's operational sections must carry no negated "
        "guidance -- if this fires the published prompt itself is wrong")

    # each injection ALONE trips exactly its own section's pin
    for marker, sentence in _NEGATED_INJECTIONS:
        single = _inject_after_heading(real, marker, sentence)
        violations = _section_polarity_violations(single)
        assert violations, (
            f"injecting {sentence!r} under the {marker!r} heading must be "
            f"REJECTED -- negated operational guidance cannot pass the "
            f"polarity pin")
        assert any(v.startswith(f"{_section_name_for(marker)}:") or
                   marker in v for v in violations), (
            f"the rejection must point at the {marker!r} section: "
            f"{violations!r}")

    # the full mutant (all three injections) trips all three sections
    mutant = real
    for marker, sentence in _NEGATED_INJECTIONS:
        mutant = _inject_after_heading(mutant, marker, sentence)
    violations = _section_polarity_violations(mutant)
    for family in ("transient section", "verification section",
                   "commit-click section"):
        assert any(v.startswith(family) for v in violations), (
            f"the full negated-guidance mutant must be rejected naming "
            f"every operational section; got: {violations!r}")


def _section_name_for(marker: str) -> str:
    """The polarity checker's family label for a section marker."""
    return {"transient": "transient section",
            "verification": "verification section",
            "commit-click": "commit-click section"}[marker]


# ---------------------------------------------------------------------------
# AC3: the console input tools point at the UIA find/invoke pair
# ---------------------------------------------------------------------------

def test_console_click_points_to_uia(fresh_server, tmp_path):
    """AC3: WHEN a client lists tools, the PUBLISHED descriptions of
    hyperv_console_click, hyperv_console_type_text and
    hyperv_console_screenshot carry a POSITIVE see-also reference to the
    UI Automation find and invoke tools (both names, a recommending
    phrase, no forbidding wording). Checked in BOTH credential variants
    (console tools sit outside the credential branches, so each variant
    must carry the same link).
    RED at base (the descriptions name neither tool), GREEN after the
    fix."""
    mod = fresh_server({})
    mcp = mod.get_mcp()
    for tool in SEE_ALSO_TOOLS:
        _assert_see_also(_tool_description(mcp, tool), tool)

    # the inline-credentials variant publishes the same links
    from mcp.server.mcpserver import MCPServer

    cfg = Config(
        unrestricted=True,
        allow_inline_credentials=True,
        audit_log_path=str(tmp_path / "audit-variant.jsonl"),
    )
    inline = MCPServer("gui_playbook_inline_variant", version="0.0.0-test")
    mod._register_tools(cfg, inline)
    for tool in SEE_ALSO_TOOLS:
        _assert_see_also(
            _tool_description(inline, tool),
            f"{tool} (inline-credentials variant)")

    # S7 negative fixtures: every forbidding construction near the tool
    # names must FAIL the see-also pin -- including the wave-2 survivor
    # ("... are forbidden" beside a genuine recommending phrase) and each
    # forbidden substring from the frozen list.
    survivor = ("See also: docs. hyperv_ui_find and hyperv_ui_invoke are "
                "forbidden")
    with pytest.raises(AssertionError, match="forbid"):
        _assert_see_also(survivor, "S7 negative fixture (the survivor)")
    for bad_substring in SEE_ALSO_FORBIDDEN_SUBSTRINGS:
        description = (
            f"Prefer hyperv_ui_find and hyperv_ui_invoke; {bad_substring} "
            f"them on locked screens")
        with pytest.raises(AssertionError, match="FORBIDDING"):
            _assert_see_also(
                description, f"S7 negative fixture ({bad_substring!r})")


# ---------------------------------------------------------------------------
# AC4 (preserving): every existing name and full schema unchanged; 85 total
# ---------------------------------------------------------------------------

def test_tool_schemas_unchanged(fresh_server, tmp_path):
    """AC4 (preserving): the DEFAULT registration publishes exactly 85
    tools -- the 84 frozen below plus hyperv_guest_start_interactive --
    and every PRE-EXISTING tool keeps its FULL inputSchema object
    DEEP-EQUAL to the frozen literal (a changed default, description,
    title, type, required list or additionalProperties flag fails on the
    exact differing path) -- in BOTH credential variants. The new #128
    tool's schema is pinned by property set: cwd/lease_id/fencing_token/
    confirm carried, username/password ONLY in the inline variant, and
    neither detach nor idempotency_key.
    RED at base only through the missing 85th tool (the 84 deep freezes
    were generated from base); the discriminating power lives in the
    deep-equality comparisons below."""
    mod = fresh_server({})
    tools = asyncio.run(mod.get_mcp().list_tools())
    schemas = {t.name: json.loads(json.dumps(_schema_of(t), sort_keys=True))
               for t in tools}

    expected_names = set(FROZEN_SCHEMAS_DEFAULT_JSON) | NEW_TOOL_NAMES
    assert len(expected_names) == 85
    actual_names = set(schemas)
    assert actual_names == expected_names, (
        f"tool inventory drifted: missing={sorted(expected_names - actual_names)} "
        f"unexpected={sorted(actual_names - expected_names)}")
    assert len(schemas) == 85, (
        f"exactly 85 tools must be registered (84 at base + #128's "
        f"hyperv_guest_start_interactive), got {len(schemas)}")

    drift = _schema_drift(schemas, FROZEN_SCHEMAS_DEFAULT_JSON)
    assert drift == [], (
        "pre-existing tool schemas must be DEEP-EQUAL to the base freeze "
        "(default registration variant):\n" + "\n".join(drift))

    # the same deep freeze under the inline-credentials registration
    from mcp.server.mcpserver import MCPServer

    cfg = Config(
        unrestricted=True,
        allow_inline_credentials=True,
        audit_log_path=str(tmp_path / "audit-variant.jsonl"),
    )
    inline = MCPServer("gui_schemas_inline_variant", version="0.0.0-test")
    mod._register_tools(cfg, inline)
    inline_schemas = {
        t.name: json.loads(json.dumps(_schema_of(t), sort_keys=True))
        for t in asyncio.run(inline.list_tools())
    }
    assert set(inline_schemas) == expected_names, (
        f"the inline-credentials variant registers the same 85 tools: "
        f"missing={sorted(expected_names - set(inline_schemas))} "
        f"unexpected={sorted(set(inline_schemas) - expected_names)}")
    drift_inline = _schema_drift(inline_schemas, FROZEN_SCHEMAS_INLINE_JSON)
    assert drift_inline == [], (
        "pre-existing tool schemas must be DEEP-EQUAL to the base freeze "
        "(inline-credentials variant):\n" + "\n".join(drift_inline))

    # the new #128 tool's exact parameter set, in BOTH variants
    must_carry = {"cwd", "lease_id", "fencing_token", "confirm"}
    forbidden = {"detach", "idempotency_key"}
    new_default = schemas["hyperv_guest_start_interactive"]
    props_default = set((new_default or {}).get("properties", {}))
    assert must_carry <= props_default, (
        f"hyperv_guest_start_interactive must carry {sorted(must_carry)}; "
        f"missing={sorted(must_carry - props_default)}")
    assert not ({"username", "password"} & props_default), (
        "the DEFAULT registration must not publish inline username/"
        "password parameters")
    assert not (forbidden & props_default), (
        f"hyperv_guest_start_interactive must NOT carry "
        f"{sorted(forbidden)} (a one-shot interactive launch is not "
        f"detachable or idempotently retryable): "
        f"{sorted(props_default)}")
    new_inline = inline_schemas["hyperv_guest_start_interactive"]
    props_inline = set((new_inline or {}).get("properties", {}))
    assert must_carry <= props_inline, (
        f"the inline variant must carry {sorted(must_carry)} too; "
        f"missing={sorted(must_carry - props_inline)}")
    assert {"username", "password"} <= props_inline, (
        "the inline-credentials variant must publish username/password on "
        "hyperv_guest_start_interactive (the guest-tool convention)")
    assert not (forbidden & props_inline), (
        f"the inline variant must NOT carry {sorted(forbidden)} either: "
        f"{sorted(props_inline)}")

    # wave-3 S5: the new tool's COMPLETE inputSchema, frozen DEEPLY in
    # BOTH variants -- full exact property set, types, defaults,
    # descriptions, titles, additionalProperties, and NO required key (a
    # registration that omits command/args/timeout_ms/vm_name/vm_id, or
    # drifts on any default or description, fails on the exact path)
    for variant, schema, frozen_json in (
            ("default", new_default, NEW_TOOL_SCHEMA_DEFAULT_JSON),
            ("inline-credentials", new_inline, NEW_TOOL_SCHEMA_INLINE_JSON)):
        live_json = json.dumps(schema, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
        assert live_json == frozen_json, (
            f"hyperv_guest_start_interactive's COMPLETE inputSchema ({variant} "
            f"variant) must be DEEP-EQUAL to the frozen literal (property "
            f"set, types, defaults, descriptions, titles, "
            f"additionalProperties, title; no required key -- every "
            f"parameter defaults): {_first_schema_diff(json.loads(frozen_json), schema)}")


# ---------------------------------------------------------------------------
# AC5: the playbook orders the paths by surface
# ---------------------------------------------------------------------------

def test_paths_are_ordered_by_surface(fresh_server):
    """AC5: the playbook's path-selection table orders the paths BY
    SURFACE, read from the CHOICE COLUMNS of each row (the cells after
    the surface column -- never substring positions across the whole
    row): the web-content row names the DevTools tools as the FIRST path
    (before the UI Automation mention), and the native-windows row names
    the UI Automation tools first (before any DevTools mention). The same
    checker accepts a correctly ordered table (non-vacuity) and rejects
    reversed guidance (the companion negative node drives a full prompt).
    RED at base (get_prompt raises for the unknown name), GREEN after the
    fix."""
    mod = fresh_server({})
    text = _prompt_text(asyncio.run(mod.get_mcp().get_prompt(PROMPT_NAME)))
    violations = _path_order_violations(text)
    assert violations == [], (
        "the path-selection table must order the paths BY SURFACE (web -> "
        "DevTools first, native -> UI Automation first), parsed from each "
        "row's CHOICE COLUMNS:\n  - " + "\n  - ".join(violations))
    # non-vacuity: the same checker accepts a correctly ordered table
    assert _path_order_violations(
        "## Path selection\n\n" + CORRECT_PATH_TABLE + "\n") == [], (
        "the choice-column checker must ACCEPT correctly ordered guidance "
        "-- the pin above is not a blanket rejection")


def test_reversed_path_guidance_is_rejected(fresh_server):
    """AC5's negative fixture: a prompt whose REAL path-selection section
    carries REVERSED guidance (UI Automation before DevTools in the
    web row's choice columns) must FAIL the ordering check even when a
    CORRECTLY ordered decoy table appears EARLIER in the prompt under an
    unrelated heading -- proving the checker binds to the Path selection
    section's choice columns, not to any table or to whole-row substring
    positions. The mutant is built from the REAL published prompt (so the
    extraction runs against the genuine section shape), and the decoy
    alone is verified clean.
    RED at base (get_prompt raises for the unknown name -- the real
    prompt must exist to be mutated), GREEN after the fix."""
    mod = fresh_server({})
    real = _prompt_text(asyncio.run(mod.get_mcp().get_prompt(PROMPT_NAME)))

    # reverse the web row's choice-column guidance inside the REAL section
    section = _extract_section(real, "path selection")
    rows = [ln for ln in section.splitlines() if ln.strip().startswith("|")]
    web_rows = [r for r in rows if "web" in r.lower()]
    assert web_rows, (
        "the real path-selection section must carry the web-content row "
        "the mutation reverses")
    web = web_rows[0]
    cells = _row_cells(web)
    assert len(cells) >= 2, (
        f"the web-content row must have a surface cell plus choice cells: "
        f"{web!r}")
    choice = "|".join(cells[1:])
    assert _UIA_TOKEN_RE.search(choice) and _DEVTOOLS_TOKEN_RE.search(
        choice), (
        f"the mutation needs both path mentions in the web row's choice "
        f"cells: {choice!r}")
    swapped_choice = _swap_first_tokens(choice)
    mutant_row = "| " + " | ".join(
        [cells[0]] + swapped_choice.split("|")) + " |"
    reversed_real = real.replace(web, mutant_row, 1)

    # the decoy: a CORRECTLY ordered table BEFORE the real section, under
    # an unrelated heading. A checker that scans the whole prompt's table
    # rows (or whole-row substring positions) would read the decoy's web
    # row first and PASS; the section-bound choice-column checker must
    # not.
    decoy = "\n".join([
        "## Appendix: quick reference",
        "",
        CORRECT_PATH_TABLE,
        "",
    ])
    mutant = decoy + "\n" + reversed_real

    violations = _path_order_violations(mutant)
    assert violations, (
        "a prompt whose REAL path-selection section carries REVERSED web "
        "guidance (UI Automation before DevTools) must be REJECTED -- the "
        "correctly ordered decoy table elsewhere must NOT mask it")
    assert any("web" in v.lower() for v in violations), (
        f"the rejection must point at the REVERSED web row: {violations!r}")
    # the decoy's own guidance is clean (the checker accepts correct order)
    assert _path_order_violations(
        "## Path selection\n\n" + CORRECT_PATH_TABLE + "\n") == [], (
        "the checker must accept correctly ordered guidance -- the "
        "rejection above is the reversal's, not a blanket refusal")
