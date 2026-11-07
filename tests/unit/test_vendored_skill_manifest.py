"""Vendored-skill manifest drift oracle (issue #118; trace
67-118-release-vendor-provenance, arm's-length acceptance-check authoring).

The four vendored skill trees under ``.agents/skills/`` (commit-pr,
issue-tracer, swarm-pr-feedback, swarm-pr-review) are checked-in copies of
ZaxbyHub/opencode-swarm content pinned to the canonical commit recorded in
``.agents/skills/vendored-skills.manifest``. This module is the CI-side
drift oracle (AC1/AC2): the manifest and the tree must describe exactly the
same file set, and every covered file must hash — sha256 over bytes with
CRLF normalized to LF, so a Windows ``* text=auto`` checkout (where *.sh
materializes as CRLF) compares equal to the LF blobs the manifest was
generated from — to the pinned digest. Any single-byte deviation fails,
including same-``version:``-string drift, and missing or extra files.

Stdlib + pytest only; no network; never reads the sibling canonical repo —
the manifest itself is the frozen oracle (the trace-side
``run_vendored_canonical_compare.sh`` separately proves the oracle's
faithfulness to the canonical blobs at the pinned commit).
"""

import hashlib
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = REPO_ROOT / ".agents" / "skills"
MANIFEST_PATH = SKILLS_DIR / "vendored-skills.manifest"
POLICY_PATH = REPO_ROOT / "docs" / "versioning-policy.md"

# The four vendored skills (issue #118). Anything else under .agents/skills/
# (including this manifest itself) is outside the oracle's scope.
VENDORED_SKILL_DIRS = (
    "commit-pr",
    "issue-tracer",
    "swarm-pr-feedback",
    "swarm-pr-review",
)

# Canonical file count at the pinned commit (blobs under
# .opencode/skills/{issue-tracer,swarm-pr-review,swarm-pr-feedback,commit-pr}).
EXPECTED_ROW_COUNT = 39

# Data-row grammar: <64-hex sha256><exactly two spaces><slash-separated relpath>.
ROW_RE = re.compile(r"^([0-9a-f]{64}) {2}(\.agents/skills/.+)$")
# Header grammar: '# canonical_commit: <40 hex>'.
CANONICAL_COMMIT_RE = re.compile(r"^# canonical_commit: ([0-9a-f]{40})$")


def _manifest_text() -> str:
    assert MANIFEST_PATH.is_file(), (
        ".agents/skills/vendored-skills.manifest is missing; the vendored "
        "byte-oracle manifest must be checked in alongside this drift test"
    )
    return MANIFEST_PATH.read_text(encoding="utf-8")


def _parse_manifest() -> dict:
    """Map relpath -> pinned sha256, rejecting malformed and duplicate rows."""
    rows: dict = {}
    problems: list = []
    for lineno, raw in enumerate(_manifest_text().splitlines(), start=1):
        if raw.startswith("#") or not raw.strip():
            continue
        match = ROW_RE.match(raw)
        if match is None:
            problems.append(f"unparsable manifest row at line {lineno}: {raw!r}")
            continue
        digest, relpath = match.group(1), match.group(2)
        if relpath in rows:
            problems.append(f"duplicate manifest row for {relpath}")
            continue
        rows[relpath] = digest
    assert problems == [], f"vendored-skills manifest is malformed: {problems}"
    return rows


def _tree_relpaths() -> set:
    """Every file under the four vendored skill directories (both directions
    of the set-equality check come from this enumeration vs the manifest)."""
    found: set = set()
    for name in VENDORED_SKILL_DIRS:
        skill_dir = SKILLS_DIR / name
        for path in skill_dir.rglob("*"):
            if path.is_file():
                found.add(path.relative_to(REPO_ROOT).as_posix())
    return found


def _normalized_sha256(path: Path) -> str:
    """sha256 over file bytes with CRLF normalized to LF (reproduction P7:
    this checkout materializes text blobs as CRLF under ``* text=auto``)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_manifest_header_pins_canonical_commit_and_repin_procedure():
    """The manifest header must name the pinned canonical commit (exactly one
    40-hex ``canonical_commit:`` line) and reference the re-pin procedure via
    the literal token ``vendored-repin`` so a stale pin is repairable through
    the documented ritual rather than a hand edit."""
    lines = _manifest_text().splitlines()
    commits = [m for m in (CANONICAL_COMMIT_RE.match(line) for line in lines) if m is not None]
    assert len(commits) == 1 and commits[0].group(1), (
        "vendored-skills manifest must carry exactly one "
        "'# canonical_commit: <40-hex>' header line; got "
        f"{len(commits)} well-formed match(es)"
    )
    assert any(line.startswith("#") and "vendored-repin" in line for line in lines), (
        "vendored-skills manifest must reference the re-pin procedure "
        "(a header comment carrying the literal token 'vendored-repin')"
    )


def test_manifest_covers_exactly_39_files():
    """AC2 pin: the canonical skill tree at the pinned commit has exactly 39
    files; the manifest must enumerate every one of them — no more, no
    fewer — so a truncated or padded manifest cannot weaken the oracle."""
    rows = _parse_manifest()
    assert len(rows) == EXPECTED_ROW_COUNT, (
        f"vendored-skills manifest covers {len(rows)} rows; expected exactly "
        f"{EXPECTED_ROW_COUNT} (the canonical file count at the pinned commit)"
    )


def test_vendored_tree_matches_manifest_in_both_directions():
    """AC1/AC2: set equality between the manifest and the vendored tree, and
    byte equality (CRLF-normalized sha256) for every covered file. One
    MISMATCH/MISSING/EXTRA line is printed per problem before failing."""
    rows = _parse_manifest()
    tree = _tree_relpaths()
    problems: list = []
    for relpath in sorted(rows):
        if relpath not in tree:
            problems.append(f"MISSING {relpath}")
            continue
        if _normalized_sha256(REPO_ROOT / relpath) != rows[relpath]:
            problems.append(f"MISMATCH {relpath}")
    for relpath in sorted(tree):
        if relpath not in rows:
            problems.append(f"EXTRA {relpath}")
    for line in problems:
        print(line)
    assert problems == [], (
        f"{len(problems)} vendored-skill drift problem(s) against "
        "vendored-skills.manifest (MISMATCH = bytes differ from the pinned "
        "sha256, MISSING = pinned file absent from the tree, EXTRA = tree "
        "file absent from the manifest); verify the canonical repo's gate "
        "issue, then rerun the documented vendored-repin ritual in "
        "docs/versioning-policy.md"
    )


def test_versioning_policy_document_exists():
    """Companion fix deliverable (issue #67, AC4): the versioning policy that
    enumerates every bump site and the re-pin ritual must exist."""
    assert POLICY_PATH.is_file(), (
        "docs/versioning-policy.md does not exist; issue #67 requires a "
        "documented versioning policy (bump sites, the frozen-file AMEND "
        "procedure, the vendored-repin ritual, and git_revision call-time "
        "semantics)"
    )
