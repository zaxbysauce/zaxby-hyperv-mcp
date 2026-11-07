"""Consumer-side versioning provenance probe (issue #67; trace
67-118-release-vendor-provenance, arm's-length acceptance-check authoring).

Release-stable by construction (dynamic: never hardcodes the current
version literal): pins that a consumer can tell which build they are
running WITHOUT reading source — the installed distribution metadata
version must agree with every independent literal surface (pyproject.toml,
``hyperv_mcp.__version__``, ``server.VERSION``), README must carry the
current release's changelog section and today-marker, and the REAL
``hyperv_server_info`` payload builder must report that same version plus
the full provenance field set. Also pins the companion fix deliverable:
docs/versioning-policy.md exists and names every required topic.

Import-level + filesystem only; the single PowerShell provenance probe is
stubbed with the pattern reused from
tests/unit/test_a01_ps_environment.py. No network, no VMs, no secrets.
"""

import importlib.metadata
import json
import os
import re
from pathlib import Path

import hyperv_mcp
import hyperv_mcp.server as server_module
from hyperv_mcp import pswindows
from hyperv_mcp.config import Config

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
POLICY_PATH = REPO_ROOT / "docs" / "versioning-policy.md"

# The versioning policy must enumerate every bump site and the supporting
# rituals/semantics (issue #67, AC4). Every literal below is required —
# a policy that silently omits a bump site or semantic fails here.
POLICY_REQUIRED_LITERALS = (
    "pyproject.toml",      # bump site: [project] version literal
    "__version__",         # bump site: src/hyperv_mcp/__init__.py literal
    "test_c03_sdk_port",   # bump site: frozen AC7 re-pin via the issue-16 AMEND
    "README",              # bump site: "## <version> changes" + today-marker
    "AMEND",               # frozen-file amendment procedure
    "hyperv_server_info",  # consumer-side provenance surface
    "git_revision",        # provenance field ...
    "call-time",           # ... whose call-time (not build-identity) semantics
    "tags",                # release tagging convention
    # Historical disambiguation rule (issue #67's founding scenario): the two
    # 0.4.0 builds (proxy-by-default vs the mcp-2.x port) are told apart by
    # hyperv_server_info's mcp_sdk_version field — the policy must name both.
    "0.4.0",
    "mcp_sdk_version",
)

# plan-critic round 2: the re-pin reference must be a REAL heading line
# (fragment-linkable), not a substring anywhere; and the README may carry
# today-markers for ONLY the current version — a stale '(<old> today)' from
# a missed previous bump must fail even though it is not the current one.
VENDORED_REPIN_HEADING_RE = re.compile(r"(?m)^#{1,6}[ \t]+vendored-repin[ \t]*$")
TODAY_MARKER_RE = re.compile(r"\((\d+\.\d+\.\d+) today\)")


def _metadata_version() -> str:
    """The installed distribution's version (the single source of truth)."""
    return importlib.metadata.version("hyperv-mcp")


def _pyproject_version() -> str:
    """The ``[project] version`` literal from pyproject.toml (tomllib on
    3.11+, the targeted literal fallback on the 3.10 floor) — the same
    pattern as tests/unit/test_version_consistency.py."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - py3.10 floor
        import re

        text = PYPROJECT_PATH.read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert match, 'pyproject.toml carries no `version = "..."` literal'
        return match.group(1)
    with open(PYPROJECT_PATH, "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def _fake_provenance_run_ps(monkeypatch):
    """Stub the PowerShell provenance probe (pattern reused from
    test_a01_ps_environment.py) so the payload builder spawns nothing and
    stays deterministic: a multi-marker/ConvertTo-Json probe script gets a
    compact JSON object with all four answers."""
    answers = {
        "path": r"C:\Windows\System32\WindowsPowerShell\v1.0",
        "edition": "Desktop",
        "version": "5.1.19041.4990",
        "psmodulepath": os.environ.get("PSModulePath", ""),
    }
    combined = json.dumps(answers)

    def fake_run_ps(script, *args, **kwargs):
        low = script.lower()
        markers = [m for m in ("psedition", "psversion", "psmodulepath", "pshome") if m in low]
        if len(markers) >= 2 or "convertto-json" in low:
            return pswindows.PSResult(stdout=combined, returncode=0)
        return pswindows.PSResult(stdout=combined, returncode=0)

    monkeypatch.setattr(pswindows, "run_ps", fake_run_ps)


def test_version_literals_single_sourced():
    """AC4: every independent version literal must equal the installed
    distribution metadata version, so no surface can drift on a future
    bump (checked dynamically — this test survives 0.13.0 and beyond)."""
    ver = _metadata_version()
    assert hyperv_mcp.__version__ == ver, (
        f"src/hyperv_mcp/__init__.py __version__={hyperv_mcp.__version__!r} "
        f"!= installed metadata version {ver!r}"
    )
    assert server_module.VERSION == ver, (
        f"server.VERSION={server_module.VERSION!r} != installed metadata "
        f"version {ver!r}"
    )
    assert _pyproject_version() == ver, (
        f"pyproject.toml version={_pyproject_version()!r} != installed "
        f"metadata version {ver!r}"
    )


def test_readme_carries_current_release_section():
    """AC4: README must carry the CURRENT version's changelog section
    (``## <ver> changes``) and today-marker (``(<ver> today)``), so a
    release that misses the README is caught without reading source."""
    ver = _metadata_version()
    text = README_PATH.read_text(encoding="utf-8")
    assert f"## {ver} changes" in text, (
        f"README.md has no '## {ver} changes' section; every release must "
        "add its changelog section (PR #121 convention)"
    )
    assert text.count(f"({ver} today)") == 1, (
        f"README.md must carry EXACTLY ONE '({ver} today)' marker (found "
        f"{text.count(f'({ver} today)')}); a stale duplicate would let two "
        "releases both claim to be 'today'"
    )
    # plan-critic round 2: stale PREVIOUS-release markers are the real
    # regression shape (a missed marker edit on the last bump) — enumerate
    # every semantic-version today-marker and require the whole set to be
    # exactly the current version.
    markers = sorted(set(TODAY_MARKER_RE.findall(text)))
    assert markers == [ver], (
        f"README today-markers {markers} must be exactly [{ver!r}]; any "
        "stale '(<old> today)' means a bump missed the marker rotation"
    )
    import re as _re
    assert _re.search(
        r"\[docs/versioning-policy\.md\]\(docs/versioning-policy\.md\)", text
    ), (
        "README.md must contain a real markdown link to "
        "docs/versioning-policy.md so the consumer-side provenance contract "
        "is discoverable from the entry document (a bare backticked path "
        "does not navigate)"
    )
    section = text.split(f"## {ver} changes", 1)[1].split("\n## ", 1)[0]
    assert len([ln for ln in section.splitlines() if ln.strip()]) >= 3, (
        f"the README '## {ver} changes' section must carry real release "
        "notes (>= 3 non-empty lines), not an empty heading"
    )


def test_readme_preserves_release_history():
    """Guard against over-assertion: the README's historical 0.12.0 section
    stays present after future bumps (history is append-only)."""
    text = README_PATH.read_text(encoding="utf-8")
    assert "## 0.12.0 changes" in text, (
        "README.md lost its historical '## 0.12.0 changes' section; release "
        "history sections must be preserved, not rewritten"
    )


def test_server_info_payload_reports_full_provenance(monkeypatch):
    """AC4: the real hyperv_server_info payload builder (default Config,
    a01-style provenance stub) reports the installed version and the full
    provenance field set — the consumer-side build-distinguishability
    surface. git_revision is a call-time tree probe, so only its presence
    and shape are pinned, never its value."""
    _fake_provenance_run_ps(monkeypatch)
    cfg = Config()
    payload = server_module._server_info_payload(cfg)

    required = (
        "version",
        "git_revision",
        "powershell",
        "hyperv_target",
        "config_path",
        "config_sha256",
        "mcp_sdk_version",
        "protocol_version",
        "feature_flags",
    )
    missing = [field for field in required if field not in payload]
    assert missing == [], (
        f"_server_info_payload is missing provenance fields: {missing}"
    )
    assert payload["version"] == _metadata_version(), (
        f"_server_info_payload version {payload['version']!r} != installed "
        f"metadata version {_metadata_version()!r}"
    )
    assert isinstance(payload["git_revision"], str) and payload["git_revision"], (
        "_server_info_payload git_revision is empty; it must carry the "
        "call-time tree revision or the literal 'unknown' for installed "
        "builds — never blank"
    )


def test_versioning_policy_document_names_every_required_topic():
    """AC4 companion deliverable: docs/versioning-policy.md exists and
    names every bump site, the AMEND procedure, the server_info semantics,
    the tagging convention, and the vendored-repin ritual."""
    assert POLICY_PATH.is_file(), (
        "docs/versioning-policy.md does not exist; issue #67 requires a "
        "documented versioning policy enumerating every bump site"
    )
    text = POLICY_PATH.read_text(encoding="utf-8")
    missing = [literal for literal in POLICY_REQUIRED_LITERALS if literal not in text]
    assert missing == [], (
        "docs/versioning-policy.md is missing required topics: "
        f"{missing}; every bump site (pyproject.toml, __version__, "
        "test_c03_sdk_port, README) plus AMEND, hyperv_server_info, "
        "git_revision call-time semantics, tags, and the vendored-repin "
        "ritual must be enumerated"
    )
    # plan-critic round 2: the re-pin anchor must be a real heading line
    # (so the manifest's docs/versioning-policy.md#vendored-repin fragment
    # link resolves), not a bare substring anywhere in the document.
    assert VENDORED_REPIN_HEADING_RE.search(text), (
        "docs/versioning-policy.md must carry a real '## vendored-repin' "
        "heading line (fragment-linkable), not the phrase as a substring"
    )
