# Versioning & provenance policy

Status: binding for every release PR (issue #67; trace
`.agents/issue-traces/67-118-release-vendor-provenance/`).
Enforced by `tests/unit/test_versioning_provenance.py` and the frozen
`tests/unit/test_version_consistency.py`; the release executor's one-shot
pin is `test_c03_sdk_port.py` (frozen AC7, see bump site 3). The README
links here from its breaking-changes section.

## Release cadence

Every PR that changes shipped behavior bumps the version, and the bump is
part of the PR (never a separate "release-only" commit after merge). Below
1.0.0, every release takes a minor bump (0.x.y -> 0.x+1.0) regardless of
breaking vs feature/fix scope, so the minor digit is the primary
update-now signal consumers learn from. This is the mandated contract: downstream consumers learn
to update from the version number alone. After a release lands, downstream
users must update **and restart** any long-running shared controller — a
running server keeps its import-time literals.

## Bump sites — the complete enumeration

A version move MUST update exactly these sites, all in the same PR:

1. `pyproject.toml` — `[project] version` (the release-time literal that
   package metadata is built from).
2. `src/hyperv_mcp/__init__.py` — `__version__` (the binding literal).
   `server.py` binds `VERSION = _pkg_version` from it at IMPORT time, so
   the CLI banner, `--version`, `--check-env`, and the MCP initialize
   `serverInfo.version` all report that literal — `VERSION` is NOT read
   from distribution metadata at runtime; metadata is the consistency
   oracle the tests use to prove the literals and an installed build agree.
3. `tests/unit/test_c03_sdk_port.py` — the frozen AC7 assertion pinning the
   `pyproject.toml` version. This file is a frozen acceptance check of the
   `issue-16-tool-concurrency` trace: change it ONLY through the AMEND
   procedure (`repro-check.sh checkpoint --slug issue-16-tool-concurrency
   --id <check-id> --reason CHECK_WRONG|AC_CHANGED_BY_USER --argv <verbatim>
   --expect <verbatim> --base <original-replay-base> -- <frozen-path>` —
   see docs/rebaseline-runbook.md for the complete invocation; argv/expect
   copied VERBATIM from the effective rows, then `repro-check.sh anchor` and
   re-publication of the receipt as a superseding comment on issue #16;
   `verify-checkpoint` must report every pair OK).
4. `README.md` — add a `## X.Y.Z changes` section at the top of the release
   notes (the changelog of record, PR #121 convention; it must carry real
   content, and the pinning test requires >= 3 non-empty lines), move the
   UNIQUE `(<ver> today)` marker sentence on the shared-controller
   breaking-changes note to the new version, add the
   `Version bump: X.Y.Z -> X.Y+1.Z` line, and keep the link to this file.
   Historical sections are append-only and must not be rewritten.

Do not hand-edit `server.py VERSION` — it derives from site 2; editing it
re-introduces the literal-desync class issue #108 closed. The pair
site-1/site-2 equality against the INSTALLED distribution metadata is
pinned by `tests/unit/test_version_consistency.py`; the README coupling,
marker uniqueness, and the server_info payload version by
`tests/unit/test_versioning_provenance.py`.

## Consumer-side build identity (how to tell two builds apart)

- The version string is the primary identity (see bump sites): every
  release moves it, every surface reports the same value.
- The README `## X.Y.Z changes` sections are the narrative changelog of
  record — each release's breaking/feature set is enumerated there, so a
  consumer can map a version to its change set without reading source.
- `hyperv_server_info` (MCP tool) is the machine-readable provenance
  surface: `version` (the frozen build's package version), `git_revision`,
  `config_path`, `config_sha256`, `mcp_sdk_version`, `protocol_version`,
  `feature_flags`, `powershell` (host PowerShell provenance), and
  `hyperv_target` (local/remote targeting).

### Historical case: the two 0.4.0 builds

Before this policy, two different breaking-change sets both shipped as
0.4.0 (proxy-by-default per issue #8, then the mcp-2.x SDK port per PR #65).
The version alone cannot distinguish them; the machine-readable
`hyperv_server_info.mcp_sdk_version` field does: a build reporting an mcp
SDK version of 1.x is the pre-port build, 2.x is the mcp-2.x port. The
README `### 0.4.0 breaking changes` section names the first set; this rule
identifies the second. Future releases must never reuse a version string.

### git_revision semantics (read this before trusting it as build identity)

`git_revision` in `hyperv_server_info` is a CALL-TIME probe of the tree the
server process is executing from — it is NOT the build provenance:

- running from a git checkout: reports that checkout's HEAD revision at
  query time, even if the installed package metadata is older (the
  0.11.0-controller-on-d6be3c4 demonstration, trace P6);
- running from a non-git location (an installed wheel, no `.git`):
  reports `"unknown"`;
- it carries no dirty marker.

Use `version` for build identity; use `git_revision` only as a best-effort
pointer to a dev checkout (an editable install's call-time revision can
legitimately differ from the build's frozen version — update and restart).

## Release provenance artifacts

- Git tags: OPTIONAL maintainer provenance. The merging maintainer MAY tag
  the merge commit `vX.Y.Z`; no check depends on tags existing, because
  unenforced ceremony drifts (the lesson of this repo's tag-free history
  through 0.12.0).
- Frozen-checkpoint ledgers: after ANY PR touching files listed in a trace
  checkpoint manifest, run `python scripts/gen_trace_drift_inventory.py
  --check` (see docs/rebaseline-runbook.md); drift must be repaired through
  the runbook's verbatim-AMEND procedure with receipt re-publication on the
  trace's recorded venue before merge.

## Vendored skill copies — `## vendored-repin` ritual

`.agents/skills/{issue-tracer,swarm-pr-review,swarm-pr-feedback,commit-pr}/`
are byte-copies of `ZaxbyHub/opencode-swarm/.opencode/skills/` pinned by
`.agents/skills/vendored-skills.manifest` (sha256 per file at
`canonical_commit`). `tests/unit/test_vendored_skill_manifest.py` fails CI
on any CONTENT drift (CRLF-normalized sha256) — including
same-`version:`-string drift — in both directions (missing/extra files
included; EOL-only divergence is invisible by design and covered by the
`.gitattributes` eol pinning). Checkout EOL of the manifest and
`*.sh` files is pinned LF via `.gitattributes` so the anchor blob comparison
(`git hash-object --no-filters`) is stable on every platform.

### vendored-repin

When the canonical side advances (e.g. ZaxbyHub/opencode-swarm#3576 lands):

1. Freshness check first: `git -C <opencode-swarm> fetch` and compare its
   canonical main HEAD to the manifest's `canonical_commit` — drift is
   visible at release time, not only when someone wonders.
2. Re-enumerate the canonical FILE LIST via
   `git ls-tree -r <commit> -- .opencode/skills/issue-tracer
   .opencode/skills/swarm-pr-review .opencode/skills/swarm-pr-feedback
   .opencode/skills/commit-pr` at the new pin (never merely re-hash the
   existing rows — added/removed canonical files must move the set).
3. Re-generate every manifest row from the new pinned commit
   (pipe the canonical blob through the same CRLF→LF normalization the
   manifest header declares: `git -C <opencode-swarm> show
   <commit>:<path> | sed 's/
$//' | sha256sum`), map each canonical
   `.opencode/skills/<x>` path to its vendored `.agents/skills/<x>` row
   path, update the `canonical_commit:` header line, and bump the
   `refresh:` line to carry the re-pin date together with the
   `vendored-repin` procedure pointer.
4. Resync the vendored files to the canonical blobs byte-for-byte.
5. Run the trace's vendored-canonical compare (manifest↔canonical fidelity
   AND tree↔manifest) before opening the PR.
6. If the canonical file COUNT changes, `EXPECTED_ROW_COUNT` in
   `tests/unit/test_vendored_skill_manifest.py` must move with it — that
   file is a frozen check of the vendoring trace: go through the AMEND
   procedure (`--reason AC_CHANGED_BY_USER`, verbatim argv/expect re-pin)
   and re-publish the anchor receipt on issue #118.

Never "fix" drift by re-hashing the drifted local bytes into the manifest —
the manifest records what canonical says, not what the vendor copy happens
to contain.

### Vendored layout mapping

Vendored copies keep canonical text byte-for-byte, so commands inside them
reference canonical paths. In THIS repository, read/execute
`.opencode/skills/<x>` as `.agents/skills/<x>`. Do not path-"fix" vendored
bytes; canonical-portability belongs to ZaxbyHub/opencode-swarm.
