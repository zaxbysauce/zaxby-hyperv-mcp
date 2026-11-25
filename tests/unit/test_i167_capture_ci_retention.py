"""The CI retention step must keep a diagnosis from a SUCCESSFUL run.

The capture exists for a SWALLOWED WinError 10038: the socket family
catches the error before any pytest reporting hook can see it, so the CI
job can SUCCEED with a captured diagnosis on disk. A failure-only
retention step would discard exactly the evidence the capture exists to
preserve - the artifact dies with the runner.
"""

import pathlib
import re

WORKFLOW = pathlib.Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"


def _retention_step() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"- name: Retain the socket-10038 diagnosis.*?"
        r"(?=\n      - name:|\n  [a-zA-Z-]+:|\Z)",
        text, re.DOTALL)
    assert match is not None, (
        "the CI workflow has no socket-10038 diagnosis retention step")
    return match.group(0)


def test_the_diagnosis_retention_runs_on_a_successful_run():
    body = _retention_step()
    assert "if: always()" in body, (
        "the diagnosis retention step must run on a SUCCESSFUL run: the "
        "captured WinError 10038 can be swallowed by the socket family, so "
        "the job can succeed with a diagnosis to keep")
    assert "if: failure()" not in body, (
        "the diagnosis retention step must not be failure-only")
    assert "if-no-files-found: ignore" in body, (
        "a run that produced no diagnosis at all must still be permitted")


def test_the_diagnosis_artifact_name_carries_the_attempt():
    body = _retention_step()
    assert "github.run_attempt" in body, (
        "upload-artifact@v4 artifact names are immutable, so a re-run "
        "attempt must be able to upload its own copy")
    assert "matrix.python-version" in body, (
        "the artifact name must carry the matrix leg, or the matrix legs "
        "would collide on one name")
