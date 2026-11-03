#!/usr/bin/env bash
# Frozen acceptance-check driver for the collated trace
# (#95 worker lifetime, #69 transport security, #37 UNC+husks,
#  #110 wheel gate, #57 log timestamps, #56 README docs).
#
# Structure copied from the 31-32-33-94-workstream-g trace's check-g.sh
# (the trace's frozen-driver pattern). run_one() cds into the tree under
# test before invoking this script: the disposable base worktree for the
# base leg, the real repository root for the head leg. The tree under test
# comes from the cwd (never BASH_SOURCE); the interpreter comes from the
# MAIN checkout's venv discovered through git's common dir. PYTHONPATH pins
# the tree under test ahead of any editable install (the vacuous-base trap).
#
# Hatchling note (#110): the wheel checks skip when hatchling is absent;
# the dev extras install hatchling at head, so the head leg runs the real
# build. HYPERV_MCP_PYTHON overrides the interpreter, as in check-g.sh.

set -uo pipefail

[ "$#" -ge 1 ] || { echo "usage: check-c.sh <pytest-node-id> [more...]" >&2; exit 2; }
tree="$(pwd -P)"

resolve_main_root() {
  local common base
  common="$(git rev-parse --git-common-dir 2>/dev/null || true)"
  if [ -n "$common" ]; then
    case "$common" in
      /* | [A-Za-z]:/* | [A-Za-z]:*)
        ;;
      *)
        common="$tree/$common"
        ;;
    esac
    if base="$(cd "$common/.." 2>/dev/null && pwd -P)"; then
      printf '%s\n' "$base"
      return 0
    fi
  fi
  return 1
}

if [ -n "${HYPERV_MCP_PYTHON:-}" ]; then
  py="$HYPERV_MCP_PYTHON"
else
  main_root="$(resolve_main_root || true)"
  py=""
  if [ -n "$main_root" ]; then
    for candidate in \
      "$main_root/.venv/Scripts/python.exe" \
      "$main_root/.venv/bin/python"; do
      if [ -x "$candidate" ]; then
        py="$candidate"
        break
      fi
    done
  fi
fi

[ -n "$py" ] || { echo "check-c: no interpreter found (set HYPERV_MCP_PYTHON)" >&2; exit 127; }

export PYTHONPATH="$tree/src${PYTHONPATH:+:$PYTHONPATH}"
exec "$py" -m pytest "$@" -q -p no:cacheprovider -o addopts=
