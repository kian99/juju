#!/usr/bin/env bash
# bench-completion.sh — Benchmark juju tab-completion with hyperfine.
#
# Runs each scenario twice: cold (cache cleared before every run) and
# warm (cache populated by warmup runs). Comparing the two shows the
# cost of the API calls vs the actual completion logic.
#
# Run from the repo root with direnv active:
#   bash scripts/bench-completion.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPLETION="$REPO_ROOT/etc/bash_completion.d/juju"

if ! command -v hyperfine &>/dev/null; then
    echo "ERROR: hyperfine not found (apt install hyperfine)" >&2
    exit 1
fi

# Prefix shared by every benchmark command.
S="source '$COMPLETION'; COMPREPLY=()"

# Scenarios: (label, COMP_WORDS array, COMP_CWORD)
declare -a NAMES=(
    "juju <Tab>"
    "juju switch <Tab>"
    "juju -c <Tab>"
    "juju deploy -<Tab>"
    "juju status -m <Tab>"
)
declare -a CMDS=(
    "$S; COMP_WORDS=(juju '');           COMP_CWORD=1; _juju_complete_2"
    "$S; COMP_WORDS=(juju switch '');    COMP_CWORD=2; _juju_complete_2"
    "$S; COMP_WORDS=(juju -c '');        COMP_CWORD=2; _juju_complete_2"
    "$S; COMP_WORDS=(juju deploy -);     COMP_CWORD=2; _juju_complete_2"
    "$S; COMP_WORDS=(juju status -m ''); COMP_CWORD=3; _juju_complete_2"
)

build_hyperfine_args() {
    local -n _names=$1
    local -n _cmds=$2
    local args=()
    for i in "${!_names[@]}"; do
        args+=(-n "${_names[$i]}" "${_cmds[$i]}")
    done
    printf '%s\0' "${args[@]}"
}

echo "=== Cold (no cache — API call on every run) ==="
mapfile -d '' cold_args < <(build_hyperfine_args NAMES CMDS)
hyperfine \
    --shell bash \
    --runs 10 \
    --prepare 'rm -f ~/.cache/juju/juju-*' \
    --export-csv "$REPO_ROOT/bench-cold.csv" \
    "${cold_args[@]}"

echo ""
echo "=== Warm (cache populated by warmup runs) ==="
mapfile -d '' warm_args < <(build_hyperfine_args NAMES CMDS)
hyperfine \
    --shell bash \
    --warmup 3 \
    --export-csv "$REPO_ROOT/bench-warm.csv" \
    "${warm_args[@]}"

echo ""
echo "Results:"
echo "  Cold: bench-cold.csv"
echo "  Warm: bench-warm.csv"
