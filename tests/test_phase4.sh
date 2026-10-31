#!/usr/bin/env bash
# Phase 4 tests for non-destructive analysis and JSON reporting.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# shellcheck source=../linux_space_booster.sh
source "$ROOT_DIR/linux_space_booster.sh"

get_filesystem_stats() {
    printf '1000 400 600 40%% /\n'
}

get_largest_directories() {
    printf '300\t/var\n100\t/path with spaces\n'
}

collect_module_analysis() {
    printf 'package-cache\tavailable\t200\n'
    printf 'snap\tunavailable\t0\n'
}

json_output=$(emit_analysis_json)

grep -Fq '"size_bytes": 1000' <<< "$json_output" || {
    printf 'not ok - JSON includes filesystem byte values\n' >&2
    exit 1
}
grep -Fq '{"path": "/path with spaces", "size_bytes": 100}' <<< "$json_output" || {
    printf 'not ok - JSON preserves directory paths with spaces\n' >&2
    exit 1
}
grep -Fq '{"name": "snap", "status": "unavailable", "estimate_bytes": 0}' <<< "$json_output" || {
    printf 'not ok - JSON includes unavailable module status\n' >&2
    exit 1
}
grep -Fq '"total_estimate_bytes": 200' <<< "$json_output" || {
    printf 'not ok - JSON total includes available estimates only\n' >&2
    exit 1
}

if [[ "$DRY_RUN" != false ]]; then
    printf 'not ok - analysis does not alter dry-run state\n' >&2
    exit 1
fi
printf 'ok - analysis JSON reports filesystem, directories, modules, and totals\n'
printf 'Phase 4 analysis tests passed\n'
