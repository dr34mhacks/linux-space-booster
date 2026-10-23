#!/usr/bin/env bash
# Focused regression tests for Phase 1 safety helpers and CLI parsing.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT_DIR/linux_space_booster.sh"
TEST_DIR=$(mktemp -d)

cleanup() {
    rm -rf -- "$TEST_DIR"
}
trap cleanup EXIT

pass=0
fail=0

assert_exists() {
    local path=$1
    local message=$2
    if [[ -e "$path" ]]; then
        printf 'ok - %s\n' "$message"
        ((pass+=1))
    else
        printf 'not ok - %s\n' "$message" >&2
        ((fail+=1))
    fi
}

assert_missing() {
    local path=$1
    local message=$2
    if [[ ! -e "$path" ]]; then
        printf 'ok - %s\n' "$message"
        ((pass+=1))
    else
        printf 'not ok - %s\n' "$message" >&2
        ((fail+=1))
    fi
}

assert_equals() {
    local actual=$1
    local expected=$2
    local message=$3
    if [[ "$actual" == "$expected" ]]; then
        printf 'ok - %s\n' "$message"
        ((pass+=1))
    else
        printf 'not ok - %s (expected %q, got %q)\n' "$message" "$expected" "$actual" >&2
        ((fail+=1))
    fi
}

# Sourcing exposes helpers without invoking the application's main function.
# shellcheck source=../linux_space_booster.sh
source "$SCRIPT"
LOG_FILE="$TEST_DIR/test.log"
ERROR_LOG_FILE="$TEST_DIR/test-errors.log"

parse_args --force --quick
assert_equals "$MODE/$FORCE_MODE/$DRY_RUN" "quick/true/false" "parser accepts force before quick"
parse_args --quick --force --dry-run
assert_equals "$MODE/$FORCE_MODE/$DRY_RUN" "quick/true/true" "parser accepts flags in any valid order"

printf 'keep' > "$TEST_DIR/dry-run file"
DRY_RUN=true
safe_remove_file "$TEST_DIR/dry-run file" "dry-run file"
assert_exists "$TEST_DIR/dry-run file" "dry run preserves files with spaces"

DRY_RUN=false
safe_remove_file "$TEST_DIR/dry-run file" "ordinary file"
assert_missing "$TEST_DIR/dry-run file" "safe_remove_file removes a permitted file"

mkdir -p "$TEST_DIR/contents"
printf visible > "$TEST_DIR/contents/visible"
printf hidden > "$TEST_DIR/contents/.hidden"
safe_remove_dir_contents "$TEST_DIR/contents" "test contents"
assert_exists "$TEST_DIR/contents" "directory cleanup preserves its parent directory"
assert_missing "$TEST_DIR/contents/visible" "directory cleanup removes visible entries"
assert_missing "$TEST_DIR/contents/.hidden" "directory cleanup removes hidden entries"

printf protected > "$TEST_DIR/protected"
safe_remove_file "" "empty path" && { printf 'not ok - empty path must fail\n' >&2; ((fail+=1)); } || { printf 'ok - empty path is rejected\n'; ((pass+=1)); }
safe_remove_file /etc/hosts "protected path" || true
assert_exists /etc/hosts "protected paths are never removed"

mkdir -p "$TEST_DIR/matches"
printf old > "$TEST_DIR/matches/old.log"
safe_find_delete "$TEST_DIR/matches" "old logs" -name '*.log' -type f
assert_missing "$TEST_DIR/matches/old.log" "safe_find_delete removes only matched files"
safe_find_delete "$TEST_DIR/matches" "unsafe predicate" -delete && { printf 'not ok - destructive find action must fail\n' >&2; ((fail+=1)); } || { printf 'ok - destructive find action is rejected\n'; ((pass+=1)); }

bash -n "$SCRIPT"
printf 'ok - bash syntax check\n'
((pass+=1))

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$SCRIPT" "$0"
    printf 'ok - ShellCheck\n'
    ((pass+=1))
else
    printf 'ok - ShellCheck not installed (skipped)\n'
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
