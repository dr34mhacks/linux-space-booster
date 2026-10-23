#!/bin/bash

#==============================================================================
#
#        ╔════════════════════════════════╗
#        ║    LINUX SPACE BOOSTER 🧹      ║
#        ╚════════════════════════════════╝
#
#             .---.
#           _/__|__\_        .-------.
#          (  o   o  )       | Trash |
#          |    ∆    |       |  Bin  |
#          |  \___/  |       |_______|
#         /|         |\
#        /_|_________|_\     [*] Deleting cache...
#          ||  ||  ||        [*] Cleaning logs...
#          []  []  []        [*] Removing junk...
#
#           🤖 Bot says: "All clean!"
#           ✅ Disk space recovered!
#
#==============================================================================
# Advanced Linux Cleanup Utility - Cross-Distribution Safe
# Compatible with: Kali Linux, Parrot OS, Ubuntu, Linux Mint, Debian
# Version: 2.0
# Original Author: Sid Joshi (github.com/dr34mhacks)
# License: MIT
#
# DESCRIPTION:
# This script safely cleans up disk space on Linux virtual machines without
# harming critical system files or user data. It includes multiple safety
# checks and handles distribution-specific cleanup operations.
#==============================================================================

set -euo pipefail

# =============================================================================
# Constants
# =============================================================================

readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_NAME="Linux-Space-Booster"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_BAD_ARGS=2
readonly EXIT_NO_PRIVILEGE=3
readonly EXIT_UNSUPPORTED=4
readonly EXIT_PARTIAL=5
readonly EXIT_FAILED=6

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Icons (Unicode)
readonly ICON_SUCCESS="✓"
readonly ICON_ERROR="✗"
readonly ICON_WARNING="!"
readonly ICON_INFO="i"
readonly ICON_SHIELD="*"
readonly ICON_ROCKET=">"
readonly ICON_CLEAN="+"
readonly ICON_DISK="D"
readonly ICON_CLOCK="T"

# Icons (ASCII fallback)
readonly ASCII_SUCCESS="[OK]"
readonly ASCII_ERROR="[ERROR]"
readonly ASCII_WARNING="[WARN]"
readonly ASCII_INFO="[INFO]"
readonly ASCII_SHIELD="[SAFE]"
readonly ASCII_ROCKET="[BOOST]"
readonly ASCII_CLEAN="[CLEAN]"
readonly ASCII_DISK="[DISK]"
readonly ASCII_CLOCK="[TIME]"

# Protected paths — never deleted or have their contents wiped
readonly CRITICAL_PATHS=(
    "/"
    "/bin"
    "/boot"
    "/dev"
    "/etc"
    "/lib"
    "/lib64"
    "/proc"
    "/sys"
    "/usr"
    "/var/lib/dpkg"
    "/var/lib/apt"
    "/var/run"
    "/var/lock"
    "/home"
    "/root"
)

# =============================================================================
# Globals (mutable state)
# =============================================================================

LOG_FILE=""
ERROR_LOG_FILE=""
BACKUP_DIR=""
DRY_RUN=false
FORCE_MODE=false
BACKUP_ENABLED=false
TOTAL_FREED=0
MODULES_FAILED=0
START_TIME=$(date +%s)
USE_EMOJI=true
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)
AVAIL_BEFORE=""
MODE=""
JSON_OUTPUT=false

# =============================================================================
# Terminal capabilities
# =============================================================================

detect_terminal_capabilities() {
    USE_EMOJI=true
    if [[ "${TERM:-dumb}" == "dumb" || "${TERM:-dumb}" == "unknown" ]]; then
        USE_EMOJI=false
    fi
    if [[ "${NO_EMOJI:-}" == "1" || "${NO_EMOJI:-}" == "true" ]]; then
        USE_EMOJI=false
    fi
    # Respect NO_COLOR (https://no-color.org)
    if [[ -n "${NO_COLOR:-}" ]]; then
        USE_EMOJI=false
    fi
}

get_icon() {
    local icon_name="$1"
    local var_name
    if [[ "$USE_EMOJI" == true ]]; then
        var_name="ICON_$icon_name"
    else
        var_name="ASCII_$icon_name"
    fi
    echo "${!var_name}"
}

# =============================================================================
# Logging
# =============================================================================

setup_log_files() {
    local user_only_mode="${1:-false}"
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    if [[ "$user_only_mode" == "true" ]]; then
        if [[ -w "$HOME" ]]; then
            LOG_FILE="$HOME/.cache/linux-space-booster-$timestamp.log"
            ERROR_LOG_FILE="$HOME/.cache/linux-space-booster-errors-$timestamp.log"
            BACKUP_DIR="$HOME/.cache/linux-space-booster-backup-$timestamp"
            mkdir -p "$HOME/.cache" 2>/dev/null
        else
            LOG_FILE="/tmp/linux-space-booster-$timestamp.log"
            ERROR_LOG_FILE="/tmp/linux-space-booster-errors-$timestamp.log"
            BACKUP_DIR="/tmp/linux-space-booster-backup-$timestamp"
        fi
    else
        LOG_FILE="/var/log/system-cleanup-$timestamp.log"
        ERROR_LOG_FILE="/var/log/system-cleanup-errors-$timestamp.log"
        BACKUP_DIR="/var/backups/linux-space-booster-$timestamp"
    fi
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
    fi

    case "$level" in
        "ERROR")   echo -e "${RED}[ERROR]${NC} $message" ;;
        "WARNING") echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        "INFO")    echo -e "${BLUE}[INFO]${NC} $message" ;;
        *)         echo -e "${WHITE}[DEBUG]${NC} $message" ;;
    esac
}

# =============================================================================
# Utility functions
# =============================================================================

get_disk_space() {
    df -h / | awk 'NR==2 {print $3, $4, $5}'
}

get_dir_size() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        du -sb "$dir" 2>/dev/null | cut -f1 || echo "0"
    else
        echo "0"
    fi
}

bytes_to_human() {
    local bytes="$1"
    if [[ $bytes -gt 1073741824 ]]; then
        echo "$(( bytes / 1073741824 )).$(( (bytes % 1073741824) / 107374182 ))GB"
    elif [[ $bytes -gt 1048576 ]]; then
        echo "$(( bytes / 1048576 )).$(( (bytes % 1048576) / 104857 ))MB"
    elif [[ $bytes -gt 1024 ]]; then
        echo "$(( bytes / 1024 ))KB"
    else
        echo "${bytes}B"
    fi
}

# =============================================================================
# Safety API — ALL destructive operations MUST go through these functions
# =============================================================================

# Check if path is a protected system path
is_critical_path() {
    local path="$1"
    for critical in "${CRITICAL_PATHS[@]}"; do
        if [[ "$path" == "$critical" ]] || [[ "$path" == "$critical"/* ]]; then
            return 0
        fi
    done
    return 1
}

# Delete a single file safely
safe_remove_file() {
    local file="$1"
    local description="${2:-$file}"

    # Reject empty path
    if [[ -z "$file" ]]; then
        log_message "ERROR" "safe_remove_file: empty path"
        return 1
    fi

    # Canonicalize path
    local canonical
    canonical=$(readlink -f "$file" 2>/dev/null) || canonical="$file"

    # Reject critical paths
    if is_critical_path "$canonical"; then
        log_message "WARNING" "Blocked critical path removal: $canonical"
        return 0
    fi

    # Check existence
    if [[ ! -e "$file" ]]; then
        return 0
    fi

    # Dry run
    if [[ "$DRY_RUN" == true ]]; then
        local size=0
        if [[ -f "$file" ]]; then
            size=$(stat -c%s "$file" 2>/dev/null || echo 0)
        fi
        log_message "INFO" "[DRY RUN] Would remove: $file ($description)"
        return 0
    fi

    # Execute
    if rm -f -- "$file" 2>/dev/null; then
        log_message "SUCCESS" "Removed: $file ($description)"
        return 0
    else
        log_message "WARNING" "Failed to remove: $file"
        MODULES_FAILED=$((MODULES_FAILED + 1))
        return 1
    fi
}

# Delete the contents of a directory (including hidden files) without
# deleting the directory itself.  Uses find -mindepth 1 to handle hidden
# entries — the old rm -rf "$dir"/* pattern silently skipped dot-files.
safe_remove_dir_contents() {
    local dir="$1"
    local description="${2:-$dir}"

    # Reject empty path
    if [[ -z "$dir" ]]; then
        log_message "ERROR" "safe_remove_dir_contents: empty path"
        return 1
    fi

    # Canonicalize path
    local canonical
    canonical=$(readlink -f "$dir" 2>/dev/null) || canonical="$dir"

    # Reject critical paths
    if is_critical_path "$canonical"; then
        log_message "WARNING" "Blocked critical path content removal: $canonical"
        return 0
    fi

    # Check existence
    if [[ ! -d "$dir" ]]; then
        return 0
    fi

    # Dry run
    if [[ "$DRY_RUN" == true ]]; then
        local size
        size=$(get_dir_size "$dir")
        local count
        count=$(find "$dir" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        log_message "INFO" "[DRY RUN] Would clear contents of: $dir ($description, $count items, $(bytes_to_human "$size"))"
        echo -e "  ${YELLOW}[DRY RUN]${NC} Would clear: $description ($(bytes_to_human "$size"), $count items)"
        return 0
    fi

    # Execute — handles hidden files, preserves the directory itself
    if find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null; then
        log_message "SUCCESS" "Cleared contents of: $dir ($description)"
        return 0
    fi

    log_message "WARNING" "Failed to clear all contents of: $dir ($description)"
    MODULES_FAILED=$((MODULES_FAILED + 1))
    return 1
}

# Find files matching caller-supplied predicates and delete them
safe_find_delete() {
    local base_dir="$1"
    local description="$2"
    shift 2
    local find_args=("$@")

    # Reject empty path
    if [[ -z "$base_dir" ]]; then
        log_message "ERROR" "safe_find_delete: empty path"
        return 1
    fi

    if [[ ${#find_args[@]} -eq 0 ]]; then
        log_message "ERROR" "safe_find_delete: no predicates supplied for $base_dir"
        return 1
    fi

    # Callers may describe matches, but cannot smuggle a destructive find
    # action past this safety boundary.
    local arg
    for arg in "${find_args[@]}"; do
        case "$arg" in
            -delete|-exec|-execdir|-ok|-okdir)
                log_message "ERROR" "safe_find_delete: destructive find action is not allowed"
                return 1
                ;;
        esac
    done

    # Canonicalize path
    local canonical
    canonical=$(readlink -f "$base_dir" 2>/dev/null) || canonical="$base_dir"

    # Reject critical paths
    if is_critical_path "$canonical"; then
        log_message "WARNING" "Blocked critical path find-delete: $canonical"
        return 0
    fi

    # Check existence
    if [[ ! -d "$base_dir" ]]; then
        return 0
    fi

    # Dry run
    if [[ "$DRY_RUN" == true ]]; then
        local count
        count=$(find "$base_dir" "${find_args[@]}" 2>/dev/null | wc -l)
        log_message "INFO" "[DRY RUN] Would find-delete in: $base_dir ($description, $count matches)"
        if [[ $count -gt 0 ]]; then
            echo -e "  ${YELLOW}[DRY RUN]${NC} Would clean: $description ($count files)"
        fi
        return 0
    fi

    # Execute
    if find "$base_dir" "${find_args[@]}" -exec rm -rf -- {} + 2>/dev/null; then
        log_message "SUCCESS" "Find-delete in: $base_dir ($description)"
        return 0
    fi

    log_message "WARNING" "Find-delete failed in: $base_dir ($description)"
    MODULES_FAILED=$((MODULES_FAILED + 1))
    return 1
}

# =============================================================================
# Module API — standardized lifecycle for cleanup modules
# =============================================================================

module_start() {
    local name="$1"
    local description="$2"
    echo -e "\n${BOLD}${PURPLE}[$name] $description${NC}"
    log_message "INFO" "Module started: $name"
}

# Returns 0 if the user confirms (or FORCE_MODE/DRY_RUN is active), 1 to skip
module_confirm() {
    local name="$1"
    local size_bytes="$2"
    local prompt="${3:-Clean $name?}"

    if [[ "$FORCE_MODE" == true ]]; then
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        return 0  # always "confirm" in dry run to show what would happen
    fi

    echo -e "${YELLOW}${prompt} ($(bytes_to_human "$size_bytes")) [Y/n]${NC}"
    local response
    read -r response
    if [[ "$response" =~ ^[Nn]$ ]]; then
        module_skip "$name" "Skipped by user"
        return 1
    fi
    return 0
}

module_skip() {
    local name="$1"
    local reason="$2"
    echo -e "  ${BLUE}ℹ${NC} $name: $reason"
    log_message "INFO" "Module skipped: $name ($reason)"
}

module_end() {
    local name="$1"
    local freed_bytes="$2"

    TOTAL_FREED=$((TOTAL_FREED + freed_bytes))

    if [[ $freed_bytes -gt 0 ]]; then
        echo -e "  ${GREEN}✓${NC} $name cleaned - ${GREEN}$(bytes_to_human "$freed_bytes")${NC} freed"
        log_message "SUCCESS" "Module completed: $name - $(bytes_to_human "$freed_bytes") freed"
    else
        echo -e "  ${BLUE}ℹ${NC} $name: Nothing to clean"
        log_message "INFO" "Module completed: $name - nothing to clean"
    fi
}

# =============================================================================
# Detection
# =============================================================================

# Validate command exists
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_message "ERROR" "Required command '$cmd' not found"
        return 1
    fi
    return 0
}

detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

get_system_info() {
    local distro
    distro=$(detect_distribution)

    case "$distro" in
        "kali"|"parrot")
            echo "penetration_testing"
            ;;
        "ubuntu"|"linuxmint"|"mint"|"pop")
            echo "desktop_ubuntu_based"
            ;;
        "debian")
            echo "debian_server"
            ;;
        "fedora"|"centos"|"rhel"|"rocky"|"alma")
            echo "rpm_based"
            ;;
        "arch"|"manjaro"|"endeavouros")
            echo "arch_based"
            ;;
        "alpine")
            echo "alpine"
            ;;
        *)
            echo "generic_linux"
            ;;
    esac
}

# =============================================================================
# Display — header, preflight, disk summary
# =============================================================================

show_header() {
    detect_terminal_capabilities
    echo
    echo -e "${BLUE}${BOLD}== $SCRIPT_NAME v$SCRIPT_VERSION ==${NC}"
    echo -e "${CYAN}Advanced Linux Disk Space Management Utility${NC}"
    echo
    local distro
    distro=$(detect_distribution | tr '[:lower:]' '[:upper:]')
    local sys_type
    sys_type=$(get_system_info)
    local kernel
    kernel=$(uname -r)
    local arch
    arch=$(uname -m)
    local current_date
    current_date=$(date '+%Y-%m-%d %H:%M:%S')
    local distro_icon
    if [[ "$USE_EMOJI" == true ]]; then
        case "$distro" in
            "KALI") distro_icon="🔒" ;;
            "PARROT") distro_icon="🦜" ;;
            "UBUNTU") distro_icon="🔶" ;;
            "DEBIAN") distro_icon="🔴" ;;
            "LINUXMINT"|"MINT") distro_icon="🍃" ;;
            *) distro_icon="🐧" ;;
        esac
    else
        distro_icon="[OS]"
    fi
    local disk_icon
    disk_icon=$(get_icon "DISK")
    local info_icon
    info_icon=$(get_icon "INFO")
    local clock_icon
    clock_icon=$(get_icon "CLOCK")
    local shield_icon
    shield_icon=$(get_icon "SHIELD")
    local computer_icon="[PC]"
    if [[ "$USE_EMOJI" == true ]]; then
        computer_icon="🖥️ "
    fi
    echo -e "${WHITE}${BOLD}SYSTEM INFORMATION${NC}"
    echo -e "  ${distro_icon} ${BOLD}Distribution:${NC} ${GREEN}$distro${NC} | ${disk_icon} ${BOLD}Kernel:${NC} ${GREEN}$kernel${NC}"
    echo -e "  ${computer_icon} ${BOLD}System Type:${NC} ${GREEN}$sys_type${NC} | ${info_icon} ${BOLD}Architecture:${NC} ${GREEN}$arch${NC}"
    echo -e "  ${clock_icon} ${BOLD}Date & Time:${NC} ${GREEN}$current_date${NC}"
    echo
    # Safety policy — technically defensible claims only
    echo -e "${WHITE}${BOLD}SAFETY POLICY${NC}"
    echo -e "  ${shield_icon} Destructive operations are scoped"
    echo -e "  ${shield_icon} Critical paths are blocked"
    echo -e "  ${shield_icon} Dry-run available (--dry-run)"
    echo -e "  ${shield_icon} Every operation is logged"
    echo
}

# Pre-flight system checks
preflight_checks() {
    local mode="${1:-}"
    local quiet_mode=false
    if [[ "$mode" == "--quiet" ]]; then
        quiet_mode=true
    fi

    log_message "INFO" "Running pre-flight system checks..."

    # Only show safety banner if not in quiet mode
    if [[ "$quiet_mode" == false ]]; then
        echo -e "\n${BOLD}${GREEN}SAFETY PROTECTION ACTIVE${NC}"
        echo -e "${GREEN}✓ Destructive operations are scoped${NC}"
        echo -e "${GREEN}✓ Critical paths are blocked${NC}"
        echo -e "${GREEN}✓ Active-file checks where supported${NC}"
        echo -e "${GREEN}✓ User data directories excluded by default${NC}"
        echo -e "${GREEN}✓ High-risk operations require confirmation${NC}"
        echo -e "${GREEN}✓ Every operation is logged${NC}"
        echo
    fi

    # Check if running as root for system cleanup
    if [[ $EUID -ne 0 ]] && [[ "$mode" != "--user-only" ]]; then
        log_message "WARNING" "Some cleanup operations require root privileges"
        if [[ "$quiet_mode" == false ]]; then
            echo -e "${YELLOW}Tip: Run with 'sudo' for complete system cleanup${NC}"
        fi
    fi

    # Check required commands — only require what this system actually needs
    local required_commands=("df" "du" "find")
    if [[ "$mode" != "--user-only" ]]; then
        # For system cleanup, we need lsof; apt is checked per-module, not globally
        if command -v lsof >/dev/null 2>&1; then
            required_commands+=("lsof")
        fi
    fi

    for cmd in "${required_commands[@]}"; do
        check_command "$cmd" || exit "$EXIT_UNSUPPORTED"
    done

    # Check disk space
    local disk_info
    read -r -a disk_info <<< "$(get_disk_space)"
    local used_percent="${disk_info[2]%\%}"

    if [[ $used_percent -gt 95 ]]; then
        log_message "WARNING" "Disk usage is critically high (${used_percent}%)"
        if [[ "$quiet_mode" == false ]]; then
            echo -e "${RED}WARNING: Disk usage is critically high! Emergency cleanup recommended.${NC}"
        fi
    fi

    log_message "SUCCESS" "Pre-flight checks completed"
    if [[ "$quiet_mode" == false ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} Pre-flight checks completed"
    fi
}

# Show current disk usage summary with visual indicators
show_disk_summary() {
    local compact_mode="${1:-}"
    if [[ "$compact_mode" == "--compact" ]]; then
        compact_mode=true
    else
        compact_mode=false
    fi

    local disk_icon
    disk_icon=$(get_icon "DISK")
    local clean_icon
    clean_icon=$(get_icon "CLEAN")

    local hr_width=$((TERM_WIDTH - 2))

    if [[ "$compact_mode" == false ]]; then
        echo -e "${WHITE}${BOLD}${disk_icon} DISK USAGE ANALYSIS ${disk_icon}${NC}"
    fi

    # Get disk usage information
    local disk_info
    read -r -a disk_info <<< "$(get_disk_space)"
    local used="${disk_info[0]}"
    local free="${disk_info[1]}"
    local usage="${disk_info[2]}"
    local usage_percent="${usage%\%}"

    local bar_length=$(( hr_width / 2 ))
    bar_length=$(( bar_length < 20 ? 20 : bar_length ))
    bar_length=$(( bar_length > 60 ? 60 : bar_length ))
    local filled_length=$(( usage_percent * bar_length / 100 ))
    local empty_length=$(( bar_length - filled_length ))

    local bar=""
    local color="${GREEN}"
    local filled_char empty_char

    if [[ $usage_percent -gt 90 ]]; then
        color="${RED}"
    elif [[ $usage_percent -gt 70 ]]; then
        color="${YELLOW}"
    fi

    # Use different chars based on terminal capability
    if [[ "$USE_EMOJI" == true ]]; then
        filled_char="█"
        empty_char="░"
    else
        filled_char="#"
        empty_char="."
    fi

    # Build the bar
    for ((i=0; i<filled_length; i++)); do
        bar="${bar}${filled_char}"
    done
    for ((i=0; i<empty_length; i++)); do
        bar="${bar}${empty_char}"
    done

    # Display disk usage information in compact format
    echo -e "  ${BOLD}Root Filesystem Usage:${NC} ${color}${bar} ${usage}${NC}"
    echo -e "  ${BOLD}Used:${NC} ${RED}${used}${NC} │ ${BOLD}Free:${NC} ${GREEN}${free}${NC}"

    # Skip cleanup targets in compact mode
    if [[ "$compact_mode" == true ]]; then
        return
    fi

    echo
    echo -e "${WHITE}${BOLD}${clean_icon} CLEANUP TARGETS ${clean_icon}${NC}"

    # Create icons with fallbacks
    local pkg_icon="[PKG]"
    local log_icon="[LOG]"
    local pg_icon="[PG]"
    local journal_icon="[JRN]"
    local tmp_icon="[TMP]"
    local home_icon="[HOME]"
    local tool_icon="[TOOL]"
    local snap_icon="[SNAP]"

    if [[ "$USE_EMOJI" == true ]]; then
        pkg_icon="📦"
        log_icon="📄"
        pg_icon="🐘"
        journal_icon="📋"
        tmp_icon="🗂️ "
        home_icon="🏠"
        tool_icon="🔧"
        snap_icon="📱"
    fi

    # APT Cache
    if command -v apt >/dev/null 2>&1; then
        local apt_cache_size
        apt_cache_size=$(get_dir_size "/var/cache/apt/archives")
        echo -e "  ${pkg_icon} APT Cache:           ${CYAN}$(bytes_to_human "$apt_cache_size")${NC}"
    fi

    # System Logs
    local log_size
    log_size=$(get_dir_size "/var/log")
    echo -e "  ${log_icon} System Logs:        ${CYAN}$(bytes_to_human "$log_size")${NC}"

    # PostgreSQL Logs (Kali-specific)
    local postgres_log_size=0
    for pg_log in /var/log/postgresql /var/lib/postgresql/*/main/log; do
        if [[ -d "$pg_log" ]]; then
            postgres_log_size=$((postgres_log_size + $(get_dir_size "$pg_log")))
        fi
    done
    if [[ $postgres_log_size -gt 0 ]]; then
        echo -e "  ${pg_icon} PostgreSQL Logs:    ${CYAN}$(bytes_to_human $postgres_log_size)${NC}"
    fi

    # Journal Logs (if systemd)
    if command -v journalctl >/dev/null 2>&1; then
        local journal_size
        journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' || echo "0B")
        echo -e "  ${journal_icon} Journal Logs:       ${CYAN}$journal_size${NC}"
    fi

    # Temporary Files
    local tmp_size
    tmp_size=$(get_dir_size "/tmp")
    echo -e "  ${tmp_icon} Temp Files:         ${CYAN}$(bytes_to_human "$tmp_size")${NC}"

    # User Caches (current user only)
    if [[ -d "$HOME/.cache" ]]; then
        local user_cache_size
        user_cache_size=$(get_dir_size "$HOME/.cache")
        echo -e "  ${home_icon} User Cache:          ${CYAN}$(bytes_to_human "$user_cache_size")${NC}"
    fi

    # Metasploit Cache (Kali-specific) - SAFE DETECTION ONLY
    local msf_cache_size=0
    for msf_logs in "$HOME/.msf4/logs" "/root/.msf4/logs"; do
        if [[ -d "$msf_logs" ]]; then
            msf_cache_size=$((msf_cache_size + $(get_dir_size "$msf_logs")))
        fi
    done
    if [[ $msf_cache_size -gt 0 ]]; then
        echo -e "  ${tool_icon} Metasploit Logs:    ${CYAN}$(bytes_to_human $msf_cache_size)${NC} ${GREEN}(safe to clean)${NC}"
    fi

    # Snap packages (Ubuntu/Mint)
    if command -v snap >/dev/null 2>&1; then
        local snap_size
        snap_size=$(get_dir_size "/var/lib/snapd/snaps")
        echo -e "  ${snap_icon} Snap Packages:      ${CYAN}$(bytes_to_human "$snap_size")${NC}"
    fi

    echo
}

# =============================================================================
# Shared cleanup helpers — extracted from duplicated code in multiple modules
# =============================================================================

# Clean browser caches for a given home directory
cleanup_browser_caches() {
    local home_dir="${1:-$HOME}"
    local total_freed=0

    local browser_cache_dirs=(
        "$home_dir/.cache/mozilla/firefox"
        "$home_dir/.cache/google-chrome"
        "$home_dir/.cache/chromium"
    )

    local cache_dir_names=("cache2" "Cache" "CachedData" "Code Cache")

    for browser_dir in "${browser_cache_dirs[@]}"; do
        if [[ -d "$browser_dir" ]]; then
            local size_before
            size_before=$(get_dir_size "$browser_dir")

            # Find and clear known cache subdirectories
            for cache_name in "${cache_dir_names[@]}"; do
                while IFS= read -r -d '' cache_path; do
                    safe_remove_dir_contents "$cache_path" "$(basename "$browser_dir")/$cache_name"
                done < <(find "$browser_dir" -name "$cache_name" -type d -print0 2>/dev/null)
            done

            local size_after
            size_after=$(get_dir_size "$browser_dir")
            local freed=$((size_before - size_after))
            total_freed=$((total_freed + freed))

            if [[ $freed -gt 0 ]]; then
                echo -e "    ${GREEN}✓${NC} $(basename "$browser_dir") cache - $(bytes_to_human $freed)"
            fi
        fi
    done

    TOTAL_FREED=$((TOTAL_FREED + total_freed))
}

# Clean thumbnail cache for a given home directory
cleanup_thumbnails_dir() {
    local home_dir="${1:-$HOME}"

    if [[ -d "$home_dir/.cache/thumbnails" ]]; then
        local size_before
        size_before=$(get_dir_size "$home_dir/.cache/thumbnails")

        safe_remove_dir_contents "$home_dir/.cache/thumbnails" "Thumbnail cache"

        local size_after
        size_after=$(get_dir_size "$home_dir/.cache/thumbnails")
        local freed=$((size_before - size_after))
        TOTAL_FREED=$((TOTAL_FREED + freed))

        if [[ $freed -gt 0 ]]; then
            echo -e "  ${GREEN}✓${NC} Thumbnail cache - $(bytes_to_human $freed)"
        fi
    fi
}

# Clean development tool caches for a given home directory
cleanup_dev_caches_dir() {
    local home_dir="${1:-$HOME}"
    local total_freed=0

    local safe_cache_dirs=(
        "$home_dir/.cache/pip"
        "$home_dir/.cache/yarn"
        "$home_dir/.cache/npm"
        "$home_dir/.cache/go-build"
        "$home_dir/.cache/composer"
    )

    for safe_cache in "${safe_cache_dirs[@]}"; do
        if [[ -d "$safe_cache" ]]; then
            local size_before
            size_before=$(get_dir_size "$safe_cache")

            safe_remove_dir_contents "$safe_cache" "$(basename "$safe_cache") cache"

            local size_after
            size_after=$(get_dir_size "$safe_cache")
            local freed=$((size_before - size_after))
            total_freed=$((total_freed + freed))

            if [[ $freed -gt 0 ]]; then
                echo -e "  ${GREEN}✓${NC} $(basename "$safe_cache") cache - $(bytes_to_human $freed)"
            fi
        fi
    done

    TOTAL_FREED=$((TOTAL_FREED + total_freed))
}

# Clean PostgreSQL logs (merged from cleanup_system_logs + cleanup_pentesting_tools)
cleanup_postgres_logs() {
    local total_freed=0
    local pg_log_dirs=(
        "/var/log/postgresql"
    )

    # Also check versioned PG log directories
    for pg_glob in /var/lib/postgresql/*/main/log /var/lib/postgresql/*/main/pg_log; do
        for pg_dir in $pg_glob; do
            if [[ -d "$pg_dir" ]]; then
                pg_log_dirs+=("$pg_dir")
            fi
        done
    done

    for log_dir in "${pg_log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            local pg_log_size
            pg_log_size=$(get_dir_size "$log_dir")
            if [[ $pg_log_size -gt 104857600 ]]; then  # > 100MB
                echo -e "\n${BOLD}${YELLOW}PostgreSQL Log Cleanup${NC}"
                echo -e "${CYAN}PostgreSQL logs: $(bytes_to_human "$pg_log_size")${NC}"
                echo -e "${GREEN}✓ Only log files older than 30 days${NC}"
                echo -e "${GREEN}✓ Active logs and database data preserved${NC}"

                if [[ "$FORCE_MODE" != true && "$DRY_RUN" != true ]]; then
                    echo -e "${YELLOW}Clean old PostgreSQL logs (30+ days)? [Y/n]${NC}"
                    local response
                    read -r response
                    if [[ "$response" =~ ^[Nn]$ ]]; then
                        continue
                    fi
                fi

                # Find current active log file to preserve it
                local active_log
                active_log=$(find "$log_dir" -name "postgresql-*.log" -mtime -1 2>/dev/null | head -1) || true

                # Clean old log files
                safe_find_delete "$log_dir" "PostgreSQL logs >30 days" \
                    -name "*.log" -mtime +30 ! -path "${active_log:-/dev/null}"
                safe_find_delete "$log_dir" "PostgreSQL archived logs" \
                    -name "*.log.*" -mtime +14

                local pg_log_size_after
                pg_log_size_after=$(get_dir_size "$log_dir")
                local freed=$((pg_log_size - pg_log_size_after))
                total_freed=$((total_freed + freed))

                if [[ $freed -gt 0 ]]; then
                    echo -e "  ${GREEN}✓${NC} PostgreSQL logs cleaned - $(bytes_to_human $freed)"
                    echo -e "  ${BLUE}ℹ${NC} Active logs and all database data preserved"
                fi
            fi
        fi
    done

    TOTAL_FREED=$((TOTAL_FREED + total_freed))
}

# =============================================================================
# Cleanup modules
# =============================================================================

# Clean APT package cache
cleanup_apt_cache() {
    module_start "APT" "Cleaning Package Cache..."

    if ! check_command "apt"; then
        module_skip "APT" "APT not available on this system"
        return 0
    fi

    local cache_size_before
    cache_size_before=$(get_dir_size "/var/cache/apt/archives")

    echo -e "${CYAN}Current APT cache size: $(bytes_to_human "$cache_size_before")${NC}"

    if [[ $cache_size_before -gt 104857600 ]]; then  # > 100MB
        if ! module_confirm "APT cache" "$cache_size_before" "This will clear downloaded package files. Continue?"; then
            return 0
        fi

        if [[ "$DRY_RUN" != true ]]; then
            # No sudo — the script is already running as root
            apt clean 2>/dev/null || log_message "WARNING" "apt clean failed"
            apt autoclean 2>/dev/null || log_message "WARNING" "apt autoclean failed"
        else
            echo -e "  ${YELLOW}[DRY RUN]${NC} Would run: apt clean, apt autoclean"
        fi

        local cache_size_after
        cache_size_after=$(get_dir_size "/var/cache/apt/archives")
        local freed=$((cache_size_before - cache_size_after))

        module_end "APT Cache" "$freed"
    else
        module_skip "APT Cache" "Already small ($(bytes_to_human "$cache_size_before"))"
    fi
}

# Clean system logs (journal + rotated logs — PostgreSQL extracted to shared helper)
cleanup_system_logs() {
    module_start "LOG" "Cleaning System Logs..."

    # Journal logs cleanup (systemd)
    if command -v journalctl >/dev/null 2>&1; then
        local journal_size_before
        journal_size_before=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' | head -1 || echo "0B")
        echo -e "${CYAN}Current journal log size: $journal_size_before${NC}"

        if [[ "$DRY_RUN" == true ]]; then
            echo -e "  ${YELLOW}[DRY RUN]${NC} Would clean journal logs older than 30 days"
            echo -e "  ${YELLOW}[DRY RUN]${NC} Would limit journal size to 500MB"
            log_message "INFO" "[DRY RUN] Journal logs cleanup would be performed"
        elif [[ "$FORCE_MODE" == true ]]; then
            # No sudo — already running as root
            journalctl --vacuum-time=30d >/dev/null 2>&1
            journalctl --vacuum-size=500M >/dev/null 2>&1
            echo -e "  ${GREEN}✓${NC} Journal logs cleaned automatically"
            log_message "SUCCESS" "Journal logs cleanup completed (force mode)"
        else
            echo -e "${YELLOW}Clean journal logs older than 30 days? [Y/n]${NC}"
            local response
            read -r response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                log_message "INFO" "Journal cleanup skipped by user"
            else
                journalctl --vacuum-time=30d >/dev/null 2>&1
                journalctl --vacuum-size=500M >/dev/null 2>&1
                echo -e "  ${GREEN}✓${NC} Journal logs cleaned"
                log_message "SUCCESS" "Journal logs cleanup completed"
            fi
        fi
    fi

    # PostgreSQL logs — use shared helper (was duplicated in cleanup_pentesting_tools)
    cleanup_postgres_logs

    # Old log files cleanup (rotated logs)
    local log_patterns=(
        "/var/log/*.log.1"
        "/var/log/*.log.*.gz"
        "/var/log/*/*.log.1"
        "/var/log/*/*.log.*.gz"
    )

    for pattern in "${log_patterns[@]}"; do
        if compgen -G "$pattern" > /dev/null; then
            local size_before=0
            local file
            for file in $pattern; do
                if [[ -f "$file" ]]; then
                    size_before=$((size_before + $(stat -c%s "$file" 2>/dev/null || echo 0)))
                fi
            done

            if [[ $size_before -gt 0 ]]; then
                if [[ "$DRY_RUN" != true ]]; then
                    local file
                    for file in $pattern; do
                        if [[ -f "$file" ]]; then
                            safe_remove_file "$file" "Rotated log"
                        fi
                    done
                else
                    echo -e "  ${YELLOW}[DRY RUN]${NC} Would remove rotated logs matching $pattern"
                fi
                TOTAL_FREED=$((TOTAL_FREED + size_before))
                echo -e "  ${GREEN}✓${NC} Old log files cleaned - $(bytes_to_human $size_before)"
            fi
        fi
    done
}

# Clean temporary files
cleanup_temp_files() {
    module_start "TMP" "Cleaning Temporary Files..."

    local temp_dirs=(
        "/tmp"
        "/var/tmp"
    )

    # Files that are safe to delete regardless of age
    local safe_patterns=(
        "*.tmp"
        "*.temp"
        "*.cache"
        "*_junk_*"
        "*junk*"
        "*.dat"
        "*.log"
        "*_temp_*"
        "temp_*"
        "tmp_*"
    )

    # Files to preserve (active system files)
    local preserve_patterns=(
        "ssh-*"
        "VMware*"
        "*.sock"
        "*.pid"
        "*.lock"
        "config-*"
        "*.pcap"
        "*.cap"
    )

    for temp_dir in "${temp_dirs[@]}"; do
        if [[ -d "$temp_dir" ]]; then
            echo -e "${CYAN}Cleaning $temp_dir...${NC}"

            local size_before
            size_before=$(get_dir_size "$temp_dir")
            local files_cleaned=0

            # First pass: Clean obviously safe files regardless of age
            echo -e "  ${BLUE}Cleaning safe temporary files...${NC}"
            for pattern in "${safe_patterns[@]}"; do
                for file in "$temp_dir"/$pattern; do
                    if [[ -f "$file" ]]; then
                        local should_preserve=false
                        local basename_file
                        basename_file=$(basename "$file")

                        # Check if file matches preserve patterns
                        for preserve_pattern in "${preserve_patterns[@]}"; do
                            # shellcheck disable=SC2254
                            if [[ "$basename_file" == $preserve_pattern ]]; then
                                should_preserve=true
                                break
                            fi
                        done

                        if [[ "$should_preserve" == false ]]; then
                            if [[ "$DRY_RUN" != true ]]; then
                                safe_remove_file "$file" "Temp file" && ((files_cleaned++)) || true
                            else
                                ((files_cleaned++))
                                echo -e "    ${YELLOW}[DRY RUN]${NC} Would delete: $file"
                            fi
                        fi
                    fi
                done
            done

            # Second pass: Clean old files (older than 3 days)
            echo -e "  ${BLUE}Cleaning files older than 3 days...${NC}"
            local old_files
            old_files=$(find "$temp_dir" -maxdepth 1 -type f -mtime +3 2>/dev/null) || true

            local file
            for file in $old_files; do
                if [[ -f "$file" ]]; then
                    local should_preserve=false
                    local basename_file
                    basename_file=$(basename "$file")

                    for preserve_pattern in "${preserve_patterns[@]}"; do
                        # shellcheck disable=SC2254
                        if [[ "$basename_file" == $preserve_pattern ]]; then
                            should_preserve=true
                            echo -e "    ${YELLOW}Preserving active file: $basename_file${NC}"
                            break
                        fi
                    done

                    if [[ "$should_preserve" == false ]]; then
                        if [[ "$DRY_RUN" != true ]]; then
                            safe_remove_file "$file" "Old temp file" && ((files_cleaned++)) || true
                        else
                            ((files_cleaned++))
                            echo -e "    ${YELLOW}[DRY RUN]${NC} Would delete: $file"
                        fi
                    fi
                fi
            done

            # Clean empty directories
            if [[ "$DRY_RUN" != true ]]; then
                safe_find_delete "$temp_dir" "Empty directories" -maxdepth 2 -type d -empty
            fi

            local size_after
            size_after=$(get_dir_size "$temp_dir")
            local freed=$((size_before - size_after))
            TOTAL_FREED=$((TOTAL_FREED + freed))

            if [[ $files_cleaned -gt 0 ]]; then
                echo -e "  ${GREEN}✓${NC} $temp_dir: $files_cleaned files cleaned - $(bytes_to_human $freed)"
            else
                echo -e "  ${BLUE}ℹ${NC} $temp_dir: No files to clean"
            fi
        fi
    done
}

# Clean user caches — uses shared helpers to avoid duplication
cleanup_user_caches() {
    module_start "USER" "Cleaning User Caches..."

    local cache_dir="$HOME/.cache"

    if [[ ! -d "$cache_dir" ]]; then
        module_skip "User Cache" "No user cache directory found"
        return 0
    fi

    local cache_size
    cache_size=$(get_dir_size "$cache_dir")
    echo -e "${CYAN}Current user cache size: $(bytes_to_human "$cache_size")${NC}"

    if [[ $cache_size -gt 52428800 ]]; then  # > 50MB
        if ! module_confirm "User caches" "$cache_size" "Clean user application caches?"; then
            return 0
        fi

        local total_before=$TOTAL_FREED

        # Browser caches — shared helper
        echo -e "  ${CYAN}Cleaning browser caches...${NC}"
        cleanup_browser_caches "$HOME"

        # Thumbnail cache — shared helper
        cleanup_thumbnails_dir "$HOME"

        # Dev caches — shared helper
        cleanup_dev_caches_dir "$HOME"

        local total_after=$TOTAL_FREED
        local total_cleaned=$((total_after - total_before))

        if [[ $total_cleaned -gt 0 ]]; then
            echo -e "\n${GREEN}User cache cleanup completed${NC}"
            echo -e "${GREEN}Total space freed: $(bytes_to_human $total_cleaned)${NC}"
        else
            echo -e "\n${BLUE}ℹ${NC} No user caches to clean"
        fi
    else
        module_skip "User Cache" "Already small ($(bytes_to_human "$cache_size"))"
    fi
}

# Clean Snap packages (Ubuntu/Mint specific)
cleanup_snap_packages() {
    if ! command -v snap >/dev/null 2>&1; then
        return 0
    fi

    module_start "SNAP" "Cleaning Snap Packages..."

    # Get current snap retention policy
    local retention
    retention=$(snap get system refresh.retain 2>/dev/null || echo "3")
    echo -e "${CYAN}Current snap retention: $retention versions${NC}"

    if ! module_confirm "Snap old revisions" "0" "Remove old snap package versions (keeping latest 2)?"; then
        return 0
    fi

    if [[ "$DRY_RUN" != true ]]; then
        # No sudo — already running as root
        snap set system refresh.retain=2 2>/dev/null || true

        # Remove old versions
        snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' |
            while read -r snapname revision; do
                snap remove "$snapname" --revision="$revision" 2>/dev/null &&
                    echo -e "  ${GREEN}✓${NC} Removed $snapname revision $revision" || true
            done
    else
        echo -e "  ${YELLOW}[DRY RUN]${NC} Would set snap retention to 2 and remove old revisions"
    fi

    echo -e "  ${GREEN}✓${NC} Snap packages cleaned"
    log_message "SUCCESS" "Snap packages cleanup completed"
}

# Clean Metasploit and penetration testing tool caches (Kali-specific)
# PostgreSQL logs and dev caches now use shared helpers to avoid duplication
cleanup_pentesting_tools() {
    module_start "PENTEST" "Cleaning Penetration Testing Tool Caches..."

    local total_before=$TOTAL_FREED

    # Clean Metasploit logs (safe operation)
    echo -e "\n${CYAN}Cleaning Metasploit Logs...${NC}"
    local msf_dirs=(
        "$HOME/.msf4/logs"
        "/root/.msf4/logs"
        "/opt/metasploit-framework/logs"
        "/var/log/metasploit"
    )

    for msf_dir in "${msf_dirs[@]}"; do
        if [[ -d "$msf_dir" ]]; then
            local size_before
            size_before=$(get_dir_size "$msf_dir")
            if [[ $size_before -gt 1048576 ]]; then  # > 1MB
                echo -e "  ${CYAN}Found Metasploit logs: $(bytes_to_human "$size_before")${NC}"

                if ! module_confirm "Metasploit logs" "$size_before" "Clean Metasploit log files? (preserves loot and scan data)"; then
                    continue
                fi

                # Clean log files but preserve important data
                safe_find_delete "$msf_dir" "Metasploit .log files" \
                    -name "*.log" -type f
                safe_find_delete "$msf_dir" "Metasploit framework logs" \
                    -name "framework.log*" -type f
                safe_find_delete "$msf_dir" "Metasploit production logs" \
                    -name "production.log*" -type f

                local size_after
                size_after=$(get_dir_size "$msf_dir")
                local freed=$((size_before - size_after))
                TOTAL_FREED=$((TOTAL_FREED + freed))

                if [[ $freed -gt 0 ]]; then
                    echo -e "  ${GREEN}✓${NC} Metasploit logs cleaned - $(bytes_to_human $freed)"
                else
                    echo -e "  ${BLUE}ℹ${NC} No Metasploit logs to clean"
                fi
            fi
        fi
    done

    # PostgreSQL logs — shared helper (no longer duplicated here)
    echo -e "\n${CYAN}Cleaning PostgreSQL Logs...${NC}"
    cleanup_postgres_logs

    # Wireshark temporary files
    local safe_wireshark_temps=(
        "/tmp/wireshark_*.tmp"
        "/tmp/dumpcap_*.tmp"
        "$HOME/.cache/wireshark/*.tmp"
        "/root/.cache/wireshark/*.tmp"
    )

    for temp_pattern in "${safe_wireshark_temps[@]}"; do
        if compgen -G "$temp_pattern" > /dev/null 2>&1; then
            echo -e "${CYAN}Found Wireshark temporary files${NC}"
            if ! module_confirm "Wireshark temps" "0" "Clean Wireshark TEMPORARY files only? (preserves all .pcap captures)"; then
                continue
            fi

            local file
            for file in $temp_pattern; do
                if [[ -f "$file" ]]; then
                    safe_remove_file "$file" "Wireshark temp"
                fi
            done
            echo -e "  ${GREEN}✓${NC} Wireshark temporary files cleaned (captures preserved)"
        fi
    done

    # Dev caches — shared helper (no longer duplicated here)
    # Only clean caches > 50MB in pentesting context
    local dev_cache_dirs=("$HOME/.cache/pip" "$HOME/.cache/npm" "$HOME/.cache/yarn"
                          "/root/.cache/pip" "/root/.cache/npm" "/root/.cache/yarn")
    local has_large_caches=false
    for cache_dir in "${dev_cache_dirs[@]}"; do
        if [[ -d "$cache_dir" ]]; then
            local cache_size
            cache_size=$(get_dir_size "$cache_dir")
            if [[ $cache_size -gt 52428800 ]]; then
                has_large_caches=true
                break
            fi
        fi
    done

    if [[ "$has_large_caches" == true ]]; then
        echo -e "\n${CYAN}Cleaning development package caches...${NC}"
        cleanup_dev_caches_dir "$HOME"
        if [[ "$HOME" != "/root" && -d "/root/.cache" ]]; then
            cleanup_dev_caches_dir "/root"
        fi
    fi

    local total_after=$TOTAL_FREED
    local total_cleaned=$((total_after - total_before))

    if [[ $total_cleaned -gt 0 ]]; then
        echo -e "\n${GREEN}Penetration testing tools cleanup completed${NC}"
        echo -e "${GREEN}Total space freed: $(bytes_to_human $total_cleaned)${NC}"
    else
        echo -e "\n${BLUE}ℹ${NC} No penetration testing tool caches to clean"
    fi
}

# Clean old kernels (Debian/Ubuntu)
cleanup_old_kernels() {
    module_start "KERNEL" "Managing Kernel Versions..."

    # Guard: only works on APT-based systems
    if ! command -v dpkg >/dev/null 2>&1; then
        module_skip "Kernel cleanup" "dpkg not available (non-Debian system)"
        return 0
    fi

    local current_kernel
    current_kernel=$(uname -r)
    local installed_kernels
    installed_kernels=$(dpkg --list | grep linux-image | grep -v "$current_kernel" | wc -l)

    echo -e "${CYAN}Current kernel: $current_kernel${NC}"
    echo -e "${CYAN}Old kernels found: $installed_kernels${NC}"

    if [[ $installed_kernels -gt 1 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL OPERATION WARNING ⚠️${NC}"
        echo -e "${RED}This operation will remove old kernel versions!${NC}"
        echo -e "${RED}Keep at least 2-3 recent kernels for system recovery.${NC}"
        echo -e "${YELLOW}Current kernel ($current_kernel) will be preserved.${NC}"
        echo
        local response
        if [[ "$DRY_RUN" == true ]]; then
            response="y"
            echo -e "${YELLOW}[DRY RUN]${NC} Would ask to remove the proposed old kernels"
        else
            echo -e "${YELLOW}Do you want to remove old kernels? [y/N]${NC}"
            read -r response
        fi

        if [[ "$response" =~ ^[Yy]$ ]]; then
            if [[ "$DRY_RUN" != true ]]; then
                # No sudo — already running as root
                apt autoremove --purge -y 2>/dev/null || log_message "WARNING" "Kernel cleanup failed"
            else
                echo -e "  ${YELLOW}[DRY RUN]${NC} Would run: apt autoremove --purge -y"
            fi
            echo -e "  ${GREEN}✓${NC} Old kernels cleaned"
            log_message "SUCCESS" "Old kernels cleanup completed"
        else
            module_skip "Kernel cleanup" "Skipped by user"
        fi
    else
        module_skip "Kernel cleanup" "No old kernels to remove"
    fi
}

# =============================================================================
# Report
# =============================================================================

generate_report() {
    detect_terminal_capabilities

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    local time_display

    if [[ $minutes -gt 0 ]]; then
        time_display="${minutes}m ${seconds}s"
    else
        time_display="${seconds} seconds"
    fi
    local success_icon
    success_icon=$(get_icon "SUCCESS")
    local info_icon
    info_icon=$(get_icon "INFO")
    local disk_icon
    disk_icon=$(get_icon "DISK")
    local clock_icon
    clock_icon=$(get_icon "CLOCK")
    local shield_icon
    shield_icon=$(get_icon "SHIELD")
    local rocket_icon
    rocket_icon=$(get_icon "ROCKET")
    local log_icon="[LOG]"

    if [[ "$USE_EMOJI" == true ]]; then
        log_icon="📝"
    fi

    local hr_width=$((TERM_WIDTH - 2))

    echo
    echo -e "${GREEN}${BOLD}${success_icon} CLEANUP COMPLETED SUCCESSFULLY ${success_icon}${NC}"
    echo

    # Get disk info for current state
    local disk_info
    read -r -a disk_info <<< "$(get_disk_space)"
    local used="${disk_info[0]}"
    local free="${disk_info[1]}"
    local usage="${disk_info[2]}"
    local usage_percent="${usage%\%}"

    local freed_human
    freed_human="$(bytes_to_human $TOTAL_FREED)"

    echo -e "${WHITE}${BOLD}${rocket_icon} CLEANUP PERFORMANCE${NC}"

    # Show per-module estimate
    if [[ $TOTAL_FREED -gt 1048576 ]]; then
        echo -e "  ${disk_icon} ${BOLD}Per-module estimate:${NC} ${GREEN}${BOLD}${freed_human}${NC} ${GREEN}${success_icon}${NC}"
    elif [[ $TOTAL_FREED -gt 0 ]]; then
        echo -e "  ${disk_icon} ${BOLD}Per-module estimate:${NC} ${YELLOW}${BOLD}${freed_human}${NC} ${YELLOW}${info_icon}${NC}"
    else
        echo -e "  ${disk_icon} ${BOLD}Per-module estimate:${NC} ${BLUE}${BOLD}${freed_human}${NC} ${BLUE}${info_icon}${NC}"
    fi

    # Show actual filesystem recovery (df-based)
    if [[ -n "${AVAIL_BEFORE:-}" ]]; then
        sync 2>/dev/null || true
        local avail_after
        avail_after=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
        if [[ -n "$avail_after" && -n "$AVAIL_BEFORE" ]]; then
            local actual_freed_kb=$((avail_after - AVAIL_BEFORE))
            if [[ $actual_freed_kb -gt 0 ]]; then
                local actual_freed_bytes=$((actual_freed_kb * 1024))
                echo -e "  ${disk_icon} ${BOLD}Actually recovered:${NC}  ${GREEN}${BOLD}$(bytes_to_human $actual_freed_bytes)${NC}"
            else
                echo -e "  ${disk_icon} ${BOLD}Actually recovered:${NC}  ${BLUE}${BOLD}0B${NC}"
            fi
        fi
    fi

    echo -e "  ${clock_icon} ${BOLD}Time Taken:${NC}         ${CYAN}${time_display}${NC}"
    echo -e "  ${log_icon} ${BOLD}Log File:${NC}           ${BLUE}$LOG_FILE${NC}"

    if [[ "$BACKUP_ENABLED" == true ]]; then
        echo -e "  ${shield_icon} ${BOLD}Backup Created:${NC}      ${GREEN}Yes${NC} (${BACKUP_DIR})"
    fi

    # Current disk status with visual bar
    echo
    echo -e "${WHITE}${BOLD}${disk_icon} CURRENT DISK STATUS${NC}"

    local bar_length=$(( hr_width / 2 ))
    bar_length=$(( bar_length < 20 ? 20 : bar_length ))
    bar_length=$(( bar_length > 60 ? 60 : bar_length ))

    local filled_length=$(( usage_percent * bar_length / 100 ))
    local empty_length=$(( bar_length - filled_length ))

    local bar=""
    local color="${GREEN}"
    local filled_char empty_char

    if [[ $usage_percent -gt 90 ]]; then
        color="${RED}"
    elif [[ $usage_percent -gt 70 ]]; then
        color="${YELLOW}"
    fi

    if [[ "$USE_EMOJI" == true ]]; then
        filled_char="█"
        empty_char="░"
    else
        filled_char="#"
        empty_char="."
    fi

    for ((i=0; i<filled_length; i++)); do
        bar="${bar}${filled_char}"
    done
    for ((i=0; i<empty_length; i++)); do
        bar="${bar}${empty_char}"
    done

    echo -e "  ${color}${bar} ${usage}${NC}"
    echo -e "  ${BOLD}Used:${NC} ${RED}${used}${NC} │ ${BOLD}Free:${NC} ${GREEN}${free}${NC}"

    # Final message based on results
    echo
    if [[ $TOTAL_FREED -gt 1048576 ]]; then
        echo -e "${success_icon} ${GREEN}${BOLD}Success!${NC} ${GREEN}Your system is now cleaner and more efficient.${NC}"
        echo -e "${info_icon} ${GREEN}Consider running this script monthly for optimal maintenance.${NC}"
    elif [[ $TOTAL_FREED -gt 0 ]]; then
        echo -e "${info_icon} ${YELLOW}${BOLD}Good!${NC} ${YELLOW}Some space was freed, but your system was already clean.${NC}"
    else
        echo -e "${info_icon} ${BLUE}${BOLD}Nice!${NC} ${BLUE}Your system was already clean - no cleanup needed.${NC}"
    fi

    echo -e "${GREEN}"
    cat << "EOF"
        ╔════════════════════════════════╗
        ║    LINUX SPACE BOOSTER 🧹      ║
        ╚════════════════════════════════╝

             .----.
           _/__|__\_         .------.
          (  o   o  )       | Trash |
          |    ∆    |       |  Bin  |
          |  \___/  |       |______|
         /|         |\
        /_|_________|_\     [*] Deleted cache...
          ||  ||  ||        [*] Cleaned logs...
          []  []  []        [*] Removed junk...

           🤖 Bot says: "All clean!"
           ✅ Disk space recovered!
EOF
    echo -e "${NC}"

    log_message "SUCCESS" "Cleanup completed - Total freed: $(bytes_to_human $TOTAL_FREED) in ${time_display}"
}

# =============================================================================
# Interactive menu
# =============================================================================

show_menu() {
    detect_terminal_capabilities

    local rocket_icon
    rocket_icon=$(get_icon "ROCKET")
    local disk_icon
    disk_icon=$(get_icon "DISK")
    local clean_icon
    clean_icon=$(get_icon "CLEAN")
    local shield_icon
    shield_icon=$(get_icon "SHIELD")
    local info_icon
    info_icon=$(get_icon "INFO")

    local ascii_art
    ascii_art=$(cat <<'EOF'

        ╔════════════════════════════════╗
        ║    LINUX SPACE BOOSTER 🧹      ║
        ╚════════════════════════════════╝

             .----.
           _/__|__\_         .------.
          (  o   o  )       | Trash |
          |    ∆    |       |  Bin  |
          |  \___/  |       |______|
         /|         |\
        /_|_________|_\     [*] Deleting cache...
          ||  ||  ||        [*] Cleaning logs...
          []  []  []        [*] Removing junk...

EOF
)

    clear

    # Show ASCII art first
    echo -e "${CYAN}${BOLD}$ascii_art${NC}"

    preflight_checks --quiet

    show_disk_summary --compact

    while true; do
        # System information in tabular format
        local distro
        distro=$(detect_distribution | tr '[:lower:]' '[:upper:]')
        local kernel
        kernel=$(uname -r)
        local arch
        arch=$(uname -m)

        # Get appropriate icons based on terminal capability
        disk_icon=$(get_icon "DISK")
        info_icon=$(get_icon "INFO")
        local computer_icon="[PC]"
        local clock_icon
        clock_icon=$(get_icon "CLOCK")
        local distro_icon="[OS]"

        if [[ "$USE_EMOJI" == true ]]; then
            computer_icon="🖥️ "
            case "$distro" in
                "KALI") distro_icon="🔒" ;;
                "PARROT") distro_icon="🦜" ;;
                "UBUNTU") distro_icon="🔶" ;;
                "DEBIAN") distro_icon="🔴" ;;
                "LINUXMINT"|"MINT") distro_icon="🍃" ;;
                *) distro_icon="🐧" ;;
            esac
        fi

        # Show a useful system overview table
        echo -e "${WHITE}${BOLD}SYSTEM OVERVIEW${NC}"

        # Get disk usage info
        local disk_info
        read -r -a disk_info <<< "$(get_disk_space)"
        local used="${disk_info[0]}"
        local free="${disk_info[1]}"
        local usage="${disk_info[2]}"
        local usage_percent="${usage%\%}"

        # Set color based on disk usage
        local usage_color="${GREEN}"
        local recommendation=""
        if [[ $usage_percent -gt 90 ]]; then
            usage_color="${RED}"
            recommendation="URGENT CLEANUP NEEDED"
        elif [[ $usage_percent -gt 70 ]]; then
            usage_color="${YELLOW}"
            recommendation="MAINTENANCE RECOMMENDED"
        else
            recommendation="SYSTEM HEALTHY"
        fi

        # Get key sizes for recommendations
        local apt_size=0
        if command -v apt >/dev/null 2>&1; then
            apt_size=$(get_dir_size "/var/cache/apt/archives")
        fi
        local apt_human
        apt_human=$(bytes_to_human $apt_size)
        local log_size
        log_size=$(get_dir_size "/var/log")
        local log_human
        log_human=$(bytes_to_human "$log_size")
        local tmp_size
        tmp_size=$(get_dir_size "/tmp")
        local tmp_human
        tmp_human=$(bytes_to_human "$tmp_size")

        # Create a clean table
        echo "+----------------------------------------------------------+"
        printf "| %-56s |\n" "SYSTEM OVERVIEW"
        echo "+----------------------------------------------------------+"

        local os_text="OS: $distro     Kernel: $kernel     Arch: $arch"
        local disk_text="Disk: $usage     Used: $used     Free: $free"
        local status_text="Status: $recommendation"
        local cache_text="Cache: $apt_human     Logs: $log_human     Temp Files: $tmp_human"

        local os_padding=$((56 - ${#os_text}))
        local disk_padding=$((56 - ${#disk_text}))
        local status_padding=$((56 - ${#status_text}))
        local cache_padding=$((56 - ${#cache_text}))

        echo -e "| OS: ${GREEN}$distro${NC}     Kernel: ${GREEN}$kernel${NC}     Arch: ${GREEN}$arch${NC}$(printf '%*s' $os_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Disk: ${usage_color}$usage${NC}     Used: ${RED}$used${NC}     Free: ${GREEN}$free${NC}$(printf '%*s' $disk_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Status: ${usage_color}$recommendation${NC}$(printf '%*s' $status_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Cache: ${CYAN}$apt_human${NC}     Logs: ${CYAN}$log_human${NC}     Temp Files: ${CYAN}$tmp_human${NC}$(printf '%*s' $cache_padding '') |"
        echo "+----------------------------------------------------------+"
        echo

        # Menu options
        echo -e "${WHITE}${BOLD}OPTIONS${NC} (enter a number):"
        echo -e "  ${WHITE}1${NC}. ${GREEN}${BOLD}Basic Cleanup${NC} - Package cache & temp files"
        echo -e "  ${WHITE}2${NC}. ${YELLOW}${BOLD}User Cleanup${NC} - Home directory cache only"
        echo -e "  ${WHITE}3${NC}. ${RED}${BOLD}Advanced Cleanup${NC} - Deep system clean"
        echo -e "  ${WHITE}4${NC}. ${BLUE}${BOLD}Dry Run${NC} - Show what would be cleaned"
        echo -e "  ${WHITE}5${NC}. ${PURPLE}${BOLD}Disk Analysis${NC} - Scan system for large files"
        echo -e "  ${WHITE}h${NC}. Help & Info  ${WHITE}q${NC}. Quit"
        echo

        echo -e "${shield_icon} ${GREEN}System files protected${NC}"
        echo -ne "${BOLD}${WHITE}Select option [1-5,h,q]: ${NC}"
        local choice
        read -r choice

        case "$choice" in
            1)
                echo -e "\n${GREEN}Starting Basic Cleanup...${NC}"
                sleep 1
                AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
                cleanup_apt_cache
                cleanup_system_logs
                cleanup_temp_files
                generate_report
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            2)
                echo -e "\n${YELLOW}Starting User-Specific Cleanup...${NC}"
                sleep 1
                AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
                user_only_cleanup
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            3)
                echo -e "\n${RED}Starting Advanced Cleanup...${NC}"
                sleep 1
                AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
                advanced_cleanup
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            4)
                echo -e "\n${BLUE}Starting Dry Run Analysis...${NC}"
                echo -e "${YELLOW}This will show what would be cleaned without making any changes${NC}"
                sleep 1

                DRY_RUN=true

                echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BLUE}║${WHITE}${BOLD}                    DRY RUN MODE - NO CHANGES WILL BE MADE                    ${NC}${BLUE}║${NC}"
                echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
                echo

                echo -e "${CYAN}${BOLD}What would be cleaned during a full system cleanup:${NC}"
                echo

                cleanup_apt_cache
                cleanup_system_logs
                cleanup_temp_files

                # Check for old kernels (if dpkg available)
                if command -v dpkg >/dev/null 2>&1; then
                    if command -v apt-get >/dev/null 2>&1; then
                        if [[ $(apt-get -s autoremove 2>/dev/null | grep -c 'linux-image') -gt 0 ]]; then
                            echo -e "\n${PURPLE}Found old kernels that could be removed:${NC}"
                            apt-get -s autoremove 2>/dev/null | grep 'linux-image' | sed 's/^/  /'
                        fi
                    fi
                fi

                DRY_RUN=false

                echo -e "\n${YELLOW}${BOLD}Summary:${NC} These items would be cleaned in a normal run."
                echo -e "${GREEN}No actual changes were made to your system.${NC}"
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            5)
                echo -e "\n${PURPLE}Starting Disk Space Analysis...${NC}"
                sleep 1

                show_disk_summary ""

                echo -e "\n${BOLD}${PURPLE}Largest Directories:${NC}"
                echo -e "${CYAN}Scanning for large directories (this may take a moment)...${NC}"

                du -h --max-depth=2 /var /home /usr /opt 2>/dev/null | sort -hr | head -10 | \
                    while IFS=$'\t' read -r size path; do
                        echo -e "  ${YELLOW}$size${NC}\t${path}"
                    done

                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            [hH])
                echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BLUE}║${WHITE}${BOLD}                         HELP & SAFETY INFORMATION                            ${NC}${BLUE}║${NC}"
                echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
                echo
                echo -e "${BOLD}${GREEN}ABOUT THIS TOOL:${NC}"
                echo -e "LINUX SPACE BOOSTER safely cleans up disk space on Linux virtual machines"
                echo -e "without harming critical system files or user data."
                echo
                echo -e "${BOLD}${YELLOW}SAFETY POLICY:${NC}"
                echo -e "✓ Destructive operations are scoped to caches and temp files"
                echo -e "✓ Critical system paths are blocked from deletion"
                echo -e "✓ Active-file checks where supported (lsof)"
                echo -e "✓ User data directories excluded by default"
                echo -e "✓ High-risk operations require confirmation"
                echo -e "✓ Every operation is logged"
                echo
                echo -e "${BOLD}${BLUE}BASIC vs ADVANCED CLEANUP:${NC}"
                echo -e "- Basic cleanup only removes safe temporary files and package caches"
                echo -e "- Advanced cleanup can also remove old kernels and deeper caches"
                echo -e "  (but always asks for confirmation first)"
                echo
                echo -e "${BOLD}${PURPLE}DRY RUN MODE:${NC}"
                echo -e "Use Dry Run mode to see what would be cleaned without making changes."
                echo
                echo -e "${BOLD}${RED}SUPPORT:${NC}"
                echo -e "For support, please contact your system administrator."
                echo
                echo -e "${CYAN}Press Enter to return to menu...${NC}"
                read -r
                ;;
            [qQ])
                echo -e "\n${GREEN}Thank you for using Linux-Space-Booster!${NC}"
                echo -e "${BLUE}Remember to run cleanup regularly for optimal system performance.${NC}"
                exit "$EXIT_SUCCESS"
                ;;
            *)
                echo -e "\n${RED}Invalid option. Please select 1-5, h, or q.${NC}"
                sleep 2
                ;;
        esac
    done
}

# =============================================================================
# Orchestration
# =============================================================================

# Quick safe cleanup
quick_cleanup() {
    echo -e "\n${GREEN}Starting Quick Safe Cleanup...${NC}"
    FORCE_MODE=true

    cleanup_apt_cache
    cleanup_temp_files
    cleanup_user_caches

    # Runtime/package removal and specialised tool cleanup stay opt-in through
    # advanced mode. The default path must not remove installed software.

    cleanup_system_logs

    generate_report
    FORCE_MODE=false
}

# Advanced cleanup with confirmations
advanced_cleanup() {
    echo -e "\n${YELLOW}Starting Advanced Cleanup...${NC}"

    cleanup_apt_cache
    cleanup_system_logs
    cleanup_temp_files
    cleanup_user_caches
    cleanup_snap_packages
    cleanup_pentesting_tools
    cleanup_old_kernels

    generate_report
}

# =============================================================================
# User management
# =============================================================================

get_real_users() {
    awk -F: '$3 >= 1000 && $3 != 65534 && $7 !~ /nologin|false/ && $1 != "nobody" {print $1 ":" $3 ":" $6}' /etc/passwd | sort
}

show_user_selection() {
    echo -e "\n${BOLD}${CYAN}SELECT USER TO CLEAN${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"

    local users
    mapfile -t users < <(get_real_users)
    local current_user
    current_user=$(whoami)

    if [[ ${#users[@]} -eq 0 ]]; then
        echo -e "${RED}No regular users found on this system.${NC}"
        return 1
    fi

    echo -e "${WHITE}Available users:${NC}"
    echo

    local i=1
    for user_info in "${users[@]}"; do
        IFS=':' read -r username uid homedir <<< "$user_info"
        local status=""

        if [[ "$username" == "$current_user" ]]; then
            status=" ${GREEN}(current user)${NC}"
        fi

        if [[ -d "$homedir" ]]; then
            local cache_size=0
            if [[ -d "$homedir/.cache" ]]; then
                cache_size=$(get_dir_size "$homedir/.cache" 2>/dev/null || echo "0")
            fi
            local cache_human
            cache_human=$(bytes_to_human "$cache_size")
            echo -e "  ${WHITE}$i${NC}. ${BOLD}$username${NC}$status"
            echo -e "     Home: ${CYAN}$homedir${NC} | Cache: ${YELLOW}$cache_human${NC}"
        else
            echo -e "  ${WHITE}$i${NC}. ${BOLD}$username${NC}$status ${RED}(home directory missing)${NC}"
        fi
        echo
        ((i++))
    done

    echo -e "  ${WHITE}0${NC}. ${RED}Cancel${NC}"
    echo
    echo -e "${YELLOW}Enter your choice (0-$((${#users[@]}))): ${NC}"

    local choice
    read -r choice

    if [[ "$choice" == "0" ]]; then
        echo -e "${BLUE}User cleanup cancelled.${NC}"
        return 1
    elif [[ "$choice" =~ ^[1-9][0-9]*$ ]] && [[ $choice -le ${#users[@]} ]]; then
        local selected_user_info="${users[$((choice-1))]}"
        local selected_username selected_uid selected_homedir
        IFS=':' read -r selected_username selected_uid selected_homedir <<< "$selected_user_info"

        echo -e "\n${GREEN}Selected user: ${BOLD}$selected_username${NC}"
        echo -e "${CYAN}Home directory: $selected_homedir${NC}"

        echo -e "\n${YELLOW}Clean cache and temporary files for user '$selected_username'? [Y/n]${NC}"
        local confirm
        read -r confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            echo -e "${BLUE}User cleanup cancelled.${NC}"
            return 1
        fi

        cleanup_selected_user "$selected_username" "$selected_homedir"
        return 0
    else
        echo -e "${RED}Invalid choice. Please try again.${NC}"
        return 1
    fi
}

# Per-user cleanup — uses shared helpers to avoid code duplication
cleanup_selected_user() {
    local username="$1"
    local homedir="$2"

    echo -e "\n${BLUE}Cleaning safe data for user: ${BOLD}$username${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"

    if [[ ! -d "$homedir" ]]; then
        echo -e "${RED}Error: Home directory $homedir does not exist${NC}"
        return 1
    fi

    if [[ ! -r "$homedir" ]]; then
        echo -e "${RED}Error: No permission to access $homedir${NC}"
        echo -e "${YELLOW}Tip: Run with sudo for system-wide user cleanup${NC}"
        return 1
    fi

    local total_before=$TOTAL_FREED

    # Browser caches — shared helper
    echo -e "\n${PURPLE}Cleaning Browser Caches...${NC}"
    cleanup_browser_caches "$homedir"

    # Thumbnail cache — shared helper
    echo -e "\n${PURPLE}Cleaning Thumbnail Cache...${NC}"
    cleanup_thumbnails_dir "$homedir"

    # Dev caches — shared helper
    echo -e "\n${PURPLE}Cleaning Development Tool Caches...${NC}"
    cleanup_dev_caches_dir "$homedir"

    # Clean temporary files
    echo -e "\n${PURPLE}Cleaning Temporary Files...${NC}"
    local temp_dirs=(
        "$homedir/tmp"
        "$homedir/.tmp"
    )

    for temp_path in "${temp_dirs[@]}"; do
        if [[ -d "$temp_path" ]]; then
            local size_before
            size_before=$(get_dir_size "$temp_path")
            if [[ $size_before -gt 0 ]]; then
                echo -e "  ${CYAN}Cleaning $(basename "$temp_path") ($(bytes_to_human "$size_before"))${NC}"
                safe_remove_dir_contents "$temp_path" "User temp directory"
                local size_after
                size_after=$(get_dir_size "$temp_path")
                local cleaned=$((size_before - size_after))
                TOTAL_FREED=$((TOTAL_FREED + cleaned))
            fi
        fi
    done

    # Clean temp files in Downloads
    for temp_pattern in "$homedir/Downloads/"*.tmp "$homedir/Downloads/"*.temp; do
        for temp_file in $temp_pattern; do
            if [[ -f "$temp_file" ]]; then
                safe_remove_file "$temp_file" "Temp download"
            fi
        done
    done

    # Clean old log files
    echo -e "\n${PURPLE}Cleaning Old Log Files...${NC}"
    if [[ -d "$homedir/.local/share" ]]; then
        local old_logs
        old_logs=$(find "$homedir/.local/share" -name "*.log" -mtime +30 2>/dev/null | wc -l)
        if [[ $old_logs -gt 0 ]]; then
            echo -e "  ${CYAN}Found $old_logs old log files (>30 days)${NC}"
            safe_find_delete "$homedir/.local/share" "Old user log files" \
                -name "*.log" -mtime +30
        fi
    fi

    local total_after=$TOTAL_FREED
    local total_cleaned=$((total_after - total_before))

    echo -e "\n${GREEN}User cleanup completed for: ${BOLD}$username${NC}"
    echo -e "${GREEN}Space freed: ${BOLD}$(bytes_to_human $total_cleaned)${NC}"

    echo -e "\n${BOLD}${BLUE}PROTECTED DATA (NOT CLEANED):${NC}"
    echo -e "${GREEN}✓ Documents, Pictures, Videos, Music${NC}"
    echo -e "${GREEN}✓ Desktop files and folders${NC}"
    echo -e "${GREEN}✓ Application settings and configurations${NC}"
    echo -e "${GREEN}✓ SSH keys and certificates${NC}"
    echo -e "${GREEN}✓ Browser bookmarks and passwords${NC}"
    echo -e "${GREEN}✓ Email data and contacts${NC}"
    echo -e "${GREEN}✓ Recent log files (< 30 days)${NC}"
}

# User-only cleanup with user selection
user_only_cleanup() {
    echo -e "\n${BLUE}Starting User-Specific Cleanup...${NC}"

    if show_user_selection; then
        generate_report
    else
        echo -e "\n${YELLOW}No cleanup performed.${NC}"
    fi
}

# =============================================================================
# Analyze (Phase 2 stub — non-destructive)
# =============================================================================

run_analyze() {
    echo -e "\n${BOLD}${CYAN}SPACE ANALYSIS${NC}"
    echo

    # Filesystem overview
    show_disk_summary ""

    # Largest directories
    echo -e "\n${BOLD}${PURPLE}Largest Directories:${NC}"
    echo -e "${CYAN}Scanning (this may take a moment)...${NC}"
    du -h --max-depth=1 / 2>/dev/null | sort -hr | head -10 | \
        while IFS=$'\t' read -r size path; do
            echo -e "  ${YELLOW}$size${NC}\t${path}"
        done

    # Cleanup opportunities
    echo -e "\n${BOLD}${PURPLE}Cleanup Opportunities:${NC}"
    local total_potential=0

    if command -v apt >/dev/null 2>&1; then
        local apt_size
        apt_size=$(get_dir_size "/var/cache/apt/archives")
        echo -e "  APT cache:          ${CYAN}$(bytes_to_human "$apt_size")${NC}"
        total_potential=$((total_potential + apt_size))
    fi

    if command -v journalctl >/dev/null 2>&1; then
        local journal_info
        journal_info=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' || echo "0B")
        echo -e "  Journal:            ${CYAN}$journal_info${NC}"
    fi

    local tmp_size
    tmp_size=$(get_dir_size "/tmp")
    echo -e "  Temp files:         ${CYAN}$(bytes_to_human "$tmp_size")${NC}"
    total_potential=$((total_potential + tmp_size))

    if [[ -d "$HOME/.cache" ]]; then
        local cache_size
        cache_size=$(get_dir_size "$HOME/.cache")
        echo -e "  User cache:         ${CYAN}$(bytes_to_human "$cache_size")${NC}"
        total_potential=$((total_potential + cache_size))
    fi

    echo -e "\n  ${BOLD}Potential recovery:   ${GREEN}~$(bytes_to_human $total_potential)${NC}"
    echo -e "\n${BLUE}Run with --clean to perform cleanup.${NC}"
}

# =============================================================================
# Help
# =============================================================================

show_help() {
    clear
    show_header
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}${BOLD}                              HELP & SAFETY GUIDE                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${WHITE}${BOLD}COMMAND LINE USAGE:${NC}"
    echo -e "  ${GREEN}sudo $0${NC}                    # Interactive menu (recommended)"
    echo -e "  ${GREEN}sudo $0 --quick${NC}            # Quick safe cleanup"
    echo -e "  ${GREEN}sudo $0 --advanced${NC}         # Advanced cleanup with confirmations"
    echo -e "  ${GREEN}$0 --user-only${NC}             # User-only cleanup (no root required)"
    echo -e "  ${GREEN}sudo $0 --dry-run${NC}          # Preview cleanup without changes"
    echo -e "  ${GREEN}sudo $0 --force --quick${NC}    # Skip confirmations (use with caution)"
    echo -e "  ${GREEN}$0 --analyze${NC}               # Analyze disk usage (no changes)"
    echo -e "  ${GREEN}$0 --version${NC}               # Show version"
    echo
    echo -e "${WHITE}${BOLD}FLAG COMBINATIONS:${NC}"
    echo -e "  Flags can be combined in any order:"
    echo -e "  ${GREEN}sudo $0 --force --quick${NC}    # same as --quick --force"
    echo -e "  ${GREEN}sudo $0 --dry-run --quick${NC}  # dry run of quick cleanup"
    echo
    echo -e "${WHITE}${BOLD}DISTRIBUTION-SPECIFIC FEATURES:${NC}"
    echo -e "  ${PURPLE}${BOLD}Kali Linux & Parrot OS:${NC}"
    echo -e "    • PostgreSQL log cleanup (Metasploit databases)"
    echo -e "    • Metasploit log file cleanup (scan data preserved)"
    echo -e "    • Wireshark temporary file cleanup (captures preserved)"
    echo -e "    • Penetration testing tool cache cleanup"
    echo
    echo -e "  ${PURPLE}${BOLD}Ubuntu & Linux Mint:${NC}"
    echo -e "    • Snap package version cleanup"
    echo -e "    • Ubuntu-specific package management"
    echo
    echo -e "  ${PURPLE}${BOLD}All Debian-based Systems:${NC}"
    echo -e "    • APT cache and orphaned package cleanup"
    echo -e "    • Safe kernel version management"
    echo -e "    • System log rotation and cleanup"
    echo
    echo -e "${WHITE}${BOLD}SAFETY POLICY:${NC}"
    echo -e "  ${GREEN}✓ Destructive operations are scoped${NC}"
    echo -e "  ${GREEN}✓ Critical paths are blocked${NC}"
    echo -e "  ${GREEN}✓ Active-file checks where supported${NC}"
    echo -e "  ${GREEN}✓ User data directories excluded by default${NC}"
    echo -e "  ${GREEN}✓ High-risk operations require confirmation${NC}"
    echo -e "  ${GREEN}✓ Every operation is logged${NC}"
    echo
    echo -e "${WHITE}${BOLD}WHAT GETS CLEANED (SAFE OPERATIONS):${NC}"
    echo -e "  ${CYAN}APT Package Cache:${NC} Downloaded .deb files (can be re-downloaded)"
    echo -e "  ${CYAN}System Logs:${NC} Old log files (active logs preserved)"
    echo -e "  ${CYAN}Temporary Files:${NC} Files in /tmp older than 3 days"
    echo -e "  ${CYAN}User Caches:${NC} Browser and application caches (can be rebuilt)"
    echo -e "  ${CYAN}Snap Packages:${NC} Old package versions (Ubuntu/Mint)"
    echo -e "  ${CYAN}Tool Logs:${NC} Old log files from penetration testing tools"
    echo
    echo -e "${WHITE}${BOLD}EXIT CODES:${NC}"
    echo -e "  0 = success"
    echo -e "  1 = general error"
    echo -e "  2 = invalid arguments"
    echo -e "  3 = insufficient privileges"
    echo -e "  4 = unsupported system (missing required tools)"
    echo -e "  5 = cleanup partially failed"
    echo -e "  6 = cleanup failed"
    echo
    echo -e "${WHITE}${BOLD}RECOVERY RECOMMENDATIONS:${NC}"
    echo -e "  ${YELLOW}•${NC} Create system backups before major cleanups"
    echo -e "  ${YELLOW}•${NC} Test in dry-run mode first for critical systems"
    echo -e "  ${YELLOW}•${NC} Run cleanup during maintenance windows"
    echo -e "  ${YELLOW}•${NC} Monitor disk space regularly to avoid emergency cleanups"
    echo
}

# =============================================================================
# Signal handling
# =============================================================================

cleanup_on_exit() {
    echo -e "\n${YELLOW}Cleanup interrupted. Exiting safely...${NC}"
    log_message "INFO" "Script interrupted by user"
    exit 130
}

trap cleanup_on_exit SIGINT SIGTERM

# =============================================================================
# Argument parsing — Phase 1 rewrite
#
# The old approach executed operations inside the case statement, so flag
# order mattered (--force --quick worked, --quick --force didn't).
# Now we parse all flags first, validate, then run a single dispatch.
# =============================================================================

parse_args() {
    MODE=""
    DRY_RUN=false
    FORCE_MODE=false
    JSON_OUTPUT=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick)
                if [[ -n "$MODE" && "$MODE" != "help" ]]; then
                    echo -e "${RED}Error: Cannot combine --quick with --$MODE${NC}"
                    exit "$EXIT_BAD_ARGS"
                fi
                MODE="quick"
                ;;
            --advanced)
                if [[ -n "$MODE" && "$MODE" != "help" ]]; then
                    echo -e "${RED}Error: Cannot combine --advanced with --$MODE${NC}"
                    exit "$EXIT_BAD_ARGS"
                fi
                MODE="advanced"
                ;;
            --user-only)
                if [[ -n "$MODE" && "$MODE" != "help" ]]; then
                    echo -e "${RED}Error: Cannot combine --user-only with --$MODE${NC}"
                    exit "$EXIT_BAD_ARGS"
                fi
                MODE="user-only"
                ;;
            --analyze)
                if [[ -n "$MODE" && "$MODE" != "help" ]]; then
                    echo -e "${RED}Error: Cannot combine --analyze with --$MODE${NC}"
                    exit "$EXIT_BAD_ARGS"
                fi
                MODE="analyze"
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --force)
                FORCE_MODE=true
                ;;
            --json)
                JSON_OUTPUT=true
                ;;
            --version)
                echo "linux-space-booster $SCRIPT_VERSION"
                exit "$EXIT_SUCCESS"
                ;;
            --help|-h)
                MODE="help"
                ;;
            *)
                echo -e "${RED}Error: Unknown option '$1'${NC}"
                echo -e "${YELLOW}Use '$0 --help' for usage information${NC}"
                echo -e "${CYAN}Or run '$0' without arguments for interactive mode${NC}"
                exit "$EXIT_BAD_ARGS"
                ;;
        esac
        shift
    done

    # Default mode
    if [[ -z "$MODE" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            MODE="advanced"  # --dry-run alone = dry run of advanced cleanup
        else
            MODE="menu"
        fi
    fi
}

validate_args() {
    # --json is currently only meaningful with --analyze
    if [[ "$JSON_OUTPUT" == true && "$MODE" != "analyze" ]]; then
        log_message "WARNING" "--json is currently only supported with --analyze"
    fi

    # --force with help/version is harmless, don't error
    # --dry-run with any mode is fine
}

run_preflight() {
    local needs_root=true

    case "$MODE" in
        help)
            needs_root=false
            ;;
        analyze)
            needs_root=false
            ;;
        user-only)
            needs_root=false
            ;;
    esac

    if [[ "$needs_root" == true ]]; then
        check_root_privileges
        setup_log_files "false"
    else
        setup_log_files "true"
    fi

    if [[ "$MODE" != "help" ]]; then
        show_header
        if [[ "$MODE" == "user-only" ]]; then
            preflight_checks "--user-only"
        else
            preflight_checks ""
        fi
    fi
}

# Privilege check — uses exit code 3 instead of generic 1
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}┌───────────────────────────────────────────────┐${NC}"
        echo -e "${RED}│          ROOT PRIVILEGES REQUIRED             │${NC}"
        echo -e "${RED}└───────────────────────────────────────────────┘${NC}"
        echo
        echo -e "${YELLOW}System cleanup requires root privileges.${NC}"
        echo -e "${CYAN}Run with: sudo $0${NC}"
        echo -e "${GREEN}For user cleanup: $0 --user-only${NC}"
        echo -e "${GREEN}For analysis: $0 --analyze${NC}"
        echo
        exit "$EXIT_NO_PRIVILEGE"
    fi
}

dispatch() {
    case "$MODE" in
        menu)
            show_disk_summary ""
            show_menu
            ;;
        quick)
            show_disk_summary ""
            AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
            quick_cleanup
            ;;
        advanced)
            show_disk_summary ""
            AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
            advanced_cleanup
            ;;
        user-only)
            show_disk_summary ""
            AVAIL_BEFORE=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
            user_only_cleanup
            ;;
        analyze)
            run_analyze
            ;;
        help)
            show_help
            ;;
        *)
            echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
            exit "$EXIT_BAD_ARGS"
            ;;
    esac
}

# =============================================================================
# Main entry point
# =============================================================================

main() {
    parse_args "$@"
    validate_args
    run_preflight
    dispatch

    # Determine exit code based on module failures
    if [[ $MODULES_FAILED -gt 0 && $TOTAL_FREED -gt 0 ]]; then
        exit "$EXIT_PARTIAL"
    elif [[ $MODULES_FAILED -gt 0 && $TOTAL_FREED -eq 0 ]]; then
        exit "$EXIT_FAILED"
    fi
    exit "$EXIT_SUCCESS"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    log_message "INFO" "Script started by user: $(whoami)"
    log_message "INFO" "Distribution: $(detect_distribution)"
    log_message "INFO" "System type: $(get_system_info)"
    main "$@"
fi
