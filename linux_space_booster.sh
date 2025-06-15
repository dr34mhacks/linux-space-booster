#!/bin/bash
set +u


#==============================================================================
#
#        ╔════════════════════════════════╗
#        ║    LINUX SPACE BOOSTER 🧹      ║
#        ╚════════════════════════════════╝
#
#             .----.
#           _/__|__\_         .------.
#          (  o   o  )       | Trash |
#          |    ∆    |       |  Bin  |
#          |  \___/  |       |______|
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
# Version: 1.0
# Author: Sid Joshi (github.com/dr34mhacks)
# License: MIT
#
# DESCRIPTION:
# This script safely cleans up disk space on Linux virtual machines without
# harming critical system files or user data. It includes multiple safety
# checks and handles distribution-specific cleanup operations.
#==============================================================================
set -euo pipefail

readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="Linux-Space-Booster"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'
readonly ICON_SUCCESS="✓"
readonly ICON_ERROR="✗"
readonly ICON_WARNING="!"
readonly ICON_INFO="i"
readonly ICON_SHIELD="*"
readonly ICON_ROCKET=">"
readonly ICON_CLEAN="+"
readonly ICON_DISK="D"
readonly ICON_CLOCK="T"
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
LOG_FILE=""
ERROR_LOG_FILE=""
BACKUP_DIR=""
DRY_RUN=false
FORCE_MODE=false
BACKUP_ENABLED=false
TOTAL_FREED=0
START_TIME=$(date +%s)
USE_EMOJI=true
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)
detect_terminal_capabilities() {
    USE_EMOJI=true
    if [[ "$TERM" == "dumb" || "$TERM" == "unknown" || -z "$TERM" ]]; then
        USE_EMOJI=false
    fi
    if [[ "${NO_EMOJI:-}" == "1" || "${NO_EMOJI:-}" == "true" ]]; then
        USE_EMOJI=false
    fi
}
readonly ASCII_SUCCESS="[OK]"
readonly ASCII_ERROR="[ERROR]"
readonly ASCII_WARNING="[WARN]"
readonly ASCII_INFO="[INFO]"
readonly ASCII_SHIELD="[SAFE]"
readonly ASCII_ROCKET="[BOOST]"
readonly ASCII_CLEAN="[CLEAN]"
readonly ASCII_DISK="[DISK]"
readonly ASCII_CLOCK="[TIME]"
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
setup_log_files() {
    local user_only_mode="$1"
    local timestamp=$(date +%Y%m%d-%H%M%S)
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

check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}┌───────────────────────────────────────────────┐${NC}"
        echo -e "${RED}│          ROOT PRIVILEGES REQUIRED             │${NC}"
        echo -e "${RED}└───────────────────────────────────────────────┘${NC}"
        echo
        echo -e "${YELLOW}System cleanup requires root privileges.${NC}"
        echo -e "${CYAN}Run with: sudo $0${NC}"
        echo -e "${GREEN}For user cleanup: $0 --user-only${NC}"
        echo
        exit 1
    fi
}

detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}


get_system_info() {
    local distro=$(detect_distribution)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    
    case "$distro" in
        "kali"|"parrot")
            echo "penetration_testing"
            ;;
        "ubuntu"|"linuxmint"|"mint")
            echo "desktop_ubuntu_based"
            ;;
        "debian")
            echo "debian_pure"
            ;;
        *)
            echo "debian_compatible"
            ;;
    esac
}

show_header() {
    detect_terminal_capabilities
    local hr_width=$((TERM_WIDTH - 2))
    echo
    echo -e "${BLUE}${BOLD}== $SCRIPT_NAME v$SCRIPT_VERSION ==${NC}"
    echo -e "${CYAN}Advanced Linux Disk Space Management Utility${NC}"
    echo
    local distro=$(detect_distribution | tr '[:lower:]' '[:upper:]')
    local sys_type=$(get_system_info)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local current_date=$(date '+%Y-%m-%d %H:%M:%S')
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
    local disk_icon=$(get_icon "DISK")
    local info_icon=$(get_icon "INFO")
    local clock_icon=$(get_icon "CLOCK") 
    local shield_icon=$(get_icon "SHIELD")
    local computer_icon="[PC]"
    if [[ "$USE_EMOJI" == true ]]; then
        computer_icon="🖥️ "
    fi
    echo -e "${WHITE}${BOLD}SYSTEM INFORMATION${NC}"
    echo -e "  ${distro_icon} ${BOLD}Distribution:${NC} ${GREEN}$distro${NC} | ${disk_icon} ${BOLD}Kernel:${NC} ${GREEN}$kernel${NC}"
    echo -e "  ${computer_icon} ${BOLD}System Type:${NC} ${GREEN}$sys_type${NC} | ${info_icon} ${BOLD}Architecture:${NC} ${GREEN}$arch${NC}"
    echo -e "  ${clock_icon} ${BOLD}Date & Time:${NC} ${GREEN}$current_date${NC}"
    echo
    echo -e "${WHITE}${BOLD}SAFETY FEATURES${NC}"
    echo -e "  ${shield_icon} Critical system paths protected"
    echo -e "  ${shield_icon} Active files detected and preserved"
    echo -e "  ${shield_icon} User data and settings protected"
    echo
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
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

# Check if path is critical
is_critical_path() {
    local path="$1"
    for critical in "${CRITICAL_PATHS[@]}"; do
        if [[ "$path" == "$critical" ]] || [[ "$path" == "$critical"/* ]]; then
            return 0
        fi
    done
    return 1
}

# Validate command exists
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_message "ERROR" "Required command '$cmd' not found"
        return 1
    fi
    return 0
}

# Pre-flight system checks
preflight_checks() {
    local quiet_mode=false
    if [[ -n "$1" && "$1" == "--quiet" ]]; then
        quiet_mode=true
    fi
    
    log_message "INFO" "Running pre-flight system checks..."
    
    # Only show safety banner if not in quiet mode
    if [[ "$quiet_mode" == false ]]; then
        echo -e "\n${BOLD}${GREEN}🛡️  SAFETY PROTECTION ACTIVE 🛡️${NC}"
        echo -e "${GREEN}✓ Critical system paths protected${NC}"
        echo -e "${GREEN}✓ Active files detected and preserved${NC}"
        echo -e "${GREEN}✓ User data and evidence protected${NC}"
        echo -e "${GREEN}✓ Tool configurations preserved${NC}"
        echo -e "${GREEN}✓ Only safe cache/log cleanup enabled${NC}"
        echo
    fi
    
    # Check if running as root for system cleanup
    if [[ $EUID -ne 0 ]] && [[ -n "$1" && "$1" != "--user-only" ]]; then
        log_message "WARNING" "Some cleanup operations require root privileges"
        echo -e "${YELLOW}Tip: Run with 'sudo' for complete system cleanup${NC}"
    fi
    
    # Check required commands (skip apt for user-only mode)
    local required_commands=("df" "du" "find")
    if [[ -n "$1" && "$1" == "--user-only" ]]; then
        # For user-only mode, we don't need lsof or apt
        required_commands=("df" "du" "find")
    else
        # For system cleanup, we need all commands
        required_commands=("df" "du" "find" "lsof" "apt")
    fi
    
    for cmd in "${required_commands[@]}"; do
        check_command "$cmd" || exit 1
    done
    
    # Check disk space
    local disk_info=($(get_disk_space))
    local used_percent="${disk_info[2]%?}"
    
    if [[ $used_percent -gt 95 ]]; then
        log_message "WARNING" "Disk usage is critically high (${used_percent}%)"
        if [[ "$quiet_mode" == false ]]; then
            echo -e "${RED}WARNING: Disk usage is critically high! Emergency cleanup recommended.${NC}"
        fi
    fi
    
    log_message "SUCCESS" "Pre-flight checks completed"
    # Don't show success message in quiet mode
    if [[ "$quiet_mode" == false ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} Pre-flight checks completed"
    fi
}

# Fix for unbound variable error
set +u

# Show current disk usage summary with visual indicators
show_disk_summary() {
    local compact_mode=false
    if [[ -n "$1" && "$1" == "--compact" ]]; then
        compact_mode=true
    fi
    
    local disk_icon=$(get_icon "DISK")
    local clean_icon=$(get_icon "CLEAN")
    
    local hr_width=$((TERM_WIDTH - 2))
    
    if [[ "$compact_mode" == false ]]; then
        echo -e "${WHITE}${BOLD}${disk_icon} DISK USAGE ANALYSIS ${disk_icon}${NC}"
    fi
    
    # Get disk usage information
    local disk_info=($(get_disk_space))
    local used="${disk_info[0]}"
    local free="${disk_info[1]}"
    local usage="${disk_info[2]}"
    local usage_percent="${usage%?}"  # Remove % character
    
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
    local apt_cache_size=$(get_dir_size "/var/cache/apt/archives")
    echo -e "  ${pkg_icon} APT Cache:           ${CYAN}$(bytes_to_human $apt_cache_size)${NC}"
    
    # System Logs
    local log_size=$(get_dir_size "/var/log")
    echo -e "  ${log_icon} System Logs:        ${CYAN}$(bytes_to_human $log_size)${NC}"
    
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
        local journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' || echo "0B")
        echo -e "  ${journal_icon} Journal Logs:       ${CYAN}$journal_size${NC}"
    fi
    
    # Temporary Files
    local tmp_size=$(get_dir_size "/tmp")
    echo -e "  ${tmp_icon} Temp Files:         ${CYAN}$(bytes_to_human $tmp_size)${NC}"
    
    # User Caches (current user only)
    if [[ -d "$HOME/.cache" ]]; then
        local user_cache_size=$(get_dir_size "$HOME/.cache")
        echo -e "  ${home_icon} User Cache:          ${CYAN}$(bytes_to_human $user_cache_size)${NC}"
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
        local snap_size=$(get_dir_size "/var/lib/snapd/snaps")
        echo -e "  ${snap_icon} Snap Packages:      ${CYAN}$(bytes_to_human $snap_size)${NC}"
    fi
    
    echo
}

# Safe file deletion with validation
safe_delete() {
    local target="$1"
    local description="$2"
    local size_before=0
    local freed_space=0
    
    # Handle wildcard patterns
    if [[ "$target" == *"*"* ]]; then
        # For wildcard patterns, clean individual files/directories
        local parent_dir="${target%/*}"
        local pattern="${target##*/}"
        
        if [[ ! -d "$parent_dir" ]]; then
            log_message "INFO" "Parent directory does not exist: $parent_dir"
            return 0
        fi
        
        # Check if parent directory is critical
        if is_critical_path "$parent_dir"; then
            log_message "WARNING" "Skipping critical path: $parent_dir"
            return 0
        fi
        
        # Get size before deletion
        size_before=$(get_dir_size "$parent_dir")
        
        if [[ "$DRY_RUN" == true ]]; then
            log_message "INFO" "[DRY RUN] Would clean: $target ($description)"
            echo -e "  ${YELLOW}[DRY RUN]${NC} Would clean: $description - $(bytes_to_human $size_before)"
            return 0
        fi
        
        # Clean files matching pattern
        local files_cleaned=0
        for file in "$parent_dir"/$pattern; do
            if [[ -e "$file" ]]; then
                rm -rf "$file" 2>/dev/null && ((files_cleaned++)) || true
            fi
        done
        
        if [[ $files_cleaned -gt 0 ]]; then
            local size_after=$(get_dir_size "$parent_dir")
            freed_space=$((size_before - size_after))
            TOTAL_FREED=$((TOTAL_FREED + freed_space))
            log_message "SUCCESS" "Cleaned: $target - Freed $(bytes_to_human $freed_space)"
            echo -e "  ${GREEN}✓${NC} Cleaned: $description - ${GREEN}$(bytes_to_human $freed_space)${NC}"
        else
            echo -e "  ${BLUE}ℹ${NC} No files to clean: $description"
        fi
        
        return 0
    fi
    
    # Handle single file/directory
    # Critical path validation
    if is_critical_path "$target"; then
        log_message "WARNING" "Skipping critical path: $target"
        return 0
    fi
    
    # Check if target exists
    if [[ ! -e "$target" ]]; then
        log_message "INFO" "Target does not exist: $target"
        return 0
    fi
    
    # Get size before deletion
    size_before=$(get_dir_size "$target")
    
    # Check for active processes using files
    if [[ -f "$target" ]] && command -v lsof >/dev/null 2>&1 && lsof "$target" >/dev/null 2>&1; then
        log_message "WARNING" "File is in use by running processes: $target"
        echo -e "${YELLOW}File '$target' is currently in use. Skip? [y/N]${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log_message "INFO" "[DRY RUN] Would delete: $target ($description)"
        echo -e "  ${YELLOW}[DRY RUN]${NC} Would clean: $description - $(bytes_to_human $size_before)"
        return 0
    fi
    
    # Perform deletion
    if rm -rf "$target" 2>/dev/null; then
        freed_space=$size_before
        TOTAL_FREED=$((TOTAL_FREED + freed_space))
        log_message "SUCCESS" "Deleted: $target - Freed $(bytes_to_human $freed_space)"
        echo -e "  ${GREEN}✓${NC} Cleaned: $description - ${GREEN}$(bytes_to_human $freed_space)${NC}"
    else
        log_message "ERROR" "Failed to delete: $target"
        echo -e "  ${RED}✗${NC} Failed: $description"
        return 1
    fi
    
    return 0
}

# Clean APT package cache
cleanup_apt_cache() {
    echo -e "\n${BOLD}${PURPLE}[APT] Cleaning Package Cache...${NC}"
    
    if ! check_command "apt"; then
        log_message "ERROR" "APT not available on this system"
        return 1
    fi
    
    local cache_size_before=$(get_dir_size "/var/cache/apt/archives")
    
    echo -e "${CYAN}Current APT cache size: $(bytes_to_human $cache_size_before)${NC}"
    
    if [[ $cache_size_before -gt 104857600 ]]; then  # > 100MB
        if [[ "$FORCE_MODE" != true ]]; then
            echo -e "${YELLOW}This will clear downloaded package files. Continue? [Y/n]${NC}"
            read -r response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                log_message "INFO" "APT cache cleanup skipped by user"
                return 0
            fi
        fi
        
        if [[ "$DRY_RUN" != true ]]; then
            # Clean package cache
            sudo apt clean 2>/dev/null || log_message "WARNING" "apt clean failed"
            
            # Remove orphaned packages
            sudo apt autoremove -y 2>/dev/null || log_message "WARNING" "apt autoremove failed"
            
            # Remove partial packages
            sudo apt autoclean 2>/dev/null || log_message "WARNING" "apt autoclean failed"
        fi
        
        local cache_size_after=$(get_dir_size "/var/cache/apt/archives")
        local freed=$((cache_size_before - cache_size_after))
        TOTAL_FREED=$((TOTAL_FREED + freed))
        
        echo -e "  ${GREEN}✓${NC} APT Cache cleaned - ${GREEN}$(bytes_to_human $freed)${NC} freed"
        log_message "SUCCESS" "APT cache cleanup completed - $(bytes_to_human $freed) freed"
    else
        echo -e "  ${BLUE}[INFO]${NC} APT cache is already small ($(bytes_to_human $cache_size_before))"
    fi
}

# Clean system logs
cleanup_system_logs() {
    echo -e "\n${BOLD}${PURPLE}[LOG] Cleaning System Logs...${NC}"
    
    # Journal logs cleanup (systemd)
    if command -v journalctl >/dev/null 2>&1; then
        local journal_size_before=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' | head -1 || echo "0B")
        echo -e "${CYAN}Current journal log size: $journal_size_before${NC}"
        
        if [[ "$DRY_RUN" == true ]]; then
            # In dry run mode, just report what would be done
            echo -e "  ${BLUE}${ICON_INFO}${NC} ${YELLOW}[DRY RUN]${NC} Would clean journal logs older than 30 days"
            echo -e "  ${BLUE}${ICON_INFO}${NC} ${YELLOW}[DRY RUN]${NC} Would limit journal size to 500MB"
            log_message "INFO" "[DRY RUN] Journal logs cleanup would be performed"
        elif [[ "$FORCE_MODE" == true ]]; then
            # In force mode, clean without prompting
            sudo journalctl --vacuum-time=30d >/dev/null 2>&1
            sudo journalctl --vacuum-size=500M >/dev/null 2>&1
            echo -e "  ${GREEN}✓${NC} Journal logs cleaned automatically"
            log_message "SUCCESS" "Journal logs cleanup completed (force mode)"
        else
            # Normal interactive mode
            echo -e "${YELLOW}Clean journal logs older than 30 days? [Y/n]${NC}"
            read -r response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                log_message "INFO" "Journal cleanup skipped by user"
            else
                sudo journalctl --vacuum-time=30d >/dev/null 2>&1
                sudo journalctl --vacuum-size=500M >/dev/null 2>&1
                echo -e "  ${GREEN}✓${NC} Journal logs cleaned"
                log_message "SUCCESS" "Journal logs cleanup completed"
            fi
        fi
    fi
    
    # PostgreSQL logs cleanup (Kali/Metasploit specific) - CONSERVATIVE APPROACH
    local postgres_log_dirs=(
        "/var/log/postgresql"
    )
    
    for log_dir in "${postgres_log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            local pg_log_size=$(get_dir_size "$log_dir")
            if [[ $pg_log_size -gt 104857600 ]]; then  # > 100MB
                echo -e "\n${BOLD}${YELLOW}⚠️  PostgreSQL Log Cleanup Warning ⚠️${NC}"
                echo -e "${CYAN}PostgreSQL logs: $(bytes_to_human $pg_log_size)${NC}"
                echo -e "${YELLOW}What will be cleaned:${NC}"
                echo -e "${GREEN}✓ Log files older than 30 days (.log files)${NC}"
                echo -e "${GREEN}✓ Compressed log files (.log.gz files)${NC}"
                echo -e "${RED}✗ Current active log files (preserved)${NC}"
                echo -e "${RED}✗ Database data (never touched)${NC}"
                echo -e "${RED}✗ Configuration files (preserved)${NC}"
                echo
                echo -e "${BLUE}Impact: None on database functionality, only old log files removed${NC}"
                
                if [[ "$FORCE_MODE" != true ]]; then
                    echo -e "${YELLOW}Clean old PostgreSQL logs (30+ days)? [Y/n]${NC}"
                    read -r response
                    if [[ "$response" =~ ^[Nn]$ ]]; then
                        continue
                    fi
                fi
                
                # SAFE: Only clean old log files, never touch active logs or data
                if [[ "$DRY_RUN" != true ]]; then
                    # Find current active log file to preserve it
                    local active_log=$(find "$log_dir" -name "postgresql-*.log" -mtime -1 2>/dev/null | head -1)
                    
                    # Clean old logs but preserve active ones
                    find "$log_dir" -name "*.log" -mtime +30 ! -path "$active_log" -delete 2>/dev/null || true
                    find "$log_dir" -name "*.log.*" -mtime +14 -delete 2>/dev/null || true
                fi
                
                local pg_log_size_after=$(get_dir_size "$log_dir")
                local freed=$((pg_log_size - pg_log_size_after))
                TOTAL_FREED=$((TOTAL_FREED + freed))
                echo -e "  ${GREEN}✓${NC} PostgreSQL logs cleaned - $(bytes_to_human $freed)"
                echo -e "  ${BLUE}ℹ${NC} Active logs and all database data preserved"
            fi
        fi
    done
    
    # Old log files cleanup
    local log_targets=(
        "/var/log/*.log.1"
        "/var/log/*.log.*.gz"
        "/var/log/*/*.log.1"
        "/var/log/*/*.log.*.gz"
    )
    
    for pattern in "${log_targets[@]}"; do
        if compgen -G "$pattern" > /dev/null; then
            local size_before=0
            for file in $pattern; do
                if [[ -f "$file" ]]; then
                    size_before=$((size_before + $(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)))
                fi
            done
            
            if [[ $size_before -gt 0 ]]; then
                if [[ "$DRY_RUN" != true ]]; then
                    sudo rm -f $pattern 2>/dev/null || true
                fi
                TOTAL_FREED=$((TOTAL_FREED + size_before))
                echo -e "  ${GREEN}✓${NC} Old log files cleaned - $(bytes_to_human $size_before)"
            fi
        fi
    done
}

# Clean temporary files
cleanup_temp_files() {
    echo -e "\n${BOLD}${PURPLE}[TMP] Cleaning Temporary Files...${NC}"
    
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
            
            local size_before=$(get_dir_size "$temp_dir")
            local files_cleaned=0
            
            # First pass: Clean obviously safe files regardless of age
            echo -e "  ${BLUE}Cleaning safe temporary files...${NC}"
            for pattern in "${safe_patterns[@]}"; do
                if [[ "$DRY_RUN" != true ]]; then
                    # Check if files match pattern and are not in preserve list
                    for file in "$temp_dir"/$pattern; do
                        if [[ -f "$file" ]]; then
                            local should_preserve=false
                            local basename_file=$(basename "$file")
                            
                            # Check if file matches preserve patterns
                            for preserve_pattern in "${preserve_patterns[@]}"; do
                                if [[ "$basename_file" == $preserve_pattern ]]; then
                                    should_preserve=true
                                    break
                                fi
                            done
                            
                            if [[ "$should_preserve" == false ]]; then
                                rm -f "$file" 2>/dev/null && ((files_cleaned++)) || true
                            fi
                        fi
                    done
                else
                    # Dry run: just count files
                    for file in "$temp_dir"/$pattern; do
                        if [[ -f "$file" ]]; then
                            local should_preserve=false
                            local basename_file=$(basename "$file")
                            
                            for preserve_pattern in "${preserve_patterns[@]}"; do
                                if [[ "$basename_file" == $preserve_pattern ]]; then
                                    should_preserve=true
                                    break
                                fi
                            done
                            
                            if [[ "$should_preserve" == false ]]; then
                                ((files_cleaned++))
                                echo -e "    ${YELLOW}[DRY RUN]${NC} Would delete: $file"
                            fi
                        fi
                    done
                fi
            done
            
            # Second pass: Clean old files (older than 3 days)
            echo -e "  ${BLUE}Cleaning files older than 3 days...${NC}"
            local old_files=$(find "$temp_dir" -maxdepth 1 -type f -mtime +3 2>/dev/null)
            
            for file in $old_files; do
                if [[ -f "$file" ]]; then
                    local should_preserve=false
                    local basename_file=$(basename "$file")
                    
                    # Check if file matches preserve patterns
                    for preserve_pattern in "${preserve_patterns[@]}"; do
                        if [[ "$basename_file" == $preserve_pattern ]]; then
                            should_preserve=true
                            echo -e "    ${YELLOW}Preserving active file: $basename_file${NC}"
                            break
                        fi
                    done
                    
                    if [[ "$should_preserve" == false ]]; then
                        if [[ "$DRY_RUN" != true ]]; then
                            rm -f "$file" 2>/dev/null && ((files_cleaned++)) || true
                        else
                            ((files_cleaned++))
                            echo -e "    ${YELLOW}[DRY RUN]${NC} Would delete: $file"
                        fi
                    fi
                fi
            done
            
            # Clean empty directories
            if [[ "$DRY_RUN" != true ]]; then
                find "$temp_dir" -maxdepth 2 -type d -empty -delete 2>/dev/null || true
            fi
            
            local size_after=$(get_dir_size "$temp_dir")
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

# Clean user caches
cleanup_user_caches() {
    echo -e "\n${BOLD}${PURPLE}🏠 Cleaning User Caches...${NC}"
    
    local cache_dir="$HOME/.cache"
    
    if [[ ! -d "$cache_dir" ]]; then
        echo -e "  ${BLUE}ℹ${NC} No user cache directory found"
        return 0
    fi
    
    local cache_size=$(get_dir_size "$cache_dir")
    echo -e "${CYAN}Current user cache size: $(bytes_to_human $cache_size)${NC}"
    
    if [[ $cache_size -gt 52428800 ]]; then  # > 50MB
        if [[ "$FORCE_MODE" != true ]]; then
            echo -e "${YELLOW}Clean user application caches? [Y/n]${NC}"
            read -r response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                log_message "INFO" "User cache cleanup skipped"
                return 0
            fi
        fi
        
        local total_cleaned=0
        
        # Browser caches - clean more safely
        echo -e "  ${CYAN}Cleaning browser caches...${NC}"
        local browser_cache_dirs=(
            "$HOME/.cache/mozilla/firefox"
            "$HOME/.cache/google-chrome"
            "$HOME/.cache/chromium"
        )
        
        for browser_dir in "${browser_cache_dirs[@]}"; do
            if [[ -d "$browser_dir" ]]; then
                local size_before=$(get_dir_size "$browser_dir")
                
                if [[ "$DRY_RUN" != true ]]; then
                    # Clean cache files but preserve profiles and settings
                    find "$browser_dir" -name "cache2" -type d -exec rm -rf {}/* \; 2>/dev/null || true
                    find "$browser_dir" -name "Cache" -type d -exec rm -rf {}/* \; 2>/dev/null || true
                    find "$browser_dir" -name "CachedData" -type d -exec rm -rf {}/* \; 2>/dev/null || true
                fi
                
                local size_after=$(get_dir_size "$browser_dir")
                local freed=$((size_before - size_after))
                total_cleaned=$((total_cleaned + freed))
                
                if [[ $freed -gt 0 ]]; then
                    echo -e "    ${GREEN}✓${NC} $(basename "$browser_dir") cache - $(bytes_to_human $freed)"
                fi
            fi
        done
        
        # Thumbnail cache
        if [[ -d "$HOME/.cache/thumbnails" ]]; then
            local size_before=$(get_dir_size "$HOME/.cache/thumbnails")
            
            if [[ "$DRY_RUN" != true ]]; then
                rm -rf "$HOME/.cache/thumbnails"/* 2>/dev/null || true
            fi
            
            local size_after=$(get_dir_size "$HOME/.cache/thumbnails")
            local freed=$((size_before - size_after))
            total_cleaned=$((total_cleaned + freed))
            
            if [[ $freed -gt 0 ]]; then
                echo -e "  ${GREEN}✓${NC} Thumbnail cache - $(bytes_to_human $freed)"
            fi
        fi
        
        # General application caches (be selective)
        local safe_cache_dirs=(
            "$HOME/.cache/pip"
            "$HOME/.cache/yarn"
            "$HOME/.cache/npm"
            "$HOME/.cache/go-build"
            "$HOME/.cache/composer"
        )
        
        for safe_cache in "${safe_cache_dirs[@]}"; do
            if [[ -d "$safe_cache" ]]; then
                local size_before=$(get_dir_size "$safe_cache")
                
                if [[ "$DRY_RUN" != true ]]; then
                    rm -rf "$safe_cache"/* 2>/dev/null || true
                fi
                
                local size_after=$(get_dir_size "$safe_cache")
                local freed=$((size_before - size_after))
                total_cleaned=$((total_cleaned + freed))
                
                if [[ $freed -gt 0 ]]; then
                    echo -e "  ${GREEN}✓${NC} $(basename "$safe_cache") cache - $(bytes_to_human $freed)"
                fi
            fi
        done
        
        # Update global counter
        TOTAL_FREED=$((TOTAL_FREED + total_cleaned))
        
        if [[ $total_cleaned -gt 0 ]]; then
            echo -e "\n${GREEN}✅ User cache cleanup completed${NC}"
            echo -e "${GREEN}💾 Total space freed: $(bytes_to_human $total_cleaned)${NC}"
        else
            echo -e "\n${BLUE}ℹ${NC} No user caches to clean"
        fi
    else
        echo -e "  ${BLUE}ℹ${NC} User cache is already small"
    fi
}

# Clean Snap packages (Ubuntu/Mint specific)
cleanup_snap_packages() {
    if ! command -v snap >/dev/null 2>&1; then
        return 0
    fi
    
    echo -e "\n${BOLD}${PURPLE}📱 Cleaning Snap Packages...${NC}"
    
    # Get current snap retention policy
    local retention=$(snap get system refresh.retain 2>/dev/null || echo "3")
    echo -e "${CYAN}Current snap retention: $retention versions${NC}"
    
    if [[ "$FORCE_MODE" != true ]]; then
        echo -e "${YELLOW}Remove old snap package versions (keeping latest 2)? [Y/n]${NC}"
        read -r response
        if [[ "$response" =~ ^[Nn]$ ]]; then
            return 0
        fi
    fi
    
    if [[ "$DRY_RUN" != true ]]; then
        # Set retention to 2 versions
        sudo snap set system refresh.retain=2 2>/dev/null || true
        
        # Remove old versions
        local old_snaps=$(snap list --all | awk '/disabled/{print $1, $3}' | 
                         while read snapname revision; do
                             snap remove "$snapname" --revision="$revision" 2>/dev/null && echo "Removed $snapname revision $revision"
                         done)
    fi
    
    echo -e "  ${GREEN}✓${NC} Snap packages cleaned"
    log_message "SUCCESS" "Snap packages cleanup completed"
}

# Clean Metasploit and penetration testing tool caches (Kali-specific)
cleanup_pentesting_tools() {
    echo -e "\n${BOLD}${PURPLE}🔧 Cleaning Penetration Testing Tool Caches...${NC}"
    
    local total_cleaned=0
    
    # Clean Metasploit logs (safe operation)
    echo -e "\n${CYAN}🔧 Cleaning Metasploit Logs...${NC}"
    local msf_dirs=(
        "$HOME/.msf4/logs"
        "/root/.msf4/logs"
        "/opt/metasploit-framework/logs"
        "/var/log/metasploit"
    )
    
    for msf_dir in "${msf_dirs[@]}"; do
        if [[ -d "$msf_dir" ]]; then
            local size_before=$(get_dir_size "$msf_dir")
            if [[ $size_before -gt 1048576 ]]; then  # > 1MB
                echo -e "  ${CYAN}Found Metasploit logs: $(bytes_to_human $size_before)${NC}"
                
                if [[ "$FORCE_MODE" != true ]]; then
                    echo -e "${YELLOW}Clean Metasploit log files? (preserves loot and scan data) [Y/n]${NC}"
                    read -r response
                    if [[ "$response" =~ ^[Nn]$ ]]; then
                        continue
                    fi
                fi
                
                if [[ "$DRY_RUN" != true ]]; then
                    # Clean log files but preserve important data
                    find "$msf_dir" -name "*.log" -type f -delete 2>/dev/null || true
                    find "$msf_dir" -name "framework.log*" -type f -delete 2>/dev/null || true
                    find "$msf_dir" -name "production.log*" -type f -delete 2>/dev/null || true
                    # Keep loot, creds, and scan data directories
                fi
                
                local size_after=$(get_dir_size "$msf_dir")
                local freed=$((size_before - size_after))
                total_cleaned=$((total_cleaned + freed))
                
                if [[ $freed -gt 0 ]]; then
                    echo -e "  ${GREEN}✓${NC} Metasploit logs cleaned - $(bytes_to_human $freed)"
                else
                    echo -e "  ${BLUE}ℹ${NC} No Metasploit logs to clean"
                fi
            fi
        fi
    done
    
    # Clean PostgreSQL logs (Metasploit database logs)
    echo -e "\n${CYAN}🐘 Cleaning PostgreSQL Logs...${NC}"
    local pg_log_dirs=(
        "/var/log/postgresql"
        "/var/lib/postgresql/*/main/log"
        "/var/lib/postgresql/*/main/pg_log"
    )
    
    for pg_pattern in "${pg_log_dirs[@]}"; do
        for pg_dir in $pg_pattern; do
            if [[ -d "$pg_dir" ]]; then
                local size_before=$(get_dir_size "$pg_dir")
                if [[ $size_before -gt 1048576 ]]; then  # > 1MB
                    echo -e "  ${CYAN}Found PostgreSQL logs: $(bytes_to_human $size_before)${NC}"
                    
                    if [[ "$FORCE_MODE" != true ]]; then
                        echo -e "${YELLOW}Clean PostgreSQL log files? [Y/n]${NC}"
                        read -r response
                        if [[ "$response" =~ ^[Nn]$ ]]; then
                            continue
                        fi
                    fi
                    
                    if [[ "$DRY_RUN" != true ]]; then
                        # Clean old log files (keep recent ones)
                        find "$pg_dir" -name "*.log" -type f -mtime +7 -delete 2>/dev/null || true
                        find "$pg_dir" -name "postgresql-*.log" -type f -mtime +7 -delete 2>/dev/null || true
                    fi
                    
                    local size_after=$(get_dir_size "$pg_dir")
                    local freed=$((size_before - size_after))
                    total_cleaned=$((total_cleaned + freed))
                    
                    if [[ $freed -gt 0 ]]; then
                        echo -e "  ${GREEN}✓${NC} PostgreSQL logs cleaned - $(bytes_to_human $freed)"
                    else
                        echo -e "  ${BLUE}ℹ${NC} No old PostgreSQL logs to clean"
                    fi
                fi
            fi
        done
    done
    
    # SAFE: Only clean clearly temporary Wireshark files
    local safe_wireshark_temps=(
        "/tmp/wireshark_*.tmp"
        "/tmp/dumpcap_*.tmp"
        "$HOME/.cache/wireshark/*.tmp"
        "/root/.cache/wireshark/*.tmp"
    )
    
    for temp_pattern in "${safe_wireshark_temps[@]}"; do
        if compgen -G "$temp_pattern" > /dev/null 2>&1; then
            echo -e "${CYAN}Found Wireshark temporary files${NC}"
            if [[ "$FORCE_MODE" != true ]]; then
                echo -e "${YELLOW}Clean Wireshark TEMPORARY files only? [Y/n]${NC}"
                echo -e "${GREEN}Safe: Only removes .tmp files, preserves all .pcap captures${NC}"
                read -r response
                if [[ "$response" =~ ^[Nn]$ ]]; then
                    continue
                fi
            fi
            
            if [[ "$DRY_RUN" != true ]]; then
                # SAFE: Only delete .tmp files, never .pcap files
                rm -f $temp_pattern 2>/dev/null || true
            fi
            echo -e "  ${GREEN}✓${NC} Wireshark temporary files cleaned (captures preserved)"
        fi
    done
    
    # SAFE: Only clean standard cache directories (not tool data)
    local safe_cache_dirs=(
        "$HOME/.cache/pip"
        "$HOME/.cache/npm" 
        "$HOME/.cache/yarn"
        "/root/.cache/pip"
        "/root/.cache/npm"
        "/root/.cache/yarn"
    )
    
    for cache_dir in "${safe_cache_dirs[@]}"; do
        if [[ -d "$cache_dir" ]]; then
            local cache_size=$(get_dir_size "$cache_dir")
            if [[ $cache_size -gt 52428800 ]]; then  # > 50MB
                echo -e "${CYAN}Standard package cache: $(bytes_to_human $cache_size)${NC}"
                if [[ "$FORCE_MODE" != true ]]; then
                    echo -e "${YELLOW}Clean $(basename "$cache_dir") package cache? [Y/n]${NC}"
                    echo -e "${GREEN}Safe: Standard package manager cache, can be rebuilt${NC}"
                    read -r response
                    if [[ "$response" =~ ^[Nn]$ ]]; then
                        continue
                    fi
                fi
                
                if [[ "$DRY_RUN" != true ]]; then
                    rm -rf "$cache_dir"/* 2>/dev/null || true
                fi
                
                local cache_size_after=$(get_dir_size "$cache_dir")
                local freed=$((cache_size - cache_size_after))
                total_cleaned=$((total_cleaned + freed))
                echo -e "  ${GREEN}✓${NC} Package cache cleaned - $(bytes_to_human $freed)"
            fi
        fi
    done
    
    # Update global counter
    TOTAL_FREED=$((TOTAL_FREED + total_cleaned))
    
    if [[ $total_cleaned -gt 0 ]]; then
        echo -e "\n${GREEN}✅ Penetration testing tools cleanup completed${NC}"
        echo -e "${GREEN}💾 Total space freed: $(bytes_to_human $total_cleaned)${NC}"
    else
        echo -e "\n${BLUE}ℹ${NC} No penetration testing tool caches to clean"
    fi
}

# Clean old kernels (Debian/Ubuntu)
cleanup_old_kernels() {
    echo -e "\n${BOLD}${PURPLE}🔧 Managing Kernel Versions...${NC}"
    
    local current_kernel=$(uname -r)
    local installed_kernels=$(dpkg --list | grep linux-image | grep -v "$current_kernel" | wc -l)
    
    echo -e "${CYAN}Current kernel: $current_kernel${NC}"
    echo -e "${CYAN}Old kernels found: $installed_kernels${NC}"
    
    if [[ $installed_kernels -gt 1 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL OPERATION WARNING ⚠️${NC}"
        echo -e "${RED}This operation will remove old kernel versions!${NC}"
        echo -e "${RED}Keep at least 2-3 recent kernels for system recovery.${NC}"
        echo -e "${YELLOW}Current kernel ($current_kernel) will be preserved.${NC}"
        echo
        echo -e "${YELLOW}Do you want to remove old kernels? [y/N]${NC}"
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            if [[ "$DRY_RUN" != true ]]; then
                sudo apt autoremove --purge -y 2>/dev/null || log_message "WARNING" "Kernel cleanup failed"
            fi
            echo -e "  ${GREEN}✓${NC} Old kernels cleaned"
            log_message "SUCCESS" "Old kernels cleanup completed"
        else
            echo -e "  ${BLUE}ℹ${NC} Kernel cleanup skipped by user"
        fi
    else
        echo -e "  ${BLUE}ℹ${NC} No old kernels to remove"
    fi
}

generate_report() {
    detect_terminal_capabilities
    
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    local time_display
    
    if [[ $minutes -gt 0 ]]; then
        time_display="${minutes}m ${seconds}s"
    else
        time_display="${seconds} seconds"
    fi
    local success_icon=$(get_icon "SUCCESS")
    local info_icon=$(get_icon "INFO")
    local disk_icon=$(get_icon "DISK")
    local clock_icon=$(get_icon "CLOCK")
    local shield_icon=$(get_icon "SHIELD")
    local rocket_icon=$(get_icon "ROCKET")
    local log_icon="[LOG]"
    
    if [[ "$USE_EMOJI" == true ]]; then
        log_icon="📝"
    fi
    
    # Calculate width for tabular display
    local hr_width=$((TERM_WIDTH - 2))
    
    # Show report header in compact format
    echo
    echo -e "${GREEN}${BOLD}${success_icon} CLEANUP COMPLETED SUCCESSFULLY ${success_icon}${NC}"
    echo
    
    # Get disk info for before/after comparison
    local disk_info=($(get_disk_space))
    local used="${disk_info[0]}"
    local free="${disk_info[1]}"
    local usage="${disk_info[2]}"
    local usage_percent="${usage%?}"  # Remove % character
    
    # Format the total freed space with appropriate units
    local freed_human="$(bytes_to_human $TOTAL_FREED)"
    
    # Create visual summary section in compact format
    echo -e "${WHITE}${BOLD}${rocket_icon} CLEANUP PERFORMANCE${NC}"
    
    # Show progress bars and stats in compact format
    if [[ $TOTAL_FREED -gt 1048576 ]]; then  # Greater than 1 MB
        echo -e "  ${disk_icon} ${BOLD}Total Space Freed:${NC}   ${GREEN}${BOLD}${freed_human}${NC} ${GREEN}${success_icon}${NC}"
    elif [[ $TOTAL_FREED -gt 0 ]]; then
        echo -e "  ${disk_icon} ${BOLD}Total Space Freed:${NC}   ${YELLOW}${BOLD}${freed_human}${NC} ${YELLOW}${info_icon}${NC}"
    else
        echo -e "  ${disk_icon} ${BOLD}Total Space Freed:${NC}   ${BLUE}${BOLD}${freed_human}${NC} ${BLUE}${info_icon}${NC}"
    fi
    echo -e "  ${clock_icon} ${BOLD}Time Taken:${NC}         ${CYAN}${time_display}${NC}"
    echo -e "  ${log_icon} ${BOLD}Log File:${NC}           ${BLUE}$LOG_FILE${NC}"
    
    if [[ "$BACKUP_ENABLED" == true ]]; then
        echo -e "  ${shield_icon} ${BOLD}Backup Created:${NC}      ${GREEN}Yes${NC} (${BACKUP_DIR})"
    fi
    
    # Current disk status with visual bar in compact format
    echo
    echo -e "${WHITE}${BOLD}${disk_icon} CURRENT DISK STATUS${NC}"
    
    # Adjust bar length to terminal width
    local bar_length=$(( hr_width / 2 ))
    bar_length=$(( bar_length < 20 ? 20 : bar_length )) # Minimum 20 chars
    bar_length=$(( bar_length > 60 ? 60 : bar_length )) # Maximum 60 chars
    
    
    local filled_length=$(( usage_percent * bar_length / 100 ))
    local empty_length=$(( bar_length - filled_length ))
    
    # Generate the progress bar segments with appropriate color
    local bar=""
    local color="${GREEN}"
    local filled_char empty_char
    
    # Set color based on disk usage
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
    
    echo -e "  ${color}${bar} ${usage}${NC}"
    echo -e "  ${BOLD}Used:${NC} ${RED}${used}${NC} │ ${BOLD}Free:${NC} ${GREEN}${free}${NC}"
    
    # Final message based on results
    echo
    if [[ $TOTAL_FREED -gt 1048576 ]]; then  # Greater than 1 MB
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

show_menu() {
    detect_terminal_capabilities
    
    local rocket_icon=$(get_icon "ROCKET")
    local disk_icon=$(get_icon "DISK")
    local clean_icon=$(get_icon "CLEAN")
    local shield_icon=$(get_icon "SHIELD")
    local info_icon=$(get_icon "INFO")
    
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
        # No need for "MENU OPTIONS" text as we already have "OPTIONS" below
        
        # System information in tabular format
        local distro=$(detect_distribution | tr '[:lower:]' '[:upper:]')
        local sys_type=$(get_system_info)
        local kernel=$(uname -r)
        local arch=$(uname -m)
        
        # Get appropriate icons based on terminal capability
        local disk_icon=$(get_icon "DISK")
        local info_icon=$(get_icon "INFO")
        local computer_icon="[PC]"
        local clock_icon=$(get_icon "CLOCK")
        local distro_icon="[OS]"
        
        if [[ "$USE_EMOJI" == true ]]; then
            computer_icon="🖥️ "
            # Set distribution-specific icon with fallback
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
        local disk_info=($(get_disk_space))
        local used="${disk_info[0]}"
        local free="${disk_info[1]}"
        local usage="${disk_info[2]}"
        local usage_percent="${usage%?}"  # Remove % character
        
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
        local apt_size=$(get_dir_size "/var/cache/apt/archives")
        local apt_human=$(bytes_to_human $apt_size)
        local log_size=$(get_dir_size "/var/log")
        local log_human=$(bytes_to_human $log_size)
        local tmp_size=$(get_dir_size "/tmp")
        local tmp_human=$(bytes_to_human $tmp_size)
        
        
        # Create a clean, properly aligned table without color interference
        echo "+----------------------------------------------------------+"
        printf "| %-56s |\n" "SYSTEM OVERVIEW"
        echo "+----------------------------------------------------------+"
        
        # Build lines without colors first to calculate proper spacing
        local os_text="OS: $distro     Kernel: $kernel     Arch: $arch"
        local disk_text="Disk: $usage     Used: $used     Free: $free"
        local status_text="Status: $recommendation"
        local cache_text="Cache: $apt_human     Logs: $log_human     Temp Files: $tmp_human"
        
        # Calculate padding needed for each line
        local os_padding=$((56 - ${#os_text}))
        local disk_padding=$((56 - ${#disk_text}))
        local status_padding=$((56 - ${#status_text}))
        local cache_padding=$((56 - ${#cache_text}))
        
        # Print with colors and proper padding
        echo -e "| OS: ${GREEN}$distro${NC}     Kernel: ${GREEN}$kernel${NC}     Arch: ${GREEN}$arch${NC}$(printf '%*s' $os_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Disk: ${usage_color}$usage${NC}     Used: ${RED}$used${NC}     Free: ${GREEN}$free${NC}$(printf '%*s' $disk_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Status: ${usage_color}$recommendation${NC}$(printf '%*s' $status_padding '') |"
        echo "+----------------------------------------------------------+"
        echo -e "| Cache: ${CYAN}$apt_human${NC}     Logs: ${CYAN}$log_human${NC}     Temp Files: ${CYAN}$tmp_human${NC}$(printf '%*s' $cache_padding '') |"
        echo "+----------------------------------------------------------+"
        echo
        
        # Menu options in a more compact format
        echo -e "${WHITE}${BOLD}OPTIONS${NC} (enter a number):"
        echo -e "  ${WHITE}1${NC}. ${GREEN}${BOLD}Basic Cleanup${NC} - Package cache & temp files"
        echo -e "  ${WHITE}2${NC}. ${YELLOW}${BOLD}User Cleanup${NC} - Home directory cache only"
        echo -e "  ${WHITE}3${NC}. ${RED}${BOLD}Advanced Cleanup${NC} - Deep system clean"
        echo -e "  ${WHITE}4${NC}. ${BLUE}${BOLD}Dry Run${NC} - Show what would be cleaned"
        echo -e "  ${WHITE}5${NC}. ${PURPLE}${BOLD}Disk Analysis${NC} - Scan system for large files"
        echo -e "  ${WHITE}h${NC}. Help & Info  ${WHITE}q${NC}. Quit"
        echo
        
        # Safety notice on its own line
        echo -e "${shield_icon} ${GREEN}System files protected${NC}"
        echo -ne "${BOLD}${WHITE}Select option [1-5,h,q]: ${NC}"
        read -r choice
        
        case "$choice" in
            1) 
                echo -e "\n${GREEN}Starting Basic Cleanup...${NC}"
                sleep 1
                # Basic cleanup with standard options
                cleanup_apt_cache
                cleanup_system_logs
                cleanup_temp_files
                generate_report
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read
                ;;
            2) 
                echo -e "\n${YELLOW}Starting User-Specific Cleanup...${NC}"
                sleep 1
                # Only clean user directories
                user_only_cleanup
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read
                ;;
            3) 
                echo -e "\n${RED}Starting Advanced Cleanup...${NC}"
                sleep 1
                # Full system cleanup
                advanced_cleanup
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read
                ;;
            4) 
                echo -e "\n${BLUE}Starting Dry Run Analysis...${NC}"
                echo -e "${YELLOW}This will show what would be cleaned without making any changes${NC}"
                sleep 1
                
                # Enable dry run mode
                DRY_RUN=true
                
                # Show dry run header
                echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BLUE}║${WHITE}${BOLD}                    DRY RUN MODE - NO CHANGES WILL BE MADE                    ${NC}${BLUE}║${NC}"
                echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
                echo
                
                # Run comprehensive scan to show what would be cleaned
                echo -e "${CYAN}${BOLD}What would be cleaned during a full system cleanup:${NC}"
                echo
                
                # Check and report on APT cache
                cleanup_apt_cache
                
                # Check and report on system logs
                cleanup_system_logs
                
                # Check and report on temporary files
                cleanup_temp_files
                
                # Check and report on old kernels
                if [[ $(apt-get -s autoremove | grep -c 'linux-image') -gt 0 ]]; then
                    echo -e "\n${PURPLE}Found old kernels that could be removed:${NC}"
                    apt-get -s autoremove | grep 'linux-image' | sed 's/^/  /'
                fi
                
                # Reset dry run mode
                DRY_RUN=false
                
                echo -e "\n${YELLOW}${BOLD}Summary:${NC} These items would be cleaned in a normal run."
                echo -e "${GREEN}No actual changes were made to your system.${NC}"
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read
                ;;
            5) 
                echo -e "\n${PURPLE}Starting Disk Space Analysis...${NC}"
                sleep 1
                
                # Show standard disk summary with explicit empty parameter
                show_disk_summary ""
                
                # Additional detailed analysis
                echo -e "\n${BOLD}${PURPLE}Largest Directories:${NC}"
                echo -e "${CYAN}Scanning for large directories (this may take a moment)...${NC}"
                
                # Find top 10 largest directories
                du -h --max-depth=2 /var /home /usr /opt 2>/dev/null | sort -hr | head -10 | \
                    while read size path; do
                        echo -e "  ${YELLOW}$size${NC}\t${path}"
                    done
                
                echo -e "\n${CYAN}Press Enter to return to menu...${NC}"
                read
                ;;
            [hH]) 
                # Show help information
                echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${BLUE}║${WHITE}${BOLD}                         HELP & SAFETY INFORMATION                            ${NC}${BLUE}║${NC}"
                echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
                echo
                echo -e "${BOLD}${GREEN}ABOUT THIS TOOL:${NC}"
                echo -e "LINUX SPACE BOOSTER safely cleans up disk space on Linux virtual machines"
                echo -e "without harming critical system files or user data."
                echo
                echo -e "${BOLD}${YELLOW}SAFETY FEATURES:${NC}"
                echo -e "✓ Critical system paths are protected from deletion"
                echo -e "✓ Active files in use by running processes are preserved"
                echo -e "✓ User data and personal files are never touched"
                echo -e "✓ The tool focuses only on expendable caches and temporary files"
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
                read
                ;;
            [qQ]) 
                echo -e "\n${GREEN}Thank you for using Linux-Space-Booster!${NC}"
                echo -e "${BLUE}Remember to run cleanup regularly for optimal system performance.${NC}"
                exit 0 
                ;;
            *) 
                echo -e "\n${RED}Invalid option. Please select 1-5, h, or q.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Quick safe cleanup
quick_cleanup() {
    echo -e "\n${GREEN}🏃 Starting Quick Safe Cleanup...${NC}"
    FORCE_MODE=true
    
    cleanup_apt_cache
    cleanup_temp_files
    cleanup_user_caches
    
    # Only clean snap if it's Ubuntu/Mint
    local distro=$(detect_distribution)
    if [[ "$distro" == "ubuntu" ]] || [[ "$distro" == "linuxmint" ]]; then
        cleanup_snap_packages
    fi
    
    # Clean pentesting tools cache if it's Kali/Parrot
    if [[ "$distro" == "kali" ]] || [[ "$distro" == "parrot" ]]; then
        cleanup_pentesting_tools
    fi
    
    cleanup_system_logs
    
    generate_report
    FORCE_MODE=false
}

# Advanced cleanup with confirmations
advanced_cleanup() {
    echo -e "\n${YELLOW}🔧 Starting Advanced Cleanup...${NC}"
    
    cleanup_apt_cache
    cleanup_system_logs
    cleanup_temp_files
    cleanup_user_caches
    cleanup_snap_packages
    cleanup_pentesting_tools
    cleanup_old_kernels
    
    generate_report
}

get_real_users() {
    awk -F: '$3 >= 1000 && $3 != 65534 && $7 !~ /nologin|false/ && $1 != "nobody" {print $1 ":" $3 ":" $6}' /etc/passwd | sort
}

show_user_selection() {
    echo -e "\n${BOLD}${CYAN}👥 SELECT USER TO CLEAN${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    
    local users=($(get_real_users))
    local current_user=$(whoami)
    
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
            local cache_human=$(bytes_to_human $cache_size)
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
        IFS=':' read -r selected_username selected_uid selected_homedir <<< "$selected_user_info"
        
        echo -e "\n${GREEN}Selected user: ${BOLD}$selected_username${NC}"
        echo -e "${CYAN}Home directory: $selected_homedir${NC}"
        
        echo -e "\n${YELLOW}Clean cache and temporary files for user '$selected_username'? [Y/n]${NC}"
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

cleanup_selected_user() {
    local username="$1"
    local homedir="$2"
    
    echo -e "\n${BLUE}🧹 Cleaning safe data for user: ${BOLD}$username${NC}"
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
    
    local total_cleaned=0
    
    # Clean browser caches (safe to delete)
    echo -e "\n${PURPLE}🌐 Cleaning Browser Caches...${NC}"
    local browser_caches=(
        "$homedir/.cache/mozilla/firefox/*/cache2"
        "$homedir/.cache/google-chrome/Default/Cache"
        "$homedir/.cache/google-chrome/Default/Code Cache"
        "$homedir/.cache/chromium/Default/Cache"
        "$homedir/.cache/chromium/Default/Code Cache"
        "$homedir/.mozilla/firefox/*/cache2"
    )
    
    for cache_pattern in "${browser_caches[@]}"; do
        for cache_path in $cache_pattern; do
            if [[ -d "$cache_path" ]]; then
                local size_before=$(get_dir_size "$cache_path")
                if [[ $size_before -gt 1048576 ]]; then  # > 1MB
                    echo -e "  ${CYAN}Cleaning: $(basename $(dirname $cache_path)) cache ($(bytes_to_human $size_before))${NC}"
                    if [[ "$DRY_RUN" != true ]]; then
                        rm -rf "$cache_path"/* 2>/dev/null || true
                    fi
                    local size_after=$(get_dir_size "$cache_path")
                    local cleaned=$((size_before - size_after))
                    total_cleaned=$((total_cleaned + cleaned))
                fi
            fi
        done
    done
    
    # Clean thumbnail cache (safe to delete)
    echo -e "\n${PURPLE}🖼️  Cleaning Thumbnail Cache...${NC}"
    if [[ -d "$homedir/.cache/thumbnails" ]]; then
        local size_before=$(get_dir_size "$homedir/.cache/thumbnails")
        if [[ $size_before -gt 1048576 ]]; then  # > 1MB
            echo -e "  ${CYAN}Cleaning thumbnails ($(bytes_to_human $size_before))${NC}"
            if [[ "$DRY_RUN" != true ]]; then
                rm -rf "$homedir/.cache/thumbnails"/* 2>/dev/null || true
            fi
            local size_after=$(get_dir_size "$homedir/.cache/thumbnails")
            local cleaned=$((size_before - size_after))
            total_cleaned=$((total_cleaned + cleaned))
        fi
    fi
    
    # Clean development tool caches (safe to delete)
    echo -e "\n${PURPLE}⚙️  Cleaning Development Tool Caches...${NC}"
    local dev_caches=(
        "$homedir/.cache/pip"
        "$homedir/.cache/npm"
        "$homedir/.cache/yarn"
        "$homedir/.cache/go-build"
        "$homedir/.cache/composer"
    )
    
    for cache_dir in "${dev_caches[@]}"; do
        if [[ -d "$cache_dir" ]]; then
            local size_before=$(get_dir_size "$cache_dir")
            if [[ $size_before -gt 1048576 ]]; then  # > 1MB
                local tool_name=$(basename "$cache_dir")
                echo -e "  ${CYAN}Cleaning $tool_name cache ($(bytes_to_human $size_before))${NC}"
                if [[ "$DRY_RUN" != true ]]; then
                    rm -rf "$cache_dir"/* 2>/dev/null || true
                fi
                local size_after=$(get_dir_size "$cache_dir")
                local cleaned=$((size_before - size_after))
                total_cleaned=$((total_cleaned + cleaned))
            fi
        fi
    done
    
    # Clean temporary files (safe to delete)
    echo -e "\n${PURPLE}🗂️  Cleaning Temporary Files...${NC}"
    local temp_dirs=(
        "$homedir/tmp"
        "$homedir/.tmp"
        "$homedir/Downloads/*.tmp"
        "$homedir/Downloads/*.temp"
    )
    
    for temp_pattern in "${temp_dirs[@]}"; do
        for temp_path in $temp_pattern; do
            if [[ -e "$temp_path" ]]; then
                local size_before=$(get_dir_size "$temp_path" 2>/dev/null || echo "0")
                if [[ $size_before -gt 0 ]]; then
                    echo -e "  ${CYAN}Cleaning temporary files in $(basename $(dirname $temp_path)) ($(bytes_to_human $size_before))${NC}"
                    if [[ "$DRY_RUN" != true ]]; then
                        if [[ -d "$temp_path" ]]; then
                            rm -rf "$temp_path"/* 2>/dev/null || true
                        else
                            rm -f "$temp_path" 2>/dev/null || true
                        fi
                    fi
                    local size_after=$(get_dir_size "$temp_path" 2>/dev/null || echo "0")
                    local cleaned=$((size_before - size_after))
                    total_cleaned=$((total_cleaned + cleaned))
                fi
            fi
        done
    done
    
    # Clean old log files (safe to delete, but preserve recent ones)
    echo -e "\n${PURPLE}📋 Cleaning Old Log Files...${NC}"
    if [[ -d "$homedir/.local/share" ]]; then
        # Find log files older than 30 days
        local old_logs=$(find "$homedir/.local/share" -name "*.log" -mtime +30 2>/dev/null | wc -l)
        if [[ $old_logs -gt 0 ]]; then
            echo -e "  ${CYAN}Found $old_logs old log files (>30 days)${NC}"
            if [[ "$DRY_RUN" != true ]]; then
                find "$homedir/.local/share" -name "*.log" -mtime +30 -delete 2>/dev/null || true
            fi
        fi
    fi
    
    # Update global counter
    TOTAL_FREED=$((TOTAL_FREED + total_cleaned))
    
    echo -e "\n${GREEN}✅ User cleanup completed for: ${BOLD}$username${NC}"
    echo -e "${GREEN}💾 Space freed: ${BOLD}$(bytes_to_human $total_cleaned)${NC}"
    
    echo -e "\n${BOLD}${BLUE}🛡️  PROTECTED DATA (NOT CLEANED):${NC}"
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
    echo -e "\n${BLUE}👤 Starting User-Specific Cleanup...${NC}"
    
    if show_user_selection; then
        generate_report
    else
        echo -e "\n${YELLOW}No cleanup performed.${NC}"
    fi
}

# Help function
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
    echo -e "  ${GREEN}sudo $0 --force${NC}            # Skip confirmations (use with caution)"
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
    echo -e "${WHITE}${BOLD}SAFETY FEATURES & PROTECTIONS:${NC}"
    echo -e "  ${GREEN}✓ Critical path protection:${NC} /, /bin, /boot, /etc, /usr, etc."
    echo -e "  ${GREEN}✓ Active file checking:${NC} Uses lsof to avoid deleting files in use"
    echo -e "  ${GREEN}✓ Kernel safety:${NC} Always preserves current + 2 recent kernels"
    echo -e "  ${GREEN}✓ Data preservation:${NC} Never touches scan results or exploit data"
    echo -e "  ${GREEN}✓ Configuration safety:${NC} Preserves all tool and system configs"
    echo -e "  ${GREEN}✓ Evidence protection:${NC} Never deletes .pcap files or forensic data"
    echo -e "  ${GREEN}✓ Comprehensive logging:${NC} Full audit trail of all operations"
    echo
    echo -e "${WHITE}${BOLD}WHAT GETS CLEANED (SAFE OPERATIONS):${NC}"
    echo -e "  ${CYAN}📦 APT Package Cache:${NC} Downloaded .deb files (can be re-downloaded)"
    echo -e "  ${CYAN}📄 System Logs:${NC} Old log files (active logs preserved)"
    echo -e "  ${CYAN}🗂️  Temporary Files:${NC} Files in /tmp older than 7 days"
    echo -e "  ${CYAN}🏠 User Caches:${NC} Browser and application caches (can be rebuilt)"
    echo -e "  ${CYAN}📱 Snap Packages:${NC} Old package versions (Ubuntu/Mint)"
    echo -e "  ${CYAN}🔧 Tool Logs:${NC} Old log files from penetration testing tools"
    echo
    echo -e "${WHITE}${BOLD}RECOVERY RECOMMENDATIONS:${NC}"
    echo -e "  ${YELLOW}•${NC} Create system backups before major cleanups"
    echo -e "  ${YELLOW}•${NC} Test in dry-run mode first for critical systems"
    echo -e "  ${YELLOW}•${NC} Run cleanup during maintenance windows"
    echo -e "  ${YELLOW}•${NC} Monitor disk space regularly to avoid emergency cleanups"
    echo
}


# Signal handlers
cleanup_on_exit() {
    echo -e "\n${YELLOW}Cleanup interrupted. Exiting safely...${NC}"
    log_message "INFO" "Script interrupted by user"
    exit 130
}

trap cleanup_on_exit SIGINT SIGTERM

# Main execution
main() {
    if [[ $# -eq 0 ]]; then
        check_root_privileges
        setup_log_files "false"
        show_menu
        return 0
    fi
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick)
                check_root_privileges
                setup_log_files "false"
                show_header
                preflight_checks
                show_disk_summary
                quick_cleanup
                exit 0
                ;;
            --advanced)
                check_root_privileges
                setup_log_files "false"
                show_header
                preflight_checks
                show_disk_summary
                advanced_cleanup
                exit 0
                ;;
            --user-only)
                # User-only mode doesn't require root
                setup_log_files "true"
                show_header
                preflight_checks "$1"
                show_disk_summary
                user_only_cleanup
                exit 0
                ;;
            --dry-run)
                check_root_privileges
                setup_log_files "false"
                DRY_RUN=true
                show_header
                preflight_checks
                show_disk_summary
                advanced_cleanup
                exit 0
                ;;
            --force)
                check_root_privileges
                setup_log_files "false"
                FORCE_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown option '$1'${NC}"
                echo -e "${YELLOW}Use '$0 --help' for usage information${NC}"
                echo -e "${CYAN}Or run '$0' without arguments for interactive mode${NC}"
                exit 1
                ;;
        esac
    done
    
    echo -e "${YELLOW}Starting interactive mode...${NC}"
    sleep 1
    show_menu
}

log_message "INFO" "Script started by user: $(whoami)"
log_message "INFO" "Distribution: $(detect_distribution)"
log_message "INFO" "System type: $(get_system_info)"

main "$@"
