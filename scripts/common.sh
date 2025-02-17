#!/bin/bash

# Set strict mode
set -euo pipefail

# Color definitions with bright variants for better visibility
readonly COLOR_RED='\033[1;31m'      # Bright Red for errors
readonly COLOR_GREEN='\033[1;32m'     # Bright Green for success
readonly COLOR_YELLOW='\033[1;33m'    # Bright Yellow for warnings
readonly COLOR_BLUE='\033[1;34m'      # Bright Blue for info
readonly COLOR_MAGENTA='\033[1;35m'   # Bright Magenta for important notes
readonly COLOR_CYAN='\033[1;36m'      # Bright Cyan for prompts
readonly COLOR_WHITE='\033[1;37m'     # Bright White for highlights
readonly COLOR_RESET='\033[0m'

# Initialize logging variables
declare LOG_FILE=${LOG_FILE:-""}

# Setup script directory early, make it readonly immediately
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Enhanced logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color=""
    
    if [[ ! "${level^^}" =~ ^(ERROR|WARNING|INFO|DEBUG|SUCCESS)$ ]]; then
        echo "[ERROR] Invalid log level: ${level}" >&2
        return 1
    fi
    
    # Sanitize message - remove control characters and limit length
    message=$(echo "$message" | tr -d '\000-\037' | cut -c1-2000)
    
    case "${level^^}" in
        "ERROR") color="$COLOR_RED" ;;
        "WARNING") color="$COLOR_YELLOW" ;;
        "SUCCESS") color="$COLOR_GREEN" ;;
        "INFO") color="$COLOR_BLUE" ;;
        "DEBUG") color="$COLOR_MAGENTA" ;;
    esac
    
    # Print to stderr for immediate visibility
    echo -e "${color}[${timestamp}] [${level^^}] ${message}${COLOR_RESET}" >&2
    
    # Log to file if configured
    if [[ -n "${LOG_FILE:-}" ]]; then
        # Ensure log directory exists with proper permissions
        if [[ ! -f "$LOG_FILE" ]]; then
            local log_dir
            log_dir=$(dirname "$LOG_FILE")
            mkdir -p "$log_dir"
            chmod 750 "$log_dir"
            touch "$LOG_FILE"
            chmod 640 "$LOG_FILE"
        fi
        echo "[${timestamp}] [${level^^}] ${message}" >> "$LOG_FILE"
    fi
}

error_exit() {
    local message="$1"
    message=$(echo "$message" | tr -d '\000-\037' | sed 's/"/\\"/g')
    log "ERROR" "$message"
    exit 1
}

# User Management with improved validation
check_user_exists() {
    local username="$1"
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        error_exit "Invalid username format: $username"
    fi
    
    if ! id "$username" >/dev/null 2>&1; then
        error_exit "User '$username' does not exist"
    fi
}

is_user_admin() {
    local username="$1"
    local in_sudo=false
    local in_sudoers=false
    
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    if ! check_user_exists "$username"; then
        return 1
    fi
    
    if groups "$username" 2>/dev/null | grep -qE '\bsudo\b'; then
        in_sudo=true
    fi
    
    if [[ -f "/etc/sudoers.d/$username" ]] || \
       grep -q "^$username.*ALL=" /etc/sudoers 2>/dev/null; then
        in_sudoers=true
    fi
    
    [[ "$in_sudo" == "true" || "$in_sudoers" == "true" ]]
}

validate_username() {
    local username="$1"
    
    # Trim whitespace and sanitize
    username=$(echo "$username" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -cd 'a-z0-9_-')
    
    [[ -n "$username" && ${#username} -ge 3 && ${#username} -le 32 && "$username" =~ ^[a-z][a-z0-9_-]*$ ]]
}

# File Operations with improved error handling
backup_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log "WARNING" "File $file does not exist, skipping backup"
        return 0
    fi
    
    local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
    if ! cp -p "$file" "$backup"; then
        error_exit "Failed to backup $file"
    fi
    
    # Preserve original permissions or set secure defaults
    if ! chmod --reference="$file" "$backup" 2>/dev/null; then
        chmod 600 "$backup"
    fi
    
    log "INFO" "Backed up $file to $backup"
}

check_ssh_key_setup() {
    local username="$1"
    local auth_keys="/home/${username}/.ssh/authorized_keys"
    
    if [[ ! -f "$auth_keys" ]] || [[ ! -s "$auth_keys" ]]; then
        error_exit "SSH keys not set up for user '$username'"
    fi
    
    # Check permissions
    local dir_perms
    local file_perms
    dir_perms=$(stat -c "%a" "/home/${username}/.ssh" 2>/dev/null)
    file_perms=$(stat -c "%a" "$auth_keys" 2>/dev/null)
    
    if [[ "$dir_perms" != "700" || "$file_perms" != "600" ]]; then
        error_exit "Incorrect SSH directory or key file permissions"
    fi
}

validate_ssh_key() {
    local key="$1"
    local key_file
    key_file=$(mktemp)
    echo "$key" > "$key_file"
    
    local result=0
    if ! ssh-keygen -l -f "$key_file" >/dev/null 2>&1; then
        result=1
    fi
    
    rm -f "$key_file"
    return $result
}

# System Checks with timeouts
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

check_ubuntu_version() {
    if [[ ! -f "/etc/os-release" ]]; then
        error_exit "Cannot determine system version - /etc/os-release not found"
    fi
    
    if ! grep -q "Ubuntu" /etc/os-release; then
        error_exit "This script requires Ubuntu Server"
    fi
    
    if command -v lsb_release >/dev/null 2>&1; then
        local version
        version=$(lsb_release -rs)
        if [[ -n "$version" ]] && command -v bc >/dev/null 2>&1; then
            if (( $(echo "$version < 20.04" | bc -l) )); then
                error_exit "This script requires Ubuntu 20.04 or later"
            fi
        fi
    fi
}

# Interactive Input with timeout
prompt_yes_no() {
    local prompt="$1"
    local default="${2:-yes}"
    local timeout="${3:-60}"
    local answer
    
    # Use read with timeout
    echo -e "${COLOR_CYAN}>>> ${prompt}${COLOR_WHITE} [${default}] (${timeout}s timeout)${COLOR_RESET}: "
    if ! read -t "$timeout" -r answer; then
        echo
        log "WARNING" "Prompt timed out, using default: $default"
        [[ "${default,,}" == "yes" ]]
        return
    fi
    
    answer=${answer:-$default}
    case "${answer,,}" in
        yes|y) return 0 ;;
        no|n) return 1 ;;
        *) log "WARNING" "Invalid response, using default: $default"
           [[ "${default,,}" == "yes" ]] ;;
    esac
}

# Script initialization
init_script() {
    # Set error handling
    set -euo pipefail
    
    # Set secure umask
    umask 0027
    
    # Verify root access
    check_root
    
    # Check Ubuntu version
    check_ubuntu_version
    
    # Initialize logging
    if [[ -n "${LOG_FILE:-}" ]]; then
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        mkdir -p "$log_dir"
        chmod 750 "$log_dir"
        touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
        chmod 640 "$LOG_FILE"
    fi
    
    # Set up trap for cleanup
    trap 'log "ERROR" "Script terminated unexpectedly"; exit 1' ERR
    trap 'log "INFO" "Script interrupted by user"; exit 130' INT TERM
}

# Export commonly used functions
export -f log error_exit check_user_exists is_user_admin validate_username
