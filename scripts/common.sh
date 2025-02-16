#!/bin/bash

# Common functions library for hardening scripts
# Source this file in other scripts using:
# source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Logging
# Define color codes
declare -r COLOR_RED='\033[0;31m'
declare -r COLOR_GREEN='\033[0;32m'
declare -r COLOR_YELLOW='\033[1;33m'
declare -r COLOR_BLUE='\033[0;34m'
declare -r COLOR_RESET='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color=""
    
    # Validate log level
    if [[ ! "${level^^}" =~ ^(ERROR|WARNING|INFO|DEBUG|SUCCESS)$ ]]; then
        echo "[ERROR] Invalid log level: ${level}" >&2
        return 1
    fi
    
    # Clean message of any special characters
    message=$(echo "$message" | tr -d '\000-\037')
    
    # Set color based on log level
    case "${level^^}" in
        "ERROR") color="$COLOR_RED" ;;
        "WARNING") color="$COLOR_YELLOW" ;;
        "SUCCESS"|"INFO") color="$COLOR_GREEN" ;;
        "DEBUG") color="$COLOR_BLUE" ;;
    esac
    
    # Print to console with color (redirect to stderr)
    echo -e "${color}[${timestamp}] [${level^^}] ${message}${COLOR_RESET}" | \
        awk '{print substr($0, 1, 2000)}' >&2
    
    # If LOG_FILE is defined, log to file without color codes
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level^^}] ${message}" | \
            awk '{print substr($0, 1, 2000)}' >> "$LOG_FILE"
    fi
}

error_exit() {
    local message="$1"
    # Ensure message is properly escaped
    message=$(echo "$message" | sed 's/"/\\"/g')
    log "ERROR" "$message"
    exit 1
}

# User Management
check_user_exists() {
    local username="$1"
    if ! id "$username" >/dev/null 2>&1; then
        error_exit "User '$username' does not exist. Create the user first with create-admin.sh"
    fi
}

is_user_admin() {
    local username="$1"
    local in_sudo=false
    local in_sudoers=false
    
    # Check sudo/admin group membership
    if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
        in_sudo=true
    fi
    
    # Check sudoers entries
    if [[ -f "/etc/sudoers.d/$username" ]] || \
       grep -q "^$username.*ALL=" /etc/sudoers 2>/dev/null; then
        in_sudoers=true
    fi
    
    # Return true if either condition is met
    if [[ "$in_sudo" == "true" ]] || [[ "$in_sudoers" == "true" ]]; then
        # Log the admin status source for debugging
        if [[ "$in_sudo" == "true" ]]; then
            log "DEBUG" "User $username is admin via group membership"
        fi
        if [[ "$in_sudoers" == "true" ]]; then
            log "DEBUG" "User $username is admin via sudoers entry"
        fi
        return 0
    fi
    
    return 1
}

validate_username() {
    local username="$1"
    
    # Trim whitespace
    username=$(echo "$username" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Debug logging
    log "DEBUG" "Validating username: '$username' (length: ${#username})"
    
    # Check if username is empty after trimming
    if [[ -z "$username" ]]; then
        log "ERROR" "Username cannot be empty"
        return 1
    fi
    
    # Check username length after trimming (3-32 chars)
    if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
        log "ERROR" "Username must be between 3 and 32 characters long (current length: ${#username})"
        return 1
    fi
    
    # Check username format (starts with lowercase letter, followed by lowercase letters, numbers, or underscores)
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        log "ERROR" "Invalid username format. Must start with a letter and contain only lowercase letters, numbers, hyphens, or underscores"
        return 1
    fi
    
    # Log successful validation
    log "DEBUG" "Username '$username' passed validation"
    return 0
}

# File Operations
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
        cp -p "$file" "$backup" || error_exit "Failed to backup $file"
        chmod --reference="$file" "$backup" 2>/dev/null || chmod 600 "$backup"
        log "INFO" "Backed up $file to $backup"
    fi
}

check_ssh_key_setup() {
    local username="$1"
    local auth_keys="/home/${username}/.ssh/authorized_keys"
    
    if [[ ! -f "$auth_keys" ]] || [[ ! -s "$auth_keys" ]]; then
        error_exit "SSH keys not set up for user '$username'. Please run setup-ssh-key.sh first"
    fi
}

validate_ssh_key() {
    local key="$1"
    if ! ssh-keygen -l -f <(echo "$key") >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# System Checks
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

check_ubuntu_version() {
    log "INFO" "Checking Ubuntu version..."
    
    # First check if /etc/os-release exists
    if [[ ! -f "/etc/os-release" ]]; then
        log "WARNING" "Could not detect Ubuntu version - /etc/os-release not found"
        if ! prompt_yes_no "Continue without Ubuntu version check" "no"; then
            error_exit "This script requires Ubuntu Server"
        fi
        return 0
    }
    
    # Check if it's Ubuntu
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log "WARNING" "This system does not appear to be running Ubuntu"
        if ! prompt_yes_no "Continue on non-Ubuntu system" "no"; then
            error_exit "This script requires Ubuntu Server"
        fi
        return 0
    fi
    
    # Try to get version
    if ! command -v lsb_release >/dev/null 2>&1; then
        log "WARNING" "lsb_release not found, skipping version check"
        return 0
    fi
    
    local version
    if ! version=$(lsb_release -rs 2>/dev/null); then
        log "WARNING" "Could not determine Ubuntu version"
        return 0
    fi
    
    if command -v bc >/dev/null 2>&1; then
        if [ "$(echo "$version < 20.04" | bc 2>/dev/null)" -eq 1 ]; then
            log "WARNING" "Ubuntu version $version is older than recommended 20.04"
            if ! prompt_yes_no "Continue with older Ubuntu version" "no"; then
                error_exit "This script requires Ubuntu 20.04 or later"
            fi
        fi
    else
        log "WARNING" "bc command not found, skipping version comparison"
    fi
}

# Interactive Input
prompt_yes_no() {
    local prompt="$1"
    local default="${2:-yes}"
    local answer
    
    while true; do
        read -rp "$prompt [${default}]: " answer
        answer=${answer:-$default}
        case "${answer,,}" in
            yes|y) return 0 ;;
            no|n) return 1 ;;
            *) echo "Please answer 'yes' or 'no'" ;;
        esac
    done
}

# Verification
verify_sudo_access() {
    local username="$1"
    local max_retries=2
    local retry=0
    local delay=1
    
    log "INFO" "Starting sudo access verification for $username..."
    
    # First check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        # Check sudo group membership
        if ! groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
            log "ERROR" "User $username is not in the sudo group"
            return 1
        fi
        
        # Test sudo access directly
        if ! su - "$username" -c "sudo -n true" 2>/dev/null; then
            log "ERROR" "Failed to verify sudo access for $username"
            return 1
        fi
        
        log "SUCCESS" "Sudo access verified for $username"
        return 0
    else
        # If not root, try sudo directly
        if sudo -n true 2>/dev/null; then
            log "SUCCESS" "Sudo access verified for current user"
            return 0
        fi
        
        log "ERROR" "Cannot verify sudo access without root privileges"
        return 1
    fi
}

verify_ssh_access() {
    local username="$1"
    if ! ssh -o PasswordAuthentication=no -o BatchMode=yes "$username@localhost" "echo 'SSH access working'" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Script initialization
init_script() {
    # Set error handling
    set -euo pipefail
    
    # Set script directory
    readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    
    # Set secure umask for file creation
    umask 0027
    
    # Check if running as root on Linux
    check_root
    
    # Initialize logging
    if [[ -n "${LOG_FILE:-}" ]]; then
        # Ensure log directory exists with proper permissions
        LOG_DIR=$(dirname "$LOG_FILE")
        if [[ ! -d "$LOG_DIR" ]]; then
            mkdir -p "$LOG_DIR"
            chmod 750 "$LOG_DIR"
        fi
        
        touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
        chmod 640 "$LOG_FILE"
    fi
}
