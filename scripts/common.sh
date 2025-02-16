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
    
    # Print to console with color
    echo -e "${color}[${timestamp}] [${level^^}] ${message}${COLOR_RESET}" | \
        awk '{print substr($0, 1, 2000)}'  # Limit line length
    
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
    if ! grep -q "Ubuntu" /etc/os-release; then
        error_exit "This script requires Ubuntu Server"
    fi
    
    local version
    version=$(lsb_release -rs)
    if [ "$(echo "$version < 20.04" | bc)" -eq 1 ]; then
        error_exit "This script requires Ubuntu 20.04 or later"
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
    log "SUCCESS" "User existence verified"
    
    # Check if user is in sudo group first
    if ! groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
        log "WARNING" "User $username is not in the sudo group"
        return 1
    fi
    log "SUCCESS" "User sudo group membership verified"
    
    # Try to refresh group membership
    log "INFO" "Attempting to refresh group membership..."
    if ! newgrp sudo >/dev/null 2>&1; then
        log "DEBUG" "Failed to refresh group membership, continuing anyway"
    fi
    
    log "INFO" "Testing sudo access with timeout..."
    while [[ $retry -lt $max_retries ]]; do
        log "INFO" "Sudo verification attempt $((retry + 1))/$max_retries"
        # Try sudo access with shorter timeout and capture error
        if su - "$username" -c "sudo -nv" 2>/dev/null; then
            log "SUCCESS" "Sudo access verified successfully for $username"
            return 0
        fi
        
        local exit_code=$?
        log "WARNING" "Sudo verification attempt $((retry + 1)) failed (exit code: $exit_code)"
        
        if [[ $retry -lt $((max_retries - 1)) ]]; then
            log "INFO" "Waiting ${delay}s before next attempt..."
            sleep $delay
            ((retry++))
            ((delay *= 2))
        else
            break
        fi
    done
    
    log "ERROR" "All sudo verification attempts failed for $username"
    log "INFO" "Please ensure user has proper sudo privileges and try again"
    return 1
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
    # Set up error handling
    set -euo pipefail
    
    # Set script directory
    readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check if running as root
    check_root
    
    # Initialize logging if LOG_FILE is defined
    if [[ -n "${LOG_FILE:-}" ]]; then
        touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}
