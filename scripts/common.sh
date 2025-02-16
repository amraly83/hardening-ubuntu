#!/bin/bash

# Set strict mode
set -euo pipefail

# Basic initialization first, before any function declarations
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'

# Initialize logging variables
declare LOG_FILE=${LOG_FILE:-""}

# Setup script directory early, make it readonly immediately
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Function declarations
fix_line_endings() {
    local file="$1"
    sed -i.bak 's/\r$//' "$file" && rm -f "${file}.bak"
}

# Fix line endings in this file immediately
fix_line_endings "${BASH_SOURCE[0]}"

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
    
    message=$(echo "$message" | tr -d '\000-\037')
    
    case "${level^^}" in
        "ERROR") color="$COLOR_RED" ;;
        "WARNING") color="$COLOR_YELLOW" ;;
        "SUCCESS"|"INFO") color="$COLOR_GREEN" ;;
        "DEBUG") color="$COLOR_BLUE" ;;
    esac
    
    echo -e "${color}[${timestamp}] [${level^^}] ${message}${COLOR_RESET}" | \
        awk '{print substr($0, 1, 2000)}' >&2
    
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level^^}] ${message}" | \
            awk '{print substr($0, 1, 2000)}' >> "$LOG_FILE"
    fi
}

error_exit() {
    local message="$1"
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
    
    if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
        in_sudo=true
    fi
    
    if [[ -f "/etc/sudoers.d/$username" ]] || \
       grep -q "^$username.*ALL=" /etc/sudoers 2>/dev/null; then
        in_sudoers=true
    fi
    
    if [[ "$in_sudo" == "true" ]] || [[ "$in_sudoers" == "true" ]]; then
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
    
    username=$(echo "$username" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    log "DEBUG" "Validating username: '$username' (length: ${#username})"
    
    if [[ -z "$username" ]]; then
        log "ERROR" "Username cannot be empty"
        return 1
    fi
    
    if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
        log "ERROR" "Username must be between 3 and 32 characters long (current length: ${#username})"
        return 1
    fi
    
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        log "ERROR" "Invalid username format. Must start with a letter and contain only lowercase letters, numbers, hyphens, or underscores"
        return 1
    fi
    
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
    
    if [[ ! -f "/etc/os-release" ]]; then
        log "WARNING" "Could not detect Ubuntu version - /etc/os-release not found"
        if ! prompt_yes_no "Continue without Ubuntu version check" "no"; then
            error_exit "This script requires Ubuntu Server"
        fi
        return 0
    fi
    
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log "WARNING" "This system does not appear to be running Ubuntu"
        if ! prompt_yes_no "Continue on non-Ubuntu system" "no"; then
            error_exit "This script requires Ubuntu Server"
        fi
        return 0
    fi
    
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
    local max_retries=3
    local retry=0
    local delay=2
    
    log "INFO" "Starting sudo access verification for $username..."
    
    # Clean the username to prevent command injection
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    # First verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Ensure sudo group membership
    if ! ensure_sudo_membership "$username"; then
        log "ERROR" "Failed to ensure sudo group membership"
        return 1
    fi
    
    # Verify sudo group membership and collect debug info
    local groups_output
    groups_output=$(groups "$username" 2>&1)
    log "DEBUG" "Group membership for $username: $groups_output"
    
    if ! echo "$groups_output" | grep -qE '\b(sudo|admin|wheel)\b'; then
        log "ERROR" "User $username is not in the sudo group (groups: $groups_output)"
        return 1
    fi
    
    # Check sudo configuration
    if [[ -f "/etc/sudoers.d/$username" ]]; then
        log "DEBUG" "Found sudoers file for $username"
        local sudoers_perms
        sudoers_perms=$(stat -c "%a %U:%G" "/etc/sudoers.d/$username" 2>&1)
        log "DEBUG" "Sudoers file permissions: $sudoers_perms"
    fi
    
    # Try sudo access with retries and verbose logging
    while [[ $retry -lt $max_retries ]]; do
        log "DEBUG" "Attempting sudo verification (attempt $((retry + 1))/$max_retries)"
        
        if [[ $EUID -eq 0 ]]; then
            # Try as root using su
            if su - "$username" -c "sudo -nv" >/dev/null 2>&1; then
                log "SUCCESS" "Sudo access verified for $username"
                return 0
            else
                local sudo_error=$?
                log "DEBUG" "sudo verification failed with exit code: $sudo_error"
            fi
        else
            # Try direct sudo if we're the user
            if [[ "$USER" == "$username" ]] && sudo -nv >/dev/null 2>&1; then
                log "SUCCESS" "Sudo access verified for current user"
                return 0
            fi
        fi
        
        log "WARNING" "Sudo verification attempt $((retry + 1)) failed, waiting ${delay}s..."
        sleep $delay
        ((retry++))
        delay=$((delay * 2))
        
        # Check sudo timestamp
        if [[ -d "/var/run/sudo/$username" ]]; then
            log "DEBUG" "Found sudo timestamp directory for $username"
        fi
    done
    
    # Final attempt with more verbose error collection
    if [[ $EUID -eq 0 ]]; then
        local verbose_output
        verbose_output=$(su - "$username" -c "sudo -v" 2>&1)
        log "DEBUG" "Final sudo verification attempt output: $verbose_output"
    fi
    
    log "ERROR" "Failed to verify sudo access for $username after $max_retries attempts"
    return 1
}

verify_ssh_access() {
    local username="$1"
    if ! ssh -o PasswordAuthentication=no -o BatchMode=yes "$username@localhost" "echo 'SSH access working'" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Verification functions
test_2fa() {
    local username="$1"
    if [[ ! -f "/home/${username}/.google_authenticator" ]]; then
        log "ERROR" "2FA not configured for $username"
        return 1
    fi
    if ! grep -q "auth required pam_google_authenticator.so" /etc/pam.d/sshd; then
        log "ERROR" "PAM not configured for 2FA"
        return 1
    fi
    return 0
}

verify_hardening() {
    if ! sshd -t; then
        log "ERROR" "SSH configuration is invalid"
        return 1
    fi
    
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        return 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        log "ERROR" "fail2ban is not running"
        return 1
    fi
    
    if ! systemctl is-active --quiet auditd; then
        log "ERROR" "audit system is not running"
        return 1
    fi
    
    return 0
}

verify_all_configurations() {
    local username="$1"
    local all_passed=true
    
    if ! verify_sudo_access "$username"; then
        log "WARNING" "Sudo access verification failed"
        all_passed=false
    fi
    
    if ! check_ssh_key_setup "$username"; then
        log "WARNING" "SSH key verification failed"
        all_passed=false
    fi
    
    if [[ -f "/home/${username}/.google_authenticator" ]]; then
        if ! test_2fa "$username"; then
            log "WARNING" "2FA verification failed"
            all_passed=false
        fi
    fi
    
    if ! verify_hardening; then
        log "WARNING" "System hardening verification failed"
        all_passed=false
    fi
    
    [[ "$all_passed" == "true" ]]
}

# Add new function for sudo group handling
ensure_sudo_membership() {
    local username="$1"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "DEBUG" "Checking sudo membership (attempt $attempt/$max_attempts)"
        
        # Check current groups
        if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
            log "SUCCESS" "User $username is in sudo group"
            return 0
        fi
        
        log "WARNING" "User $username not in sudo group, attempting to add..."
        
        # Try to add to sudo group
        if usermod -aG sudo "$username"; then
            log "INFO" "Added $username to sudo group"
            
            # Force group update
            if pkill -SIGHUP -u "$username" >/dev/null 2>&1; then
                log "DEBUG" "Sent SIGHUP to user processes"
            fi
            
            # Verify group membership again
            if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b'; then
                log "SUCCESS" "Verified sudo group membership"
                return 0
            fi
        fi
        
        log "WARNING" "Sudo group modification attempt $attempt failed"
        sleep 2
        ((attempt++))
    done
    
    log "ERROR" "Failed to ensure sudo membership after $max_attempts attempts"
    return 1
}

# Script initialization
init_script() {
    # Set error handling
    set -euo pipefail
    
    # Set secure umask for file creation
    umask 0027
    
    # Check if running as root on Linux
    check_root
    
    # Initialize logging
    if [[ -n "${LOG_FILE:-}" ]]; then
        local LOG_DIR
        LOG_DIR=$(dirname "$LOG_FILE")
        if [[ ! -d "$LOG_DIR" ]]; then
            mkdir -p "$LOG_DIR"
            chmod 750 "$LOG_DIR"
        fi
        
        touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
        chmod 640 "$LOG_FILE"
    fi
}
