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
    
    # Ensure sudo group membership first
    if ! ensure_sudo_membership "$username"; then
        log "ERROR" "Failed to ensure sudo group membership"
        return 1
    fi
    
    # Initialize sudo for first use - this is important!
    if [[ $EUID -eq 0 ]]; then
        log "DEBUG" "Initializing sudo access for $username"
        # Create sudoers.d file if it doesn't exist
        if [[ ! -f "/etc/sudoers.d/$username" ]]; then
            echo "$username ALL=(ALL) ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
            log "DEBUG" "Created sudoers entry for $username"
        fi
        
        # Reset sudo timestamp and touch it to initialize
        log "DEBUG" "Resetting and initializing sudo timestamp"
        sudo -K -u "$username" 2>/dev/null || true
        if ! su - "$username" -c "sudo -v" >/dev/null 2>&1; then
            log "DEBUG" "Initial sudo validation failed, retrying with timestamp reset"
        fi
    fi
    
    # Function to test sudo access with debugging
    test_sudo_access() {
        local test_user="$1"
        local test_cmd="$2"
        local debug_output
        
        log "DEBUG" "Testing sudo access with command: $test_cmd"
        if debug_output=$(su - "$test_user" -c "$test_cmd" 2>&1); then
            log "DEBUG" "Sudo test successful"
            return 0
        else
            log "DEBUG" "Sudo test failed with output: $debug_output"
            return 1
        fi
    }
    
    # Try different sudo test commands with full error reporting
    local sudo_tests=(
        "sudo -nv"              # Non-interactive validate
        "sudo -n true"          # Non-interactive simple command
        "sudo -n id"            # Non-interactive id command
        "sudo -n /bin/true"     # Non-interactive full path command
    )
    
    # Try each test with retries
    for test_cmd in "${sudo_tests[@]}"; do
        retry=0
        while [[ $retry -lt $max_retries ]]; do
            log "DEBUG" "Attempting sudo verification with '$test_cmd' (attempt $((retry + 1))/$max_retries)"
            
            if test_sudo_access "$username" "$test_cmd"; then
                log "SUCCESS" "Sudo access verified for $username using: $test_cmd"
                return 0
            fi
            
            # After first failure, try to fix common issues
            if [[ $retry -eq 0 ]]; then
                log "DEBUG" "First attempt failed, trying fixes..."
                
                # Refresh group membership
                log "DEBUG" "Refreshing group membership"
                pkill -SIGHUP -u "$username" >/dev/null 2>&1 || true
                sleep 1
                
                # Fix permissions
                if [[ $EUID -eq 0 ]]; then
                    log "DEBUG" "Fixing home directory permissions"
                    chown -R "$username:$username" "/home/$username" 2>/dev/null || true
                    chmod 750 "/home/$username" 2>/dev/null || true
                    
                    # Verify sudoers entry
                    log "DEBUG" "Verifying sudoers configuration"
                    if [[ -f "/etc/sudoers.d/$username" ]]; then
                        chmod 440 "/etc/sudoers.d/$username"
                    fi
                fi
            fi
            
            log "DEBUG" "Sudo test failed, waiting ${delay}s before retry..."
            sleep $delay
            ((retry++))
            delay=$((delay * 2))
        done
    done
    
    # If all tests failed, try to collect diagnostic information
    log "DEBUG" "Collecting sudo diagnostic information..."
    
    if [[ $EUID -eq 0 ]]; then
        # Check sudoers configuration
        local sudoers_output
        sudoers_output=$(grep -r "$username" /etc/sudoers.d/ 2>/dev/null || true)
        log "DEBUG" "Sudoers entries: ${sudoers_output:-none found}"
        
        # Check group membership
        local groups_output
        groups_output=$(groups "$username" 2>&1)
        log "DEBUG" "Group membership: $groups_output"
        
        # Check sudo configuration
        if visudo -c >/dev/null 2>&1; then
            log "DEBUG" "Sudoers syntax is valid"
        else
            log "ERROR" "Sudoers syntax check failed"
        fi
        
        # Try one last time with standard sudo after all fixes
        if su - "$username" -c "sudo -v" >/dev/null 2>&1; then
            log "SUCCESS" "Sudo access verified after fixes"
            return 0
        fi
    fi
    
    log "ERROR" "Failed to verify sudo access for $username after exhausting all options"
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
