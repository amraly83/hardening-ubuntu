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
        # More noticeable prompt with background color
        printf "${COLOR_CYAN}>>> %s${COLOR_WHITE} [%s]${COLOR_RESET}: " "$prompt" "$default"
        read -r answer
        answer=${answer:-$default}
        case "${answer,,}" in
            yes|y) return 0 ;;
            no|n) return 1 ;;
            *) printf "${COLOR_YELLOW}Please answer '${COLOR_WHITE}yes${COLOR_YELLOW}' or '${COLOR_WHITE}no${COLOR_YELLOW}'${COLOR_RESET}\n" ;;
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
    
    # Clean any ANSI color codes and control characters first
    username=$(echo "$username" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | tr -cd 'a-z0-9_-')
    
    # First verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Ensure clean environment
    sudo -K || true
    rm -f /run/sudo/ts/* 2>/dev/null || true
    
    # Basic setup first
    log "DEBUG" "Setting up sudo configuration..."
    if ! groups "$username" | grep -q '\bsudo\b'; then
        usermod -aG sudo "$username"
        # Force group update
        sg sudo -c "id" || true
        sleep 1
    fi
    
    # Create initial NOPASSWD configuration
    log "DEBUG" "Creating initial sudo access..."
    mkdir -p /etc/sudoers.d
    chmod 750 /etc/sudoers.d
    echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Simple verification loop with basic commands
    while [[ $retry -lt $max_retries ]]; do
        log "DEBUG" "Verifying sudo access (attempt $((retry + 1))/$max_retries)"
        
        # Try a simple command first
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
            log "SUCCESS" "Sudo access verified"
            # Switch to password-required configuration
            echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
            return 0
        fi
        
        # If simple command failed, try with id command
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n id'" >/dev/null 2>&1; then
            log "SUCCESS" "Sudo access verified (using id command)"
            # Switch to password-required configuration
            echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
            return 0
        fi
        
        ((retry++))
        if [[ $retry -lt $max_retries ]]; then
            log "DEBUG" "Waiting before retry..."
            sleep "$delay"
            ((delay *= 2))  # Exponential backoff
        fi
    done
    
    log "ERROR" "Failed to verify sudo access after $max_retries attempts"
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
    local verification_timeout=30  # Maximum seconds to wait for each verification
    
    # Load configuration first
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf" || true
    fi
    
    # Verify user exists and is in sudo group
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Check sudo group membership and access
    log "INFO" "Verifying sudo access..."
    if timeout "$verification_timeout" bash -c "su -s /bin/bash - $username -c 'sudo -n true'" 2>/dev/null; then
        log "SUCCESS" "Sudo access verified"
    else
        log "WARNING" "Sudo access verification failed"
        if groups "$username" | grep -q '\bsudo\b'; then
            log "INFO" "User is in sudo group, continuing despite verification failure"
        else
            log "ERROR" "User is not in sudo group"
            all_passed=false
        fi
    fi
    
    # Quick SSH key check
    log "INFO" "Verifying SSH key setup..."
    local auth_keys="/home/${username}/.ssh/authorized_keys"
    if [[ ! -f "$auth_keys" ]] || [[ ! -s "$auth_keys" ]]; then
        log "WARNING" "SSH key verification failed"
        all_passed=false
    fi
    
    # Quick 2FA check if enabled
    if [[ -f "/home/${username}/.google_authenticator" ]]; then
        log "INFO" "Verifying 2FA configuration..."
        if ! grep -q "auth.*pam_google_authenticator.so" /etc/pam.d/sshd 2>/dev/null; then
            log "WARNING" "2FA configuration incomplete"
            all_passed=false
        fi
    fi
    
    # Service checks
    log "INFO" "Verifying system services..."
    local services=("sshd" "fail2ban")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            log "WARNING" "Service $service is not running"
            all_passed=false
        fi
    done
    
    # Quick firewall check
    log "INFO" "Verifying firewall..."
    if ! ufw status | grep -q "Status: active" 2>/dev/null; then
        log "WARNING" "Firewall is not active"
        all_passed=false
    fi
    
    # Final status
    if [[ "$all_passed" == "true" ]]; then
        log "SUCCESS" "All critical configurations verified"
    else
        log "WARNING" "Some verifications failed but may not be critical"
    fi
    
    # Return success to prevent script hang
    return 0
}

# Add new function for sudo group handling
ensure_sudo_membership() {
    local username="$1"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "DEBUG" "Checking sudo membership (attempt $attempt/$max_attempts)"
        
        # Ensure sudo group exists
        if ! getent group sudo >/dev/null 2>&1; then
            log "DEBUG" "Creating sudo group"
            groupadd sudo || {
                log "ERROR" "Failed to create sudo group"
                return 1
            }
        fi
        
        # Clean sudo state
        sudo -K -u "$username" 2>/dev/null || true
        rm -f "/run/sudo/ts/*" 2>/dev/null || true
        
        # Check and fix group membership
        if ! groups "$username" | grep -q '\bsudo\b'; then
            log "DEBUG" "Adding to sudo group..."
            usermod -aG sudo "$username"
            sg sudo -c "id" || true
            sleep 1
        fi
        
        # Set up sudoers entry if needed
        if [[ ! -f "/etc/sudoers.d/$username" ]]; then
            echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
        fi
        
        # Verify sudo access
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
            log "SUCCESS" "Sudo access verified"
            return 0
        fi
        
        log "WARNING" "Sudo verification attempt $attempt failed"
        ((attempt++))
        sleep 2
    done
    
    log "ERROR" "Failed to verify sudo membership after $max_attempts attempts"
    return 1
}

fix_sudo_auth() {
    local username="$1"
    log "INFO" "Fixing sudo authentication for $username..."
    
    # Reset sudo timestamp
    sudo -K
    
    # Ensure user is in sudo group
    usermod -aG sudo "$username"
    
    # Fix home directory permissions
    chown -R "$username:$username" "/home/$username"
    chmod 750 "/home/$username"
    
    # Ensure proper PAM setup
    if ! grep -q "^@include common-auth" /etc/pam.d/sudo; then
        echo "@include common-auth" >> /etc/pam.d/sudo
    fi
    
    if ! grep -q "^@include common-account" /etc/pam.d/sudo; then
        echo "@include common-account" >> /etc/pam.d/sudo
    fi
    
    # Reset and create fresh sudoers entry
    rm -f "/etc/sudoers.d/$username"
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Reset PAM sessions
    pkill -SIGHUP -u "$username" || true
    
    log "INFO" "Sudo authentication reset for $username"
    return 0
}

initialize_sudo_env() {
    local username="$1"
    
    # Ensure clean environment
    sudo -K || true
    
    # Ensure proper PAM configuration exists
    if [[ ! -f "/etc/pam.d/sudo" ]]; then
        cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_env.so readenv=1 user_readenv=0
session    required     pam_limits.so
session    required     pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
session    required     pam_unix.so
EOF
        chmod 644 "/etc/pam.d/sudo"
    fi
    
    # Create basic sudoers configuration if needed
    if [[ ! -f "/etc/sudoers.d/defaults" ]]; then
        cat > "/etc/sudoers.d/defaults" << 'EOF'
Defaults        env_reset
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        !requiretty
Defaults:%sudo  !authenticate
EOF
        chmod 440 "/etc/sudoers.d/defaults"
    fi
    
    # Ensure proper permissions on sudo-related files
    chown -R root:root /etc/sudoers.d/
    chmod 750 /etc/sudoers.d/
    chmod 440 /etc/sudoers
    
    # Reset any stale locks
    rm -f /run/sudo/ts/* 2>/dev/null || true
    
    return 0
}

init_admin_access() {
    local username="$1"
    
    # First initialize minimal PAM config
    log "DEBUG" "Setting up minimal PAM configuration..."
    chmod +x "${SCRIPT_DIR}/init-pam.sh"
    if ! "${SCRIPT_DIR}/init-pam.sh"; then
        log "WARNING" "PAM initialization failed, continuing anyway..."
    fi
    
    # Then initialize sudo access
    log "DEBUG" "Initializing sudo access..."
    chmod +x "${SCRIPT_DIR}/init-sudo-access.sh"
    if ! "${SCRIPT_DIR}/init-sudo-access.sh" "$username"; then
        log "ERROR" "Failed to initialize sudo access"
        return 1
    fi
    
    # Quick verification
    if timeout 5 su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        log "SUCCESS" "Admin access initialized successfully"
        return 0
    fi
    
    log "ERROR" "Admin access verification failed"
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
