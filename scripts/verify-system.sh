#!/bin/bash
# Standalone verification script for system hardening
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory and fix common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/common.sh"

# Fix and source common functions
if [[ -f "$COMMON_SH" ]]; then
    sed -i 's/\r$//' "$COMMON_SH"
    source "$COMMON_SH"
else
    echo "Error: common.sh not found in $SCRIPT_DIR" >&2
    exit 1
fi

# Initialize variables
LOG_FILE="/var/log/server-hardening.log"
CONFIG_FILE="/etc/server-hardening/hardening.conf"

# Define enhanced color codes for better visibility
readonly COLOR_ERROR='\033[1;31m'      # Bright Red for errors
readonly COLOR_WARNING='\033[1;33m'    # Bright Yellow for warnings
readonly COLOR_INFO='\033[1;34m'       # Bright Blue for info
readonly COLOR_SUCCESS='\033[1;32m'    # Bright Green for success
readonly COLOR_PROMPT='\033[1;36m'     # Bright Cyan for prompts
readonly COLOR_HIGHLIGHT='\033[1;37m'  # Bright White for highlights
readonly COLOR_RESET='\033[0m'

# Basic logging function with enhanced colors
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    local color=""
    timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    case "${level^^}" in
        "ERROR") 
            color="$COLOR_ERROR"
            message="❌ $message"
            ;;
        "WARNING") 
            color="$COLOR_WARNING"
            message="⚠️  $message"
            ;;
        "INFO") 
            color="$COLOR_INFO"
            message="ℹ️  $message"
            ;;
        "SUCCESS") 
            color="$COLOR_SUCCESS"
            message="✅ $message"
            ;;
        "DEBUG") 
            color="$COLOR_INFO"
            message="🔍 $message"
            ;;
    esac
    
    echo -e "${color}[$timestamp] [${level^^}] ${message}${COLOR_RESET}" >&2
    if [[ -n "${LOG_FILE:-}" ]]; then
        # Strip color codes and emoji for log file
        echo "[$timestamp] [${level^^}] ${message}" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' >> "$LOG_FILE"
    fi
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
    
    # Set defaults if not defined
    SSH_PORT=${SSH_PORT:-22}
    SSH_ALLOW_USERS=${SSH_ALLOW_USERS:-}
    MFA_ENABLED=${MFA_ENABLED:-yes}
}

# Verify a specific user
verify_user() {
    local username="$1"
    local status=0
    
    # Clean and validate username first
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        log "ERROR" "Invalid username format: $username"
        return 1
    fi
    
    # Check user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Check sudo group membership
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "ERROR" "User is not in sudo group"
        status=1
    fi
    
    # Check sudoers entry
    if [[ ! -f "/etc/sudoers.d/$username" ]]; then
        log "ERROR" "No sudoers configuration found for user"
        status=1
    else
        # Verify sudoers file permissions
        local perms=$(stat -c "%a" "/etc/sudoers.d/$username" 2>/dev/null || echo "000")
        if [[ "$perms" != "440" ]]; then
            log "ERROR" "Incorrect permissions on sudoers file: $perms (should be 440)"
            status=1
        fi
    fi
    
    # Verify sudo access
    if ! timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
        log "ERROR" "Failed to verify sudo access"
        status=1
    else
        log "SUCCESS" "Sudo access verified"
    fi
    
    # Check SSH keys
    log "INFO" "Checking SSH keys..."
    if [[ ! -f "/home/${username}/.ssh/authorized_keys" ]] || \
       [[ ! -s "/home/${username}/.ssh/authorized_keys" ]]; then
        log "ERROR" "SSH keys not properly configured"
        status=1
    else
        log "SUCCESS" "SSH keys verified"
    fi
    
    # Check 2FA if enabled
    if [[ "${MFA_ENABLED,,}" == "yes" ]]; then
        log "INFO" "Checking 2FA configuration..."
        if [[ ! -f "/home/${username}/.google_authenticator" ]]; then
            log "WARNING" "2FA not configured"
            status=1
        elif ! grep -q "auth.*pam_google_authenticator.so" /etc/pam.d/sshd 2>/dev/null; then
            log "WARNING" "2FA PAM configuration incomplete"
            status=1
        else
            log "SUCCESS" "2FA configuration verified"
        fi
    fi
    
    return $status
}

# Verify system services
verify_services() {
    local status=0
    
    # Check SSH configuration
    log "INFO" "Verifying SSH configuration..."
    if ! sshd -t >/dev/null 2>&1; then
        log "ERROR" "Invalid SSH configuration"
        status=1
    else
        log "SUCCESS" "SSH configuration verified"
    fi
    
    # Check essential services
    for service in sshd fail2ban; do
        log "INFO" "Checking $service status..."
        if ! systemctl is-active --quiet "$service"; then
            log "ERROR" "$service is not running"
            status=1
        else
            log "SUCCESS" "$service is running"
        fi
    done
    
    # Check firewall
    log "INFO" "Checking firewall status..."
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        status=1
    else
        log "SUCCESS" "Firewall is active"
    fi
    
    return $status
}

# Main verification function
main() {
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 username"
        exit 1
    fi
    
    local username="$1"
    local all_passed=0
    
    echo -e "\n${COLOR_HIGHLIGHT}=== System Verification Starting ===${COLOR_RESET}\n"
    log "INFO" "Starting system verification..."
    
    # Load configuration
    load_config
    
    # Clean username and verify
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    echo -e "\n${COLOR_PROMPT}>>> Verifying user: ${COLOR_HIGHLIGHT}$username${COLOR_RESET}\n"
    verify_user "$username" || all_passed=1
    
    echo -e "\n${COLOR_PROMPT}>>> Verifying system services${COLOR_RESET}\n"
    verify_services || all_passed=1
    
    # Final status
    echo
    if [[ $all_passed -eq 0 ]]; then
        echo -e "${COLOR_SUCCESS}✅ All verifications passed${COLOR_RESET}"
        echo -e "${COLOR_SUCCESS}✅ System verification completed successfully${COLOR_RESET}"
    else
        echo -e "${COLOR_WARNING}⚠️  Some verifications failed${COLOR_RESET}"
        echo -e "${COLOR_WARNING}⚠️  System verification completed with warnings${COLOR_RESET}"
    fi
    echo
    
    return $all_passed
}

# Check arguments
if [[ $# -ne 1 ]]; then
    echo -e "${COLOR_ERROR}Usage: $0 username${COLOR_RESET}"
    exit 1
fi

# Run main function
main "$1"