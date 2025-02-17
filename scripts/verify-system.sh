#!/bin/bash
# Comprehensive system verification script
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/common.sh"

# Source common functions
if [[ -f "$COMMON_SH" ]]; then
    source "$COMMON_SH"
else
    echo "Error: common.sh not found in $SCRIPT_DIR" >&2
    exit 1
fi

# Initialize variables with defaults
LOG_FILE="${LOG_FILE:-/var/log/server-hardening.log}"
CONFIG_FILE="${CONFIG_FILE:-/etc/server-hardening/hardening.conf}"

# Define enhanced color codes for better visibility
readonly COLOR_ERROR='\033[1;31m'      # Bright Red for errors
readonly COLOR_WARNING='\033[1;33m'    # Bright Yellow for warnings
readonly COLOR_INFO='\033[1;34m'       # Bright Blue for info
readonly COLOR_SUCCESS='\033[1;32m'    # Bright Green for success
readonly COLOR_PROMPT='\033[1;36m'     # Bright Cyan for prompts
readonly COLOR_HIGHLIGHT='\033[1;37m'  # Bright White for highlights
readonly COLOR_RESET='\033[0m'

# Check if required commands exist
check_requirements() {
    local missing_cmds=()
    local required_cmds=("ssh" "sshd" "ufw" "fail2ban-client" "systemctl" "stat" "grep" "id")
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if ((${#missing_cmds[@]} > 0)); then
        log "ERROR" "Missing required commands: ${missing_cmds[*]}"
        return 1
    fi
    return 0
}

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

# Load configuration with validation
load_config() {
    local config_loaded=false
    
    if [[ -f "$CONFIG_FILE" ]]; then
        if ! source "$CONFIG_FILE"; then
            log "ERROR" "Failed to load configuration from $CONFIG_FILE"
            return 1
        fi
        config_loaded=true
    fi
    
    # Set defaults if not defined or validate existing values
    SSH_PORT=${SSH_PORT:-22}
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || ((SSH_PORT < 1 || SSH_PORT > 65535)); then
        log "ERROR" "Invalid SSH_PORT value: $SSH_PORT"
        return 1
    fi
    
    SSH_ALLOW_USERS=${SSH_ALLOW_USERS:-}
    MFA_ENABLED=${MFA_ENABLED:-yes}
    if [[ "${MFA_ENABLED,,}" != "yes" && "${MFA_ENABLED,,}" != "no" ]]; then
        log "ERROR" "Invalid MFA_ENABLED value: $MFA_ENABLED (must be 'yes' or 'no')"
        return 1
    fi
    
    return 0
}

# Verify a specific user with improved error handling
verify_user() {
    local username="$1"
    local status=0
    
    # Clean and validate username first
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
    if ! groups "$username" 2>/dev/null | grep -q '\bsudo\b'; then
        log "ERROR" "User is not in sudo group"
        status=1
    fi
    
    # Check SSH directory and keys with proper error handling
    local ssh_dir="/home/${username}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"
    
    if [[ ! -d "$ssh_dir" ]]; then
        log "ERROR" "SSH directory does not exist: $ssh_dir"
        status=1
    elif [[ "$(stat -c "%a" "$ssh_dir" 2>/dev/null)" != "700" ]]; then
        log "ERROR" "Incorrect SSH directory permissions"
        status=1
    fi
    
    if [[ ! -f "$auth_keys" ]]; then
        log "ERROR" "Authorized keys file does not exist: $auth_keys"
        status=1
    elif [[ "$(stat -c "%a" "$auth_keys" 2>/dev/null)" != "600" ]]; then
        log "ERROR" "Incorrect authorized_keys file permissions"
        status=1
    fi
    
    # Check 2FA if enabled
    if [[ "${MFA_ENABLED,,}" == "yes" ]]; then
        if [[ ! -f "/home/${username}/.google_authenticator" ]]; then
            log "ERROR" "2FA not configured for user"
            status=1
        elif ! grep -q "^auth.*pam_google_authenticator.so" /etc/pam.d/sshd 2>/dev/null; then
            log "ERROR" "2FA PAM configuration incomplete"
            status=1
        fi
    fi
    
    return $status
}

# Verify system services with timeout
verify_services() {
    local status=0
    local timeout_duration=5
    
    # Check SSH configuration
    log "INFO" "Verifying SSH configuration..."
    if ! timeout "$timeout_duration" sshd -t >/dev/null 2>&1; then
        log "ERROR" "Invalid SSH configuration"
        status=1
    fi
    
    # Check essential services
    local services=("sshd" "fail2ban")
    for service in "${services[@]}"; do
        if ! command -v systemctl >/dev/null 2>&1; then
            log "ERROR" "systemctl not available"
            return 1
        fi
        
        log "INFO" "Checking $service status..."
        if ! timeout "$timeout_duration" systemctl is-active --quiet "$service"; then
            log "ERROR" "$service is not running"
            status=1
        fi
    done
    
    # Check firewall
    if command -v ufw >/dev/null 2>&1; then
        log "INFO" "Checking firewall status..."
        if ! timeout "$timeout_duration" ufw status | grep -q "Status: active"; then
            log "ERROR" "Firewall is not active"
            status=1
        fi
    else
        log "ERROR" "UFW firewall not installed"
        status=1
    fi
    
    return $status
}

# Main verification function
verify_system() {
    local username="$1"
    local success=true
    
    # Check requirements first
    if ! check_requirements; then
        log "ERROR" "System requirements not met"
        return 1
    fi
    
    # Load and validate configuration
    if ! load_config; then
        log "ERROR" "Configuration validation failed"
        return 1
    fi
    
    # Core checks
    log "INFO" "Starting system verification..."
    
    if ! verify_services; then
        log "ERROR" "Service verification failed"
        success=false
    fi
    
    if ! verify_user "$username"; then
        log "ERROR" "User verification failed"
        success=false
    fi
    
    if [ "$success" = true ]; then
        log "SUCCESS" "All system verifications passed"
        return 0
    else
        log "ERROR" "System verification failed"
        return 1
    fi
}

# Main execution
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 username" >&2
        exit 1
    fi
    
    # Ensure script is run as root
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
    
    verify_system "$1"
}

main "$@"