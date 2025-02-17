#!/bin/bash
# Comprehensive system verification script
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

verify_system() {
    local username="$1"
    local success=true
    
    # Core Service Checks
    echo "=== Verifying Core Services ==="
    services=("sshd" "fail2ban" "ufw" "unattended-upgrades")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log "ERROR" "Service $service is not running"
            success=false
        fi
    done

    # SSH Configuration
    echo "=== Verifying SSH Configuration ==="
    if ! sshd -t; then
        log "ERROR" "SSH configuration is invalid"
        success=false
    fi

    # Firewall Status
    echo "=== Verifying Firewall Rules ==="
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        success=false
    fi

    # File Permissions
    echo "=== Verifying Critical File Permissions ==="
    files_to_check=(
        "/etc/ssh/sshd_config:600"
        "/etc/sudoers:440"
        "/etc/sudoers.d:750"
    )
    for entry in "${files_to_check[@]}"; do
        file="${entry%:*}"
        perm="${entry#*:}"
        if ! check_file_permissions "$file" "$perm"; then
            log "ERROR" "Incorrect permissions on $file"
            success=false
        fi
    done

    # Network Security
    echo "=== Verifying Network Security ==="
    if ! check_network_security; then
        log "ERROR" "Network security checks failed"
        success=false
    fi

    # User Security
    echo "=== Verifying User Security ==="
    if ! verify_user_security "$username"; then
        log "ERROR" "User security checks failed"
        success=false
    fi

    # Automatic Updates
    echo "=== Verifying Automatic Updates ==="
    if ! check_automatic_updates; then
        log "WARNING" "Automatic updates may not be properly configured"
    fi

    # Service Configurations
    echo "=== Verifying Service Configurations ==="
    if ! verify_service_configs; then
        log "ERROR" "Service configuration validation failed"
        success=false
    fi

    # Return Results
    if [ "$success" = true ]; then
        log "SUCCESS" "All system verifications passed"
        return 0
    else
        log "ERROR" "Some system verifications failed"
        return 1
    fi
}

check_file_permissions() {
    local file="$1"
    local expected_perm="$2"
    local actual_perm

    if [[ ! -e "$file" ]]; then
        return 1
    fi

    actual_perm=$(stat -c "%a" "$file")
    [[ "$actual_perm" == "$expected_perm" ]]
}

check_network_security() {
    # Check common network security settings
    local sysctl_params=(
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.tcp_syncookies=1"
    )

    for param in "${sysctl_params[@]}"; do
        key="${param%=*}"
        expected="${param#*=}"
        actual=$(sysctl -n "$key" 2>/dev/null || echo "NOT_FOUND")
        
        if [[ "$actual" != "$expected" ]]; then
            return 1
        fi
    done

    return 0
}

verify_user_security() {
    local username="$1"
    
    # Check user exists and is in sudo group
    if ! id "$username" >/dev/null 2>&1 || ! groups "$username" | grep -q "\bsudo\b"; then
        return 1
    fi

    # Check SSH directory permissions
    local ssh_dir="/home/$username/.ssh"
    if [[ -d "$ssh_dir" ]]; then
        if [[ "$(stat -c "%a" "$ssh_dir")" != "700" ]]; then
            return 1
        fi
    fi

    return 0
}

check_automatic_updates() {
    # Check if unattended-upgrades is installed and configured
    if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
        return 1
    fi

    # Verify configuration exists
    if [[ ! -f "/etc/apt/apt.conf.d/50unattended-upgrades" ]]; then
        return 1
    fi

    return 0
}

verify_service_configs() {
    # Check fail2ban configuration
    if ! fail2ban-client ping >/dev/null 2>&1; then
        return 1
    fi

    # Check SSH Protocol version
    if ! grep -q "^Protocol 2" /etc/ssh/sshd_config; then
        return 1
    fi

    return 0
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 username"
    exit 1
fi

verify_system "$1"