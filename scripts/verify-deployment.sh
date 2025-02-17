#!/bin/bash
# Deployment verification script
set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

verify_deployment() {
    local success=true
    local username="$1"
    local config_file="/etc/server-hardening/hardening.conf"
    
    # Load configuration
    if [[ -f "$config_file" ]]; then
        source "$config_file"
    else
        log "ERROR" "Configuration file not found"
        return 1
    fi
    
    # Security Service Checks
    echo "=== Verifying Security Services ==="
    services_check || success=false
    
    # SSH Hardening Checks
    echo "=== Verifying SSH Configuration ==="
    ssh_check || success=false
    
    # Firewall Configuration
    echo "=== Verifying Firewall Rules ==="
    firewall_check || success=false
    
    # PAM and 2FA Configuration
    echo "=== Verifying PAM and 2FA ==="
    pam_check || success=false
    
    # System Security Settings
    echo "=== Verifying System Security ==="
    system_security_check || success=false
    
    # Package Security
    echo "=== Verifying Package Security ==="
    package_security_check || success=false
    
    # User Security
    echo "=== Verifying User Security ==="
    user_security_check "$username" || success=false
    
    # Network Security
    echo "=== Verifying Network Security ==="
    network_security_check || success=false
    
    if [[ "$success" == "true" ]]; then
        log "SUCCESS" "Deployment verification completed successfully"
        return 0
    else
        log "ERROR" "Deployment verification failed"
        return 1
    fi
}

services_check() {
    local required_services=(
        "sshd:SSH Server"
        "fail2ban:Brute Force Protection"
        "ufw:Firewall"
        "unattended-upgrades:Automatic Updates"
    )
    
    local failed=false
    for service in "${required_services[@]}"; do
        local name="${service%%:*}"
        local desc="${service#*:}"
        if ! systemctl is-active --quiet "$name"; then
            log "ERROR" "$desc ($name) is not running"
            failed=true
        fi
    done
    
    ! "$failed"
}

ssh_check() {
    local config="/etc/ssh/sshd_config"
    local failed=false
    
    # Required SSH settings
    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["X11Forwarding"]="no"
        ["MaxAuthTries"]="3"
    )
    
    for key in "${!ssh_settings[@]}"; do
        if ! grep -q "^${key} ${ssh_settings[$key]}" "$config"; then
            log "ERROR" "SSH setting $key=${ssh_settings[$key]} not properly configured"
            failed=true
        fi
    done
    
    # Verify custom SSH port
    if ! grep -q "^Port ${SSH_PORT:-3333}" "$config"; then
        log "ERROR" "Custom SSH port not properly configured"
        failed=true
    fi
    
    ! "$failed"
}

firewall_check() {
    # Check UFW status
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        return 1
    fi
    
    # Verify required ports
    local required_ports=(${SSH_PORT:-3333} ${FIREWALL_ADDITIONAL_PORTS//,/ })
    for port in "${required_ports[@]}"; do
        if ! ufw status | grep -q "$port"; then
            log "ERROR" "Required port $port not configured in firewall"
            return 1
        fi
    done
    
    return 0
}

pam_check() {
    local failed=false
    
    # Check PAM configuration
    if [[ "${MFA_ENABLED:-yes}" == "yes" ]]; then
        if ! grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
            log "ERROR" "2FA PAM module not properly configured"
            failed=true
        fi
    fi
    
    # Verify secure PAM settings
    if ! grep -q "auth required pam_unix.so" /etc/pam.d/common-auth; then
        log "ERROR" "Basic PAM authentication not properly configured"
        failed=true
    fi
    
    ! "$failed"
}

system_security_check() {
    local failed=false
    
    # Check sysctl security settings
    declare -A sysctl_settings=(
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["kernel.sysrq"]="0"
    )
    
    for setting in "${!sysctl_settings[@]}"; do
        local value
        value=$(sysctl -n "$setting" 2>/dev/null || echo "NOT_SET")
        if [[ "$value" != "${sysctl_settings[$setting]}" ]]; then
            log "ERROR" "System security setting $setting not properly configured"
            failed=true
        fi
    done
    
    ! "$failed"
}

package_security_check() {
    local failed=false
    
    # Check if automatic updates are enabled
    if [[ "${ENABLE_AUTO_UPDATES:-yes}" == "yes" ]]; then
        if ! grep -q "APT::Periodic::Unattended-Upgrade \"1\"" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
            log "ERROR" "Automatic updates not properly configured"
            failed=true
        fi
    fi
    
    ! "$failed"
}

user_security_check() {
    local username="$1"
    local failed=false
    
    # Check user exists and is in sudo group
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "Admin user $username does not exist"
        failed=true
    elif ! groups "$username" | grep -q "\bsudo\b"; then
        log "ERROR" "Admin user $username is not in sudo group"
        failed=true
    fi
    
    # Check SSH directory permissions
    local ssh_dir="/home/$username/.ssh"
    if [[ -d "$ssh_dir" ]]; then
        if [[ "$(stat -c "%a" "$ssh_dir")" != "700" ]]; then
            log "ERROR" "Incorrect SSH directory permissions for $username"
            failed=true
        fi
        
        if [[ -f "$ssh_dir/authorized_keys" ]] && [[ "$(stat -c "%a" "$ssh_dir/authorized_keys")" != "600" ]]; then
            log "ERROR" "Incorrect authorized_keys permissions for $username"
            failed=true
        fi
    fi
    
    ! "$failed"
}

network_security_check() {
    local failed=false
    
    # Check IPv6 status
    if [[ "${ENABLE_IPV6:-no}" == "no" ]] && ! grep -q "^net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.d/99-security.conf; then
        log "ERROR" "IPv6 not properly disabled"
        failed=true
    fi
    
    # Check network hardening
    if ! grep -q "net.ipv4.tcp_syncookies = 1" /etc/sysctl.d/99-security.conf; then
        log "ERROR" "TCP SYN cookie protection not enabled"
        failed=true
    fi
    
    ! "$failed"
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 username"
    exit 1
fi

verify_deployment "$1"