#!/bin/bash
# Comprehensive system verification script
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Initialize variables with defaults
readonly DEFAULT_CONFIG="/etc/server-hardening/hardening.conf"
readonly DEFAULT_LOG="/var/log/server-hardening.log"
readonly REQUIRED_DIRS=(
    "/etc/server-hardening"
    "/var/log"
)
readonly REQUIRED_SERVICES=(
    "sshd"
    "fail2ban"
    "ufw"
)

# State tracking
declare -A VERIFICATION_RESULTS

verify_filesystem() {
    log "INFO" "Verifying filesystem requirements..."
    local status=0
    
    # Check required directories
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log "ERROR" "Required directory missing: $dir"
            status=1
        fi
    done
    
    # Check configuration file
    if [[ ! -f "$DEFAULT_CONFIG" ]]; then
        log "ERROR" "Configuration file missing: $DEFAULT_CONFIG"
        status=1
    else
        # Verify config permissions
        local config_perms
        config_perms=$(stat -c "%a" "$DEFAULT_CONFIG")
        if [[ "$config_perms" != "600" ]]; then
            log "ERROR" "Invalid configuration file permissions: $config_perms (should be 600)"
            status=1
        fi
    fi
    
    VERIFICATION_RESULTS["filesystem"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_packages() {
    log "INFO" "Verifying required packages..."
    local status=0
    local required_packages=(
        "openssh-server"
        "ufw"
        "fail2ban"
        "libpam-google-authenticator"
    )
    
    for pkg in "${required_packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            log "ERROR" "Required package not installed: $pkg"
            status=1
        fi
    done
    
    VERIFICATION_RESULTS["packages"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_services() {
    log "INFO" "Verifying service states..."
    local status=0
    
    for service in "${REQUIRED_SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log "ERROR" "Required service not running: $service"
            status=1
        fi
        if ! systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log "ERROR" "Required service not enabled: $service"
            status=1
        fi
    done
    
    # Verify SSH configuration
    if ! sshd -t >/dev/null 2>&1; then
        log "ERROR" "Invalid SSH configuration"
        status=1
    fi
    
    # Verify fail2ban jails
    if ! fail2ban-client ping >/dev/null 2>&1; then
        log "ERROR" "fail2ban service not responding"
        status=1
    elif ! fail2ban-client status sshd >/dev/null 2>&1; then
        log "ERROR" "fail2ban SSH jail not configured"
        status=1
    fi
    
    # Verify firewall
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        status=1
    fi
    
    VERIFICATION_RESULTS["services"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_security_config() {
    log "INFO" "Verifying security configurations..."
    local status=0
    
    # Verify SSH hardening
    local ssh_config="/etc/ssh/sshd_config"
    local required_ssh_settings=(
        "^PermitRootLogin no"
        "^PasswordAuthentication no"
        "^PubkeyAuthentication yes"
        "^X11Forwarding no"
    )
    
    for setting in "${required_ssh_settings[@]}"; do
        if ! grep -q "$setting" "$ssh_config"; then
            log "ERROR" "Missing SSH security setting: $setting"
            status=1
        fi
    done
    
    # Verify PAM configuration
    if [[ ! -f "/etc/pam.d/sshd" ]]; then
        log "ERROR" "PAM SSH configuration missing"
        status=1
    elif ! grep -q "^auth.*pam_google_authenticator.so" "/etc/pam.d/sshd"; then
        log "ERROR" "2FA PAM configuration missing"
        status=1
    fi
    
    # Verify sysctl security settings
    local required_sysctl=(
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.all.accept_source_route=0"
        "kernel.sysrq=0"
    )
    
    for setting in "${required_sysctl[@]}"; do
        local key="${setting%=*}"
        local value="${setting#*=}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null)
        if [[ "$actual" != "$value" ]]; then
            log "ERROR" "Invalid sysctl setting: $key = $actual (should be $value)"
            status=1
        fi
    done
    
    VERIFICATION_RESULTS["security_config"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_user() {
    local username="$1"
    log "INFO" "Verifying user configuration for: $username"
    local status=0
    
    # Basic user verification
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User does not exist: $username"
        status=1
    else
        # Check sudo access
        if ! groups "$username" | grep -q '\bsudo\b'; then
            log "ERROR" "User not in sudo group: $username"
            status=1
        fi
        
        # Check SSH directory and keys
        local ssh_dir="/home/$username/.ssh"
        local auth_keys="$ssh_dir/authorized_keys"
        
        if [[ ! -d "$ssh_dir" ]]; then
            log "ERROR" "SSH directory missing: $ssh_dir"
            status=1
        elif [[ "$(stat -c '%a' "$ssh_dir")" != "700" ]]; then
            log "ERROR" "Invalid SSH directory permissions"
            status=1
        fi
        
        if [[ ! -f "$auth_keys" ]]; then
            log "ERROR" "SSH authorized_keys missing: $auth_keys"
            status=1
        elif [[ "$(stat -c '%a' "$auth_keys")" != "600" ]]; then
            log "ERROR" "Invalid authorized_keys permissions"
            status=1
        fi
        
        # Check 2FA setup
        if [[ ! -f "/home/$username/.google_authenticator" ]]; then
            log "ERROR" "2FA not configured for user"
            status=1
        elif [[ "$(stat -c '%a' "/home/$username/.google_authenticator")" != "400" ]]; then
            log "ERROR" "Invalid 2FA file permissions"
            status=1
        fi
    fi
    
    VERIFICATION_RESULTS["user_config"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

generate_report() {
    local report_file="/var/log/security-verification-report.txt"
    local total=0
    local passed=0
    
    {
        echo "=== System Security Verification Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "System: $(uname -a)"
        echo
        
        echo "=== Verification Results ==="
        for check in "${!VERIFICATION_RESULTS[@]}"; do
            echo "${check}: ${VERIFICATION_RESULTS[$check]}"
            ((total++))
            [[ "${VERIFICATION_RESULTS[$check]}" == "PASS" ]] && ((passed++))
        done
        echo
        
        echo "=== Summary ==="
        echo "Total Checks: $total"
        echo "Passed: $passed"
        echo "Failed: $((total - passed))"
        echo "Success Rate: $(( (passed * 100) / total ))%"
        echo
        
        echo "=== System Status ==="
        echo "Services:"
        for service in "${REQUIRED_SERVICES[@]}"; do
            systemctl status "$service" | grep -E "^[[:space:]]*(Active|Status):" || true
        done
        echo
        
        if [[ $passed -lt $total ]]; then
            echo "=== Recommendations ==="
            if [[ "${VERIFICATION_RESULTS[filesystem]:-FAIL}" == "FAIL" ]]; then
                echo "- Check directory permissions and configuration files"
            fi
            if [[ "${VERIFICATION_RESULTS[packages]:-FAIL}" == "FAIL" ]]; then
                echo "- Install missing required packages"
            fi
            if [[ "${VERIFICATION_RESULTS[services]:-FAIL}" == "FAIL" ]]; then
                echo "- Verify service configurations and restart required services"
            fi
            if [[ "${VERIFICATION_RESULTS[security_config]:-FAIL}" == "FAIL" ]]; then
                echo "- Review security settings in SSH, PAM, and sysctl"
            fi
            if [[ "${VERIFICATION_RESULTS[user_config]:-FAIL}" == "FAIL" ]]; then
                echo "- Check user permissions, SSH keys, and 2FA setup"
            fi
        fi
        
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Verification report generated: $report_file"
}

main() {
    local username="$1"
    local exit_status=0
    
    # Check root access
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
    
    # Validate username
    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        error_exit "Invalid username format: $username"
    fi
    
    log "INFO" "Starting system verification..."
    
    # Run all verifications
    verify_filesystem || exit_status=1
    verify_packages || exit_status=1
    verify_services || exit_status=1
    verify_security_config || exit_status=1
    verify_user "$username" || exit_status=1
    
    # Generate verification report
    generate_report
    
    if [[ $exit_status -eq 0 ]]; then
        log "SUCCESS" "All system verifications passed"
    else
        log "ERROR" "System state verification failed"
    fi
    
    return $exit_status
}

# Check arguments
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <username>" >&2
    exit 1
fi

main "$1"