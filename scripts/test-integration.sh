#!/bin/bash
# Comprehensive integration test suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test configuration
TEST_USER="testadmin"
TEST_EMAIL="test@localhost"
SSH_TEST_PORT=3333
TEST_LOG="/tmp/security-test.log"

run_integration_tests() {
    local success=true
    
    log "INFO" "Starting integration test suite..."
    
    # Create test environment
    setup_test_env || {
        error_exit "Failed to setup test environment"
    }
    
    # Run test cases
    test_user_creation || success=false
    test_ssh_configuration || success=false
    test_2fa_setup || success=false
    test_firewall_rules || success=false
    test_pam_configuration || success=false
    test_sudo_access || success=false
    test_security_monitoring || success=false
    
    # Clean up
    cleanup_test_env
    
    # Generate test report
    generate_test_report "$success"
    
    if [[ "$success" == "true" ]]; then
        log "SUCCESS" "All integration tests passed"
        return 0
    else
        log "ERROR" "Some integration tests failed"
        return 1
    fi
}

setup_test_env() {
    log "INFO" "Setting up test environment..."
    
    # Create test configuration
    mkdir -p "/etc/server-hardening"
    cat > "/etc/server-hardening/hardening.conf" << EOF
SSH_PORT=$SSH_TEST_PORT
SSH_ALLOW_USERS=$TEST_USER
ADMIN_EMAIL=$TEST_EMAIL
FIREWALL_ADDITIONAL_PORTS=80,443
MFA_ENABLED=yes
ENABLE_AUTO_UPDATES=yes
ENABLE_IPV6=no
EOF
    
    # Generate test SSH key
    ssh-keygen -t ed25519 -f "/tmp/test_key" -N "" -C "test@localhost"
    
    return 0
}

test_user_creation() {
    log "INFO" "Testing user creation..."
    
    # Create test user
    if ! "${SCRIPT_DIR}/create-admin.sh" "$TEST_USER"; then
        log "ERROR" "User creation failed"
        return 1
    fi
    
    # Verify user exists and has sudo access
    if ! id "$TEST_USER" >/dev/null 2>&1 || ! groups "$TEST_USER" | grep -q "\bsudo\b"; then
        log "ERROR" "User verification failed"
        return 1
    fi
    
    return 0
}

test_ssh_configuration() {
    log "INFO" "Testing SSH configuration..."
    
    # Setup SSH keys
    if ! "${SCRIPT_DIR}/setup-ssh-key.sh" "$TEST_USER" < "/tmp/test_key.pub"; then
        log "ERROR" "SSH key setup failed"
        return 1
    fi
    
    # Test SSH access
    if ! timeout 10 ssh -i /tmp/test_key -p "$SSH_TEST_PORT" -o StrictHostKeyChecking=no "$TEST_USER@localhost" true; then
        log "ERROR" "SSH access verification failed"
        return 1
    fi
    
    return 0
}

test_2fa_setup() {
    log "INFO" "Testing 2FA configuration..."
    
    # Setup 2FA
    if ! "${SCRIPT_DIR}/setup-2fa.sh" "$TEST_USER"; then
        log "ERROR" "2FA setup failed"
        return 1
    fi
    
    # Verify PAM configuration
    if ! grep -q "auth required pam_google_authenticator.so" /etc/pam.d/sshd; then
        log "ERROR" "2FA PAM configuration verification failed"
        return 1
    fi
    
    return 0
}

test_firewall_rules() {
    log "INFO" "Testing firewall configuration..."
    
    # Check UFW status
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        return 1
    fi
    
    # Verify SSH port is allowed
    if ! ufw status | grep -q "$SSH_TEST_PORT/tcp"; then
        log "ERROR" "SSH port not configured in firewall"
        return 1
    fi
    
    return 0
}

test_pam_configuration() {
    log "INFO" "Testing PAM configuration..."
    
    # Test PAM configuration
    if ! "${SCRIPT_DIR}/configure-pam.sh" test; then
        log "ERROR" "PAM configuration failed"
        return 1
    fi
    
    # Verify PAM modules
    if ! pamtester -v sudo "$TEST_USER" authenticate 2>/dev/null; then
        log "ERROR" "PAM authentication test failed"
        return 1
    fi
    
    return 0
}

test_sudo_access() {
    log "INFO" "Testing sudo access..."
    
    # Test sudo configuration
    if ! "${SCRIPT_DIR}/init-sudo.sh" "$TEST_USER"; then
        log "ERROR" "Sudo initialization failed"
        return 1
    fi
    
    # Verify sudo access
    if ! sudo -u "$TEST_USER" sudo -n true; then
        log "ERROR" "Sudo access verification failed"
        return 1
    fi
    
    return 0
}

test_security_monitoring() {
    log "INFO" "Testing security monitoring..."
    
    # Start monitoring service
    if ! systemctl start security-monitor.service; then
        log "ERROR" "Failed to start security monitoring"
        return 1
    fi
    
    # Verify monitoring is active
    if ! systemctl is-active --quiet security-monitor.service; then
        log "ERROR" "Security monitoring service not running"
        return 1
    fi
    
    return 0
}

cleanup_test_env() {
    log "INFO" "Cleaning up test environment..."
    
    # Remove test user
    userdel -r "$TEST_USER" 2>/dev/null || true
    
    # Remove test files
    rm -f "/tmp/test_key" "/tmp/test_key.pub"
    
    # Stop monitoring service
    systemctl stop security-monitor.service 2>/dev/null || true
}

generate_test_report() {
    local success="$1"
    local report_file="${TEST_LOG%.log}-report.txt"
    
    {
        echo "=== Security Hardening Integration Test Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Overall Status: $([ "$success" == "true" ] && echo "PASSED" || echo "FAILED")"
        echo
        echo "=== Test Environment ==="
        echo "Test User: $TEST_USER"
        echo "SSH Port: $SSH_TEST_PORT"
        echo "System: $(uname -a)"
        echo
        echo "=== Test Results ==="
        echo "1. User Creation: $(grep "test_user_creation" "$TEST_LOG" | tail -1)"
        echo "2. SSH Configuration: $(grep "test_ssh_configuration" "$TEST_LOG" | tail -1)"
        echo "3. 2FA Setup: $(grep "test_2fa_setup" "$TEST_LOG" | tail -1)"
        echo "4. Firewall Rules: $(grep "test_firewall_rules" "$TEST_LOG" | tail -1)"
        echo "5. PAM Configuration: $(grep "test_pam_configuration" "$TEST_LOG" | tail -1)"
        echo "6. Sudo Access: $(grep "test_sudo_access" "$TEST_LOG" | tail -1)"
        echo "7. Security Monitoring: $(grep "test_security_monitoring" "$TEST_LOG" | tail -1)"
        echo
        echo "=== System Status ==="
        echo "Services:"
        systemctl status sshd fail2ban ufw security-monitor.service | grep Active:
        echo
        echo "=== Recommendations ==="
        if [[ "$success" != "true" ]]; then
            echo "- Review failed test logs in $TEST_LOG"
            echo "- Check service configurations"
            echo "- Verify system requirements"
            echo "- Run individual test cases for debugging"
        fi
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Test report generated at $report_file"
}

# Main execution
if [[ "${1:-}" == "--ci" ]]; then
    # CI mode - exit on first failure
    set -e
fi

run_integration_tests "$@"