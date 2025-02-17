#!/bin/bash
# Comprehensive integration test suite for server hardening
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test configuration
readonly TEST_USER="testadmin"
readonly TEST_EMAIL="test@localhost"
readonly SSH_TEST_PORT=3333
readonly TEST_LOG="/var/log/security-test.log"
readonly TEST_TIMEOUT=300  # 5 minutes total timeout
readonly STEP_TIMEOUT=60   # 1 minute per step timeout

# Store test results
declare -A TEST_RESULTS

setup_test_env() {
    log "INFO" "Setting up test environment..."
    
    # Create test directories
    mkdir -p "/etc/server-hardening"
    
    # Generate unique test configuration
    local test_config="/etc/server-hardening/hardening.conf"
    cat > "$test_config" << EOF
SSH_PORT=$SSH_TEST_PORT
SSH_ALLOW_USERS=$TEST_USER
ADMIN_EMAIL=$TEST_EMAIL
FIREWALL_ADDITIONAL_PORTS=80,443
MFA_ENABLED=yes
ENABLE_AUTO_UPDATES=yes
ENABLE_IPV6=no
EOF
    chmod 600 "$test_config"
    
    # Generate test SSH key with strong encryption
    local key_file="/tmp/test_key"
    if ! ssh-keygen -t ed25519 -a 100 -f "$key_file" -N "" -C "test@localhost"; then
        error_exit "Failed to generate SSH key"
    fi
    chmod 600 "$key_file"
    
    # Initialize test log
    : > "$TEST_LOG"
    chmod 600 "$TEST_LOG"
    
    TEST_RESULTS["environment_setup"]="PASS"
    return 0
}

run_with_timeout() {
    local timeout="$1"
    local description="$2"
    shift 2
    
    log "INFO" "Running: $description"
    
    if ! timeout "$timeout" "$@"; then
        if [[ $? -eq 124 ]]; then
            log "ERROR" "$description timed out after ${timeout}s"
        else
            log "ERROR" "$description failed"
        fi
        return 1
    fi
    return 0
}

test_user_creation() {
    log "INFO" "Testing user creation and administration..."
    local status=0
    
    # Create test user with proper validation
    if ! run_with_timeout "$STEP_TIMEOUT" "User creation" "${SCRIPT_DIR}/create-admin.sh" "$TEST_USER"; then
        status=1
    fi
    
    # Verify user setup
    if ! id "$TEST_USER" >/dev/null 2>&1; then
        log "ERROR" "User creation verification failed"
        status=1
    fi
    
    # Verify sudo access
    if ! groups "$TEST_USER" | grep -q "\bsudo\b"; then
        log "ERROR" "Sudo group membership verification failed"
        status=1
    fi
    
    # Verify home directory permissions
    local home_dir="/home/$TEST_USER"
    if [[ ! -d "$home_dir" ]] || [[ "$(stat -c '%a' "$home_dir")" != "750" ]]; then
        log "ERROR" "Home directory permissions verification failed"
        status=1
    fi
    
    TEST_RESULTS["user_creation"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_ssh_configuration() {
    log "INFO" "Testing SSH configuration and access..."
    local status=0
    
    # Setup SSH keys
    if ! run_with_timeout "$STEP_TIMEOUT" "SSH key setup" \
        "${SCRIPT_DIR}/setup-ssh-key.sh" -u "$TEST_USER" -k "/tmp/test_key.pub"; then
        status=1
    fi
    
    # Verify SSH configuration
    local config_checks=(
        "^Port $SSH_TEST_PORT"
        "^PermitRootLogin no"
        "^PasswordAuthentication no"
        "^PubkeyAuthentication yes"
    )
    
    for check in "${config_checks[@]}"; do
        if ! grep -q "$check" /etc/ssh/sshd_config; then
            log "ERROR" "Missing SSH configuration: $check"
            status=1
        fi
    done
    
    # Test SSH connection
    if ! run_with_timeout 10 "SSH connection test" \
        ssh -i /tmp/test_key -p "$SSH_TEST_PORT" \
            -o StrictHostKeyChecking=no \
            -o BatchMode=yes \
            "$TEST_USER@localhost" "true"; then
        log "ERROR" "SSH connection test failed"
        status=1
    fi
    
    TEST_RESULTS["ssh_configuration"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_2fa_setup() {
    log "INFO" "Testing 2FA configuration..."
    local status=0
    
    # Setup 2FA
    if ! run_with_timeout "$STEP_TIMEOUT" "2FA setup" \
        "${SCRIPT_DIR}/setup-2fa.sh" -u "$TEST_USER" -f; then
        status=1
    fi
    
    # Verify 2FA configuration
    if ! run_with_timeout "$STEP_TIMEOUT" "2FA verification" \
        "${SCRIPT_DIR}/verify-2fa.sh" -u "$TEST_USER"; then
        status=1
    fi
    
    # Test 2FA functionality
    if ! run_with_timeout "$STEP_TIMEOUT" "2FA testing" \
        "${SCRIPT_DIR}/test-2fa.sh" -u "$TEST_USER"; then
        status=1
    fi
    
    TEST_RESULTS["2fa_setup"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_firewall_rules() {
    log "INFO" "Testing firewall configuration..."
    local status=0
    
    # Check UFW installation and status
    if ! command -v ufw >/dev/null 2>&1; then
        log "ERROR" "UFW not installed"
        status=1
    elif ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        status=1
    fi
    
    # Verify required ports
    local required_ports=("$SSH_TEST_PORT" "80" "443")
    for port in "${required_ports[@]}"; do
        if ! ufw status | grep -q "$port/tcp.*ALLOW"; then
            log "ERROR" "Required port $port not allowed in firewall"
            status=1
        fi
    done
    
    # Test firewall blocking
    if nc -w 1 -z localhost 23 2>/dev/null; then
        log "ERROR" "Firewall allowing unauthorized port 23"
        status=1
    fi
    
    TEST_RESULTS["firewall_rules"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_security_monitoring() {
    log "INFO" "Testing security monitoring services..."
    local status=0
    
    # Check required services
    local required_services=("fail2ban" "auditd" "security-monitor")
    for service in "${required_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log "ERROR" "Service $service is not running"
            status=1
        fi
    done
    
    # Verify fail2ban configuration
    if ! fail2ban-client status sshd >/dev/null 2>&1; then
        log "ERROR" "fail2ban SSH jail not configured"
        status=1
    fi
    
    # Check audit rules
    if ! auditctl -l | grep -q "watch=/etc/passwd"; then
        log "ERROR" "Basic audit rules not configured"
        status=1
    fi
    
    TEST_RESULTS["security_monitoring"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

cleanup_test_env() {
    log "INFO" "Cleaning up test environment..."
    
    # Stop test services
    systemctl stop security-monitor.service 2>/dev/null || true
    
    # Remove test user and related files
    if id "$TEST_USER" >/dev/null 2>&1; then
        pkill -u "$TEST_USER" || true
        userdel -r "$TEST_USER" 2>/dev/null || true
    fi
    
    # Clean up test files
    rm -f "/tmp/test_key" "/tmp/test_key.pub"
    rm -f "/etc/server-hardening/hardening.conf"
    
    # Archive test logs
    if [[ -f "$TEST_LOG" ]]; then
        mv "$TEST_LOG" "${TEST_LOG}.$(date +%Y%m%d_%H%M%S).bak"
    fi
}

generate_test_report() {
    local report_file="/var/log/security-integration-report.txt"
    local total_tests=${#TEST_RESULTS[@]}
    local passed_tests=0
    
    {
        echo "=== Security Hardening Integration Test Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "System: $(uname -a)"
        echo
        
        echo "=== Test Results ==="
        for test in "${!TEST_RESULTS[@]}"; do
            echo "${test}: ${TEST_RESULTS[$test]}"
            [[ "${TEST_RESULTS[$test]}" == "PASS" ]] && ((passed_tests++))
        done
        echo
        
        echo "=== Summary ==="
        echo "Total Tests: $total_tests"
        echo "Passed: $passed_tests"
        echo "Failed: $((total_tests - passed_tests))"
        echo "Success Rate: $(( (passed_tests * 100) / total_tests ))%"
        echo
        
        echo "=== System Status ==="
        echo "Services:"
        systemctl status sshd fail2ban ufw 2>/dev/null || true
        echo
        
        echo "=== Security Configurations ==="
        echo "SSH Version: $(ssh -V 2>&1)"
        echo "Firewall Status: $(ufw status | grep Status)"
        echo "fail2ban Status: $(fail2ban-client status 2>/dev/null || echo 'Not running')"
        echo
        
        if [[ $passed_tests -lt $total_tests ]]; then
            echo "=== Failed Tests Analysis ==="
            for test in "${!TEST_RESULTS[@]}"; do
                if [[ "${TEST_RESULTS[$test]}" != "PASS" ]]; then
                    echo "- $test: Check logs for details"
                fi
            done
            echo
            echo "=== Recommendations ==="
            echo "1. Review failed test logs in $TEST_LOG"
            echo "2. Verify system requirements"
            echo "3. Check service configurations"
            echo "4. Run individual test scripts for detailed diagnostics"
        fi
        
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Test report generated: $report_file"
    
    return $(( passed_tests < total_tests ))
}

main() {
    local start_time
    start_time=$(date +%s)
    
    # Parse command line options
    local ci_mode=0
    while getopts "c" opt; do
        case $opt in
            c) ci_mode=1 ;;
            *) error_exit "Usage: $0 [-c]" ;;
        esac
    done
    
    # Check if running as root
    check_root
    
    # Trap cleanup on exit
    trap cleanup_test_env EXIT
    
    log "INFO" "Starting integration test suite..."
    
    # Run tests with timeout protection
    if ! run_with_timeout "$TEST_TIMEOUT" "Complete test suite" bash -c '
        setup_test_env &&
        test_user_creation &&
        test_ssh_configuration &&
        test_2fa_setup &&
        test_firewall_rules &&
        test_security_monitoring
    '; then
        log "ERROR" "Integration tests failed or timed out"
        generate_test_report
        exit 1
    fi
    
    # Generate final report
    generate_test_report
    
    # Calculate execution time
    local end_time
    end_time=$(date +%s)
    log "INFO" "Test suite completed in $((end_time - start_time)) seconds"
    
    # Exit based on test results
    local failed_tests=0
    for result in "${TEST_RESULTS[@]}"; do
        [[ "$result" != "PASS" ]] && ((failed_tests++))
    done
    
    [[ $failed_tests -eq 0 ]] || exit 1
}

# Run main function
main "$@"