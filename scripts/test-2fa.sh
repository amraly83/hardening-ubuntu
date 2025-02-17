#!/bin/bash
# Automated 2FA testing suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test configuration
readonly TEST_USER="test2fa"
readonly TEST_PASS="Test2FA!$(openssl rand -hex 8)"
readonly TEST_LOG="/var/log/2fa-test.log"
readonly TEST_TIMEOUT=30
readonly MAX_RETRIES=3

# Test states for reporting
declare -A TEST_RESULTS

setup_test_env() {
    log "INFO" "Setting up test environment..."
    
    # Check if test user already exists
    if id "$TEST_USER" >/dev/null 2>&1; then
        log "INFO" "Cleaning up existing test user..."
        cleanup_test_env
    fi
    
    # Create test user with secure shell and home
    if ! useradd -m -s /bin/bash "$TEST_USER"; then
        error_exit "Failed to create test user"
    fi
    
    # Set password securely
    echo "$TEST_USER:$TEST_PASS" | chpasswd
    
    # Add to sudo group for complete testing
    usermod -aG sudo "$TEST_USER"
    
    # Setup SSH directory with proper permissions
    local ssh_dir="/home/$TEST_USER/.ssh"
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown -R "$TEST_USER:$TEST_USER" "/home/$TEST_USER"
    
    # Generate test SSH key pair
    local key_file="/tmp/test_ssh_key"
    if ! ssh-keygen -t ed25519 -f "$key_file" -N "" -C "2fa_test_$(date +%s)"; then
        error_exit "Failed to generate SSH key"
    fi
    
    # Setup authorized keys
    cat "${key_file}.pub" > "${ssh_dir}/authorized_keys"
    chmod 600 "${ssh_dir}/authorized_keys"
    chown "$TEST_USER:$TEST_USER" "${ssh_dir}/authorized_keys"
    
    TEST_RESULTS["environment_setup"]="PASS"
    return 0
}

test_pam_configuration() {
    log "INFO" "Testing PAM configuration..."
    local status=0
    
    # Check PAM module installation
    if ! dpkg -l libpam-google-authenticator >/dev/null 2>&1; then
        log "ERROR" "Google Authenticator PAM module not installed"
        status=1
    fi
    
    # Verify PAM configuration file
    local pam_file="/etc/pam.d/sshd"
    if [[ ! -f "$pam_file" ]]; then
        log "ERROR" "PAM sshd configuration file missing"
        status=1
    else
        # Check required PAM configurations
        local required_configs=(
            "auth required pam_google_authenticator.so"
            "auth required pam_unix.so"
            "@include common-auth"
        )
        
        for config in "${required_configs[@]}"; do
            if ! grep -q "$config" "$pam_file"; then
                log "ERROR" "Missing PAM configuration: $config"
                status=1
            fi
        done
        
        # Verify file permissions
        if [[ "$(stat -c '%a' "$pam_file")" != "644" ]]; then
            log "ERROR" "Incorrect PAM file permissions"
            status=1
        fi
    fi
    
    TEST_RESULTS["pam_configuration"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_ssh_configuration() {
    log "INFO" "Testing SSH configuration..."
    local status=0
    
    # Get SSH port from configuration
    local ssh_port=22
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf"
        ssh_port="${SSH_PORT:-22}"
    fi
    
    # Verify SSH configuration
    local config_file="/etc/ssh/sshd_config"
    local required_settings=(
        "ChallengeResponseAuthentication yes"
        "UsePAM yes"
        "AuthenticationMethods publickey,keyboard-interactive"
        "KbdInteractiveAuthentication yes"
        "Port $ssh_port"
    )
    
    for setting in "${required_settings[@]}"; do
        local key="${setting%% *}"
        if ! grep -qE "^${key}\s" "$config_file"; then
            log "ERROR" "Missing SSH configuration: $setting"
            status=1
        fi
    done
    
    # Test SSH service status
    if ! systemctl is-active --quiet sshd; then
        log "ERROR" "SSH service not running"
        status=1
    fi
    
    # Verify SSH configuration syntax
    if ! sshd -t; then
        log "ERROR" "Invalid SSH configuration"
        status=1
    fi
    
    TEST_RESULTS["ssh_configuration"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_google_authenticator() {
    log "INFO" "Testing Google Authenticator setup..."
    local status=0
    
    # Generate test configuration
    local ga_options=(
        "--time-based"
        "--disallow-reuse"
        "--force"
        "--rate-limit=3"
        "--rate-time=30"
        "--window-size=3"
        "--emergency-codes=1"
    )
    
    if ! su - "$TEST_USER" -c "google-authenticator ${ga_options[*]}"; then
        log "ERROR" "Failed to initialize Google Authenticator"
        status=1
    fi
    
    # Verify configuration file
    local ga_file="/home/$TEST_USER/.google_authenticator"
    if [[ ! -f "$ga_file" ]]; then
        log "ERROR" "Google Authenticator configuration file not created"
        status=1
    else
        # Check file permissions and ownership
        local perms owner group
        perms=$(stat -c '%a' "$ga_file")
        owner=$(stat -c '%U' "$ga_file")
        group=$(stat -c '%G' "$ga_file")
        
        if [[ "$perms" != "400" ]]; then
            log "ERROR" "Incorrect Google Authenticator file permissions: $perms"
            status=1
        fi
        
        if [[ "$owner" != "$TEST_USER" || "$group" != "$TEST_USER" ]]; then
            log "ERROR" "Incorrect Google Authenticator file ownership"
            status=1
        fi
        
        # Validate configuration content
        if ! grep -q "^[0-9A-Z]\{16\}$" "$ga_file" || \
           ! grep -q "^\" RATE_LIMIT" "$ga_file"; then
            log "ERROR" "Invalid Google Authenticator configuration content"
            status=1
        fi
    fi
    
    TEST_RESULTS["google_authenticator"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

test_authentication_methods() {
    log "INFO" "Testing authentication methods..."
    local status=0
    local key_file="/tmp/test_ssh_key"
    local ssh_port=22
    
    # Get configured SSH port
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf"
        ssh_port="${SSH_PORT:-22}"
    fi
    
    # Test cases
    local test_cases=(
        "keyboard-interactive"
        "publickey"
        "password"
    )
    
    for auth_method in "${test_cases[@]}"; do
        log "DEBUG" "Testing $auth_method authentication..."
        if timeout "$TEST_TIMEOUT" ssh -i "$key_file" \
                                     -o PreferredAuthentications="$auth_method" \
                                     -o BatchMode=yes \
                                     -o StrictHostKeyChecking=no \
                                     -o ConnectTimeout=5 \
                                     -p "$ssh_port" \
                                     "$TEST_USER@localhost" true 2>/dev/null; then
            log "ERROR" "Authentication succeeded with $auth_method only"
            status=1
        fi
    done
    
    TEST_RESULTS["authentication_methods"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

cleanup_test_env() {
    log "INFO" "Cleaning up test environment..."
    
    # Kill any running test sessions
    pkill -u "$TEST_USER" || true
    
    # Remove test user and home directory
    userdel -r "$TEST_USER" 2>/dev/null || true
    
    # Clean up test files
    rm -f "/tmp/test_ssh_key" "/tmp/test_ssh_key.pub"
    
    # Remove test logs
    rm -f "$TEST_LOG"
}

generate_test_report() {
    local report_file="/var/log/2fa-test-report.txt"
    local total_tests=${#TEST_RESULTS[@]}
    local passed_tests=0
    
    {
        echo "=== 2FA Testing Report ==="
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
        
        echo "=== System Configuration ==="
        echo "PAM Version: $(dpkg -l libpam-google-authenticator | grep '^ii' | awk '{print $3}')"
        echo "SSH Version: $(ssh -V 2>&1)"
        echo "System Time: $(date)"
        echo "Timezone: $(timedatectl | grep "Time zone")"
        echo
        
        if [[ $passed_tests -lt $total_tests ]]; then
            echo "=== Recommendations ==="
            echo "1. Run verify-2fa.sh for detailed diagnostics"
            echo "2. Check system logs for errors"
            echo "3. Verify PAM and SSH configurations"
            echo "4. Test manual 2FA authentication"
        fi
        
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Test report generated: $report_file"
    
    # Return overall success/failure
    return $(( passed_tests < total_tests ))
}

main() {
    local retries=0
    
    # Check if running as root
    check_root
    
    # Initialize test results
    declare -g -A TEST_RESULTS
    
    while (( retries < MAX_RETRIES )); do
        log "INFO" "Starting 2FA test suite (attempt $((retries + 1))/$MAX_RETRIES)..."
        
        # Setup test environment
        if ! setup_test_env; then
            ((retries++))
            continue
        fi
        
        # Run test suite
        test_pam_configuration
        test_ssh_configuration
        test_google_authenticator
        test_authentication_methods
        
        # Generate report
        generate_test_report
        
        # Clean up
        cleanup_test_env
        
        # Check if all tests passed
        local all_passed=true
        for result in "${TEST_RESULTS[@]}"; do
            if [[ "$result" != "PASS" ]]; then
                all_passed=false
                break
            fi
        done
        
        if [[ "$all_passed" == "true" ]]; then
            log "SUCCESS" "All 2FA tests completed successfully"
            exit 0
        fi
        
        ((retries++))
        [[ $retries -lt $MAX_RETRIES ]] && sleep 5
    done
    
    log "ERROR" "2FA tests failed after $MAX_RETRIES attempts"
    exit 1
}

# Run main function with error handling
main "$@"