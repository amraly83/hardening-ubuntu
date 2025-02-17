#!/bin/bash
# Automated 2FA testing script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

TEST_USER="test2fa"
TEST_PASS="Test2FA!$(date +%s)"
TEST_LOG="/var/log/2fa-test.log"

test_2fa_setup() {
    local success=true
    
    log "INFO" "Starting 2FA testing suite..."
    
    # Create test environment
    setup_test_env || return 1
    
    # Run test cases
    test_pam_configuration || success=false
    test_ssh_configuration || success=false
    test_google_authenticator || success=false
    test_authentication_flow || success=false
    
    # Cleanup
    cleanup_test_env
    
    # Generate test report
    generate_test_report "$success"
    
    return $([ "$success" == "true" ])
}

setup_test_env() {
    log "INFO" "Setting up test environment..."
    
    # Create test user
    useradd -m -s /bin/bash "$TEST_USER" || return 1
    echo "$TEST_USER:$TEST_PASS" | chpasswd
    
    # Add to sudo group for testing
    usermod -aG sudo "$TEST_USER"
    
    # Create SSH directory
    mkdir -p "/home/$TEST_USER/.ssh"
    chmod 700 "/home/$TEST_USER/.ssh"
    chown "$TEST_USER:$TEST_USER" "/home/$TEST_USER/.ssh"
    
    return 0
}

test_pam_configuration() {
    log "INFO" "Testing PAM configuration..."
    
    # Check PAM module installation
    if ! dpkg -l libpam-google-authenticator >/dev/null 2>&1; then
        log "ERROR" "Google Authenticator PAM module not installed"
        return 1
    fi
    
    # Verify PAM configuration
    local pam_file="/etc/pam.d/sshd"
    if ! grep -q "auth required pam_google_authenticator.so" "$pam_file"; then
        log "ERROR" "PAM configuration missing Google Authenticator"
        return 1
    fi
    
    # Test PAM module functionality
    if ! pamtester -v sshd "$TEST_USER" authenticate 2>/dev/null; then
        log "ERROR" "PAM authentication test failed"
        return 1
    fi
    
    return 0
}

test_ssh_configuration() {
    log "INFO" "Testing SSH configuration..."
    
    # Verify SSH configuration
    local config_file="/etc/ssh/sshd_config"
    local required_settings=(
        "ChallengeResponseAuthentication yes"
        "UsePAM yes"
        "AuthenticationMethods publickey,keyboard-interactive"
    )
    
    for setting in "${required_settings[@]}"; do
        if ! grep -q "^$setting" "$config_file"; then
            log "ERROR" "Missing SSH configuration: $setting"
            return 1
        fi
    done
    
    # Test SSH service
    if ! systemctl is-active --quiet sshd; then
        log "ERROR" "SSH service not running"
        return 1
    fi
    
    return 0
}

test_google_authenticator() {
    log "INFO" "Testing Google Authenticator setup..."
    
    # Generate test configuration
    su - "$TEST_USER" -c "google-authenticator -t -d -f -r 3 -R 30 -w 3" || {
        log "ERROR" "Failed to initialize Google Authenticator"
        return 1
    }
    
    # Verify configuration file
    if [[ ! -f "/home/$TEST_USER/.google_authenticator" ]]; then
        log "ERROR" "Google Authenticator configuration file not created"
        return 1
    fi
    
    # Check file permissions
    local file_perms
    file_perms=$(stat -c '%a' "/home/$TEST_USER/.google_authenticator")
    if [[ "$file_perms" != "400" ]]; then
        log "ERROR" "Incorrect Google Authenticator file permissions: $file_perms"
        return 1
    fi
    
    return 0
}

test_authentication_flow() {
    log "INFO" "Testing complete authentication flow..."
    
    # Generate test SSH key
    local test_key="/tmp/test_ssh_key"
    ssh-keygen -t ed25519 -f "$test_key" -N "" -C "2fa_test" || return 1
    
    # Add key to authorized_keys
    cat "${test_key}.pub" >> "/home/$TEST_USER/.ssh/authorized_keys"
    chmod 600 "/home/$TEST_USER/.ssh/authorized_keys"
    chown "$TEST_USER:$TEST_USER" "/home/$TEST_USER/.ssh/authorized_keys"
    
    # Test authentication (this will fail as expected without 2FA code)
    if ssh -i "$test_key" -o BatchMode=yes -o StrictHostKeyChecking=no "$TEST_USER@localhost" true 2>/dev/null; then
        log "ERROR" "SSH access granted without 2FA"
        return 1
    fi
    
    # Clean up test key
    rm -f "$test_key" "${test_key}.pub"
    
    return 0
}

cleanup_test_env() {
    log "INFO" "Cleaning up test environment..."
    
    # Remove test user and home directory
    userdel -r "$TEST_USER" 2>/dev/null || true
    
    # Remove any test files
    rm -f "/tmp/test_ssh_key" "/tmp/test_ssh_key.pub"
}

generate_test_report() {
    local success="$1"
    local report_file="/var/log/2fa-test-report.txt"
    
    {
        echo "=== 2FA Testing Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Status: $([ "$success" == "true" ] && echo "PASSED" || echo "FAILED")"
        echo
        echo "=== Test Environment ==="
        echo "Test User: $TEST_USER"
        echo "PAM Module: $(dpkg -l libpam-google-authenticator | grep '^ii' | awk '{print $3}')"
        echo "SSH Version: $(ssh -V 2>&1)"
        echo
        echo "=== Configuration Status ==="
        echo "PAM Config:"
        grep "auth.*pam_google_authenticator.so" /etc/pam.d/sshd 2>/dev/null || echo "Not configured"
        echo
        echo "SSH Config:"
        grep -E "ChallengeResponseAuthentication|UsePAM|AuthenticationMethods" /etc/ssh/sshd_config
        echo
        echo "=== Test Results ==="
        echo "PAM Configuration: $(test_pam_configuration >/dev/null 2>&1 && echo "PASS" || echo "FAIL")"
        echo "SSH Configuration: $(test_ssh_configuration >/dev/null 2>&1 && echo "PASS" || echo "FAIL")"
        echo "Google Authenticator: $(test_google_authenticator >/dev/null 2>&1 && echo "PASS" || echo "FAIL")"
        echo "Authentication Flow: $(test_authentication_flow >/dev/null 2>&1 && echo "PASS" || echo "FAIL")"
        echo
        echo "=== Recommendations ==="
        if [[ "$success" != "true" ]]; then
            echo "- Review PAM configuration"
            echo "- Check SSH settings"
            echo "- Verify Google Authenticator setup"
            echo "- Test manual authentication"
        else
            echo "- Perform manual 2FA verification"
            echo "- Document backup codes"
            echo "- Train users on 2FA process"
        fi
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Test report generated: $report_file"
}

# Main execution
test_2fa_setup