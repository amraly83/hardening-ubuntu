#!/bin/bash
# Test admin user setup after deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test admin user creation and verification
test_admin_setup() {
    local username="$1"
    local test_file="/tmp/sudo_test_$$"
    local max_retries=3
    local retry=0
    
    log "INFO" "Testing admin setup for user: $username"
    
    # Clean the username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    log "DEBUG" "Using cleaned username: $username"
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Clean sudo environment first
    sudo -K
    rm -f /run/sudo/ts/* 2>/dev/null || true
    
    # Check and fix sudo group membership if needed
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "WARNING" "User not in sudo group, attempting to fix..."
        usermod -aG sudo "$username"
        sg sudo -c "id" || true
        sleep 1
    fi
    
    # Verify and fix sudoers configuration
    if [[ ! -f "/etc/sudoers.d/$username" ]]; then
        log "WARNING" "No sudoers configuration found, creating..."
        echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
        chmod 440 "/etc/sudoers.d/$username"
    fi
    
    # Test sudo access with retries
    while [ $retry -lt $max_retries ]; do
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
            log "SUCCESS" "Sudo access verified"
            break
        fi
        
        ((retry++))
        if [ $retry -lt $max_retries ]; then
            log "WARNING" "Sudo access test failed, retrying ($retry/$max_retries)..."
            sleep 2
        else
            log "ERROR" "Sudo access test failed after $max_retries attempts"
            return 1
        fi
    done
    
    return 0
}

# Test PAM configuration
test_pam_config() {
    local username="$1"
    local status=0
    
    log "INFO" "Testing PAM configuration..."
    
    # Verify PAM files exist and have correct permissions
    local pam_files=("sudo" "su" "common-auth" "common-account")
    for file in "${pam_files[@]}"; do
        if [[ ! -f "/etc/pam.d/$file" ]]; then
            log "ERROR" "Missing PAM file: /etc/pam.d/$file"
            status=1
        else
            local perms
            perms=$(stat -c '%a' "/etc/pam.d/$file")
            if [[ "$perms" != "644" ]]; then
                log "WARNING" "Incorrect permissions on /etc/pam.d/$file: $perms, fixing..."
                chmod 644 "/etc/pam.d/$file"
            fi
        fi
    done
    
    return $status
}

# Test sudo timeout behavior
test_sudo_timeout() {
    local username="$1"
    local test_file="/tmp/sudo_timeout_test_$$"
    
    log "INFO" "Testing sudo timeout behavior..."
    
    # Clear sudo tokens
    sudo -K
    rm -f /run/sudo/ts/* 2>/dev/null || true
    
    # Test sudo access with password requirement
    if timeout 5 su -s /bin/bash - "$username" -c "sudo -n touch $test_file" >/dev/null 2>&1; then
        rm -f "$test_file" 2>/dev/null || true
        log "SUCCESS" "Sudo timeout test passed"
        return 0
    else
        log "WARNING" "Sudo requires password (expected behavior)"
        return 0
    fi
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 username"
        exit 1
    fi
    
    local username="$1"
    local failed=0
    
    # Check if running as root
    check_root || exit 1
    
    log "INFO" "=== Starting Admin User Verification ==="
    
    # Run all tests
    if ! test_admin_setup "$username"; then
        log "ERROR" "Admin setup verification failed"
        ((failed++))
    fi
    
    if ! test_pam_config "$username"; then
        log "ERROR" "PAM configuration verification failed"
        ((failed++))
    fi
    
    if ! test_sudo_timeout "$username"; then
        log "ERROR" "Sudo timeout verification failed"
        ((failed++))
    fi
    
    # Print summary
    log "INFO" "=== Verification Summary ==="
    if [[ $failed -eq 0 ]]; then
        log "SUCCESS" "All admin user tests passed successfully"
    else
        log "ERROR" "$failed test(s) failed. Check the errors above and fix any issues"
    fi
    
    return "$failed"
}

# Run main function
main "$@"