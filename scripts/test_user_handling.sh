#!/bin/bash
# Test script for user handling and verification
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Run a single test with proper output formatting
run_test() {
    local test_name="$1"
    shift
    local start_time=$(date +%s)
    
    log "INFO" "=== Running Test: ${test_name} ==="
    
    if "$@"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log "SUCCESS" "✓ PASS: ${test_name} (${duration}s)"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log "ERROR" "✗ FAIL: ${test_name} (${duration}s)"
        return 1
    fi
}

# Test PAM configuration
test_pam_configuration() {
    local status=0
    
    # Test PAM file existence and permissions
    local pam_files=("sudo" "su" "common-auth" "common-account")
    for file in "${pam_files[@]}"; do
        if [[ ! -f "/etc/pam.d/$file" ]]; then
            log "ERROR" "Missing PAM file: /etc/pam.d/$file"
            status=1
            continue
        fi
        
        local perms
        perms=$(stat -c '%a' "/etc/pam.d/$file")
        if [[ "$perms" != "644" ]]; then
            log "WARNING" "Fixing permissions on /etc/pam.d/$file: $perms -> 644"
            chmod 644 "/etc/pam.d/$file" || status=1
        fi
    done
    
    # Test PAM authentication
    if ! "${SCRIPT_DIR}/init-pam.sh"; then
        log "ERROR" "PAM initialization failed"
        status=1
    fi
    
    return $status
}

# Test sudo configuration
test_sudo_configuration() {
    local test_user="testsudo$$"
    local status=0
    
    # Create test user
    log "INFO" "Creating test user: $test_user"
    if ! useradd -m -s /bin/bash "$test_user"; then
        log "ERROR" "Failed to create test user"
        return 1
    fi
    
    # Test sudo group operations
    log "INFO" "Testing sudo group operations..."
    if ! getent group sudo >/dev/null 2>&1; then
        log "WARNING" "Creating sudo group"
        groupadd sudo || status=1
    fi
    
    usermod -aG sudo "$test_user"
    if ! groups "$test_user" | grep -q '\bsudo\b'; then
        log "ERROR" "Failed to add user to sudo group"
        status=1
    fi
    
    # Test sudoers.d configuration
    log "INFO" "Testing sudoers.d configuration..."
    if [[ ! -d "/etc/sudoers.d" ]]; then
        log "WARNING" "Creating /etc/sudoers.d"
        mkdir -p /etc/sudoers.d
        chmod 750 /etc/sudoers.d
    fi
    
    echo "$test_user ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$test_user"
    chmod 440 "/etc/sudoers.d/$test_user"
    
    # Verify sudo access
    log "INFO" "Verifying sudo access..."
    if ! timeout 5 su -s /bin/bash - "$test_user" -c "sudo -n true"; then
        log "ERROR" "Sudo access verification failed"
        status=1
    fi
    
    # Cleanup
    log "INFO" "Cleaning up test user..."
    rm -f "/etc/sudoers.d/$test_user"
    userdel -r "$test_user" 2>/dev/null || true
    
    return $status
}

# Test user validation
test_username_validation() {
    local test_cases=(
        "validuser:0"
        "valid-user:0"
        "valid_user123:0"
        ".user:1"
        "-user:1"
        "User:1"
        "user@host:1"
        "user space:1"
    )
    
    local failed=0
    
    for test_case in "${test_cases[@]}"; do
        local username="${test_case%%:*}"
        local expected_result="${test_case##*:}"
        
        log "DEBUG" "Testing username: '$username'"
        
        local cleaned_username
        cleaned_username=$(echo "$username" | tr -cd 'a-z0-9_-')
        
        if validate_username "$cleaned_username" >/dev/null 2>&1; then
            local actual_result=0
        else
            local actual_result=1
        fi
        
        if [ "$actual_result" -eq "$expected_result" ]; then
            log "SUCCESS" "Username validation test passed: $username"
        else
            log "ERROR" "Username validation test failed: $username"
            ((failed++))
        fi
    done
    
    return $failed
}

# Test admin user creation workflow
test_admin_workflow() {
    local test_user="testadmin$$"
    local status=0
    
    # Test full admin creation workflow
    log "INFO" "Testing admin creation workflow..."
    
    # Initialize PAM first
    if ! "${SCRIPT_DIR}/init-pam.sh"; then
        log "ERROR" "PAM initialization failed"
        return 1
    fi
    
    # Create admin user
    if ! echo "$test_user" | "${SCRIPT_DIR}/create-admin.sh"; then
        log "ERROR" "Admin user creation failed"
        status=1
    fi
    
    # Verify sudo access
    if ! "${SCRIPT_DIR}/verify-sudo.sh" "$test_user"; then
        log "ERROR" "Sudo access verification failed"
        status=1
    fi
    
    # Verify admin setup
    if ! "${SCRIPT_DIR}/verify-admin-setup.sh" "$test_user"; then
        log "ERROR" "Admin setup verification failed"
        status=1
    fi
    
    # Cleanup
    log "INFO" "Cleaning up test admin user..."
    rm -f "/etc/sudoers.d/$test_user"
    userdel -r "$test_user" 2>/dev/null || true
    
    return $status
}

# Main test execution
main() {
    local failed=0
    local total=0
    
    # Check if running as root
    check_root || exit 1
    
    # Run all tests
    run_test "PAM Configuration" test_pam_configuration || ((failed++))
    ((total++))
    
    run_test "Sudo Configuration" test_sudo_configuration || ((failed++))
    ((total++))
    
    run_test "Username Validation" test_username_validation || ((failed++))
    ((total++))
    
    run_test "Admin Workflow" test_admin_workflow || ((failed++))
    ((total++))
    
    # Print summary
    log "INFO" "=== Test Summary ==="
    log "INFO" "Total Tests: $total"
    if [ $failed -eq 0 ]; then
        log "SUCCESS" "All tests passed ($total/$total)"
    else
        log "ERROR" "$failed/$total tests failed"
    fi
    
    return $failed
}

# Run main function
main "$@"