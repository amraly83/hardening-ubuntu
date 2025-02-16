#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize test environment
LOG_FILE="/var/log/server-hardening-test.log"
init_script

run_test() {
    local test_name="$1"
    local result=0
    
    echo "=== Running Test: $test_name ==="
    shift
    if "$@"; then
        echo "✓ PASS: $test_name"
    else
        echo "✗ FAIL: $test_name"
        result=1
    fi
    echo "===================="
    return $result
}

test_existing_admin_user() {
    # Create a test admin user
    local test_user="testadmin$$"
    adduser --gecos "" --disabled-password "$test_user"
    usermod -aG sudo "$test_user"
    
    # Test create-admin.sh with existing admin
    echo "$test_user" | ./create-admin.sh
    local result=$?
    
    # Cleanup
    deluser --remove-home "$test_user"
    
    return $result
}

test_existing_regular_user() {
    # Create a test regular user
    local test_user="testuser$$"
    adduser --gecos "" --disabled-password "$test_user"
    
    # Test create-admin.sh with existing non-admin
    echo -e "$test_user\nyes" | ./create-admin.sh
    local result=$?
    
    # Verify user is now admin
    if groups "$test_user" | grep -q sudo; then
        result=0
    else
        result=1
    fi
    
    # Cleanup
    deluser --remove-home "$test_user"
    
    return $result
}

test_invalid_username() {
    # Test with invalid username
    echo "root123" | ./create-admin.sh
    # Should return non-zero exit code
    [[ $? -ne 0 ]]
}

main() {
    local failed=0
    
    # Run all tests
    run_test "Existing Admin User" test_existing_admin_user || ((failed++))
    run_test "Existing Regular User" test_existing_regular_user || ((failed++))
    run_test "Invalid Username" test_invalid_username || ((failed++))
    
    echo "Test Summary:"
    echo "Total Failed Tests: $failed"
    
    return $failed
}

main "$@"