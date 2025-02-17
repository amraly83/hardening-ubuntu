#!/bin/bash
# Test script for user handling and verification
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions after fixing line endings
COMMON_SH="${SCRIPT_DIR}/common.sh"
if [[ -f "$COMMON_SH" ]]; then
    sed -i 's/\r$//' "$COMMON_SH"
    source "$COMMON_SH"
fi

# Colors for test output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_BLUE='\033[1;34m'
readonly COLOR_RESET='\033[0m'

# Run a single test with proper output formatting
run_test() {
    local test_name="$1"
    shift
    local start_time=$(date +%s)
    
    echo -e "\n${COLOR_BLUE}=== Running Test: ${test_name} ===${COLOR_RESET}"
    
    if "$@"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${COLOR_GREEN}✓ PASS: ${test_name} (${duration}s)${COLOR_RESET}"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${COLOR_RED}✗ FAIL: ${test_name} (${duration}s)${COLOR_RESET}"
        return 1
    fi
}

# Test username validation
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
        "uid0rootgid27sudogroups27sudo0rootwebadmin:1"
    )
    
    local failed=0
    
    for test_case in "${test_cases[@]}"; do
        local username="${test_case%%:*}"
        local expected_result="${test_case##*:}"
        
        echo -n "Testing username: '$username' ... "
        
        # Clean the username first
        local cleaned_username=$(echo "$username" | tr -cd 'a-z0-9_-')
        
        # Validate using common.sh function
        if validate_username "$cleaned_username" >/dev/null 2>&1; then
            local actual_result=0
        else
            local actual_result=1
        fi
        
        if [ "$actual_result" -eq "$expected_result" ]; then
            echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
        else
            echo -e "${COLOR_RED}FAIL${COLOR_RESET}"
            ((failed++))
        fi
    done
    
    return $failed
}

# Test sudo access verification
test_sudo_verification() {
    local test_user="testadmin$$"
    local status=0
    
    echo "Creating test user: $test_user"
    if ! adduser --gecos "" --disabled-password "$test_user" >/dev/null 2>&1; then
        echo "Failed to create test user"
        return 1
    fi
    
    # Test with clean username
    echo "Testing clean username verification..."
    if ! timeout 10 "${SCRIPT_DIR}/verify-sudo.sh" "$test_user"; then
        echo "Clean username verification failed"
        status=1
    fi
    
    # Test with malformed username
    echo "Testing malformed username verification..."
    local malformed="uid0${test_user}gid27sudogroups27sudo0root${test_user}"
    if timeout 10 "${SCRIPT_DIR}/verify-sudo.sh" "$malformed" >/dev/null 2>&1; then
        echo "Malformed username verification should have failed but passed"
        status=1
    fi
    
    # Cleanup
    deluser --remove-home "$test_user" >/dev/null 2>&1 || true
    
    return $status
}

# Test admin user creation and verification
test_admin_creation() {
    local test_user="testadmin$$"
    local status=0
    
    # Test creation with clean username
    echo "Testing admin user creation..."
    if ! echo "$test_user" | "${SCRIPT_DIR}/create-admin.sh" >/dev/null 2>&1; then
        echo "Admin user creation failed"
        status=1
    fi
    
    # Verify sudo access
    echo "Verifying sudo access..."
    if ! timeout 10 "${SCRIPT_DIR}/verify-sudo.sh" "$test_user"; then
        echo "Sudo access verification failed"
        status=1
    fi
    
    # Cleanup
    deluser --remove-home "$test_user" >/dev/null 2>&1 || true
    
    return $status
}

# Main test execution
main() {
    local failed=0
    local total=0
    
    # Run all tests
    run_test "Username Validation" test_username_validation || ((failed++))
    ((total++))
    
    run_test "Sudo Verification" test_sudo_verification || ((failed++))
    ((total++))
    
    run_test "Admin Creation" test_admin_creation || ((failed++))
    ((total++))
    
    # Print summary
    echo -e "\n=== Test Summary ==="
    echo "Total Tests: $total"
    echo -e "Passed: ${COLOR_GREEN}$((total - failed))${COLOR_RESET}"
    echo -e "Failed: ${COLOR_RED}$failed${COLOR_RESET}"
    
    return $failed
}

# Run main function with error handling
if ! main "$@"; then
    echo -e "\n${COLOR_RED}Some tests failed${COLOR_RESET}"
    exit 1
fi