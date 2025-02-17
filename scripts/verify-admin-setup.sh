#!/bin/bash
# Test admin user setup after deployment
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_RESET='\033[0m'

# Test admin user creation and verification
test_admin_setup() {
    local username="$1"
    local test_file="/tmp/sudo_test_$$"
    
    echo -e "${COLOR_CYAN}Testing admin setup for user: $username${COLOR_RESET}"
    
    # Step 1: Clean the username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    echo "Using cleaned username: $username"
    
    # Step 2: Verify user exists
    echo -n "Checking user existence... "
    if ! id "$username" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "User $username does not exist"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    # Step 3: Check sudo group membership
    echo -n "Checking sudo group membership... "
    if ! groups "$username" | grep -q '\bsudo\b'; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "User is not in sudo group"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    # Step 4: Check sudoers configuration
    echo -n "Checking sudoers configuration... "
    if [[ ! -f "/etc/sudoers.d/$username" ]]; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "No sudoers configuration found"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    # Step 5: Test sudo access with timeout
    echo -n "Testing sudo access... "
    if ! timeout 5 su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "Sudo access test failed"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    # Step 6: Test file creation with sudo
    echo -n "Testing sudo file operations... "
    if ! su -s /bin/bash - "$username" -c "sudo touch $test_file" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "Could not create test file with sudo"
        return 1
    fi
    rm -f "$test_file"
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    echo -e "\n${COLOR_GREEN}All admin user tests passed successfully${COLOR_RESET}"
    return 0
}

# Function to test sudo timeout behavior
test_sudo_timeout() {
    local username="$1"
    
    echo -e "\n${COLOR_CYAN}Testing sudo timeout behavior...${COLOR_RESET}"
    
    # Clear any existing sudo tokens
    sudo -K
    
    # Test initial sudo access
    echo -n "Testing initial sudo access... "
    if ! timeout 5 su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}Required password (expected)${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    fi
    
    # Test sudo timestamp
    echo -n "Testing sudo timestamp... "
    if ! su -s /bin/bash - "$username" -c "sudo touch /tmp/sudo_test_$$" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    return 0
}

# Function to check PAM configuration
check_pam_config() {
    local username="$1"
    
    echo -e "\n${COLOR_CYAN}Checking PAM configuration...${COLOR_RESET}"
    
    # Check sudo PAM configuration
    echo -n "Checking sudo PAM config... "
    if [[ ! -f "/etc/pam.d/sudo" ]]; then
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        echo "Missing sudo PAM configuration"
        return 1
    fi
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    
    # Check basic authentication
    echo -n "Testing PAM authentication... "
    if ! pamtester sudo "$username" authenticate >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}Authentication required (expected)${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    fi
    
    return 0
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        echo -e "${COLOR_RED}Usage: $0 username${COLOR_RESET}"
        exit 1
    }
    
    local username="$1"
    local failed=0
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_RED}Error: This script must be run as root${COLOR_RESET}"
        exit 1
    }
    
    echo -e "${COLOR_CYAN}=== Starting Admin User Verification ===${COLOR_RESET}"
    
    # Run all tests
    if ! test_admin_setup "$username"; then
        echo -e "${COLOR_RED}Admin setup verification failed${COLOR_RESET}"
        ((failed++))
    fi
    
    if ! test_sudo_timeout "$username"; then
        echo -e "${COLOR_RED}Sudo timeout verification failed${COLOR_RESET}"
        ((failed++))
    fi
    
    if ! check_pam_config "$username"; then
        echo -e "${COLOR_RED}PAM configuration verification failed${COLOR_RESET}"
        ((failed++))
    fi
    
    # Print summary
    echo -e "\n${COLOR_CYAN}=== Verification Summary ===${COLOR_RESET}"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}All admin user tests passed successfully${COLOR_RESET}"
        echo "The admin user setup is working correctly"
    else
        echo -e "${COLOR_RED}${failed} test(s) failed${COLOR_RESET}"
        echo "Please check the errors above and fix any issues"
    fi
    
    return "$failed"
}

# Run main function
main "$@"