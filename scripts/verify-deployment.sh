#!/bin/bash
# Verify deployment and script functionality
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
readonly COLOR_BLUE='\033[1;34m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_RESET='\033[0m'

# Function to run a test with proper formatting
run_test() {
    local test_name="$1"
    shift
    
    echo -e "\n${COLOR_BLUE}=== Testing: ${test_name} ===${COLOR_RESET}"
    if "$@"; then
        echo -e "${COLOR_GREEN}✓ PASS: ${test_name}${COLOR_RESET}"
        return 0
    else
        echo -e "${COLOR_RED}✗ FAIL: ${test_name}${COLOR_RESET}"
        return 1
    fi
}

# Test script permissions and line endings
test_script_integrity() {
    local failed=0
    
    echo "Checking script integrity..."
    while IFS= read -r -d '' script; do
        echo -n "Checking $(basename "$script")... "
        
        # Check executable permission
        if [[ ! -x "$script" ]]; then
            echo -e "${COLOR_RED}Not executable${COLOR_RESET}"
            ((failed++))
            continue
        fi
        
        # Check for DOS line endings
        if file "$script" | grep -q "CRLF"; then
            echo -e "${COLOR_YELLOW}CRLF line endings found, fixing...${COLOR_RESET}"
            sed -i 's/\r$//' "$script"
            continue
        fi
        
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    done < <(find "$SCRIPT_DIR" -type f -name "*.sh" -print0)
    
    return "$failed"
}

# Test sudo configuration
test_sudo_config() {
    local test_user="testuser$$"
    
    # Create test user
    useradd -m -s /bin/bash "$test_user"
    usermod -aG sudo "$test_user"
    
    # Test sudo access
    if timeout 10 su -s /bin/bash - "$test_user" -c "sudo -n true"; then
        local result=0
    else
        local result=1
    fi
    
    # Cleanup
    userdel -r "$test_user"
    
    return "$result"
}

# Test PAM configuration
test_pam_config() {
    local failed=0
    
    # Check essential PAM files
    for file in /etc/pam.d/{sudo,su,sshd}; do
        if [[ ! -f "$file" ]]; then
            echo -e "${COLOR_RED}Missing PAM file: $file${COLOR_RESET}"
            ((failed++))
            continue
        fi
        
        # Check permissions
        if [[ "$(stat -c "%a" "$file")" != "644" ]]; then
            echo -e "${COLOR_YELLOW}Incorrect permissions on $file, fixing...${COLOR_RESET}"
            chmod 644 "$file"
        fi
    done
    
    return "$failed"
}

# Test SSH configuration
test_ssh_config() {
    # Verify sshd configuration
    if ! sshd -t; then
        return 1
    fi
    
    # Check if SSH service is running
    if ! systemctl is-active --quiet sshd; then
        return 1
    fi
    
    return 0
}

# Test firewall configuration
test_firewall_config() {
    # Check if UFW is installed and enabled
    if ! command -v ufw >/dev/null 2>&1; then
        echo -e "${COLOR_RED}UFW is not installed${COLOR_RESET}"
        return 1
    fi
    
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${COLOR_RED}Firewall is not active${COLOR_RESET}"
        return 1
    fi
    
    return 0
}

# Test fail2ban configuration
test_fail2ban_config() {
    # Check if fail2ban is installed and running
    if ! systemctl is-active --quiet fail2ban; then
        return 1
    fi
    
    # Check jail configuration
    if ! fail2ban-client ping >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

# Main function
main() {
    local failed=0
    
    echo -e "${COLOR_CYAN}Starting deployment verification...${COLOR_RESET}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_RED}Error: This script must be run as root${COLOR_RESET}"
        exit 1
    fi
    
    # Run all tests
    run_test "Script Integrity" test_script_integrity || ((failed++))
    run_test "Sudo Configuration" test_sudo_config || ((failed++))
    run_test "PAM Configuration" test_pam_config || ((failed++))
    run_test "SSH Configuration" test_ssh_config || ((failed++))
    run_test "Firewall Configuration" test_firewall_config || ((failed++))
    run_test "Fail2ban Configuration" test_fail2ban_config || ((failed++))
    
    # Print summary
    echo -e "\n${COLOR_BLUE}=== Verification Summary ===${COLOR_RESET}"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}All tests passed successfully${COLOR_RESET}"
        echo -e "\nThe deployment is properly configured and ready to use."
    else
        echo -e "${COLOR_RED}${failed} test(s) failed${COLOR_RESET}"
        echo -e "\nPlease check the errors above and fix any issues before proceeding."
    fi
    
    return "$failed"
}

# Run main function
main "$@"