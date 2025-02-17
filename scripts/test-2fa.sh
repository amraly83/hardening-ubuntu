#!/bin/bash
# Test 2FA setup and functionality for admin user
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    sed -i 's/\r$//' "${SCRIPT_DIR}/common.sh"
    source "${SCRIPT_DIR}/common.sh"
fi

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_RESET='\033[0m'

# Test Google Authenticator setup
test_ga_setup() {
    local username="$1"
    local ga_file="/home/${username}/.google_authenticator"
    
    echo -n "Testing Google Authenticator setup... "
    
    # Check if GA file exists and has content
    if [[ ! -f "$ga_file" ]] || [[ ! -s "$ga_file" ]]; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "Google Authenticator file missing or empty"
        return 1
    fi
    
    # Check file permissions
    local perms
    perms=$(stat -c "%a" "$ga_file")
    if [[ "$perms" != "400" ]]; then
        echo -e "${COLOR_YELLOW}Warning${COLOR_RESET}"
        echo "Incorrect permissions on GA file: $perms (fixing...)"
        chmod 400 "$ga_file"
        chown "${username}:${username}" "$ga_file"
    else
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    fi
    
    return 0
}

# Test PAM configuration
test_pam_config() {
    echo -n "Testing PAM configuration... "
    
    # Check PAM module installation
    if ! dpkg -l | grep -q "libpam-google-authenticator"; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "Google Authenticator PAM module not installed"
        return 1
    fi
    
    # Check PAM configuration
    if ! grep -q "^auth.*required.*pam_google_authenticator.so" /etc/pam.d/sshd; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "PAM not configured for Google Authenticator"
        return 1
    fi
    
    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
    return 0
}

# Test SSH configuration
test_ssh_config() {
    echo -n "Testing SSH configuration... "
    
    local sshd_config="/etc/ssh/sshd_config"
    local failed=0
    
    # Check required SSH settings
    if ! grep -q "^ChallengeResponseAuthentication.*yes" "$sshd_config"; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "ChallengeResponseAuthentication not enabled"
        ((failed++))
    fi
    
    if ! grep -q "^AuthenticationMethods.*keyboard-interactive" "$sshd_config"; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "keyboard-interactive authentication not configured"
        ((failed++))
    fi
    
    # Verify SSH configuration syntax
    if ! sshd -t >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Failed${COLOR_RESET}"
        echo "Invalid SSH configuration"
        ((failed++))
    fi
    
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
        return 0
    fi
    
    return 1
}

# Test SSH connection with 2FA
test_ssh_connection() {
    local username="$1"
    local test_port=22
    
    # Get configured SSH port
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf"
        test_port="${SSH_PORT:-22}"
    fi
    
    echo -n "Testing SSH with 2FA requirement... "
    
    # Test connection with keyboard-interactive auth
    if ! timeout 5 ssh -o PreferredAuthentications=keyboard-interactive \
                      -o BatchMode=yes \
                      -o StrictHostKeyChecking=no \
                      -p "$test_port" \
                      "${username}@localhost" "true" 2>/dev/null; then
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
        echo "2FA prompt working as expected"
        return 0
    fi
    
    echo -e "${COLOR_RED}Failed${COLOR_RESET}"
    echo "SSH connection succeeded without 2FA"
    return 1
}

# Main test function
main() {
    if [[ $# -ne 1 ]]; then
        echo -e "${COLOR_RED}Usage: $0 <admin_username>${COLOR_RESET}"
        exit 1
    fi
    
    local username="$1"
    local failed=0
    
    # Check if running as root
    check_root
    
    # Clean username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    echo -e "\n${COLOR_CYAN}=== Testing 2FA Setup for: $username ===${COLOR_RESET}"
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Error: User $username does not exist${COLOR_RESET}"
        exit 1
    fi
    
    # Run all tests
    if ! test_ga_setup "$username"; then
        echo "Google Authenticator setup test failed"
        ((failed++))
    fi
    
    if ! test_pam_config; then
        echo "PAM configuration test failed"
        ((failed++))
    fi
    
    if ! test_ssh_config; then
        echo "SSH configuration test failed"
        ((failed++))
    fi
    
    if ! test_ssh_connection "$username"; then
        echo "SSH connection test failed"
        ((failed++))
    fi
    
    # Print summary
    echo -e "\n${COLOR_CYAN}=== Test Summary ===${COLOR_RESET}"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}All 2FA tests passed successfully${COLOR_RESET}"
        echo "You can now test 2FA login in another terminal"
        echo "Command: ssh -o PreferredAuthentications=keyboard-interactive ${username}@localhost"
    else
        echo -e "${COLOR_RED}${failed} test(s) failed${COLOR_RESET}"
        echo "Please check the errors above and fix any issues"
    fi
    
    return $failed
}

# Run main function
main "$@"