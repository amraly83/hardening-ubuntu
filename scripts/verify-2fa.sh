#!/bin/bash
# Verify 2FA setup for admin user
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

# Function to verify 2FA configuration
verify_2fa_config() {
    local username="$1"
    local status=0
    
    log "INFO" "Verifying 2FA configuration for $username..."
    
    # Check Google Authenticator file
    local ga_file="/home/${username}/.google_authenticator"
    if [[ ! -f "$ga_file" ]]; then
        log "ERROR" "Google Authenticator file not found"
        return 1
    fi
    
    # Check file permissions
    local perms
    perms=$(stat -c "%a" "$ga_file")
    if [[ "$perms" != "400" ]]; then
        log "ERROR" "Incorrect permissions on Google Authenticator file: $perms (should be 400)"
        chmod 400 "$ga_file"
        chown "${username}:${username}" "$ga_file"
        status=1
    fi
    
    # Check PAM configuration
    if ! grep -q "^auth.*required.*pam_google_authenticator.so" /etc/pam.d/sshd; then
        log "ERROR" "PAM not configured for Google Authenticator"
        status=1
    fi
    
    # Check SSH configuration
    local sshd_config="/etc/ssh/sshd_config"
    if ! grep -q "^ChallengeResponseAuthentication.*yes" "$sshd_config"; then
        log "ERROR" "SSH not configured for challenge-response authentication"
        status=1
    fi
    
    if ! grep -q "^AuthenticationMethods.*keyboard-interactive" "$sshd_config"; then
        log "ERROR" "SSH not configured for keyboard-interactive authentication"
        status=1
    fi
    
    return $status
}

# Function to test SSH with 2FA
test_ssh_2fa() {
    local username="$1"
    local test_port=22
    
    # Get configured SSH port
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf"
        test_port="${SSH_PORT:-22}"
    fi
    
    # Try connecting with keyboard-interactive auth
    log "INFO" "Testing SSH 2FA authentication..."
    if ! timeout 5 ssh -o PreferredAuthentications=keyboard-interactive \
                      -o BatchMode=yes \
                      -o StrictHostKeyChecking=no \
                      -p "$test_port" \
                      "${username}@localhost" "true" 2>/dev/null; then
        log "SUCCESS" "2FA prompt working as expected (connection refused without 2FA code)"
        return 0
    else
        log "ERROR" "SSH connection succeeded without 2FA"
        return 1
    fi
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 <admin_username>"
        exit 1
    fi
    
    local username="$1"
    local failed=0
    
    # Check if running as root
    check_root
    
    # Clean username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    echo -e "\n${COLOR_CYAN}=== Verifying 2FA Setup for: $username ===${COLOR_RESET}"
    
    # Verify user exists and is admin
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        exit 1
    fi
    
    if ! is_user_admin "$username"; then
        log "ERROR" "User $username is not an admin user"
        exit 1
    fi
    
    # Run verifications
    if ! verify_2fa_config "$username"; then
        log "ERROR" "2FA configuration verification failed"
        ((failed++))
    fi
    
    if ! test_ssh_2fa "$username"; then
        log "ERROR" "2FA SSH test failed"
        ((failed++))
    fi
    
    # Print summary
    echo -e "\n${COLOR_CYAN}=== Verification Summary ===${COLOR_RESET}"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}All 2FA verifications passed${COLOR_RESET}"
        echo "The 2FA setup is working correctly"
    else
        echo -e "${COLOR_RED}${failed} verification(s) failed${COLOR_RESET}"
        echo "Please check the errors above and fix any issues"
    fi
    
    return $failed
}

# Run main function
main "$@"