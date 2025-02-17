#!/bin/bash
# Verify 2FA setup for system users
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Constants for expected configurations
readonly REQUIRED_PAM_MODS=(
    "pam_google_authenticator.so"
    "pam_unix.so"
)

readonly REQUIRED_SSH_CONFIG=(
    "ChallengeResponseAuthentication yes"
    "AuthenticationMethods publickey,keyboard-interactive"
    "KbdInteractiveAuthentication yes"
    "UsePAM yes"
)

# Function to verify Google Authenticator setup
verify_ga_setup() {
    local username="$1"
    local ga_file="/home/${username}/.google_authenticator"
    local status=0
    
    log "INFO" "Verifying Google Authenticator setup..."
    
    # Check file existence
    if [[ ! -f "$ga_file" ]]; then
        log "ERROR" "Google Authenticator file not found: $ga_file"
        return 1
    fi
    
    # Check file permissions and ownership
    local perms owner group
    perms=$(stat -c "%a" "$ga_file")
    owner=$(stat -c "%U" "$ga_file")
    group=$(stat -c "%G" "$ga_file")
    
    if [[ "$perms" != "400" ]]; then
        log "ERROR" "Incorrect permissions on $ga_file: $perms (should be 400)"
        status=1
    fi
    
    if [[ "$owner" != "$username" || "$group" != "$username" ]]; then
        log "ERROR" "Incorrect ownership on $ga_file: $owner:$group (should be $username:$username)"
        status=1
    fi
    
    # Validate file contents
    if ! grep -q "^[0-9A-Z]\{16\}$" "$ga_file" || ! grep -q "^\" RATE_LIMIT" "$ga_file"; then
        log "ERROR" "Invalid Google Authenticator configuration"
        status=1
    fi
    
    return $status
}

# Function to verify PAM configuration
verify_pam_config() {
    local status=0
    log "INFO" "Verifying PAM configuration..."
    
    # Check PAM sshd configuration
    local pam_file="/etc/pam.d/sshd"
    if [[ ! -f "$pam_file" ]]; then
        log "ERROR" "PAM sshd configuration file not found"
        return 1
    fi
    
    # Verify required PAM modules
    for mod in "${REQUIRED_PAM_MODS[@]}"; do
        if ! grep -q "^auth.*$mod" "$pam_file"; then
            log "ERROR" "Missing required PAM module: $mod"
            status=1
        fi
    done
    
    # Check PAM file permissions
    local perms
    perms=$(stat -c "%a" "$pam_file")
    if [[ "$perms" != "644" ]]; then
        log "ERROR" "Incorrect permissions on $pam_file: $perms (should be 644)"
        status=1
    fi
    
    return $status
}

# Function to verify SSH configuration
verify_ssh_config() {
    local status=0
    log "INFO" "Verifying SSH configuration..."
    
    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        log "ERROR" "SSH configuration file not found"
        return 1
    fi
    
    # Check required SSH settings
    for config in "${REQUIRED_SSH_CONFIG[@]}"; do
        local key="${config%% *}"
        if ! grep -q "^${key}" "$sshd_config"; then
            log "ERROR" "Missing SSH configuration: $config"
            status=1
        elif ! grep -q "^${config}$" "$sshd_config"; then
            log "ERROR" "Incorrect SSH configuration for: $key"
            status=1
        fi
    done
    
    # Verify SSH configuration syntax
    if ! sshd -t; then
        log "ERROR" "Invalid SSH configuration"
        status=1
    fi
    
    return $status
}

# Function to test SSH 2FA connection
test_ssh_2fa() {
    local username="$1"
    local test_port=22
    local config_file="/etc/server-hardening/hardening.conf"
    
    log "INFO" "Testing SSH 2FA authentication..."
    
    # Get configured SSH port
    if [[ -f "$config_file" ]]; then
        # shellcheck source=/dev/null
        source "$config_file"
        test_port="${SSH_PORT:-22}"
    fi
    
    # Test SSH connection with keyboard-interactive auth
    log "DEBUG" "Testing keyboard-interactive authentication..."
    if timeout 5 ssh -o PreferredAuthentications=keyboard-interactive \
                    -o BatchMode=yes \
                    -o StrictHostKeyChecking=no \
                    -o ConnectTimeout=5 \
                    -p "$test_port" \
                    "${username}@localhost" "true" 2>/dev/null; then
        log "ERROR" "SSH connection succeeded without 2FA"
        return 1
    fi
    
    # Test SSH connection with public key only
    log "DEBUG" "Testing public key authentication..."
    if timeout 5 ssh -o PreferredAuthentications=publickey \
                    -o BatchMode=yes \
                    -o StrictHostKeyChecking=no \
                    -o ConnectTimeout=5 \
                    -p "$test_port" \
                    "${username}@localhost" "true" 2>/dev/null; then
        log "ERROR" "SSH connection succeeded with public key only"
        return 1
    fi
    
    log "SUCCESS" "2FA authentication working as expected"
    return 0
}

# Function to verify system service status
verify_services() {
    local status=0
    log "INFO" "Verifying system services..."
    
    # Check SSH service
    if ! systemctl is-active --quiet sshd; then
        log "ERROR" "SSH service is not running"
        status=1
    fi
    
    # Check SSH service configuration
    if ! systemctl show sshd | grep -q "^LoadState=loaded$"; then
        log "ERROR" "SSH service is not properly loaded"
        status=1
    fi
    
    return $status
}

# Main function
main() {
    local username=""
    local verbose=0
    local failed=0
    
    # Parse command line options
    while getopts "u:v" opt; do
        case $opt in
            u) username="$OPTARG" ;;
            v) verbose=1 ;;
            *) error_exit "Usage: $0 -u <username> [-v]" ;;
        esac
    done
    
    if [[ -z "$username" ]]; then
        error_exit "Username is required. Usage: $0 -u <username> [-v]"
    fi
    
    # Check if running as root
    check_root
    
    # Validate username
    if ! validate_username "$username"; then
        error_exit "Invalid username format: $username"
    fi
    
    # Verify user exists and is admin
    if ! id "$username" >/dev/null 2>&1; then
        error_exit "User $username does not exist"
    fi
    
    if ! is_user_admin "$username"; then
        error_exit "User $username is not an admin user"
    fi
    
    echo -e "\n${COLOR_CYAN}=== Starting 2FA Verification for: $username ===${COLOR_RESET}"
    
    # Run all verifications
    declare -A checks=(
        ["Google Authenticator setup"]="verify_ga_setup"
        ["PAM configuration"]="verify_pam_config"
        ["SSH configuration"]="verify_ssh_config"
        ["System services"]="verify_services"
        ["SSH 2FA authentication"]="test_ssh_2fa"
    )
    
    for check in "${!checks[@]}"; do
        echo -e "\n${COLOR_CYAN}Checking: $check${COLOR_RESET}"
        if ! ${checks[$check]} "$username"; then
            log "ERROR" "$check verification failed"
            ((failed++))
        else
            log "SUCCESS" "$check verification passed"
        fi
    done
    
    # Print summary
    echo -e "\n${COLOR_CYAN}=== Verification Summary ===${COLOR_RESET}"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}✓ All 2FA verifications passed${COLOR_RESET}"
        echo -e "The 2FA setup is properly configured and working"
    else
        echo -e "${COLOR_RED}✗ ${failed} verification(s) failed${COLOR_RESET}"
        echo -e "Please review the errors above and run setup-2fa.sh to fix issues"
        exit 1
    fi
    
    return 0
}

# Run main function with all arguments
main "$@"