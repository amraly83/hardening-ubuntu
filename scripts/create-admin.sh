#!/bin/bash
# Create and set up admin user with proper handling for 2FA
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions after fixing line endings
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

# Function to create admin user
create_admin() {
    local username="$1"
    local status=0
    
    # Clean username first
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    log "DEBUG" "Creating admin user: $username"
    
    # Create user if doesn't exist
    if ! id "$username" >/dev/null 2>&1; then
        log "INFO" "Creating new user: $username"
        useradd -m -s /bin/bash "$username" || {
            log "ERROR" "Failed to create user"
            return 1
        }
        
        # Set password
        echo -e "\n${COLOR_CYAN}Please set a password for $username${COLOR_RESET}"
        if ! passwd "$username"; then
            log "ERROR" "Failed to set password"
            return 1
        fi
    else
        log "INFO" "User $username already exists"
    fi
    
    # Initialize sudo access
    if ! init_admin_access "$username"; then
        log "ERROR" "Failed to initialize admin access"
        status=1
    fi
    
    # Initialize PAM for later 2FA setup
    if ! "${SCRIPT_DIR}/init-pam.sh"; then
        log "WARNING" "PAM initialization had issues"
    fi
    
    # Verify final setup
    if ! verify_admin_setup "$username"; then
        log "ERROR" "Failed to verify admin setup"
        status=1
    fi
    
    return $status
}

# Function to verify admin setup
verify_admin_setup() {
    local username="$1"
    local status=0
    
    log "INFO" "Verifying admin setup for $username"
    
    # Check sudo group membership
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "ERROR" "User is not in sudo group"
        status=1
    fi
    
    # Check sudoers entry
    if [[ ! -f "/etc/sudoers.d/$username" ]]; then
        log "ERROR" "No sudoers configuration found"
        status=1
    else
        # Verify sudoers file permissions
        local perms
        perms=$(stat -c "%a" "/etc/sudoers.d/$username" 2>/dev/null || echo "000")
        if [[ "$perms" != "440" ]]; then
            log "ERROR" "Incorrect permissions on sudoers file: $perms (should be 440)"
            status=1
        fi
    fi
    
    # Verify sudo access with timeout
    if ! timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
        log "ERROR" "Failed to verify sudo access"
        status=1
    else
        log "SUCCESS" "Sudo access verified"
    fi
    
    if [[ $status -eq 0 ]]; then
        log "SUCCESS" "Admin setup verified successfully"
    else
        log "ERROR" "Admin setup verification failed"
    fi
    
    return $status
}

# Main function
main() {
    # Check if running as root
    check_root
    
    # Get username from stdin or argument
    local username=""
    if [[ $# -eq 1 ]]; then
        username="$1"
    else
        echo -e "${COLOR_CYAN}Enter username for new admin user:${COLOR_RESET} "
        read -r username
    fi
    
    # Validate username
    if ! validate_username "$username"; then
        exit 1
    fi
    
    # Create admin user
    if ! create_admin "$username"; then
        log "ERROR" "Failed to create admin user"
        exit 1
    fi
    
    # Output username for the calling script
    echo "$username"
    exit 0
}

# Run main function
main "$@"