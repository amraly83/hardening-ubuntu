#!/bin/bash
# Create and set up admin user with proper handling for 2FA
set -euo pipefail

# Fix line endings and setup
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Function to create admin user
create_admin() {
    local username="$1"
    local status=0
    
    # Clean username first
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    log "DEBUG" "Creating admin user: $username"
    
    # Ensure PAM directory exists
    mkdir -p /etc/pam.d
    
    # Initialize PAM first to ensure authentication works
    log "INFO" "Initializing PAM configuration..."
    if ! "${SCRIPT_DIR}/init-pam.sh"; then
        # Try to fix PAM initialization
        log "WARNING" "Initial PAM setup failed, attempting recovery..."
        if ! "${SCRIPT_DIR}/configure-pam.sh"; then
            log "ERROR" "PAM initialization failed"
            return 1
        fi
    fi
    
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
    
    # Initialize sudo access with retries
    log "INFO" "Setting up sudo access..."
    local sudo_attempts=3
    local attempt=1
    
    while [[ $attempt -le $sudo_attempts ]]; do
        if "${SCRIPT_DIR}/init-sudo-access.sh" "$username"; then
            break
        fi
        log "WARNING" "Sudo initialization attempt $attempt failed, retrying..."
        sleep 2
        ((attempt++))
        
        if [[ $attempt -gt $sudo_attempts ]]; then
            log "ERROR" "Failed to initialize sudo access after $sudo_attempts attempts"
            return 1
        fi
    done
    
    # Verify final setup
    log "INFO" "Verifying admin setup..."
    if ! "${SCRIPT_DIR}/verify-admin-setup.sh" "$username"; then
        log "ERROR" "Admin setup verification failed"
        return 1
    fi
    
    log "SUCCESS" "Admin user setup completed successfully"
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