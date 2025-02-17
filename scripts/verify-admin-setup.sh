#!/bin/bash
# Test admin user setup after deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

test_admin_setup() {
    local username="$1"
    local test_file="/tmp/sudo_test_$$"
    local max_retries=3
    local retry=0
    
    log "INFO" "Testing admin setup for user: $username"
    
    # Clean the username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    log "DEBUG" "Using cleaned username: $username"
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Reset sudo environment completely
    clean_sudo_env "$username"
    sleep 2  # Give time for environment cleanup
    
    # First ensure the user is in sudo group
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "WARNING" "User not in sudo group, fixing..."
        usermod -aG sudo "$username"
        sg sudo -c "id" || true
        sleep 2
    fi
    
    # Create test sudo configuration
    log "DEBUG" "Setting up test sudo configuration..."
    mkdir -p /etc/sudoers.d
    chmod 750 /etc/sudoers.d
    echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Verify basic sudo access works
    while [ $retry -lt $max_retries ]; do
        log "DEBUG" "Testing sudo access (attempt $((retry + 1))/$max_retries)"
        
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
            log "SUCCESS" "Basic sudo access verified"
            
            # Switch to password-required configuration
            echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
            return 0
        fi
        
        ((retry++))
        if [ $retry -lt $max_retries ]; then
            log "WARNING" "Sudo test failed, retrying..."
            clean_sudo_env "$username"
            sleep 3
        fi
    done
    
    log "ERROR" "Failed to verify sudo access after $max_retries attempts"
    return 1
}

# Main function execution
main() {
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 username"
        exit 1
    fi
    
    # Check if running as root
    check_root || exit 1
    
    log "INFO" "=== Starting Admin User Verification ==="
    
    # Test admin setup
    if ! test_admin_setup "$1"; then
        log "ERROR" "Admin setup verification failed"
        exit 1
    fi
    
    log "SUCCESS" "Admin user verification completed successfully"
    exit 0
}

# Run main function
main "$@"