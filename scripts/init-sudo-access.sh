#!/bin/bash
# Initialize sudo access in a clean environment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Main sudo initialization function
init_sudo_access() {
    local username="$1"
    
    # Validate username and existence
    if ! validate_username "$username"; then
        exit 1
    fi
    
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User does not exist: $username"
        exit 1
    fi
    
    # First clean the environment completely
    clean_sudo_env "$username"
    
    # Ensure sudo group membership
    if ! ensure_sudo_membership "$username"; then
        log "ERROR" "Failed to ensure sudo group membership"
        exit 1
    fi
    
    # Setup initial sudo access with NOPASSWD for testing
    log "INFO" "Setting up initial sudo access..."
    if ! setup_sudo_access("$username" true); then
        log "ERROR" "Failed to setup initial sudo access"
        exit 1
    fi
    
    # Verify sudo access works
    log "INFO" "Verifying sudo access..."
    if ! test_sudo_access("$username" 3); then
        log "ERROR" "Failed to verify sudo access"
        exit 1
    fi
    
    # Switch to password-required configuration
    log "INFO" "Applying final sudo configuration..."
    if ! setup_sudo_access("$username" false); then
        log "ERROR" "Failed to apply final sudo configuration"
        exit 1
    fi
    
    log "SUCCESS" "Sudo access initialized successfully"
    return 0
}

# Run initialization
init_sudo_access "$@"