#!/bin/bash
# Test admin user setup after deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Test admin user creation and verification
test_admin_setup() {
    local username="$1"
    local max_attempts=3
    local attempt=1
    
    log "INFO" "Testing admin setup for user: $username"
    
    # Clean the username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    log "DEBUG" "Using cleaned username: $username"
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Clean and reset sudo environment completely
    clean_sudo_env "$username"
    
    while [ $attempt -le $max_attempts ]; do
        log "INFO" "Verification attempt $attempt of $max_attempts"
        
        # Setup temporary NOPASSWD sudo access for testing
        if ! setup_sudo_access "$username" true; then
            log "ERROR" "Failed to setup initial sudo access"
            ((attempt++))
            sleep 2
            continue
        fi
        
        # Test sudo access
        if test_sudo_access "$username" 2; then
            log "SUCCESS" "Initial sudo access verification passed"
            
            # Switch to password-required configuration
            if setup_sudo_access "$username" false; then
                log "SUCCESS" "Final sudo configuration applied"
                return 0
            else
                log "ERROR" "Failed to apply final sudo configuration"
            fi
        fi
        
        ((attempt++))
        if [ $attempt -le $max_attempts ]; then
            log "WARNING" "Verification attempt failed, retrying..."
            clean_sudo_env "$username"
            sleep 3
        fi
    done
    
    log "ERROR" "Failed to verify admin setup after $max_attempts attempts"
    return 1
}

# Test PAM configuration
test_pam_config() {
    local username="$1"
    local status=0
    
    log "INFO" "Testing PAM configuration..."
    
    # Ensure PAM directory exists
    if [[ ! -d "/etc/pam.d" ]]; then
        log "WARNING" "Creating missing PAM directory"
        mkdir -p /etc/pam.d
        chmod 755 /etc/pam.d
    fi
    
    # Verify PAM files exist and have correct permissions
    local pam_files=("sudo" "su" "common-auth" "common-account")
    for file in "${pam_files[@]}"; do
        if [[ ! -f "/etc/pam.d/$file" ]]; then
            log "ERROR" "Missing PAM file: /etc/pam.d/$file"
            status=1
        else
            local perms
            perms=$(stat -c '%a' "/etc/pam.d/$file")
            if [[ "$perms" != "644" ]]; then
                log "WARNING" "Fixing permissions on /etc/pam.d/$file: $perms -> 644"
                chmod 644 "/etc/pam.d/$file" || status=1
            fi
        fi
    done
    
    # Verify PAM sudo configuration
    if ! grep -q "^auth.*pam_unix.so" /etc/pam.d/sudo 2>/dev/null; then
        log "WARNING" "PAM sudo configuration may be incomplete"
        status=1
    fi
    
    return $status
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 username"
        exit 1
    fi
    
    local username="$1"
    local failed=0
    
    # Check if running as root
    check_root || exit 1
    
    log "INFO" "=== Starting Admin User Verification ==="
    
    # Test PAM configuration first
    if ! test_pam_config "$username"; then
        log "ERROR" "PAM configuration verification failed"
        ((failed++))
    fi
    
    # Test admin setup
    if ! test_admin_setup "$username"; then
        log "ERROR" "Admin setup verification failed"
        ((failed++))
    fi
    
    # Print summary
    log "INFO" "=== Verification Summary ==="
    if [[ $failed -eq 0 ]]; then
        log "SUCCESS" "All admin user tests passed successfully"
    else
        log "ERROR" "$failed test(s) failed. Check the errors above and fix any issues"
    fi
    
    return "$failed"
}

# Run main function
main "$@"