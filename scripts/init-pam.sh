#!/bin/bash
# Initialize PAM configuration with proper cross-platform handling
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RESET='\033[0m'

# Function to safely backup PAM files
backup_pam_file() {
    local file="$1"
    local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
    
    if [[ -f "$file" ]]; then
        log "INFO" "Backing up ${file}..."
        cp -p "$file" "$backup" || {
            log "ERROR" "Failed to backup ${file}"
            return 1
        }
        chmod --reference="$file" "$backup" 2>/dev/null || chmod 644 "$backup"
    fi
    return 0
}

# Initialize basic PAM configuration
init_basic_pam() {
    # Backup existing configurations
    backup_pam_file "/etc/pam.d/sudo" || return 1
    backup_pam_file "/etc/pam.d/su" || return 1
    
    # Create directory if it doesn't exist
    mkdir -p /etc/pam.d
    
    # Create basic sudo PAM configuration
    cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_unix.so try_first_pass
auth       required     pam_unix.so
account    required     pam_unix.so
session    required     pam_limits.so
session    required     pam_unix.so
EOF
    chmod 644 "/etc/pam.d/sudo"
    
    # Create basic su PAM configuration
    cat > "/etc/pam.d/su" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_rootok.so
auth       required     pam_unix.so try_first_pass
account    required     pam_unix.so
session    required     pam_unix.so
EOF
    chmod 644 "/etc/pam.d/su"
    
    # Ensure common-auth exists with basic configuration
    if [[ ! -f "/etc/pam.d/common-auth" ]]; then
        cat > "/etc/pam.d/common-auth" << 'EOF'
#%PAM-1.0
auth    [success=1 default=ignore]  pam_unix.so nullok_secure try_first_pass
auth    requisite                   pam_deny.so
auth    required                    pam_permit.so
EOF
        chmod 644 "/etc/pam.d/common-auth"
    fi
    
    # Create basic group configuration
    cat > "/etc/pam.d/common-account" << 'EOF'
#%PAM-1.0
account [success=1 new_authtok_reqd=done default=ignore]  pam_unix.so
account requisite                                         pam_deny.so
account required                                         pam_permit.so
EOF
    chmod 644 "/etc/pam.d/common-account"
    
    return 0
}

# Verify PAM configuration
verify_pam_config() {
    local errors=0
    
    # Check file permissions
    for file in /etc/pam.d/{sudo,su,common-auth,common-account}; do
        if [[ -f "$file" ]]; then
            local perms
            perms=$(stat -c "%a" "$file")
            if [[ "$perms" != "644" ]]; then
                log "WARNING" "Fixing permissions on ${file} (${perms} -> 644)"
                chmod 644 "$file" || ((errors++))
            fi
        else
            log "ERROR" "Required PAM file ${file} not found"
            ((errors++))
        fi
    done
    
    # Test sudo configuration
    if ! sudo -n true 2>/dev/null; then
        log "WARNING" "Basic sudo test failed"
        ((errors++))
    fi
    
    return $errors
}

# Main function
main() {
    local status=0
    
    log "INFO" "Initializing PAM configuration..."
    
    # Check if running as root
    check_root || exit 1
    
    # Initialize basic PAM configuration
    if ! init_basic_pam; then
        log "ERROR" "Failed to initialize PAM configuration"
        status=1
    fi
    
    # Verify configuration
    log "INFO" "Verifying PAM configuration..."
    if ! verify_pam_config; then
        log "WARNING" "PAM configuration verification had issues"
        status=1
    fi
    
    if [[ $status -eq 0 ]]; then
        log "SUCCESS" "PAM initialization completed successfully"
    else
        log "WARNING" "PAM initialization completed with warnings"
    fi
    
    return $status
}

# Run main function
main "$@"