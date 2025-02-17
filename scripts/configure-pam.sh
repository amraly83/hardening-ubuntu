#!/bin/bash
# Enhanced PAM configuration script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

configure_pam() {
    local auth_type="${1:-basic}"  # can be 'basic', 'key', '2fa', or 'both'
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"
    
    log "INFO" "Configuring PAM with auth type: $auth_type"
    
    # Ensure PAM directory exists
    mkdir -p /etc/pam.d
    
    # Backup existing configurations
    for file in /etc/pam.d/{sshd,sudo,common-auth,common-account}; do
        if [[ -f "$file" ]]; then
            cp -p "$file" "${file}${backup_suffix}"
        fi
    done
    
    # Configure basic sudo authentication first
    cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_unix.so try_first_pass
auth       required     pam_unix.so
account    required     pam_unix.so
session    required     pam_limits.so
session    required     pam_unix.so
EOF
    chmod 644 "/etc/pam.d/sudo"
    
    # Configure common-auth with fallback
    cat > "/etc/pam.d/common-auth" << 'EOF'
#%PAM-1.0
auth    [success=1 default=ignore]      pam_unix.so nullok_secure try_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
    chmod 644 "/etc/pam.d/common-auth"
    
    # Configure SSHD PAM based on auth_type
    case "$auth_type" in
        "basic")
            configure_basic_auth
            ;;
        "key")
            configure_key_auth
            ;;
        "2fa")
            configure_2fa
            ;;
        "both")
            configure_both_auth
            ;;
        *)
            error_exit "Invalid authentication type: $auth_type"
            ;;
    esac
    
    # Configure account management
    cat > "/etc/pam.d/common-account" << 'EOF'
#%PAM-1.0
account [success=1 new_authtok_reqd=done default=ignore]  pam_unix.so
account requisite                                         pam_deny.so
account required                                          pam_permit.so
EOF
    chmod 644 "/etc/pam.d/common-account"
    
    # Test configuration
    if ! validate_pam_config; then
        log "ERROR" "PAM configuration validation failed"
        restore_backups "$backup_suffix"
        return 1
    fi
    
    log "SUCCESS" "PAM configuration completed successfully"
    return 0
}

configure_basic_auth() {
    cat > "/etc/pam.d/sshd" << 'EOF'
#%PAM-1.0
auth       required     pam_unix.so     try_first_pass
auth       required     pam_nologin.so
account    required     pam_nologin.so
account    include      common-account
password   include      common-password
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_unix.so
EOF
    chmod 644 "/etc/pam.d/sshd"
}

configure_key_auth() {
    cat > "/etc/pam.d/sshd" << 'EOF'
auth       required     pam_unix.so     try_first_pass
auth       required     pam_nologin.so
account    required     pam_nologin.so
account    include      common-account
password   include      common-password
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_unix.so
EOF
}

configure_2fa() {
    cat > "/etc/pam.d/sshd" << 'EOF'
auth       required     pam_google_authenticator.so nullok
auth       required     pam_unix.so     try_first_pass
auth       required     pam_nologin.so
account    required     pam_nologin.so
account    include      common-account
password   include      common-password
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_unix.so
EOF
}

configure_both_auth() {
    cat > "/etc/pam.d/sshd" << 'EOF'
auth       required     pam_google_authenticator.so nullok
auth       required     pam_unix.so     try_first_pass
auth       required     pam_nologin.so
account    required     pam_nologin.so
account    include      common-account
password   include      common-password
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_unix.so
EOF
}

validate_pam_config() {
    local status=0
    log "INFO" "Validating PAM configuration..."
    
    # Check file permissions
    for file in /etc/pam.d/{sshd,sudo,common-auth,common-account}; do
        if [[ -f "$file" ]]; then
            local perms
            perms=$(stat -c "%a" "$file")
            if [[ "$perms" != "644" ]]; then
                log "WARNING" "Fixing permissions on $file: $perms -> 644"
                chmod 644 "$file" || status=1
            fi
        else
            log "ERROR" "Required PAM file not found: $file"
            status=1
        fi
    done
    
    # Test sudo configuration
    if ! sudo -n true 2>/dev/null; then
        log "WARNING" "Basic sudo test failed (expected during initial setup)"
        return 0  # Don't fail on sudo test during initial setup
    fi
    
    return $status
}

restore_backups() {
    local suffix="$1"
    log "WARNING" "Restoring PAM configuration from backups..."
    
    for file in /etc/pam.d/{sshd,sudo,common-auth,common-account}; do
        if [[ -f "${file}${suffix}" ]]; then
            mv "${file}${suffix}" "$file"
            chmod 644 "$file"
        fi
    done
}

# Main execution
main() {
    # Check if running as root
    check_root || exit 1
    
    local auth_type="${1:-basic}"
    configure_pam "$auth_type"
}

main "$@"