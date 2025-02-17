#!/bin/bash
# Enhanced PAM configuration script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

configure_pam() {
    local auth_type="${1:-both}"  # can be 'key', '2fa', or 'both'
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"
    
    # Backup existing configurations
    for file in /etc/pam.d/{sshd,common-auth,common-account}; do
        cp -p "$file" "${file}${backup_suffix}"
    done
    
    # Configure common-auth with fallback
    cat > "/etc/pam.d/common-auth" << 'EOF'
auth    [success=1 default=ignore]      pam_unix.so nullok_secure try_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF

    # Configure SSHD PAM
    case "$auth_type" in
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
account [success=1 new_authtok_reqd=done default=ignore]  pam_unix.so
account requisite                                         pam_deny.so
account required                                          pam_permit.so
EOF

    # Test configuration
    if ! validate_pam_config; then
        log "ERROR" "PAM configuration validation failed"
        restore_backups "$backup_suffix"
        return 1
    fi
    
    log "SUCCESS" "PAM configuration completed successfully"
    return 0
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
    # Test PAM configuration without breaking current session
    if ! pam-auth-update --package >/dev/null 2>&1; then
        return 1
    fi
    
    # Verify basic auth still works
    if ! pamtester -v sudo root authenticate 2>/dev/null; then
        return 1
    fi
    
    return 0
}

restore_backups() {
    local suffix="$1"
    log "WARNING" "Restoring PAM configuration from backups..."
    
    for file in /etc/pam.d/{sshd,common-auth,common-account}; do
        if [[ -f "${file}${suffix}" ]]; then
            mv "${file}${suffix}" "$file"
        fi
    done
}

# Main execution
if [[ $# -lt 1 ]]; then
    auth_type="both"
else
    auth_type="$1"
fi

configure_pam "$auth_type"