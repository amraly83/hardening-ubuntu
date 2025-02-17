#!/bin/bash
# Enhanced sudo initialization script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

init_sudo() {
    local username="$1"
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"
    
    # Backup existing sudo configuration
    cp -p /etc/sudoers "/etc/sudoers${backup_suffix}"
    
    # Create secure sudoers.d directory if it doesn't exist
    if [[ ! -d "/etc/sudoers.d" ]]; then
        mkdir -p "/etc/sudoers.d"
        chmod 750 "/etc/sudoers.d"
    fi
    
    # Create a custom sudo configuration for the user
    cat > "/etc/sudoers.d/01-${username}" << EOF
# Sudo configuration for $username
# Created by hardening script on $(date)

# User privilege specification
$username ALL=(ALL:ALL) ALL

# Security settings
Defaults:$username timestamp_timeout=15
Defaults:$username passwd_tries=3
Defaults:$username badpass_message="Invalid password. Access denied."
Defaults:$username log_input,log_output
Defaults:$username iolog_dir=/var/log/sudo-io/%{user}

# Allow session persistence for SSH agent
Defaults:$username env_keep += "SSH_AUTH_SOCK"

# Secure path
Defaults:$username secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
    
    # Set proper permissions
    chmod 440 "/etc/sudoers.d/01-${username}"
    
    # Create sudo I/O logging directory
    mkdir -p "/var/log/sudo-io/${username}"
    chmod 700 "/var/log/sudo-io/${username}"
    
    # Validate sudo configuration
    if ! visudo -c -f "/etc/sudoers" || ! visudo -c -f "/etc/sudoers.d/01-${username}"; then
        log "ERROR" "Invalid sudo configuration"
        mv "/etc/sudoers${backup_suffix}" /etc/sudoers
        rm -f "/etc/sudoers.d/01-${username}"
        return 1
    fi
    
    # Test sudo access
    if ! test_sudo_access "$username"; then
        log "ERROR" "Failed to verify sudo access"
        mv "/etc/sudoers${backup_suffix}" /etc/sudoers
        rm -f "/etc/sudoers.d/01-${username}"
        return 1
    fi
    
    # Set up sudo log rotation
    setup_sudo_logging
    
    log "SUCCESS" "Sudo initialization completed for $username"
    return 0
}

test_sudo_access() {
    local username="$1"
    local test_cmd="true"
    
    # Try sudo access with timeout
    timeout 5 su -c "sudo -n $test_cmd" "$username" >/dev/null 2>&1 || {
        # If immediate sudo fails, try with password prompt
        log "WARNING" "Non-password sudo failed, testing with password prompt..."
        if ! timeout 10 su -c "sudo $test_cmd" "$username" >/dev/null 2>&1; then
            return 1
        fi
    }
    
    return 0
}

setup_sudo_logging() {
    # Configure sudo log rotation
    cat > "/etc/logrotate.d/sudo" << 'EOF'
/var/log/sudo-io/*/*/*/*/* {
    rotate 7
    daily
    compress
    missingok
    notifempty
    create 0600 root root
}
EOF
    
    # Set up auditd rules for sudo
    if command -v auditctl >/dev/null 2>&1; then
        cat > "/etc/audit/rules.d/99-sudo.rules" << 'EOF'
-w /etc/sudoers -p wa -k sudo_conf_changes
-w /etc/sudoers.d/ -p wa -k sudo_conf_changes
-w /var/log/sudo-io -p wa -k sudo_log_access
EOF
        # Reload audit rules
        auditctl -R /etc/audit/rules.d/99-sudo.rules || true
    fi
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 username"
    exit 1
fi

init_sudo "$1"