#!/bin/bash
# Enhanced sudo initialization script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

init_sudo() {
    local username="$1"
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"
    
    # Validate input
    if ! validate_username "$username"; then
        log "ERROR" "Invalid username format: $username"
        return 1
    fi
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User does not exist: $username"
        return 1
    fi
    
    # Clean sudo environment
    log "DEBUG" "Cleaning sudo environment..."
    sudo -K
    rm -f /run/sudo/ts/* 2>/dev/null || true
    
    # Backup existing sudo configuration
    if [[ -f /etc/sudoers ]]; then
        log "INFO" "Backing up sudoers configuration..."
        cp -p /etc/sudoers "/etc/sudoers${backup_suffix}"
    fi
    
    # Ensure sudo group exists
    if ! getent group sudo >/dev/null 2>&1; then
        log "INFO" "Creating sudo group..."
        groupadd sudo
    fi
    
    # Add user to sudo group
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "INFO" "Adding $username to sudo group..."
        usermod -aG sudo "$username"
        sg sudo -c "id" || true
    fi
    
    # Setup sudoers.d directory
    log "INFO" "Setting up sudoers.d directory..."
    mkdir -p "/etc/sudoers.d"
    chmod 750 "/etc/sudoers.d"
    
    # Create user sudo configuration
    log "INFO" "Creating sudo configuration for $username..."
    cat > "/etc/sudoers.d/01-${username}" << EOF
# Sudo configuration for $username
# Created by hardening script on $(date)

# User privilege specification
$username ALL=(ALL:ALL) ALL

# Security settings
Defaults:$username    timestamp_timeout=15
Defaults:$username    passwd_tries=3
Defaults:$username    badpass_message="Invalid password. Please try again."
Defaults:$username    log_input,log_output
Defaults:$username    iolog_dir=/var/log/sudo-io/%{user}
Defaults:$username    logfile=/var/log/sudo.log

# Environment settings
Defaults:$username    env_reset
Defaults:$username    env_keep += "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults:$username    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults:$username    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults:$username    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults:$username    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults:$username    env_keep += "SSH_AUTH_SOCK"

# Secure path
Defaults:$username    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
    
    # Set secure permissions
    chmod 440 "/etc/sudoers.d/01-${username}"
    
    # Setup logging directories
    setup_sudo_logging "$username"
    
    # Validate configurations
    if ! validate_sudo_config "$username"; then
        log "ERROR" "Sudo configuration validation failed"
        restore_sudo_backup "/etc/sudoers${backup_suffix}"
        return 1
    fi
    
    # Test sudo access
    if ! test_sudo_access "$username"; then
        log "ERROR" "Sudo access verification failed"
        restore_sudo_backup "/etc/sudoers${backup_suffix}"
        return 1
    fi
    
    log "SUCCESS" "Sudo initialization completed successfully for $username"
    return 0
}

validate_sudo_config() {
    local username="$1"
    local status=0
    
    # Check main sudoers file
    if ! visudo -c -f "/etc/sudoers" >/dev/null 2>&1; then
        log "ERROR" "Invalid main sudoers configuration"
        status=1
    fi
    
    # Check user-specific configuration
    if ! visudo -c -f "/etc/sudoers.d/01-${username}" >/dev/null 2>&1; then
        log "ERROR" "Invalid user sudoers configuration"
        status=1
    fi
    
    # Verify permissions
    local perms
    perms=$(stat -c '%a' "/etc/sudoers.d/01-${username}" 2>/dev/null || echo "000")
    if [[ "$perms" != "440" ]]; then
        log "ERROR" "Invalid permissions on user sudoers file: $perms (expected 440)"
        status=1
    fi
    
    return $status
}

test_sudo_access() {
    local username="$1"
    local max_retries=3
    local retry=0
    local success=false
    
    log "INFO" "Testing sudo access for $username..."
    
    while [[ $retry -lt $max_retries ]]; do
        # Try sudo access with timeout
        if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
            success=true
            break
        fi
        
        ((retry++))
        if [[ $retry -lt $max_retries ]]; then
            log "WARNING" "Sudo test failed, retrying ($retry/$max_retries)..."
            sleep 2
        fi
    done
    
    if [[ "$success" = true ]]; then
        log "SUCCESS" "Sudo access verified"
        return 0
    else
        log "ERROR" "Failed to verify sudo access after $max_retries attempts"
        return 1
    fi
}

setup_sudo_logging() {
    local username="$1"
    
    # Create logging directories
    mkdir -p "/var/log/sudo-io/${username}"
    chmod 700 "/var/log/sudo-io/${username}"
    
    # Setup log rotation
    cat > "/etc/logrotate.d/sudo" << 'EOF'
/var/log/sudo.log /var/log/sudo-io/*/*/*/*/* {
    rotate 7
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        systemctl kill -s USR1 sudo.service || true
    endscript
}
EOF
    
    # Setup audit rules if available
    if command -v auditctl >/dev/null 2>&1; then
        cat > "/etc/audit/rules.d/99-sudo.rules" << 'EOF'
# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudo_conf_changes
-w /etc/sudoers.d/ -p wa -k sudo_conf_changes
-w /var/log/sudo-io -p wa -k sudo_log_access

# Monitor sudo commands
-a exit,always -F arch=b64 -S execve -F exe=/usr/bin/sudo -k sudo_commands
-a exit,always -F arch=b32 -S execve -F exe=/usr/bin/sudo -k sudo_commands
EOF
        # Reload audit rules
        auditctl -R /etc/audit/rules.d/99-sudo.rules 2>/dev/null || true
    fi
}

restore_sudo_backup() {
    local backup_file="$1"
    
    if [[ -f "$backup_file" ]]; then
        log "INFO" "Restoring sudo configuration from backup..."
        mv "$backup_file" /etc/sudoers
        chmod 440 /etc/sudoers
    fi
}

# Main execution
main() {
    if [[ $# -lt 1 ]]; then
        log "ERROR" "Usage: $0 username"
        exit 1
    }
    
    # Check if running as root
    check_root || exit 1
    
    # Initialize sudo for user
    if ! init_sudo "$1"; then
        log "ERROR" "Sudo initialization failed"
        exit 1
    fi
}

main "$@"