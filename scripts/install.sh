#!/bin/bash
# Main installation wrapper script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

LOG_FILE="/var/log/server-hardening.log"
BACKUP_DIR="/var/backups/server-hardening/$(date +%Y%m%d_%H%M%S)"
CONFIG_DIR="/etc/server-hardening"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Trap for cleanup on script exit
trap cleanup EXIT

cleanup() {
    if [[ -f "$SCRIPT_DIR/.install.lock" ]]; then
        rm -f "$SCRIPT_DIR/.install.lock"
    fi
}

# Ensure only one installation runs at a time
if ! mkdir "$SCRIPT_DIR/.install.lock" 2>/dev/null; then
    error_exit "Another installation is in progress"
fi

# Backup existing configuration
backup_config() {
    log "INFO" "Backing up current configuration..."
    
    # List of critical files to backup
    local files=(
        "/etc/ssh/sshd_config"
        "/etc/pam.d/sshd"
        "/etc/pam.d/common-auth"
        "/etc/fail2ban/jail.local"
        "/etc/ufw/user.rules"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            cp -p "$file" "$BACKUP_DIR/$(basename "$file").bak"
        fi
    done
    
    # Backup user data
    if [[ -d "/home" ]]; then
        find /home -maxdepth 2 -name ".ssh" -type d -exec cp -rp {} "$BACKUP_DIR"/ \;
    fi
}

# Function to rollback changes if something fails
rollback() {
    local stage="$1"
    log "WARNING" "Rolling back changes from stage: $stage"
    
    case "$stage" in
        "admin_user")
            if [[ -n "${NEW_USER:-}" ]]; then
                userdel -r "$NEW_USER" || true
            fi
            ;;
        "ssh_config")
            if [[ -f "$BACKUP_DIR/sshd_config.bak" ]]; then
                cp -f "$BACKUP_DIR/sshd_config.bak" /etc/ssh/sshd_config
                systemctl restart sshd
            fi
            ;;
        "firewall")
            ufw --force reset
            if [[ -f "$BACKUP_DIR/user.rules.bak" ]]; then
                cp -f "$BACKUP_DIR/user.rules.bak" /etc/ufw/user.rules
                ufw --force reload
            fi
            ;;
        *)
            log "ERROR" "Unknown rollback stage: $stage"
            ;;
    esac
}

# Main installation flow
main() {
    local stage=""
    
    # Start installation
    log "INFO" "Starting server hardening installation..."
    
    # Fix critical permissions first
    stage="permissions"
    if ! "${SCRIPT_DIR}/fix-permissions.sh"; then
        error_exit "Failed to fix critical permissions"
    fi
    
    # Run preflight checks
    stage="preflight"
    if ! "${SCRIPT_DIR}/preflight.sh"; then
        error_exit "Preflight checks failed"
    fi
    
    # Backup existing configuration
    backup_config
    
    # Create and configure admin user
    stage="admin_user"
    if ! "${SCRIPT_DIR}/create-admin.sh"; then
        rollback "$stage"
        error_exit "Failed to create admin user"
    fi
    
    # Configure SSH
    stage="ssh_config"
    if ! "${SCRIPT_DIR}/setup-ssh-key.sh" "${NEW_USER:-}"; then
        rollback "$stage"
        error_exit "Failed to configure SSH"
    fi
    
    # Setup 2FA if enabled
    if [[ "${MFA_ENABLED:-yes}" == "yes" ]]; then
        stage="2fa"
        if ! "${SCRIPT_DIR}/setup-2fa.sh" "${NEW_USER:-}"; then
            rollback "$stage"
            error_exit "Failed to configure 2FA"
        fi
    fi
    
    # Apply system hardening
    stage="hardening"
    if ! "${SCRIPT_DIR}/harden.sh"; then
        rollback "$stage"
        error_exit "Failed to apply system hardening"
    fi
    
    # Run validation suite
    stage="validation"
    if ! "${SCRIPT_DIR}/validate.sh" "${NEW_USER:-}"; then
        log "WARNING" "Some validations failed. Please check the validation report."
    fi
    
    # Generate final report
    stage="reporting"
    if ! "${SCRIPT_DIR}/verify-deployment.sh" "${NEW_USER:-}"; then
        log "WARNING" "Deployment verification found issues. Please check the deployment report."
    fi
    
    log "SUCCESS" "Server hardening completed successfully"
    echo
    echo "=== Installation Complete ==="
    echo "Please review the following files:"
    echo "1. Validation Report: /var/log/hardening-validation-report.txt"
    echo "2. Installation Log: $LOG_FILE"
    echo "3. Configuration Backup: $BACKUP_DIR"
    echo
    echo "IMPORTANT: Test SSH access with the new configuration before logging out!"
}

# Run main with error handling
main "$@"