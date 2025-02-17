#!/bin/bash
# Main installation wrapper script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Configuration variables
readonly LOG_FILE="/var/log/server-hardening.log"
readonly BACKUP_DIR="/var/backups/server-hardening/$(date +%Y%m%d_%H%M%S)"
readonly CONFIG_DIR="/etc/server-hardening"
readonly LOCK_FILE="$SCRIPT_DIR/.install.lock"
readonly MAX_RETRIES=3
readonly RETRY_DELAY=5

# Create backup directory
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Trap for cleanup on script exit
trap cleanup EXIT INT TERM

cleanup() {
    if [[ -d "$LOCK_FILE" ]]; then
        rm -rf "$LOCK_FILE"
    fi
    # Kill any hanging processes
    for pid in $(jobs -p); do
        kill -TERM "$pid" 2>/dev/null || true
    done
}

check_installation_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        if [[ -d "$LOCK_FILE" ]]; then
            local lock_age
            lock_age=$(( $(date +%s) - $(stat -c %Y "$LOCK_FILE") ))
            if [[ $lock_age -gt 3600 ]]; then  # 1 hour timeout
                log "WARNING" "Removing stale installation lock"
                rm -rf "$LOCK_FILE"
                mkdir "$LOCK_FILE"
            else
                error_exit "Another installation is in progress"
            fi
        fi
    fi
}

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
            chmod 600 "$BACKUP_DIR/$(basename "$file").bak"
        fi
    done
    
    # Backup user data
    if [[ -d "/home" ]]; then
        find /home -maxdepth 2 -name ".ssh" -type d -exec cp -rp {} "$BACKUP_DIR"/ \;
        find "$BACKUP_DIR" -type f -exec chmod 600 {} \;
        find "$BACKUP_DIR" -type d -exec chmod 700 {} \;
    fi
}

rollback() {
    local stage="$1"
    log "WARNING" "Rolling back changes from stage: $stage"
    
    case "$stage" in
        "admin_user")
            if [[ -n "${NEW_USER:-}" ]]; then
                log "INFO" "Removing created admin user: $NEW_USER"
                userdel -r "$NEW_USER" 2>/dev/null || true
            fi
            ;;
        "ssh_config")
            if [[ -f "$BACKUP_DIR/sshd_config.bak" ]]; then
                log "INFO" "Restoring SSH configuration"
                cp -f "$BACKUP_DIR/sshd_config.bak" /etc/ssh/sshd_config
                chmod 600 /etc/ssh/sshd_config
                systemctl restart sshd || true
            fi
            ;;
        "firewall")
            log "INFO" "Resetting firewall configuration"
            ufw --force reset || true
            if [[ -f "$BACKUP_DIR/user.rules.bak" ]]; then
                cp -f "$BACKUP_DIR/user.rules.bak" /etc/ufw/user.rules
                chmod 640 /etc/ufw/user.rules
                ufw --force reload || true
            fi
            ;;
        "2fa")
            if [[ -n "${NEW_USER:-}" ]]; then
                log "INFO" "Removing 2FA configuration"
                rm -f "/home/$NEW_USER/.google_authenticator" || true
                sed -i '/auth.*pam_google_authenticator.so/d' /etc/pam.d/sshd || true
            fi
            ;;
        "pam")
            for file in common-auth sshd; do
                if [[ -f "$BACKUP_DIR/${file}.bak" ]]; then
                    log "INFO" "Restoring PAM configuration: $file"
                    cp -f "$BACKUP_DIR/${file}.bak" "/etc/pam.d/$file"
                    chmod 644 "/etc/pam.d/$file"
                fi
            done
            ;;
        *)
            log "ERROR" "Unknown rollback stage: $stage"
            ;;
    esac
}

verify_with_retry() {
    local script="$1"
    shift
    local retry=0
    local success=false
    
    while (( retry < MAX_RETRIES )); do
        if [[ $retry -gt 0 ]]; then
            log "INFO" "Retrying verification (attempt $((retry + 1))/$MAX_RETRIES)..."
            sleep "$((RETRY_DELAY * retry))"
        fi
        
        if "$script" "$@" 2>&1 | tee -a "$LOG_FILE"; then
            success=true
            break
        fi
        
        ((retry++))
    done
    
    if [[ "$success" != "true" ]]; then
        return 1
    fi
    return 0
}

main() {
    local stage=""
    local -a failed_stages=()
    
    # Check installation lock
    check_installation_lock
    
    # Start installation
    log "INFO" "Starting server hardening installation..."
    
    # Verify initial system state
    stage="state_verification"
    if ! verify_with_retry "${SCRIPT_DIR}/verify-state.sh"; then
        error_exit "System state verification failed - Please check logs and resolve issues"
    fi
    
    # Fix critical permissions first
    stage="permissions"
    if ! verify_with_retry "${SCRIPT_DIR}/fix-permissions.sh"; then
        error_exit "Failed to fix critical permissions"
    fi
    
    # Run preflight checks
    stage="preflight"
    if ! verify_with_retry "${SCRIPT_DIR}/preflight.sh"; then
        error_exit "Preflight checks failed"
    fi
    
    # Backup existing configuration
    backup_config
    
    # Create and configure admin user
    stage="admin_user"
    if ! verify_with_retry "${SCRIPT_DIR}/create-admin.sh"; then
        failed_stages+=("$stage")
        rollback "$stage"
    fi
    
    # Configure SSH
    stage="ssh_config"
    if ! verify_with_retry "${SCRIPT_DIR}/setup-ssh-key.sh" "${NEW_USER:-}"; then
        failed_stages+=("$stage")
        rollback "$stage"
    fi
    
    # Setup 2FA if enabled
    if [[ "${MFA_ENABLED:-yes}" == "yes" ]]; then
        stage="2fa"
        if ! verify_with_retry "${SCRIPT_DIR}/setup-2fa.sh" "${NEW_USER:-}"; then
            failed_stages+=("$stage")
            rollback "$stage"
        fi
    fi
    
    # Apply system hardening
    stage="hardening"
    if ! verify_with_retry "${SCRIPT_DIR}/harden.sh"; then
        failed_stages+=("$stage")
        rollback "$stage"
    fi
    
    # Run final system verification
    stage="system_verification"
    if ! verify_with_retry "${SCRIPT_DIR}/verify-system.sh" "${NEW_USER:-}"; then
        failed_stages+=("$stage")
    fi
    
    # Generate final report
    if ! "${SCRIPT_DIR}/verify-deployment.sh" "${NEW_USER:-}" > "${BACKUP_DIR}/deployment-report.txt" 2>&1; then
        log "WARNING" "Deployment verification found issues"
        failed_stages+=("deployment")
    fi
    
    # Check if any stages failed
    if (( ${#failed_stages[@]} > 0 )); then
        log "ERROR" "Installation failed at stages: ${failed_stages[*]}"
        echo
        echo "=== Installation Failed ==="
        echo "The following stages failed:"
        printf '%s\n' "${failed_stages[@]}"
        echo
        echo "Please check the following files for details:"
        echo "1. Installation Log: $LOG_FILE"
        echo "2. System State Report: /var/log/system-state-report.txt"
        echo "3. Deployment Report: ${BACKUP_DIR}/deployment-report.txt"
        exit 1
    fi
    
    log "SUCCESS" "Server hardening completed successfully"
    echo
    echo "=== Installation Complete ==="
    echo "Please review the following files:"
    echo "1. Installation Log: $LOG_FILE"
    echo "2. Configuration Backup: $BACKUP_DIR"
    echo "3. Deployment Report: ${BACKUP_DIR}/deployment-report.txt"
    echo
    echo "IMPORTANT: Test SSH access with the new configuration before logging out!"
}

# Run main with error handling
main "$@"