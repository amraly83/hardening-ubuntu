#!/bin/bash
# Emergency recovery script for system access restoration
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

BACKUP_DIR="/var/backups/server-hardening"
RECOVERY_LOG="/var/log/recovery-actions.log"

recover_system_access() {
    local mode="${1:-all}"
    local username="${2:-}"
    local success=true
    
    log "WARNING" "Starting system recovery in $mode mode"
    
    case "$mode" in
        "ssh")
            restore_ssh_access
            ;;
        "2fa")
            restore_2fa_access "$username"
            ;;
        "sudo")
            restore_sudo_access "$username"
            ;;
        "all")
            restore_ssh_access
            [[ -n "$username" ]] && restore_2fa_access "$username"
            [[ -n "$username" ]] && restore_sudo_access "$username"
            ;;
        *)
            error_exit "Invalid recovery mode: $mode"
            ;;
    esac
    
    # Verify recovery
    if ! verify_system_access "$username"; then
        log "ERROR" "Recovery verification failed"
        return 1
    fi
    
    log "SUCCESS" "System recovery completed successfully"
    return 0
}

restore_ssh_access() {
    log "INFO" "Restoring SSH access..."
    
    # Find latest SSH backup
    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -name "sshd_config.*.bak" -type f -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2)
    
    if [[ -n "$latest_backup" ]]; then
        # Backup current config
        cp -p /etc/ssh/sshd_config "/etc/ssh/sshd_config.emergency.$(date +%s)"
        
        # Restore from backup
        cp -p "$latest_backup" /etc/ssh/sshd_config
        chmod 600 /etc/ssh/sshd_config
        
        # Enable password authentication temporarily
        sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
        
        # Restart SSH service
        systemctl restart sshd
    else
        # Create emergency SSH config
        cat > /etc/ssh/sshd_config << 'EOF'
# Emergency SSH Configuration
Port 22
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
        chmod 600 /etc/ssh/sshd_config
        systemctl restart sshd
    fi
}

restore_2fa_access() {
    local username="$1"
    log "INFO" "Restoring 2FA configuration for $username..."
    
    # Backup current PAM config
    cp -p /etc/pam.d/sshd "/etc/pam.d/sshd.emergency.$(date +%s)"
    
    # Temporarily disable 2FA
    sed -i '/pam_google_authenticator.so/d' /etc/pam.d/sshd
    
    # Update SSH config to disable 2FA requirement
    sed -i 's/^ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    
    systemctl restart sshd
}

restore_sudo_access() {
    local username="$1"
    log "INFO" "Restoring sudo access for $username..."
    
    # Ensure user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Add user to sudo group
    usermod -aG sudo "$username"
    
    # Create emergency sudo access
    echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/emergency_${username}"
    chmod 440 "/etc/sudoers.d/emergency_${username}"
}

verify_system_access() {
    local username="$1"
    local success=true
    
    # Verify SSH service
    if ! systemctl is-active --quiet sshd; then
        log "ERROR" "SSH service is not running"
        success=false
    fi
    
    # Test SSH port
    if ! nc -zv localhost 22 2>/dev/null; then
        log "ERROR" "SSH port 22 is not accessible"
        success=false
    fi
    
    # Verify user access if username provided
    if [[ -n "$username" ]]; then
        # Check user existence
        if ! id "$username" >/dev/null 2>&1; then
            log "ERROR" "User $username does not exist"
            success=false
        fi
        
        # Check sudo group membership
        if ! groups "$username" | grep -q "\bsudo\b"; then
            log "ERROR" "User $username is not in sudo group"
            success=false
        fi
        
        # Test sudo access
        if ! sudo -u "$username" sudo -n true 2>/dev/null; then
            log "ERROR" "Sudo access verification failed for $username"
            success=false
        fi
    fi
    
    return $([ "$success" == "true" ])
}

cleanup_emergency_access() {
    local username="$1"
    log "INFO" "Cleaning up emergency access..."
    
    # Remove emergency sudo configuration
    rm -f "/etc/sudoers.d/emergency_${username}"
    
    # Restore original SSH configuration
    if [[ -f "/etc/ssh/sshd_config.emergency.$(date +%Y%m%d)" ]]; then
        mv "/etc/ssh/sshd_config.emergency.$(date +%Y%m%d)" /etc/ssh/sshd_config
        systemctl restart sshd
    fi
    
    # Re-enable 2FA if it was disabled
    if [[ -f "/etc/pam.d/sshd.emergency.$(date +%Y%m%d)" ]]; then
        mv "/etc/pam.d/sshd.emergency.$(date +%Y%m%d)" /etc/pam.d/sshd
        systemctl restart sshd
    fi
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 [ssh|2fa|sudo|all] [username]"
    echo "Examples:"
    echo "  $0 ssh          # Restore SSH access only"
    echo "  $0 all admin    # Restore all access for user 'admin'"
    exit 1
fi

# Log all recovery actions
exec 1> >(tee -a "$RECOVERY_LOG") 2>&1

recover_system_access "$@"