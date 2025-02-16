#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

# Configuration variables with defaults
SSH_PORT="3333"
SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
FIREWALL_ADDITIONAL_PORTS="80,443,3306,465,587,993,995"
MFA_ENABLED="yes"
ENABLE_AUTO_UPDATES="yes"
ENABLE_IPV6="no"

# Load configuration if exists
CONFIG_FILE="/etc/server-hardening/hardening.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    log "INFO" "Loading configuration from $CONFIG_FILE"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

configure_ssh() {
    log "INFO" "Configuring SSH..."
    
    # Backup SSH config
    backup_file "/etc/ssh/sshd_config"
    
    # Check for SSH keys before disabling password auth
    if [[ -n "$SSH_ALLOW_USERS" ]]; then
        for user in $SSH_ALLOW_USERS; do
            if ! check_ssh_key_setup "$user" 2>/dev/null; then
                error_exit "User $user does not have SSH keys configured. Please run setup-ssh-key.sh first"
            fi
        done
    else
        error_exit "SSH_ALLOW_USERS must be configured"
    fi
    
    # Generate new SSH config
    cat > "/etc/ssh/sshd_config" << 'EOF'
# Security hardened sshd_config
Port ${SSH_PORT}
Protocol 2

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication ${MFA_ENABLED}
UsePAM yes

# Allow only specific users
AllowUsers ${SSH_ALLOW_USERS}

# Security options
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 0
Banner /etc/issue.net

# Use strong algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
    
    # Test configuration
    if ! sshd -t; then
        log "ERROR" "SSH configuration test failed"
        restore_from_backup "/etc/ssh/sshd_config"
        error_exit "Invalid SSH configuration"
    fi
    
    systemctl restart sshd
}

configure_firewall() {
    log "INFO" "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow "$SSH_PORT"/tcp
    
    # Allow additional ports
    IFS=',' read -ra PORTS <<< "$FIREWALL_ADDITIONAL_PORTS"
    for port in "${PORTS[@]}"; do
        ufw allow "$port"/tcp
    done
    
    # Enable firewall
    ufw --force enable
}

configure_fail2ban() {
    log "INFO" "Configuring fail2ban..."
    
    # Backup fail2ban config
    backup_file "/etc/fail2ban/jail.local"
    
    # Create custom configuration
    cat > "/etc/fail2ban/jail.local" << 'EOF'
[DEFAULT]
bantime = 24h
findtime = 48h
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 1h
bantime = 24h
EOF
    
    systemctl restart fail2ban
}

configure_automatic_updates() {
    log "INFO" "Configuring automatic updates..."
    
    # Backup configuration
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Configure unattended upgrades
    cat > "/etc/apt/apt.conf.d/50unattended-upgrades" << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    
    # Enable automatic updates
    cat > "/etc/apt/apt.conf.d/20auto-upgrades" << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

configure_sysctl() {
    log "INFO" "Configuring system security settings..."
    
    # Backup sysctl config
    backup_file "/etc/sysctl.conf"
    
    # Configure kernel parameters
    cat > "/etc/sysctl.d/99-security.conf" << 'EOF'
# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv6 settings
net.ipv6.conf.all.disable_ipv6 = ${ENABLE_IPV6//yes/0}
net.ipv6.conf.default.disable_ipv6 = ${ENABLE_IPV6//yes/0}
net.ipv6.conf.lo.disable_ipv6 = ${ENABLE_IPV6//yes/0}

# System security
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
fs.suid_dumpable = 0

# Additional hardening
kernel.randomize_va_space = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF
    
    # Apply changes
    sysctl -p /etc/sysctl.d/99-security.conf
}

restore_from_backup() {
    local file="$1"
    local latest_backup
    
    latest_backup=$(find "$(dirname "$file")" -name "$(basename "$file").*.bak" -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2)
    
    if [[ -n "$latest_backup" ]]; then
        log "INFO" "Restoring $file from $latest_backup"
        cp -p "$latest_backup" "$file"
        return 0
    fi
    
    return 1
}

main() {
    if [[ "${1:-}" == "--restore" ]]; then
        log "INFO" "Restoring configuration from backups..."
        restore_from_backup "/etc/ssh/sshd_config" && systemctl restart sshd
        restore_from_backup "/etc/fail2ban/jail.local" && systemctl restart fail2ban
        restore_from_backup "/etc/apt/apt.conf.d/50unattended-upgrades"
        restore_from_backup "/etc/sysctl.conf" && sysctl -p
        log "INFO" "Restore completed"
        exit 0
    fi
    
    # Create necessary directories
    mkdir -p "/etc/server-hardening"
    
    # Copy example config if no config exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cp "$(dirname "${BASH_SOURCE[0]}")/../examples/config/hardening.conf.example" "$CONFIG_FILE"
        log "WARNING" "No configuration file found. Copied example to $CONFIG_FILE"
        log "INFO" "Please review and edit $CONFIG_FILE before running this script again"
        exit 1
    fi
    
    # Perform hardening
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_automatic_updates
    configure_sysctl
    
    log "INFO" "System hardening completed successfully"
    echo "================================================================"
    echo "System hardening complete. Please verify:"
    echo "1. SSH access works on port $SSH_PORT"
    echo "2. Firewall is active with correct rules"
    echo "3. fail2ban is running"
    echo "4. Automatic updates are configured"
    echo "================================================================"
}

main "$@"