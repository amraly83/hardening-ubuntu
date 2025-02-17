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
    
    # Generate new SSH config with proper variable expansion
    cat > "/etc/ssh/sshd_config" << EOF
# Security hardened sshd_config
Port $SSH_PORT
Protocol 2

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication ${MFA_ENABLED}
UsePAM yes

# Allow only specific users
AllowUsers $SSH_ALLOW_USERS

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

configure_pam() {
    log "INFO" "Configuring PAM for sudo and su..."
    
    # Backup PAM files
    backup_file "/etc/pam.d/sudo"
    backup_file "/etc/pam.d/su"
    
    # Configure sudo PAM
    cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_unix.so try_first_pass
auth       sufficient   pam_sudo.so
session    required     pam_env.so readenv=1 user_readenv=0
session    required     pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
session    required     pam_unix.so
EOF
    
    # Configure su PAM
    cat > "/etc/pam.d/su" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_rootok.so
auth       [success=ignore default=2] pam_succeed_if.so uid = 0 use_uid quiet
auth       sufficient   pam_wheel.so trust use_uid group=sudo
auth       sufficient   pam_unix.so try_first_pass
auth       required     pam_deny.so
password   include      common-password
session    include      common-session
session    optional     pam_xauth.so
EOF

    # Verify PAM configuration syntax
    if ! pam-auth-update --dry-run >/dev/null 2>&1; then
        log "ERROR" "Invalid PAM configuration"
        restore_from_backup "/etc/pam.d/sudo"
        restore_from_backup "/etc/pam.d/su"
        return 1
    fi
    
    log "SUCCESS" "PAM configuration updated"
    return 0
}

configure_sudo() {
    log "INFO" "Configuring sudo policies..."
    
    # Backup sudoers file
    backup_file "/etc/sudoers"
    backup_file "/etc/pam.d/sudo"
    
    # Configure sudo PAM to handle passwords correctly
    cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       required      pam_unix.so
auth       required      pam_env.so
session    required      pam_env.so readenv=1 user_readenv=0
session    required      pam_limits.so
session    required      pam_unix.so
session    required      pam_permit.so
@include common-auth
@include common-account
@include common-session-noninteractive
EOF

    # Create sudo group configuration
    cat > "/etc/sudoers.d/sudo-group" << 'EOF'
# Allow sudo group members to execute any command
%sudo   ALL=(ALL:ALL) ALL

# Do not require tty
Defaults:%sudo !requiretty

# Set PATH for sudo users
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Configure password handling
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        timestamp_timeout=15
EOF

    chmod 440 "/etc/sudoers.d/sudo-group"
    
    # Create specific rules for user switching
    cat > "/etc/sudoers.d/user-switching" << 'EOF'
# Allow sudo users to switch between each other without re-entering password
Defaults:%sudo !tty_tickets
Defaults:%sudo timestamp_timeout=15

# Keep environment variables needed for proper operation
Defaults env_keep += "LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET"
Defaults env_keep += "HOME EDITOR SYSTEMD_EDITOR"
Defaults env_keep += "XAUTHORITY DISPLAY SSH_AUTH_SOCK"
EOF

    chmod 440 "/etc/sudoers.d/user-switching"
    
    # Validate sudoers configuration
    if ! visudo -c -f /etc/sudoers; then
        log "ERROR" "Invalid sudoers configuration"
        rm -f "/etc/sudoers.d/sudo-group"
        rm -f "/etc/sudoers.d/user-switching"
        return 1
    fi
    
    # Fix permissions on important directories
    chmod 755 /usr/bin/sudo
    chmod 440 /etc/sudoers
    chmod 750 /etc/sudoers.d
    
    log "SUCCESS" "Sudo configuration updated"
    return 0
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
    
    # Set default config path
    CONFIG_FILE="${CONFIG_FILE:-/etc/server-hardening/hardening.conf}"
    
    # If no config exists, copy example and prompt for review
    if [[ ! -f "$CONFIG_FILE" ]]; then
        local example_config="$(dirname "${BASH_SOURCE[0]}")/../examples/config/hardening.conf.example"
        if [[ ! -f "$example_config" ]]; then
            error_exit "Example configuration file not found: $example_config"
        fi
        
        # Copy example config
        cp "$example_config" "$CONFIG_FILE" || error_exit "Failed to copy example config"
        chmod 600 "$CONFIG_FILE"
        
        # Show configuration and prompt for review
        echo "================================================================"
        echo "No configuration file found. Default configuration:"
        echo "----------------------------------------------------------------"
        cat "$CONFIG_FILE"
        echo "----------------------------------------------------------------"
        echo "Please review the configuration above."
        echo "You can:"
        echo "1. Continue with these default settings"
        echo "2. Exit, edit $CONFIG_FILE, and run again"
        echo "================================================================"
        
        if ! prompt_yes_no "Would you like to continue with default settings" "no"; then
            log "INFO" "Please edit $CONFIG_FILE and run this script again"
            exit 0
        fi
        
        log "INFO" "Proceeding with default configuration"
    fi
    
    # Source configuration file
    log "INFO" "Loading configuration from $CONFIG_FILE"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE" || error_exit "Failed to load configuration"
    
    # Validate required settings and their formats
    # Validate SSH port
    if [[ -z "${SSH_PORT}" ]]; then
        error_exit "Required configuration variable SSH_PORT is not set in $CONFIG_FILE"
    fi
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        error_exit "Invalid SSH_PORT: '$SSH_PORT'. Must be a number between 1 and 65535"
    fi
    
    # Validate SSH allow users
    if [[ -z "${SSH_ALLOW_USERS}" ]]; then
        error_exit "Required configuration variable SSH_ALLOW_USERS is not set in $CONFIG_FILE"
    fi
    
    # Validate firewall ports
    if [[ -z "${FIREWALL_ADDITIONAL_PORTS}" ]]; then
        error_exit "Required configuration variable FIREWALL_ADDITIONAL_PORTS is not set in $CONFIG_FILE"
    fi
    for port in $(echo "$FIREWALL_ADDITIONAL_PORTS" | tr ',' ' '); do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            error_exit "Invalid port in FIREWALL_ADDITIONAL_PORTS: '$port'. Must be a number between 1 and 65535"
        fi
    done
    
    # Convert yes/no settings to proper format
    MFA_ENABLED=$(echo "${MFA_ENABLED:-yes}" | tr '[:upper:]' '[:lower:]')
    ENABLE_AUTO_UPDATES=$(echo "${ENABLE_AUTO_UPDATES:-yes}" | tr '[:upper:]' '[:lower:]')
    ENABLE_IPV6=$(echo "${ENABLE_IPV6:-no}" | tr '[:upper:]' '[:lower:]')
    
    # Validate yes/no settings
    for var in MFA_ENABLED ENABLE_AUTO_UPDATES ENABLE_IPV6; do
        if [[ ! "${!var}" =~ ^(yes|no)$ ]]; then
            error_exit "Invalid value for $var: '${!var}'. Must be 'yes' or 'no'"
        fi
    done
    
    # Perform hardening
    configure_ssh || error_exit "Failed to configure SSH"
    configure_firewall || error_exit "Failed to configure firewall"
    configure_fail2ban || error_exit "Failed to configure fail2ban"
    configure_automatic_updates || error_exit "Failed to configure automatic updates"
    configure_sysctl || error_exit "Failed to configure sysctl"
    configure_pam || error_exit "Failed to configure PAM"
    configure_sudo || error_exit "Failed to configure sudo"
    
    log "INFO" "System hardening completed successfully"
    echo "================================================================"
    echo "System hardening complete. Please verify:"
    echo "1. SSH access works on port $SSH_PORT"
    echo "2. Firewall is active with correct rules"
    echo "3. fail2ban is running"
    echo "4. Automatic updates are configured"
    echo "5. User switching works without authentication for sudo users"
    echo "    Example: su - otheruser (should work without password)"
    echo "================================================================"
}

main "$@"