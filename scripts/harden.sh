#!/bin/bash
# Source common functions and initialize script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Initialize variables with defaults
declare -A CONFIG=(
    [SSH_PORT]="22"
    [SSH_ALLOW_USERS]=""
    [ADMIN_EMAIL]="root@localhost"
    [FIREWALL_ADDITIONAL_PORTS]="80,443"
    [MFA_ENABLED]="yes"
    [ENABLE_AUTO_UPDATES]="yes"
    [ENABLE_IPV6]="no"
)

# Load and validate configuration
load_configuration() {
    local config_file="${1:-/etc/server-hardening/hardening.conf}"
    
    if [[ -f "$config_file" ]]; then
        log "INFO" "Loading configuration from $config_file"
        # shellcheck source=/dev/null
        source "$config_file" || error_exit "Failed to load configuration"
        
        # Update CONFIG array with loaded values
        CONFIG[SSH_PORT]=${SSH_PORT:-${CONFIG[SSH_PORT]}}
        CONFIG[SSH_ALLOW_USERS]=${SSH_ALLOW_USERS:-${CONFIG[SSH_ALLOW_USERS]}}
        CONFIG[ADMIN_EMAIL]=${ADMIN_EMAIL:-${CONFIG[ADMIN_EMAIL]}}
        CONFIG[FIREWALL_ADDITIONAL_PORTS]=${FIREWALL_ADDITIONAL_PORTS:-${CONFIG[FIREWALL_ADDITIONAL_PORTS]}}
        CONFIG[MFA_ENABLED]=${MFA_ENABLED:-${CONFIG[MFA_ENABLED]}}
        CONFIG[ENABLE_AUTO_UPDATES]=${ENABLE_AUTO_UPDATES:-${CONFIG[ENABLE_AUTO_UPDATES]}}
        CONFIG[ENABLE_IPV6]=${ENABLE_IPV6:-${CONFIG[ENABLE_IPV6]}}
    fi
    
    # Validate configuration
    validate_configuration
}

validate_configuration() {
    # Validate SSH port
    if ! [[ "${CONFIG[SSH_PORT]}" =~ ^[0-9]+$ ]] || \
       (( CONFIG[SSH_PORT] < 1 || CONFIG[SSH_PORT] > 65535 )); then
        error_exit "Invalid SSH_PORT: '${CONFIG[SSH_PORT]}'. Must be between 1 and 65535"
    fi
    
    # Validate SSH_ALLOW_USERS
    if [[ -z "${CONFIG[SSH_ALLOW_USERS]}" ]]; then
        error_exit "SSH_ALLOW_USERS must be configured"
    fi
    
    # Validate email format
    if [[ ! "${CONFIG[ADMIN_EMAIL]}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error_exit "Invalid ADMIN_EMAIL format: ${CONFIG[ADMIN_EMAIL]}"
    fi
    
    # Validate ports
    local IFS=','
    read -ra ports <<< "${CONFIG[FIREWALL_ADDITIONAL_PORTS]}"
    for port in "${ports[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
            error_exit "Invalid port in FIREWALL_ADDITIONAL_PORTS: '$port'"
        fi
    done
    
    # Validate yes/no options
    local yes_no_vars=("MFA_ENABLED" "ENABLE_AUTO_UPDATES" "ENABLE_IPV6")
    for var in "${yes_no_vars[@]}"; do
        if [[ ! "${CONFIG[$var],,}" =~ ^(yes|no)$ ]]; then
            error_exit "Invalid $var value: '${CONFIG[$var]}'. Must be 'yes' or 'no'"
        fi
    done
}

configure_ssh() {
    log "INFO" "Configuring SSH..."
    
    # Backup existing configuration
    backup_file "/etc/ssh/sshd_config"
    
    # Validate SSH keys for allowed users
    for user in ${CONFIG[SSH_ALLOW_USERS]}; do
        if ! check_ssh_key_setup "$user"; then
            error_exit "User $user does not have SSH keys configured"
        fi
    done
    
    # Generate new SSH config
    cat > "/etc/ssh/sshd_config" << EOF
# Security hardened sshd_config
Port ${CONFIG[SSH_PORT]}
Protocol 2

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication ${CONFIG[MFA_ENABLED]}
UsePAM yes

# Allow only specific users
AllowUsers ${CONFIG[SSH_ALLOW_USERS]}

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
    
    systemctl restart sshd || error_exit "Failed to restart SSH service"
}

configure_firewall() {
    log "INFO" "Configuring firewall..."
    
    # Verify UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        error_exit "UFW is not installed"
    }
    
    # Reset UFW with confirmation
    if ! ufw --force reset; then
        error_exit "Failed to reset UFW"
    fi
    
    # Configure default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    if ! ufw allow "${CONFIG[SSH_PORT]}"/tcp; then
        error_exit "Failed to configure SSH port in firewall"
    fi
    
    # Allow additional ports
    local IFS=','
    read -ra ports <<< "${CONFIG[FIREWALL_ADDITIONAL_PORTS]}"
    for port in "${ports[@]}"; do
        if ! ufw allow "$port"/tcp; then
            log "WARNING" "Failed to add port $port to firewall"
        fi
    done
    
    # Enable firewall
    if ! ufw --force enable; then
        error_exit "Failed to enable firewall"
    fi
}

configure_fail2ban() {
    log "INFO" "Configuring fail2ban..."
    
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        error_exit "fail2ban is not installed"
    fi
    
    backup_file "/etc/fail2ban/jail.local"
    
    # Create fail2ban configuration
    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 24h
findtime = 48h
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ${CONFIG[SSH_PORT]}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 1h
bantime = 24h
EOF
    
    if ! systemctl restart fail2ban; then
        error_exit "Failed to restart fail2ban"
    fi
}

configure_automatic_updates() {
    [[ "${CONFIG[ENABLE_AUTO_UPDATES],,}" != "yes" ]] && return 0
    
    log "INFO" "Configuring automatic updates..."
    
    # Verify unattended-upgrades is installed
    if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
        error_exit "unattended-upgrades is not installed"
    fi
    
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Configure unattended upgrades
    cat > "/etc/apt/apt.conf.d/50unattended-upgrades" << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Mail "${CONFIG[ADMIN_EMAIL]}";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    
    # Enable automatic updates
    cat > "/etc/apt/apt.conf.d/20auto-upgrades" << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

configure_sysctl() {
    log "INFO" "Configuring system security settings..."
    
    backup_file "/etc/sysctl.conf"
    
    # Configure kernel parameters
    cat > "/etc/sysctl.d/99-security.conf" << EOF
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
net.ipv6.conf.all.disable_ipv6 = ${CONFIG[ENABLE_IPV6],,}
net.ipv6.conf.default.disable_ipv6 = ${CONFIG[ENABLE_IPV6],,}
net.ipv6.conf.lo.disable_ipv6 = ${CONFIG[ENABLE_IPV6],,}

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
    
    if ! sysctl -p /etc/sysctl.d/99-security.conf; then
        error_exit "Failed to apply sysctl settings"
    fi
}

main() {
    # Initialize script
    init_script
    
    # Load configuration
    load_configuration "/etc/server-hardening/hardening.conf"
    
    # Perform hardening steps with error handling
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_automatic_updates
    configure_sysctl
    
    log "SUCCESS" "System hardening completed successfully"
    
    # Print verification instructions
    cat << EOF
================================================================
System hardening complete. Please verify:
1. SSH access works on port ${CONFIG[SSH_PORT]}
2. Firewall is active and configured correctly
3. fail2ban is running and monitoring SSH
4. Automatic updates are properly configured
5. System security settings are applied

Run verify-system.sh to perform automated verification
================================================================
EOF
}

main "$@"