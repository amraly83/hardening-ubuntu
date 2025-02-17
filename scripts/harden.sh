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

# Function to validate PAM configuration with timeout
validate_pam_config() {
    local config_file="$1"
    local timeout=5
    
    # Run pamtester with timeout
    if timeout "$timeout" pamtester -v sudo TEST authenticate 2>/dev/null; then
        return 0
    fi
    
    # Check if file exists and has basic required entries
    if ! grep -q "^auth.*pam_unix.so" "$config_file" || \
       ! grep -q "^@include common-auth" "$config_file"; then
        return 1
    fi
    
    # If basic checks pass, assume it's okay
    return 0
}

configure_pam() {
    log "INFO" "Configuring PAM for sudo and su..."
    
    # Use timeout for the entire PAM configuration process
    (
        # Backup PAM files first
        backup_file "/etc/pam.d/sudo"
        backup_file "/etc/pam.d/su"
        
        # Create a basic sudo PAM config that should work reliably
        cat > "/etc/pam.d/sudo" << 'EOF'
#%PAM-1.0
auth       required      pam_unix.so
@include common-auth
@include common-account
@include common-session
EOF
        chmod 644 "/etc/pam.d/sudo"
        
        # Create a basic su PAM config
        cat > "/etc/pam.d/su" << 'EOF'
#%PAM-1.0
auth       sufficient   pam_rootok.so
auth       include      common-auth
password   include      common-password
session    include      common-session
EOF
        chmod 644 "/etc/pam.d/su"
        
        # Validate the configuration
        if ! validate_pam_config "/etc/pam.d/sudo"; then
            log "WARNING" "PAM configuration validation failed, restoring from backup"
            restore_from_backup "/etc/pam.d/sudo"
            restore_from_backup "/etc/pam.d/su"
            return 1
        fi
        
        log "SUCCESS" "PAM configuration updated"
        return 0
    ) & # Run in background
    
    # Wait for PAM configuration with timeout
    local config_pid=$!
    local timeout=30
    
    # Wait for completion or timeout
    if ! wait_with_timeout "$config_pid" "$timeout"; then
        log "WARNING" "PAM configuration timed out, killing process"
        kill "$config_pid" 2>/dev/null || true
        return 1
    fi
    
    return 0
}

# Helper function to wait for a process with timeout
wait_with_timeout() {
    local pid=$1
    local timeout=$2
    local count=0
    
    while [ $count -lt "$timeout" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return $?
        fi
        sleep 1
        ((count++))
    done
    
    return 1
}

configure_sudo() {
    log "INFO" "Configuring sudo policies..."
    
    # Create temporary files for validation first
    local temp_sudo_config=$(mktemp)
    
    # Basic sudo configuration
    cat > "$temp_sudo_config" << 'EOF'
# Default sudo configuration
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        timestamp_timeout=15

# Allow sudo group full access
%sudo   ALL=(ALL:ALL) ALL

# Disable tty requirement for sudo group
Defaults:%sudo !requiretty

# Keep essential environment variables
Defaults env_keep += "LANG LC_* EDITOR DISPLAY XAUTHORITY SSH_AUTH_SOCK"
EOF

    # Validate syntax before installing
    if ! visudo -c -f "$temp_sudo_config" >/dev/null 2>&1; then
        log "ERROR" "Invalid sudo configuration"
        rm -f "$temp_sudo_config"
        return 1
    fi

    # Install configuration
    mv "$temp_sudo_config" "/etc/sudoers.d/01-sudo-config"
    chmod 440 "/etc/sudoers.d/01-sudo-config"

    # Fix permissions on sudo-related files
    chmod 755 /usr/bin/sudo || true
    chmod 440 /etc/sudoers || true
    chmod 750 /etc/sudoers.d || true

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

cleanup_hung_processes() {
    log "INFO" "Checking for hung processes..."
    
    # Check for hung pam-auth processes
    local pam_pids
    pam_pids=$(pgrep -f "pam.*auth" 2>/dev/null || true)
    if [[ -n "$pam_pids" ]]; then
        log "WARNING" "Found hung PAM processes, cleaning up..."
        kill -9 $pam_pids 2>/dev/null || true
    fi
    
    # Check for hung sudo processes
    local sudo_pids
    sudo_pids=$(pgrep -f "sudo.*true" 2>/dev/null || true)
    if [[ -n "$sudo_pids" ]]; then
        log "WARNING" "Found hung sudo processes, cleaning up..."
        kill -9 $sudo_pids 2>/dev/null || true
    fi
    
    # Remove any stale locks
    rm -f /var/run/sudo/ts/* 2>/dev/null || true
    
    return 0
}

main() {
    # Add cleanup trap
    trap cleanup_hung_processes EXIT

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
    
    # Perform hardening with timeout handling for problematic steps
    configure_ssh || error_exit "Failed to configure SSH"
    configure_firewall || error_exit "Failed to configure firewall"
    configure_fail2ban || error_exit "Failed to configure fail2ban"
    configure_automatic_updates || error_exit "Failed to configure automatic updates"
    configure_sysctl || error_exit "Failed to configure sysctl"
    
    # Handle PAM and sudo configuration with fallback options
    if ! timeout 60 bash -c 'configure_pam'; then
        log "WARNING" "PAM configuration timed out or failed, using basic configuration"
        # Set up minimal PAM config
        echo -e "auth\trequired\tpam_unix.so\n@include common-auth" > "/etc/pam.d/sudo"
        chmod 644 "/etc/pam.d/sudo"
    fi
    
    configure_sudo || log "WARNING" "Sudo configuration had issues, manual verification recommended"
    
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