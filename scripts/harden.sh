#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Script version and global variables
readonly VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/server-hardening.log"
readonly BACKUP_DIR="/var/backups/server-hardening"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"
readonly DATE=$(date +%Y%m%d_%H%M%S)
readonly CONFIG_FILE="${SCRIPT_DIR}/hardening.conf"
readonly LOCK_FILE="/var/run/server-hardening.lock"
readonly REQUIRED_SPACE=1024  # Required free space in MB

# Configuration variables with defaults
SSH_PORT="3333"
SSH_ALLOW_USERS="amraly"
ADMIN_EMAIL="amraly1983@gmail.com"
FAIL2BAN_BANTIME="24h"
FAIL2BAN_FINDTIME="48h"
FAIL2BAN_MAXRETRY="5"
GRUB_PASSWORD=""
MFA_ENABLED="yes"
FIREWALL_ADDITIONAL_PORTS="80,443,3306,465,587,993,995"
ENABLE_IPV6="no"
ENABLE_AUTO_UPDATES="yes"
ENABLE_AUTO_REBOOT="no"
AUTO_REBOOT_TIME="02:00"
UPDATE_EMAIL_REPORTS="yes"
UPDATE_EMAIL_LEVEL="on-change"
UPDATE_SCHEDULE="daily"
UPDATE_CUSTOM_CRON=""
UPDATE_DOWNLOAD_ONLY="no"
UPDATE_NOTIFY_NO_REBOOT="yes"
UPDATE_MAX_SIZE="100"

# Improved lock file handling
check_and_create_lock() {
    # Ensure directory exists
    lock_dir=$(dirname "${LOCK_FILE}")
    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir" || error_exit "Cannot create lock directory: $lock_dir"
    fi

    # Check if lock file exists and is valid
    if [[ -f "${LOCK_FILE}" ]]; then
        pid=$(cat "${LOCK_FILE}" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            error_exit "Another instance of the script is already running (PID: $pid)"
        else
            # Lock file exists but process is not running
            rm -f "${LOCK_FILE}"
        fi
    fi

    # Create new lock file
    echo $$ > "${LOCK_FILE}" || error_exit "Cannot create lock file"
}

# Trap handlers for cleanup
cleanup() {
    local rc=$?
    if [[ -f "${LOCK_FILE}" ]] && [[ "$(cat ${LOCK_FILE})" == "$$" ]]; then
        rm -f "${LOCK_FILE}"
    fi
    if [[ $rc -ne 0 ]]; then
        log "ERROR" "Script failed with exit code $rc"
        if [[ -d "${BACKUP_DIR}" ]]; then
            restore_from_backup
        fi
    fi
    exit $rc
}

trap cleanup EXIT
trap 'trap - HUP; cleanup' HUP
trap 'trap - INT; cleanup' INT
trap 'trap - TERM; cleanup' TERM

# Utility functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
    
    if [[ "${level}" == "ERROR" ]]; then
        logger -p user.err "server-hardening: ${message}"
    fi
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-yes}"
    local answer
    
    while true; do
        read -rp "$prompt [${default}]: " answer
        answer=${answer:-$default}
        case "${answer,,}" in
            yes|y) return 0 ;;
            no|n) return 1 ;;
            *) echo "Please answer 'yes' or 'no'" ;;
        esac
    done
}

prompt_value() {
    local prompt="$1"
    local default="$2"
    local answer
    
    read -rp "$prompt [${default}]: " answer
    echo "${answer:-$default}"
}

prompt_password() {
    local prompt="$1"
    local password1 password2
    
    while true; do
        read -srp "$prompt: " password1
        echo
        read -srp "Confirm password: " password2
        echo
        
        if [[ "$password1" == "$password2" ]]; then
            echo "$password1"
            break
        else
            echo "Passwords don't match. Please try again."
        fi
    done
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -p "$file" "${file}.${DATE}.bak" || log "WARNING" "Failed to backup $file"
    fi
}

# Validation functions
validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

validate_disk_space() {
    local free_space
    free_space=$(df -m /var | awk 'NR==2 {print $4}')
    if [ "${free_space}" -lt "${REQUIRED_SPACE}" ]; then
        error_exit "Insufficient disk space. Required: ${REQUIRED_SPACE}MB, Available: ${free_space}MB"
    fi
}

check_system_requirements() {
    log "INFO" "Checking system requirements..."
    
    if ! grep -q "Ubuntu" /etc/os-release; then
        error_exit "This script requires Ubuntu Server"
    fi
    
    local version
    version=$(lsb_release -rs)
    if [ "$(echo "$version < 20.04" | bc)" -eq 1 ]; then
        error_exit "This script requires Ubuntu 20.04 or later"
    fi
    
    local cpu_cores memory_mb
    cpu_cores=$(nproc)
    memory_mb=$(free -m | awk '/^Mem:/{print $2}')
    
    if [ "$cpu_cores" -lt 2 ]; then
        log "WARNING" "Less than 2 CPU cores available. Performance may be impacted."
    fi
    
    if [ "$memory_mb" -lt 2048 ]; then
        log "WARNING" "Less than 2GB RAM available. Performance may be impacted."
    fi
    
    validate_disk_space
    
    local required_commands=(
        "openssl"
        "awk"
        "sed"
        "grep"
        "systemctl"
        "ufw"
        "apt-get"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "Required command not found: $cmd"
        fi
    done
}

check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    local required_packages=(
        "auditd"
        "aide"
        "ufw"
        "libpam-google-authenticator"
        "apparmor"
        "apparmor-utils"
        "openssh-server"
        "postfix"
        "fail2ban"
    )

    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log "INFO" "Installing $package..."
            apt-get install -y "$package" || error_exit "Failed to install $package"
        fi
    done
}

# Improved backup system function
backup_system() {
    log "INFO" "Creating system backup..."
    
    # Create backup directory with proper permissions
    mkdir -p "${BACKUP_DIR}" || error_exit "Cannot create backup directory"
    chmod 700 "${BACKUP_DIR}"
    
    local backup_locations=(
        "/etc/ssh"
        "/etc/pam.d"
        "/etc/security"
        "/etc/ufw"
        "/etc/fail2ban"
        "/etc/audit"
        "/etc/sysctl.d"
        "/etc/apt/apt.conf.d"
    )
    
    local backup_date_dir="${BACKUP_DIR}/${DATE}"
    mkdir -p "$backup_date_dir"
    
    for location in "${backup_locations[@]}"; do
        if [[ -e "$location" ]]; then
            local dest_dir="${backup_date_dir}${location}"
            mkdir -p "$(dirname "$dest_dir")"
            cp -rp "$location" "$dest_dir" || log "WARNING" "Failed to backup $location"
        fi
    done
    
    # Create manifest with timestamps
    {
        echo "# Backup created on $(date)"
        echo "# System: $(uname -a)"
        find "${backup_date_dir}" -type f -exec md5sum {} \;
    } > "${backup_date_dir}/MANIFEST"
    
    chmod 600 "${backup_date_dir}/MANIFEST"
    log "INFO" "Backup completed at ${backup_date_dir}"
}

# Improved restore function
restore_from_backup() {
    local latest_backup
    if [[ -n "${DATE}" ]] && [[ -d "${BACKUP_DIR}/${DATE}" ]]; then
        latest_backup="${BACKUP_DIR}/${DATE}"
    else
        latest_backup=$(find "${BACKUP_DIR}" -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2)
    fi

    if [[ -d "$latest_backup" ]] && [[ -f "${latest_backup}/MANIFEST" ]]; then
        log "INFO" "Restoring system from backup: $latest_backup"
        
        while IFS= read -r line; do
            if [[ "$line" =~ ^#.*$ ]]; then continue; fi
            
            local checksum=$(echo "$line" | awk '{print $1}')
            local file_path=$(echo "$line" | awk '{print $2}')
            local original_path=${file_path#"$latest_backup"}
            
            if [[ -f "$file_path" ]]; then
                local dir=$(dirname "$original_path")
                if [[ ! -d "$dir" ]]; then
                    mkdir -p "$dir"
                fi
                cp -p "$file_path" "$original_path" || log "ERROR" "Failed to restore $original_path"
            fi
        done < "${latest_backup}/MANIFEST"
        
        log "INFO" "System restore completed from $latest_backup"
        return 0
    else
        log "ERROR" "No valid backup found for restoration"
        return 1
    fi
}

gather_user_input() {
    echo "=== Ubuntu Server Hardening Configuration ==="
    echo "Please provide the following information:"
    
    # SSH Configuration
    echo "--- SSH Configuration ---"
    SSH_PORT=$(prompt_value "Enter SSH port number" "$SSH_PORT")
    SSH_ALLOW_USERS=$(prompt_value "Enter allowed SSH users (space-separated, empty for all)" "$SSH_ALLOW_USERS")
    
    if prompt_yes_no "Enable Multi-Factor Authentication" "$MFA_ENABLED"; then
        MFA_ENABLED="yes"
    else
        MFA_ENABLED="no"
    fi
    
    # GRUB Password
    echo "--- GRUB Configuration ---"
    GRUB_PASSWORD=$(prompt_password "Enter GRUB bootloader password")
    
    # Network Configuration
    echo "--- Network Configuration ---"
    if prompt_yes_no "Enable IPv6" "$ENABLE_IPV6"; then
        ENABLE_IPV6="yes"
    else
        ENABLE_IPV6="no"
    fi
    
    FIREWALL_ADDITIONAL_PORTS=$(prompt_value "Enter additional ports to open (format: 80,443 for HTTP/HTTPS)" "$FIREWALL_ADDITIONAL_PORTS")
    
    # Automatic Updates Configuration
    echo "--- Automatic Updates Configuration ---"
    if prompt_yes_no "Enable automatic security updates" "$ENABLE_AUTO_UPDATES"; then
        ENABLE_AUTO_UPDATES="yes"
        
        echo "Select update schedule:"
        echo "1) Daily"
        echo "2) Weekly"
        echo "3) Custom schedule"
        while true; do
            read -rp "Enter choice [1-3]: " schedule_choice
            case $schedule_choice in
                1) UPDATE_SCHEDULE="daily" ; break ;;
                2) UPDATE_SCHEDULE="weekly" ; break ;;
                3) 
                    echo "Enter custom cron schedule (e.g., '0 3 * * 0' for Sunday 3AM):"
                    read -rp "Cron schedule: " UPDATE_CUSTOM_CRON
                    UPDATE_SCHEDULE="custom"
                    break 
                    ;;
                *) echo "Please enter 1, 2, or 3" ;;
            esac
        done

        if prompt_yes_no "Enable email reports for updates" "$UPDATE_EMAIL_REPORTS"; then
            UPDATE_EMAIL_REPORTS="yes"
            ADMIN_EMAIL=$(prompt_value "Enter administrator email" "$ADMIN_EMAIL")
            
            echo "Select email notification level:"
            echo "1) On any change (recommended)"
            echo "2) Only on errors"
            echo "3) Always send report"
            while true; do
                read -rp "Enter choice [1-3]: " email_choice
                case $email_choice in
                    1) UPDATE_EMAIL_LEVEL="on-change" ; break ;;
                    2) UPDATE_EMAIL_LEVEL="only-on-error" ; break ;;
                    3) UPDATE_EMAIL_LEVEL="always" ; break ;;
                    *) echo "Please enter 1, 2, or 3" ;;
                esac
            done
        fi

        UPDATE_MAX_SIZE=$(prompt_value "Enter maximum update size in MB before requiring approval" "$UPDATE_MAX_SIZE")
        
        if prompt_yes_no "Enable download-only mode (updates won't be installed automatically)" "no"; then
            UPDATE_DOWNLOAD_ONLY="yes"
        fi

        if prompt_yes_no "Enable automatic reboot after updates" "$ENABLE_AUTO_REBOOT"; then
            ENABLE_AUTO_REBOOT="yes"
            AUTO_REBOOT_TIME=$(prompt_value "Enter automatic reboot time (24h format)" "$AUTO_REBOOT_TIME")
        else
            ENABLE_AUTO_REBOOT="no"
            if prompt_yes_no "Send notification when reboot is needed" "yes"; then
                UPDATE_NOTIFY_NO_REBOOT="yes"
            fi
        fi
    fi
    
    save_configuration
}

save_configuration() {
    cat > "$CONFIG_FILE" <<EOF
# Hardening Configuration
SSH_PORT=$SSH_PORT
SSH_ALLOW_USERS=$SSH_ALLOW_USERS
ADMIN_EMAIL=$ADMIN_EMAIL
FAIL2BAN_BANTIME=$FAIL2BAN_BANTIME
FAIL2BAN_FINDTIME=$FAIL2BAN_FINDTIME
FAIL2BAN_MAXRETRY=$FAIL2BAN_MAXRETRY
MFA_ENABLED=$MFA_ENABLED
ENABLE_IPV6=$ENABLE_IPV6
FIREWALL_ADDITIONAL_PORTS=$FIREWALL_ADDITIONAL_PORTS
ENABLE_AUTO_UPDATES=$ENABLE_AUTO_UPDATES
ENABLE_AUTO_REBOOT=$ENABLE_AUTO_REBOOT
AUTO_REBOOT_TIME=$AUTO_REBOOT_TIME
UPDATE_EMAIL_REPORTS=$UPDATE_EMAIL_REPORTS
UPDATE_EMAIL_LEVEL=$UPDATE_EMAIL_LEVEL
UPDATE_SCHEDULE=$UPDATE_SCHEDULE
UPDATE_CUSTOM_CRON="$UPDATE_CUSTOM_CRON"
UPDATE_DOWNLOAD_ONLY=$UPDATE_DOWNLOAD_ONLY
UPDATE_NOTIFY_NO_REBOOT=$UPDATE_NOTIFY_NO_REBOOT
UPDATE_MAX_SIZE=$UPDATE_MAX_SIZE
EOF

    # Save GRUB password securely
    echo "$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 > "${CONFIG_FILE}.grub"
    chmod 600 "${CONFIG_FILE}.grub"
}

load_configuration() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
}

verify_ssh_keys() {
    local username="$1"
    local authorized_keys="/home/${username}/.ssh/authorized_keys"
    
    # Check if .ssh directory exists
    if [[ ! -d "/home/${username}/.ssh" ]]; then
        log "WARNING" "SSH directory not found for user ${username}"
        return 1
    fi
    
    # Check if authorized_keys exists and has content
    if [[ ! -f "$authorized_keys" ]] || [[ ! -s "$authorized_keys" ]]; then
        log "WARNING" "No SSH keys found for user ${username}"
        return 1
    fi
    
    # Verify permissions
    if [[ "$(stat -c %a "/home/${username}/.ssh")" != "700" ]]; then
        log "INFO" "Fixing .ssh directory permissions for ${username}"
        chmod 700 "/home/${username}/.ssh"
    fi
    
    if [[ "$(stat -c %a "$authorized_keys")" != "600" ]]; then
        log "INFO" "Fixing authorized_keys permissions for ${username}"
        chmod 600 "$authorized_keys"
    fi
    
    return 0
}

configure_ssh() {
    log "INFO" "Hardening SSH configuration..."
    
    # Verify SSH keys before proceeding
    local all_users_have_keys=true
    IFS=' ' read -ra USERS <<< "$SSH_ALLOW_USERS"
    
    for user in "${USERS[@]}"; do
        if ! verify_ssh_keys "$user"; then
            all_users_have_keys=false
            log "ERROR" "User ${user} does not have SSH keys configured"
        fi
    done
    
    if [[ "$all_users_have_keys" == "false" ]]; then
        if ! prompt_yes_no "Some users don't have SSH keys. Continuing will disable password authentication. Continue?" "no"; then
            error_exit "Please set up SSH keys for all users before running this script"
        fi
    fi
    
    backup_file "/etc/ssh/sshd_config"
    
    # First, create a temporary config and test it
    local temp_config="/etc/ssh/sshd_config.new"
    cat > "$temp_config" <<EOF
# Security hardened sshd_config
Port ${SSH_PORT}
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication ${MFA_ENABLED}
EOF

    if [[ -n "$SSH_ALLOW_USERS" ]]; then
        echo "AllowUsers $SSH_ALLOW_USERS" >> "$temp_config"
    fi

    if [[ "$MFA_ENABLED" == "yes" ]]; then
        echo "AuthenticationMethods publickey,keyboard-interactive" >> "$temp_config"
    else
        echo "AuthenticationMethods publickey" >> "$temp_config"
    fi

    cat >> "$temp_config" <<EOF
# Security
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Hardening
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
EOF

    # Test the configuration before applying
    if ! sshd -t -f "$temp_config"; then
        rm -f "$temp_config"
        error_exit "SSH configuration test failed"
    fi
    
    # Apply the configuration
    mv "$temp_config" "/etc/ssh/sshd_config"
    systemctl restart sshd || error_exit "Failed to restart SSH service"
    
    log "WARNING" "Password authentication has been disabled. Make sure you have working SSH key access!"
    echo "================================================================="
    echo "IMPORTANT: Password authentication has been disabled!"
    echo "Make sure you keep your SSH keys safe and have a backup."
    echo "If you get locked out, you will need console access to recover."
    echo "================================================================="
}

configure_firewall() {
    log "INFO" "Configuring UFW firewall..."
    
    ufw --force reset
    
    ufw default deny incoming
    ufw default deny outgoing
    
    ufw allow "${SSH_PORT}/tcp"
    ufw allow out 53
    ufw allow out 80
    ufw allow out 443
    ufw allow out 123
    
    if [[ -n "$FIREWALL_ADDITIONAL_PORTS" ]]; then
        IFS=',' read -ra PORTS <<< "$FIREWALL_ADDITIONAL_PORTS"
        for port in "${PORTS[@]}"; do
            ufw allow "$port"
        done
    fi
    
    if [[ "$ENABLE_IPV6" == "no" ]]; then
        sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
    fi
    
    ufw logging on
    ufw --force enable
}

configure_fail2ban() {
    log "INFO" "Configuring fail2ban..."
    
    backup_file "/etc/fail2ban/jail.local"
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = ${FAIL2BAN_BANTIME}
findtime = ${FAIL2BAN_FINDTIME}
maxretry = ${FAIL2BAN_MAXRETRY}

destemail = ${ADMIN_EMAIL}
sender = fail2ban@localhost
mta = mail
action = %(action_mwl)s

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
backend = systemd

[sshd-ddos]
enabled = true
port = ${SSH_PORT}
filter = sshd-ddos
logpath = /var/log/auth.log
backend = systemd
EOF

    systemctl restart fail2ban || error_exit "Failed to restart fail2ban"
}

configure_automatic_updates() {
    log "INFO" "Configuring automatic security updates..."
    
    apt-get install -y unattended-upgrades apt-listchanges

    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    backup_file "/etc/apt/apt.conf.d/20auto-upgrades"
    backup_file "/etc/apt/apt.conf.d/10periodic"
    
    cat > "/etc/apt/apt.conf.d/50unattended-upgrades" <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "${ENABLE_AUTO_REBOOT}";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::Size-Reporting "true";
Unattended-Upgrade::MaxSize "${UPDATE_MAX_SIZE}";
Unattended-Upgrade::Download-Only "${UPDATE_DOWNLOAD_ONLY}";
Unattended-Upgrade::Verbose "true";
EOF

    if [[ "$UPDATE_EMAIL_REPORTS" == "yes" ]]; then
        cat >> "/etc/apt/apt.conf.d/50unattended-upgrades" <<EOF
Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailReport "${UPDATE_EMAIL_LEVEL}";
Unattended-Upgrade::MailOnlyOnError "false";
EOF
    fi

    if [[ "$UPDATE_NOTIFY_NO_REBOOT" == "yes" && "$ENABLE_AUTO_REBOOT" == "no" ]]; then
        echo 'Unattended-Upgrade::NotifyOnlyOnRebootRequired "true";' >> "/etc/apt/apt.conf.d/50unattended-upgrades"
    fi

    case $UPDATE_SCHEDULE in
        "daily")
            cat > "/etc/apt/apt.conf.d/10periodic" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
            ;;
        "weekly")
            cat > "/etc/apt/apt.conf.d/10periodic" <<EOF
APT::Periodic::Update-Package-Lists "7";
APT::Periodic::Download-Upgradeable-Packages "7";
APT::Periodic::Unattended-Upgrade "7";
APT::Periodic::AutocleanInterval "7";
EOF
            ;;
        "custom")
            rm -f /etc/apt/apt.conf.d/10periodic
            cat > "/etc/cron.d/custom-unattended-upgrades" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
$UPDATE_CUSTOM_CRON root unattended-upgrade
EOF
            ;;
    esac

    mkdir -p /var/log/unattended-upgrades
    
    if ! unattended-upgrade --dry-run --debug; then
        error_exit "Automatic updates configuration test failed"
    fi
    
    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
}

generate_documentation() {
    log "INFO" "Generating system documentation..."
    
    local doc_dir="${SCRIPT_DIR}/documentation"
    mkdir -p "$doc_dir"
    
    {
        echo "# System Hardening Documentation"
        echo "Generated: $(date)"
        echo "Script Version: ${VERSION}"
        echo
        echo "## System Information"
        echo "Ubuntu Version: $(lsb_release -ds)"
        echo "Kernel Version: $(uname -r)"
        echo
        echo "## Security Configurations"
        echo "### SSH Configuration"
        echo "\`\`\`"
        grep -v "^#" /etc/ssh/sshd_config || echo "Not available"
        echo "\`\`\`"
        echo
        echo "### Firewall Rules"
        echo "\`\`\`"
        ufw status verbose || echo "Not available"
        echo "\`\`\`"
        echo
        echo "### Automatic Updates Configuration"
        echo "\`\`\`"
        grep -v "^#" /etc/apt/apt.conf.d/50unattended-upgrades || echo "Not available"
        echo "\`\`\`"
    } > "${doc_dir}/system-configuration.md"
    
    {
        echo "# Emergency Recovery Procedures"
        echo
        echo "## Backup Location"
        echo "System configurations are backed up to: ${BACKUP_DIR}/${DATE}"
        echo
        echo "## Restore Procedure"
        echo "1. Log in as root"
        echo "2. Run: ${SCRIPT_DIR}/$(basename "$0") --restore"
        echo
        echo "## Emergency Contacts"
        echo "System Administrator: ${ADMIN_EMAIL}"
    } > "${doc_dir}/recovery-procedures.md"
    
    chmod 600 "${doc_dir}"/*
}

verify_changes() {
    log "INFO" "Verifying system changes..."
    local checks_failed=0
    
    if ! sshd -t; then
        log "ERROR" "SSH configuration validation failed"
        ((checks_failed++))
    fi
    
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "Firewall is not active"
        ((checks_failed++))
    fi
    
    if ! systemctl is-active fail2ban >/dev/null 2>&1; then
        log "ERROR" "fail2ban is not running"
        ((checks_failed++))
    fi
    
    local critical_services=(
        "sshd"
        "ufw"
        "fail2ban"
        "unattended-upgrades"
    )
    
    for service in "${critical_services[@]}"; do
        if ! systemctl is-active "$service" >/dev/null 2>&1; then
            log "ERROR" "Critical service $service is not running"
            ((checks_failed++))
        fi
    done
    
    if [ "$checks_failed" -gt 0 ]; then
        error_exit "System verification failed with $checks_failed errors"
    fi
}

check_user_access() {
    local current_user="${SUDO_USER:-$USER}"
    local is_root=false
    local has_other_users=false
    local has_sudo_users=false
    
    # Check if current user is root
    if [[ "$current_user" == "root" ]]; then
        is_root=true
    fi
    
    # Check for non-system users with login shells
    while IFS=: read -r username _ uid _ _ home shell; do
        # Skip system users and users without login shells
        if [[ "$uid" -ge 1000 ]] && [[ "$shell" =~ /bash$ || "$shell" =~ /sh$ ]]; then
            if [[ "$username" != "root" ]]; then
                has_other_users=true
                # Check if user has sudo rights
                if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b' || \
                   [[ -f "/etc/sudoers.d/$username" ]] || \
                   grep -q "^$username.*ALL=" /etc/sudoers 2>/dev/null; then
                    has_sudo_users=true
                fi
            fi
        fi
    done < /etc/passwd

    # Critical safety check
    if [[ "$is_root" == "true" ]] && [[ "$has_other_users" == "false" ]]; then
        cat <<EOF
======================= CRITICAL SECURITY WARNING =======================
You are running this script as root, and there are no other user accounts
with login access. Proceeding would lock you out of the system after reboot!

You MUST create at least one additional user account with sudo privileges
before running this hardening script.

To create a new admin user, run:
    adduser newusername
    usermod -aG sudo newusername

Then set up SSH keys for this user before proceeding.
====================================================================
EOF
        return 1
    fi

    if [[ "$is_root" == "true" ]] && [[ "$has_sudo_users" == "false" ]]; then
        cat <<EOF
======================= CRITICAL SECURITY WARNING =======================
You are running this script as root, and there are no other users with
sudo privileges. Proceeding would leave the system without administrative
access after reboot!

You MUST grant sudo privileges to at least one regular user account
before running this hardening script.

To grant sudo access to an existing user:
    usermod -aG sudo existingusername

Then set up SSH keys for this user before proceeding.
====================================================================
EOF
        return 1
    fi

    return 0
}

main() {
    check_and_create_lock
    
    touch "$LOG_FILE" || error_exit "Cannot create log file"
    chmod 600 "$LOG_FILE"
    
    log "INFO" "Starting server hardening (Version ${VERSION})"
    
    check_system_requirements
    
    # Add the user access check
    if ! check_user_access; then
        error_exit "Critical security check failed. Please create additional admin user first."
    fi
    
    backup_system
    
    if [[ -f "$CONFIG_FILE" ]] && prompt_yes_no "Found existing configuration. Use it"; then
        load_configuration
    else
        gather_user_input
    fi
    
    # Execute hardening functions
    local failed_steps=()
    
    for step in check_prerequisites configure_ssh configure_firewall configure_fail2ban configure_automatic_updates; do
        if ! $step; then
            failed_steps+=("$step")
            log "ERROR" "Step $step failed"
        fi
    done
    
    verify_changes
    generate_documentation
    
    if [ ${#failed_steps[@]} -eq 0 ]; then
        log "INFO" "Server hardening completed successfully"
    else
        log "ERROR" "Server hardening completed with ${#failed_steps[@]} failed steps:"
        printf '%s\n' "${failed_steps[@]}" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    cat <<EOF

=== Hardening Summary ===
Version: ${VERSION}
Log File: ${LOG_FILE}
Backup Location: ${BACKUP_DIR}/${DATE}
Documentation: ${SCRIPT_DIR}/documentation/

Next Steps:
1. Review the generated documentation
2. Test system access and functionality
3. Store backup and recovery procedures securely
4. Schedule regular security audits

Support:
For issues or assistance, contact: ${ADMIN_EMAIL}
EOF
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "--restore" ]]; then
        restore_from_backup
    else
        main "$@"
    fi
fi