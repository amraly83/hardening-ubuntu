#!/bin/bash
# Enhanced SSH key setup script
set -euo pipefail

# Determine script directory portably
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

setup_ssh_keys() {
    local username="$1"
    local home_dir
    
    home_dir=$(getent passwd "$username" | cut -d: -f6)
    local ssh_dir="${home_dir}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"

    # Verify user exists
    if ! id -u "$username" >/dev/null 2>&1; then
        error_exit "User $username does not exist"
    fi

    log "INFO" "Setting up SSH keys for user $username"

    # Backup existing SSH configuration
    if [[ -d "$ssh_dir" ]]; then
        cp -rp "$ssh_dir" "${ssh_dir}${backup_suffix}"
    fi

    # Create .ssh directory with secure permissions
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$username:$username" "$ssh_dir"

    # Prompt for public key
    local pub_key=""
    while [[ -z "$pub_key" ]]; do
        echo "Please paste the public key for $username (or enter path to public key file):"
        read -r input
        if [[ -f "$input" ]]; then
            pub_key=$(cat "$input")
        else
            pub_key="$input"
        fi

        # Validate key format
        if ! validate_ssh_key "$pub_key"; then
            log "ERROR" "Invalid SSH key format"
            pub_key=""
            continue
        fi
    done

    # Add key to authorized_keys with proper permissions
    echo "$pub_key" > "$auth_keys"
    chmod 600 "$auth_keys"
    chown "$username:$username" "$auth_keys"

    # Configure SSH server for key-based auth
    configure_ssh_server

    # Verify SSH access
    if ! verify_ssh_access "$username"; then
        log "ERROR" "Failed to verify SSH access"
        restore_ssh_backup "$ssh_dir" "$backup_suffix"
        return 1
    fi

    log "SUCCESS" "SSH key setup completed for $username"
    return 0
}

validate_ssh_key() {
    local key="$1"
    local key_types="ssh-rsa ssh-ed25519 ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521"
    
    # Check if key starts with valid type
    local valid_start=0
    for type in $key_types; do
        if [[ "$key" =~ ^$type ]]; then
            valid_start=1
            break
        fi
    done

    if [[ $valid_start -eq 0 ]]; then
        return 1
    fi

    # Check key length and format
    if ! [[ "$key" =~ ^[A-Za-z0-9+/]+[=]{0,3}$ ]]; then
        return 1
    fi

    # Additional validation using ssh-keygen
    if ! echo "$key" | ssh-keygen -l -f - >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

configure_ssh_server() {
    local sshd_config="/etc/ssh/sshd_config"
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"

    # Backup existing config
    if [[ -f "$sshd_config" ]]; then
        cp -p "$sshd_config" "${sshd_config}${backup_suffix}"
    else
        log "ERROR" "No sshd_config found at $sshd_config"
        return 1
    fi

    # Update SSH configuration
    cat > "$sshd_config" << 'EOF'
# Security hardened sshd_config
# Generated by hardening script
# Protocol version
Protocol 2

# Authentication
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
UsePAM yes

# Security options
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 0

# Strict modes
StrictModes yes

# Key exchange and ciphers
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
EOF

    # Test configuration
    if ! sshd -t; then
        log "ERROR" "Invalid SSH configuration"
        mv "${sshd_config}${backup_suffix}" "$sshd_config"
        return 1
    fi

    # Restart sshd
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd
    elif command -v service >/dev/null 2>&1; then
        service sshd restart
    else
        log "ERROR" "Could not restart sshd - system service manager not found"
        return 1
    fi

    return 0
}

verify_ssh_access() {
    local username="$1"
    local home_dir
    home_dir=$(getent passwd "$username" | cut -d: -f6)
    
    # Check SSH key files exist
    if ! stat "${home_dir}/.ssh" >/dev/null 2>&1 || \
       ! stat "${home_dir}/.ssh/authorized_keys" >/dev/null 2>&1; then
        log "ERROR" "SSH directory or authorized_keys file not found"
        return 1
    fi
    
    # Test SSH connection
    if ! timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$username@localhost" true; then
        log "ERROR" "Failed SSH connection test"
        return 1
    fi
    
    # Verify permissions
    if [[ "$(stat -c "%a" "${home_dir}/.ssh")" != "700" ]] || \
       [[ "$(stat -c "%a" "${home_dir}/.ssh/authorized_keys")" != "600" ]]; then
        log "ERROR" "Incorrect SSH directory or key file permissions"
        return 1
    fi
    
    return 0
}

restore_ssh_backup() {
    local ssh_dir="$1"
    local backup_suffix="$2"
    
    if [[ -d "${ssh_dir}${backup_suffix}" ]]; then
        rm -rf "$ssh_dir"
        mv "${ssh_dir}${backup_suffix}" "$ssh_dir"
    fi
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 username"
    exit 1
fi

setup_ssh_keys "$1"
