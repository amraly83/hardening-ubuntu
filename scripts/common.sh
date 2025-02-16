#!/bin/bash

# Common functions library for hardening scripts
# Source this file in other scripts using:
# source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}"
    
    # If LOG_FILE is defined, also log to file
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
    fi
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

# User Management
check_user_exists() {
    local username="$1"
    if ! id "$username" >/dev/null 2>&1; then
        error_exit "User '$username' does not exist. Create the user first with create-admin.sh"
    fi
}

is_user_admin() {
    local username="$1"
    if groups "$username" | grep -qE '\b(sudo|admin|wheel)\b' || \
       [[ -f "/etc/sudoers.d/$username" ]] || \
       grep -q "^$username.*ALL=" /etc/sudoers 2>/dev/null; then
        return 0
    fi
    return 1
}

validate_username() {
    local username="$1"
    # Check username length
    if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
        error_exit "Username must be between 3 and 32 characters long"
    fi
    
    # Check username format
    if [[ ! "$username" =~ ^[a-z][-a-z0-9]*$ ]]; then
        error_exit "Invalid username. Use only lowercase letters, numbers, and hyphens. Must start with a letter"
    fi
    
    # Check against system usernames
    local reserved_names=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "messagebus" "syslog" "_apt" "tss" "uuidd" "tcpdump" "avahi-autoipd" "usbmux" "dnsmasq" "kernoops" "avahi" "cups-pk-helper" "rtkit" "whoopsie" "sssd" "speech-dispatcher" "nm-openvpn" "saned" "colord" "geoclue" "pulse" "gnome-initial-setup" "hplip" "gdm" "lightdm" "sshd" "mysql" "postgresql" "mongodb" "redis" "rabbitmq" "elasticsearch")
    
    for reserved in "${reserved_names[@]}"; do
        if [[ "$username" == "$reserved" ]]; then
            error_exit "Username '$username' is reserved for system use"
        fi
    done
}

# File Operations
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
        cp -p "$file" "$backup" || error_exit "Failed to backup $file"
        log "INFO" "Backed up $file to $backup"
    fi
}

check_ssh_key_setup() {
    local username="$1"
    local auth_keys="/home/${username}/.ssh/authorized_keys"
    
    if [[ ! -f "$auth_keys" ]] || [[ ! -s "$auth_keys" ]]; then
        error_exit "SSH keys not set up for user '$username'. Please run setup-ssh-key.sh first"
    fi
}

validate_ssh_key() {
    local key="$1"
    if ! ssh-keygen -l -f <(echo "$key") >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# System Checks
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

check_ubuntu_version() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        error_exit "This script requires Ubuntu Server"
    fi
    
    local version
    version=$(lsb_release -rs)
    if [ "$(echo "$version < 20.04" | bc)" -eq 1 ]; then
        error_exit "This script requires Ubuntu 20.04 or later"
    fi
}

# Interactive Input
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

# Verification
verify_sudo_access() {
    local username="$1"
    if ! su - "$username" -c "sudo -n true" 2>/dev/null; then
        return 1
    fi
    return 0
}

verify_ssh_access() {
    local username="$1"
    if ! ssh -o PasswordAuthentication=no -o BatchMode=yes "$username@localhost" "echo 'SSH access working'" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Script initialization
init_script() {
    # Set up error handling
    set -euo pipefail
    
    # Set script directory
    readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check if running as root
    check_root
    
    # Initialize logging if LOG_FILE is defined
    if [[ -n "${LOG_FILE:-}" ]]; then
        touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}