#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/server-setup.log"

# Utility functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
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

error_exit() {
    log "ERROR" "$1"
    exit 1
}

verify_script() {
    local script="$1"
    if [[ ! -f "$script" ]]; then
        error_exit "Required script not found: $script"
    fi
    if [[ ! -x "$script" ]]; then
        chmod +x "$script" || error_exit "Cannot make $script executable"
    fi
}

verify_ssh_access() {
    local username="$1"
    log "INFO" "Testing SSH access for $username..."
    
    # Try SSH login with key (this will use the default key)
    if ! ssh -o PasswordAuthentication=no -o BatchMode=yes "$username@localhost" "echo 'SSH access working'"; then
        return 1
    fi
    return 0
}

verify_sudo_access() {
    local username="$1"
    if ! su - "$username" -c "sudo -n true" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Main setup process
main() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    # Verify all required scripts exist
    local required_scripts=(
        "${SCRIPT_DIR}/create-admin.sh"
        "${SCRIPT_DIR}/setup-ssh-key.sh"
        "${SCRIPT_DIR}/setup-2fa.sh"
        "${SCRIPT_DIR}/harden.sh"
    )

    for script in "${required_scripts[@]}"; do
        verify_script "$script"
    done

    # Step 1: Create admin user if needed
    echo "=== Step 1: Admin User Setup ==="
    if [[ -z "${SSH_ALLOW_USERS:-}" ]]; then
        read -p "Enter username for the new admin user: " NEW_ADMIN_USER
        log "INFO" "Creating new admin user: $NEW_ADMIN_USER"
        if ! "${SCRIPT_DIR}/create-admin.sh" "$NEW_ADMIN_USER"; then
            error_exit "Failed to create admin user"
        fi
    fi

    # Step 2: SSH Key Setup
    echo "=== Step 2: SSH Key Setup ==="
    read -p "Enter the username to set up SSH key for: " SSH_USER
    log "INFO" "Setting up SSH keys for $SSH_USER"
    
    echo "Please have your SSH public key ready (from your local machine's ~/.ssh/id_ed25519.pub)"
    if ! "${SCRIPT_DIR}/setup-ssh-key.sh" "$SSH_USER"; then
        error_exit "Failed to set up SSH keys"
    fi

    # Verify SSH key access
    if ! verify_ssh_access "$SSH_USER"; then
        error_exit "SSH key authentication test failed. Please verify your key setup"
    fi

    # Step 3: 2FA Setup (if desired)
    echo "=== Step 3: Two-Factor Authentication Setup ==="
    if prompt_yes_no "Would you like to set up 2FA for SSH access" "yes"; then
        log "INFO" "Setting up 2FA for $SSH_USER"
        echo "Please have Google Authenticator app ready on your mobile device"
        if ! "${SCRIPT_DIR}/setup-2fa.sh" "$SSH_USER"; then
            error_exit "Failed to set up 2FA"
        fi
        
        echo "Please test 2FA login in a new terminal before continuing!"
        if ! prompt_yes_no "Have you successfully tested 2FA login" "no"; then
            error_exit "Please verify 2FA login before proceeding"
        fi
    fi

    # Verify sudo access
    if ! verify_sudo_access "$SSH_USER"; then
        error_exit "Sudo access test failed for $SSH_USER. Please verify sudo privileges"
    fi

    # Step 4: System Hardening
    echo "=== Step 4: System Hardening ==="
    echo "Please review the following default values in harden.sh before proceeding:"
    echo "- SSH_PORT=\"3333\""
    echo "- SSH_ALLOW_USERS=\"$SSH_USER\""
    echo "- FIREWALL_ADDITIONAL_PORTS=\"80,443,3306,465,587,993,995\""
    
    if prompt_yes_no "Would you like to proceed with system hardening" "no"; then
        log "INFO" "Starting system hardening..."
        if ! "${SCRIPT_DIR}/harden.sh"; then
            error_exit "System hardening failed"
        fi
    else
        log "INFO" "System hardening skipped"
        echo "You can run the hardening script later with: sudo ./harden.sh"
        exit 0
    fi

    # Final verification
    echo "=== Setup Complete ==="
    echo "Please verify:"
    echo "1. SSH access works with your key"
    echo "2. 2FA works (if enabled)"
    echo "3. Sudo access works"
    echo "4. Review generated documentation in ${SCRIPT_DIR}/documentation/"
    
    log "INFO" "Setup completed successfully"
}

main "$@"