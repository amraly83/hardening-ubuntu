#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-setup.log"
init_script

# Install dependencies first
log "INFO" "Checking and installing dependencies..."
if ! "${SCRIPT_DIR}/install-deps.sh"; then
    error_exit "Failed to install required dependencies"
fi

# Run preflight checks first
if ! "${SCRIPT_DIR}/preflight.sh"; then
    error_exit "Pre-flight checks failed. Please resolve issues before proceeding"
fi

check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Verify Ubuntu version
    check_ubuntu_version
    
    # Check required commands
    local required_commands=(
        "ssh-keygen"
        "adduser"
        "usermod"
        "systemctl"
        "ufw"
        "apt-get"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "Required command not found: $cmd"
        fi
    done
    
    # Verify all scripts exist and are executable
    local required_scripts=(
        "${SCRIPT_DIR}/create-admin.sh"
        "${SCRIPT_DIR}/setup-ssh-key.sh"
        "${SCRIPT_DIR}/setup-2fa.sh"
        "${SCRIPT_DIR}/harden.sh"
    )

    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$script" ]]; then
            error_exit "Required script not found: $script"
        fi
        chmod +x "$script"
    done
}

setup_admin_user() {
    echo "=== Step 1: Admin User Setup ==="
    read -p "Enter username for the new admin user: " NEW_ADMIN_USER
    
    log "INFO" "Creating new admin user: $NEW_ADMIN_USER"
    if ! "${SCRIPT_DIR}/create-admin.sh" "$NEW_ADMIN_USER"; then
        error_exit "Failed to create admin user"
    fi
    
    # Verify sudo access
    if ! verify_sudo_access "$NEW_ADMIN_USER"; then
        error_exit "Failed to verify sudo access for $NEW_ADMIN_USER"
    fi
    
    echo "$NEW_ADMIN_USER"  # Return username for next steps
}

setup_ssh_keys() {
    local username="$1"
    echo "=== Step 2: SSH Key Setup ==="
    
    log "INFO" "Setting up SSH keys for $username"
    echo "Please have your SSH public key ready (from your local machine's ~/.ssh/id_ed25519.pub)"
    
    if ! "${SCRIPT_DIR}/setup-ssh-key.sh" "$username"; then
        error_exit "Failed to set up SSH keys"
    fi
    
    # Verify SSH access
    if ! verify_ssh_access "$username"; then
        log "WARNING" "Could not verify SSH access automatically"
        if ! prompt_yes_no "Have you tested SSH access in another terminal" "no"; then
            error_exit "Please verify SSH access before continuing"
        fi
    fi
}

setup_2fa() {
    local username="$1"
    echo "=== Step 3: Two-Factor Authentication Setup ==="
    
    if prompt_yes_no "Would you like to set up 2FA for SSH access" "yes"; then
        log "INFO" "Setting up 2FA for $username"
        echo "Please have Google Authenticator app ready on your mobile device"
        
        if ! "${SCRIPT_DIR}/setup-2fa.sh" "$username"; then
            error_exit "Failed to set up 2FA"
        fi
        
        echo "Please test 2FA login in a new terminal before continuing!"
        if ! prompt_yes_no "Have you successfully tested 2FA login" "no"; then
            error_exit "Please verify 2FA login before proceeding"
        fi
    else
        log "INFO" "2FA setup skipped"
    fi
}

run_hardening() {
    echo "=== Step 4: System Hardening ==="
    echo "Please review the following settings before proceeding:"
    echo "- SSH_PORT=\"3333\""
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
}

main() {
    # Display welcome message
    echo "================================================================"
    echo "Ubuntu Server Security Hardening Setup"
    echo "This script will guide you through the server hardening process"
    echo "================================================================"
    
    # Check prerequisites
    check_prerequisites
    
    # Create admin user if needed
    USERNAME=$(setup_admin_user)
    
    # Set up SSH keys
    setup_ssh_keys "$USERNAME"
    
    # Set up 2FA
    setup_2fa "$USERNAME"
    
    # Run system hardening
    run_hardening
    
    # Final verification
    echo "=== Setup Complete ==="
    echo "Please verify:"
    echo "1. SSH access works with your key"
    echo "2. 2FA works (if enabled)"
    echo "3. Sudo access works"
    echo "4. Review generated documentation in ${SCRIPT_DIR}/../docs/"
    
    log "INFO" "Setup completed successfully"
}

main "$@"