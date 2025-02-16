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
    local NEW_ADMIN_USER
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        read -p "Enter username for the new admin user: " NEW_ADMIN_USER
        
        # First validate the username format
        if ! validate_username "$NEW_ADMIN_USER" 2>/dev/null; then
            log "ERROR" "Invalid username format"
            ((attempt++))
            continue
        fi
        
        # Check if user exists
        if id "$NEW_ADMIN_USER" >/dev/null 2>&1; then
            if is_user_admin "$NEW_ADMIN_USER"; then
                log "INFO" "User '$NEW_ADMIN_USER' already exists and is already an admin"
                if prompt_yes_no "Would you like to use this existing admin user" "yes"; then
                    echo "Verifying sudo access for $NEW_ADMIN_USER..."
                    if verify_sudo_access "$NEW_ADMIN_USER"; then
                        log "INFO" "Sudo access verified for $NEW_ADMIN_USER"
                        echo
                        echo "================================================================"
                        echo "Using existing admin user: $NEW_ADMIN_USER"
                        echo "Current configuration will be preserved"
                        echo "You can reconfigure SSH keys and 2FA in the next steps"
                        echo "================================================================"
                        echo
                        return 0  # Exit function successfully with implicit return of username
                    else
                        log "WARNING" "Failed to verify sudo access for existing admin user"
                        if prompt_yes_no "Would you like to try fixing sudo access" "yes"; then
                            echo "Attempting to fix sudo access..."
                            if ! groups "$NEW_ADMIN_USER" | grep -q sudo; then
                                usermod -aG sudo "$NEW_ADMIN_USER"
                            fi
                            # Verify again after fix attempt
                            if verify_sudo_access "$NEW_ADMIN_USER"; then
                                log "INFO" "Sudo access fixed and verified"
                                echo
                                echo "================================================================"
                                echo "Sudo access has been fixed for: $NEW_ADMIN_USER"
                                echo "Current configuration will be preserved"
                                echo "You can reconfigure SSH keys and 2FA in the next steps"
                                echo "================================================================"
                                echo
                                return 0  # Exit function successfully with implicit return of username
                            fi
                        fi
                    fi
                fi
            else
                log "WARNING" "User '$NEW_ADMIN_USER' exists but is not an admin"
                if prompt_yes_no "Would you like to grant admin privileges to this user" "no"; then
                    log "INFO" "Adding '$NEW_ADMIN_USER' to sudo group"
                    if usermod -aG sudo "$NEW_ADMIN_USER"; then
                        # Verify sudo access after adding to group
                        if verify_sudo_access "$NEW_ADMIN_USER"; then
                            log "INFO" "Sudo access granted and verified"
                            echo "$NEW_ADMIN_USER"
                            return 0
                        else
                            log "ERROR" "Failed to verify sudo access after granting privileges"
                        fi
                    else
                        log "ERROR" "Failed to add user to sudo group"
                    fi
                fi
            fi
            
            # If we get here, all attempts to use/fix existing user failed
            if [[ $attempt -eq $max_attempts ]]; then
                error_exit "Maximum attempts reached. Please resolve sudo access issues before proceeding"
            fi
            echo "Please enter a different username"
            ((attempt++))
            continue
            
        else
            # Create new user
            log "INFO" "Creating new admin user: $NEW_ADMIN_USER"
            if ! "${SCRIPT_DIR}/create-admin.sh" "$NEW_ADMIN_USER"; then
                if [[ $attempt -eq $max_attempts ]]; then
                    error_exit "Failed to create admin user after $max_attempts attempts"
                fi
                ((attempt++))
                continue
            fi
            
            # Verify sudo access for new user
            if verify_sudo_access "$NEW_ADMIN_USER"; then
                log "INFO" "Sudo access verified for new user"
                echo "$NEW_ADMIN_USER"
                return 0
            else
                log "ERROR" "Failed to verify sudo access for new user"
                ((attempt++))
                continue
            fi
        fi
    done
    
    error_exit "Failed to set up admin user after $max_attempts attempts"
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