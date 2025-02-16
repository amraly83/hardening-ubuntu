#!/bin/bash
# Set log file first
LOG_FILE="/var/log/server-setup.log"

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script after sourcing
init_script

check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Quick environment check
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        error_exit "This script must be run on a Linux system"
    fi
    
    # Verify scripts exist
    for script in create-admin.sh setup-ssh-key.sh setup-2fa.sh harden.sh; do
        if [[ ! -f "${SCRIPT_DIR}/$script" ]]; then
            error_exit "Required script not found: $script"
        fi
        chmod +x "${SCRIPT_DIR}/$script" || log "WARNING" "Could not make $script executable"
    done
    
    return 0
}

setup_admin_user() {
    echo -e "\n=== Step 1: Admin User Setup ===" >&2
    local NEW_ADMIN_USER
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        read -r -p "Enter username for the new admin user: " NEW_ADMIN_USER >&2
        
        # Check if username is empty
        if [[ -z "$NEW_ADMIN_USER" ]]; then
            log "ERROR" "Username cannot be empty" >&2
            ((attempt++))
            continue
        fi
        
        # First validate the username format
        if ! validate_username "$NEW_ADMIN_USER" >&2; then
            ((attempt++))
            continue
        fi
        
        # Check if user exists
        if id "$NEW_ADMIN_USER" >/dev/null 2>&1; then
            if is_user_admin "$NEW_ADMIN_USER"; then
                log "INFO" "User '$NEW_ADMIN_USER' already exists and is already an admin" >&2
                if prompt_yes_no "Would you like to use this existing admin user" "yes" >&2; then
                    # Output just the username to stdout, everything else to stderr
                    printf "%s" "$NEW_ADMIN_USER"
                    return 0
                fi
            else
                log "WARNING" "User '$NEW_ADMIN_USER' exists but is not an admin" >&2
                if prompt_yes_no "Would you like to grant admin privileges to this user" "no" >&2; then
                    log "INFO" "Adding '$NEW_ADMIN_USER' to sudo group" >&2
                    if usermod -aG sudo "$NEW_ADMIN_USER"; then
                        # Verify sudo access after adding to group
                        if verify_sudo_access "$NEW_ADMIN_USER"; then
                            log "INFO" "Sudo access granted and verified" >&2
                            printf "%s" "$NEW_ADMIN_USER"
                            return 0
                        else
                            log "ERROR" "Failed to verify sudo access after granting privileges" >&2
                        fi
                    else
                        log "ERROR" "Failed to add user to sudo group" >&2
                    fi
                fi
            fi
            
            # If we get here, all attempts to use/fix existing user failed
            if [[ $attempt -eq $max_attempts ]]; then
                error_exit "Maximum attempts reached. Please resolve sudo access issues before proceeding"
            fi
            echo "Please enter a different username" >&2
            ((attempt++))
            continue
            
        else
            # Create new user
            log "INFO" "Creating new admin user: $NEW_ADMIN_USER" >&2
            if ! "${SCRIPT_DIR}/create-admin.sh" "$NEW_ADMIN_USER"; then
                if [[ $attempt -eq $max_attempts ]]; then
                    error_exit "Failed to create admin user after $max_attempts attempts"
                fi
                ((attempt++))
                continue
            fi
            
            # Verify sudo access for new user
            if verify_sudo_access "$NEW_ADMIN_USER"; then
                log "INFO" "Sudo access verified for new user" >&2
                printf "%s" "$NEW_ADMIN_USER"
                return 0
            else
                log "ERROR" "Failed to verify sudo access for new user" >&2
                ((attempt++))
                continue
            fi
        fi
    done
    
    error_exit "Failed to set up admin user after $max_attempts attempts"
}

setup_ssh_keys() {
    local username="$1"
    echo -e "\n=== Step 2: SSH Key Setup ==="
    
    # Clean any color codes from username
    username=$(echo "$username" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | tr -d '\n')
    
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
    
    # Check prerequisites (minimal check for required files)
    check_prerequisites
    
    # Create admin user and store the username
    USERNAME=""
    while [[ -z "$USERNAME" ]]; do
        USERNAME=$(setup_admin_user)
        USERNAME=$(echo "$USERNAME" | tr -d '\n')
        if [[ -z "$USERNAME" ]]; then
            log "ERROR" "Failed to get valid username, retrying..."
            sleep 1
        fi
    done
    
    # Verify username is valid
    if ! validate_username "$USERNAME"; then
        error_exit "Invalid username after creation: $USERNAME"
    fi
    
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