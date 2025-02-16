#!/bin/bash

# Set strict mode
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run script preloader first
"${SCRIPT_DIR}/script-preloader.sh" || {
    echo "Error: Failed to prepare scripts"
    exit 1
}

# Set log file (before sourcing common.sh)
LOG_FILE="/var/log/server-hardening.log"

# Source common functions (now safe after preloader)
source "${SCRIPT_DIR}/common.sh"

# Initialize script
init_script

# Source progress functions
source "${SCRIPT_DIR}/progress.sh" || {
    echo "Error: Failed to source ${SCRIPT_DIR}/progress.sh"
    exit 1
}

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

# Function to prompt for continuation with progress tracking
confirm_continue() {
    local step="$1"
    local default="${2:-yes}"
    
    track_progress "$step" "completed"
    echo -e "\nStep completed: $step"
    show_progress
    
    if ! prompt_yes_no "Continue to next step?" "$default"; then
        if ! prompt_yes_no "Are you sure you want to exit?" "no"; then
            return 0
        fi
        log "INFO" "Setup paused after $step"
        echo "You can resume setup later by running this script again"
        exit 0
    fi
    return 0
}

# Function to verify step completion with progress tracking
verify_step() {
    local step="$1"
    local check_command="$2"
    
    log "INFO" "Verifying step: $step"
    track_progress "$step" "verifying"
    
    if ! eval "$check_command"; then
        log "ERROR" "Verification failed for: $step"
        track_progress "$step" "failed"
        if ! prompt_yes_no "Retry this step?" "yes"; then
            error_exit "Setup failed at: $step"
        fi
        return 1
    fi
    
    log "SUCCESS" "Verified successfully: $step"
    track_progress "$step" "verified"
    return 0
}

# Main setup process with progress tracking
main() {
    # Check if resuming from previous session
    if resume_from_last; then
        if prompt_yes_no "Resume from last completed step?" "yes"; then
            log "INFO" "Resuming setup"
        else
            if ! prompt_yes_no "Start fresh? This will reset progress" "no"; then
                exit 0
            fi
            rm -f "$PROGRESS_FILE"
        fi
    fi
    
    # Display welcome message
    echo "================================================================"
    echo "Ubuntu Server Security Hardening Setup"
    echo "This script will guide you through the server hardening process"
    echo "================================================================"
    
    # Check prerequisites
    check_prerequisites
    confirm_continue "Prerequisites verification"
    
    # Setup admin user with verification
    local USERNAME=""
    while [[ -z "$USERNAME" ]]; do
        USERNAME=$(setup_admin_user)
        USERNAME=$(echo "$USERNAME" | tr -d '\n')
        if [[ -z "$USERNAME" ]]; then
            log "ERROR" "Failed to get valid username, retrying..."
            sleep 1
        fi
    done
    
    verify_step "Admin user setup" "verify_sudo_access '$USERNAME'" || {
        error_exit "Failed to verify admin user setup"
    }
    confirm_continue "Admin user setup"
    
    # Setup SSH keys with verification
    setup_ssh_keys "$USERNAME"
    verify_step "SSH key setup" "check_ssh_key_setup '$USERNAME'" || {
        error_exit "Failed to verify SSH key setup"
    }
    confirm_continue "SSH key setup"
    
    # Setup 2FA if requested
    if prompt_yes_no "Would you like to set up 2FA?" "yes"; then
        setup_2fa "$USERNAME"
        verify_step "2FA setup" "test_2fa '$USERNAME'" || {
            error_exit "Failed to verify 2FA setup"
        }
        confirm_continue "2FA setup"
    fi
    
    # Run system hardening with verification
    if prompt_yes_no "Proceed with system hardening?" "yes"; then
        run_hardening
        verify_step "System hardening" "verify_hardening" || {
            error_exit "Failed to verify system hardening"
        }
        confirm_continue "System hardening"
    fi
    
    # Final verification
    log "INFO" "Running final verification..."
    if ! verify_all_configurations "$USERNAME"; then
        log "WARNING" "Some verifications failed. Please check the logs."
        if ! prompt_yes_no "Continue despite verification warnings?" "no"; then
            error_exit "Setup incomplete - verification failed"
        fi
    fi
    
    # Setup complete
    echo "=== Setup Complete ==="
    echo "Please verify:"
    echo "1. SSH access works with your key"
    echo "2. 2FA works (if enabled)"
    echo "3. Sudo access works"
    echo "4. Review generated documentation in ${SCRIPT_DIR}/../docs/"
    
    log "INFO" "Setup completed successfully"
}

# Run main function with error handling
main "$@" || {
    log "ERROR" "Setup failed"
    track_progress "setup" "failed"
    exit 1
}