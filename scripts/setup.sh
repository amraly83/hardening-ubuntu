#!/bin/bash

# Set strict mode
set -euo pipefail

# Set log file before anything else
LOG_FILE="/var/log/server-hardening.log"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for required commands including jq
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Verify dependencies are installed
if ! check_command jq; then
    echo "Running dependency installation..."
    if ! "${SCRIPT_DIR}/install-deps.sh"; then
        echo "Error: Failed to install required dependencies"
        exit 1
    fi
fi

# Fix line endings in script-preloader first
sed -i 's/\r$//' "${SCRIPT_DIR}/script-preloader.sh"
chmod +x "${SCRIPT_DIR}/script-preloader.sh"

# Run script preloader
"${SCRIPT_DIR}/script-preloader.sh" || {
    echo "Error: Failed to prepare scripts"
    exit 1
}

# Source common functions (now safe after preloader)
source "${SCRIPT_DIR}/common.sh" || {
    echo "Error: Failed to source common.sh"
    exit 1
}

# Initialize script (after sourcing common.sh)
init_script || {
    echo "Error: Failed to initialize script"
    exit 1
}

# Source progress tracking functions
source "${SCRIPT_DIR}/progress.sh" || {
    echo "Error: Failed to source progress.sh"
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
    local USERNAME=""
    local max_attempts=3
    local attempt=1
    
    echo -e "\n=== Step 1: Admin User Setup ===" >&2
    
    while [[ $attempt -le $max_attempts ]]; do
        # Get username input
        read -r -p "Enter username for the new admin user: " USERNAME >&2
        
        # Check if username is empty
        if [[ -z "$USERNAME" ]]; then
            log "ERROR" "Username cannot be empty" >&2
            ((attempt++))
            continue
        fi
        
        # Clean username immediately
        USERNAME=$(echo "$USERNAME" | tr -cd 'a-z0-9_-')
        
        # Create admin user
        if USERNAME=$("${SCRIPT_DIR}/create-admin.sh" "$USERNAME"); then
            # Store username in progress tracking
            set_username "$USERNAME"
            track_progress "admin_user" "completed"
            printf "%s" "$USERNAME"
            return 0
        fi
        
        ((attempt++))
        if [[ $attempt -le $max_attempts ]]; then
            log "WARNING" "Admin user creation failed, retrying..." >&2
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
    echo -e "\n=== Step 3: Two-Factor Authentication Setup ==="
    
    # Ensure we're working with the new admin user
    if [[ -z "$username" ]]; then
        log "ERROR" "No admin username provided for 2FA setup"
        return 1
    fi
    
    if prompt_yes_no "Would you like to set up 2FA for SSH access" "yes"; then
        log "INFO" "Setting up 2FA for admin user: $username"
        echo "Please have Google Authenticator app ready on your mobile device"
        
        if ! "${SCRIPT_DIR}/setup-2fa.sh" "$username"; then
            error_exit "Failed to set up 2FA"
        fi
        
        # Verify 2FA setup
        if ! verify_step "2FA setup" "$username"; then
            error_exit "2FA verification failed"
        fi
        
        track_progress "2fa" "completed"
        if ! prompt_yes_no "Have you successfully tested 2FA login in another terminal" "no"; then
            error_exit "Please verify 2FA login before proceeding"
        fi
    else
        log "INFO" "2FA setup skipped"
        track_progress "2fa" "skipped"
    fi
}

run_hardening() {
    echo "=== Step 4: System Hardening ==="
    local config_file="/etc/server-hardening/hardening.conf"

    if [[ ! -f "$config_file" ]]; then
        echo "Preparing default configuration..."
        mkdir -p "/etc/server-hardening"
        cp "${SCRIPT_DIR}/../examples/config/hardening.conf.example" "$config_file" || {
            error_exit "Failed to create initial configuration"
        }
        chmod 600 "$config_file"
    fi

    echo "Current hardening configuration:"
    echo "----------------------------------------------------------------"
    cat "$config_file"
    echo "----------------------------------------------------------------"
    echo "You can:"
    echo "1. Continue with these settings"
    echo "2. Edit the configuration now"
    
    if prompt_yes_no "Would you like to edit the configuration before proceeding" "yes"; then
        if command -v nano >/dev/null 2>&1; then
            nano "$config_file"
        elif command -v vi >/dev/null 2>&1; then
            vi "$config_file"
        else
            error_exit "No text editor (nano/vi) found to edit configuration"
        fi
        
        echo "Configuration updated. Please review:"
        echo "----------------------------------------------------------------"
        cat "$config_file"
        echo "----------------------------------------------------------------"
    fi
    
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
    local username="$2"
    
    log "INFO" "Verifying step: $step"
    track_progress "$step" "verifying"
    
    case "$step" in
        "Admin user setup")
            if ! verify_admin_setup "$username"; then
                log "ERROR" "Verification failed for: $step"
                track_progress "$step" "failed"
                return 1
            fi
            ;;
        "SSH key setup")
            if ! check_ssh_key_setup "$username"; then
                log "ERROR" "Verification failed for: $step"
                track_progress "$step" "failed"
                return 1
            fi
            ;;
        "2FA setup")
            if ! test_2fa "$username"; then
                log "ERROR" "Verification failed for: $step"
                track_progress "$step" "failed"
                return 1
            fi
            ;;
        "System hardening")
            if ! verify_hardening; then
                log "ERROR" "Verification failed for: $step"
                track_progress "$step" "failed"
                return 1
            fi
            ;;
        *)
            log "ERROR" "Unknown verification step: $step"
            track_progress "$step" "failed"
            return 1
            ;;
    esac
    
    log "SUCCESS" "Verified successfully: $step"
    track_progress "$step" "verified"
    return 0
}

# Function to safely verify sudo access with auto-repair
verify_admin_setup() {
    local username="$1"
    
    # Clean username - only keep alphanumeric, dash and underscore
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    log "INFO" "Starting admin verification for user: $username"
    
    # Basic user existence check
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Verify sudo group membership
    if ! groups "$username" | grep -q '\bsudo\b'; then
        log "WARNING" "User not in sudo group, attempting to fix..."
        usermod -aG sudo "$username"
        # Force group update
        sg sudo -c "id" || true
    fi
    
    # Ensure sudoers.d exists and has correct permissions
    if [[ ! -d "/etc/sudoers.d" ]]; then
        mkdir -p "/etc/sudoers.d"
        chmod 750 "/etc/sudoers.d"
    fi
    
    # Set up clean sudoers entry
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Verify sudo access
    log "DEBUG" "Testing sudo access..."
    if ! timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
        log "ERROR" "Sudo verification failed"
        return 1
    fi
    
    log "SUCCESS" "Admin user setup verified successfully"
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
        USERNAME=$(echo "$USERNAME" | tr -cd 'a-z0-9_-')
        if [[ -z "$USERNAME" ]]; then
            log "ERROR" "Failed to get valid username, retrying..."
            sleep 1
        fi
    done
    
    # Store username in progress tracking
    set_username "$USERNAME"
    
    verify_step "Admin user setup" "$USERNAME" || {
        error_exit "Failed to verify admin user setup"
    }
    confirm_continue "Admin user setup"
    
    # Setup SSH keys with verification
    setup_ssh_keys "$USERNAME"
    verify_step "SSH key setup" "$USERNAME" || {
        error_exit "Failed to verify SSH key setup"
    }
    confirm_continue "SSH key setup"
    
    # Setup 2FA specifically for the new admin user
    setup_2fa "$USERNAME"
    if is_step_completed "2fa"; then
        verify_step "2FA setup" "$USERNAME" || {
            error_exit "Failed to verify 2FA setup"
        }
        confirm_continue "2FA setup"
    fi
    
    # Run system hardening with verification
    if prompt_yes_no "Proceed with system hardening?" "yes"; then
        run_hardening
        verify_step "System hardening" "$USERNAME" || {
            error_exit "Failed to verify system hardening"
        }
        confirm_continue "System hardening"
    fi
    
    # Final verification using standalone script
    log "INFO" "Running final verification..."
    chmod +x "${SCRIPT_DIR}/verify-system.sh"
    if ! timeout 60 "${SCRIPT_DIR}/verify-system.sh" "$USERNAME"; then
        log "WARNING" "Some verifications failed"
        echo "Please check the warnings above and verify manually:"
        echo "1. Try 'sudo -v' to check sudo access"
        echo "2. SSH: ssh ${USERNAME}@localhost -p ${ssh_port:-22}"
        echo "3. Run 'systemctl status sshd fail2ban' to check services"
    else
        log "SUCCESS" "System verification completed successfully"
    fi
    
    # Show final status
    echo "=== Setup Complete ==="
    echo "IMPORTANT: Before logging out, please verify in a new terminal:"
    echo "1. SSH access: ssh ${USERNAME}@localhost -p ${ssh_port:-22}"
    echo "2. 2FA works (if enabled): You should be prompted for code"
    echo "3. Sudo access: Run 'sudo -v' after login"
    echo "4. Review documentation in ${SCRIPT_DIR}/../docs/"
    echo
    echo "If you experience any issues, refer to docs/troubleshooting.md"
    
    log "INFO" "Setup completed"
    return 0
}

# Run main function with error handling
main "$@" || {
    log "ERROR" "Setup failed"
    track_progress "setup" "failed"
    exit 1
}