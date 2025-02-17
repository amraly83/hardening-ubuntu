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
                    # Initialize sudo before returning
                    if [[ $EUID -eq 0 ]]; then
                        log "DEBUG" "Pre-initializing sudo access..." >&2
                        # Reset sudo timestamp
                        sudo -K -u "$NEW_ADMIN_USER" 2>/dev/null || true
                        # Ensure sudo group
                        usermod -aG sudo "$NEW_ADMIN_USER" 2>/dev/null || true
                        # Create sudoers entry
                        echo "$NEW_ADMIN_USER ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$NEW_ADMIN_USER"
                        chmod 440 "/etc/sudoers.d/$NEW_ADMIN_USER"
                        # Wait for changes to take effect
                        sleep 2
                    fi
                    printf "%s" "$NEW_ADMIN_USER"
                    return 0
                fi
            else
                log "WARNING" "User '$NEW_ADMIN_USER' exists but is not an admin" >&2
                if prompt_yes_no "Would you like to grant admin privileges to this user" "no" >&2; then
                    log "INFO" "Adding '$NEW_ADMIN_USER' to sudo group" >&2
                    if usermod -aG sudo "$NEW_ADMIN_USER"; then
                        # Initialize sudo access
                        if [[ $EUID -eq 0 ]]; then
                            log "DEBUG" "Pre-initializing sudo access..." >&2
                            echo "$NEW_ADMIN_USER ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$NEW_ADMIN_USER"
                            chmod 440 "/etc/sudoers.d/$NEW_ADMIN_USER"
                            sleep 2
                        fi
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
            
            # Pre-initialize sudo access for new user
            if [[ $EUID -eq 0 ]]; then
                log "DEBUG" "Pre-initializing sudo access for new user..." >&2
                # Ensure sudo group membership
                usermod -aG sudo "$NEW_ADMIN_USER"
                # Create sudoers entry
                echo "$NEW_ADMIN_USER ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$NEW_ADMIN_USER"
                chmod 440 "/etc/sudoers.d/$NEW_ADMIN_USER"
                # Wait for changes to take effect
                sleep 2
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
    # Clean the username to prevent command injection
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    log "INFO" "Starting admin verification for $username"
    
    # First verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User $username does not exist"
        return 1
    fi
    
    # Check current sudo group membership
    local group_check
    group_check=$(groups "$username" 2>&1)
    log "DEBUG" "Current groups: $group_check"
    
    # Initialize sudo config
    if [[ $EUID -eq 0 ]]; then
        log "DEBUG" "Initializing sudo configuration..."
        
        # Ensure proper sudoers.d setup
        log "DEBUG" "Setting up sudoers.d directory"
        mkdir -p /etc/sudoers.d
        chmod 750 /etc/sudoers.d
        
        # Create sudoers include if missing
        if ! grep -q "^#includedir /etc/sudoers.d" /etc/sudoers; then
            echo "#includedir /etc/sudoers.d" >> /etc/sudoers
        fi
        
        # Always start with NOPASSWD configuration
        local sudoers_file="/etc/sudoers.d/$username"
        log "DEBUG" "Creating temporary NOPASSWD sudo access"
        echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "$sudoers_file"
        chmod 440 "$sudoers_file"
        
        # Validate sudoers syntax
        if ! visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            log "ERROR" "Invalid sudoers entry for $username"
            rm -f "$sudoers_file"
            return 1
        fi
        
        # Reset sudo timestamp and environment
        log "DEBUG" "Resetting sudo environment"
        sudo -k || true  # Reset all sudo timestamps
        sudo -K -u "$username" 2>/dev/null || true  # Reset user's sudo timestamp
        
        # Ensure clean environment for sudo tests
        unset SUDO_ASKPASS SUDO_EDITOR SUDO_PROMPT || true
        
        # Force refresh of user's groups
        log "DEBUG" "Refreshing group membership"
        pkill -SIGHUP -u "$username" >/dev/null 2>&1 || true
        
        # Initial sudo test with NOPASSWD
        log "DEBUG" "Testing initial NOPASSWD sudo access"
        if ! su -l "$username" -c "sudo -n true" >/dev/null 2>&1; then
            log "DEBUG" "Initial NOPASSWD test failed, trying group refresh"
            usermod -aG sudo "$username"
            pkill -SIGHUP -u "$username" >/dev/null 2>&1 || true
            sleep 2
            
            # Try again after group refresh
            if ! su -l "$username" -c "sudo -n true" >/dev/null 2>&1; then
                log "ERROR" "Failed to verify sudo access even with NOPASSWD"
                return 1
            fi
        fi
        
        # If NOPASSWD test succeeds, switch to password-required configuration
        log "DEBUG" "NOPASSWD verification successful, switching to password-required configuration"
        echo "$username ALL=(ALL:ALL) ALL" > "$sudoers_file"
        chmod 440 "$sudoers_file"
        
        # Final verification that user is in sudo group
        if ! groups "$username" | grep -q '\bsudo\b'; then
            log "ERROR" "User is not in sudo group after configuration"
            return 1
        fi
        
        log "SUCCESS" "Sudo access configured successfully"
        return 0
    else
        log "ERROR" "Root privileges required for sudo initialization"
        return 1
    fi
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
    
    # Setup 2FA if requested
    if prompt_yes_no "Would you like to set up 2FA?" "yes"; then
        setup_2fa "$USERNAME"
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
    
    # Final verification with timeout
    log "INFO" "Running final verification..."
    local verify_timeout=60
    if ! timeout "$verify_timeout" verify_all_configurations "$USERNAME"; then
        log "WARNING" "Final verification exceeded ${verify_timeout} seconds"
        echo "Some verifications timed out but critical components are in place."
        echo "You may want to manually verify:"
        echo "1. Try 'sudo -v' to check sudo access"
        echo "2. Check SSH key login in a new terminal"
        echo "3. Verify 2FA if enabled"
        echo "4. Check service status with 'systemctl status sshd fail2ban'"
    fi
    
    # Always show final status regardless of verification result
    echo "=== Setup Complete ==="
    echo "IMPORTANT: Before logging out, please verify in a new terminal:"
    echo "1. SSH access works with your key on port $SSH_PORT"
    echo "2. 2FA works (if enabled)"
    echo "3. Sudo access works with 'sudo -v'"
    echo "4. Review generated documentation in ${SCRIPT_DIR}/../docs/"
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