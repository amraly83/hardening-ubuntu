#!/bin/bash
# Setup 2FA (Google Authenticator) for system users
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Constants for Google Authenticator settings
readonly GA_WINDOW_SIZE=3        # Allow 3 tokens before/after current one
readonly GA_RATE_LIMIT=3         # Max 3 login attempts per 30 seconds
readonly GA_RATE_TIME=30         # Time window for rate limiting (seconds)
readonly GA_DISALLOW_REUSE=1     # Disallow token reuse
readonly GA_TOKENS_LAG=1         # Emergency scratch codes

# Function to install required packages
install_dependencies() {
    local pkg="libpam-google-authenticator"
    local max_retries=3
    local retry=0
    local delay=5
    
    log "INFO" "Installing required packages..."
    
    while (( retry < max_retries )); do
        if ! fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            if apt-get update && apt-get install -y "$pkg"; then
                log "SUCCESS" "Package installation completed"
                return 0
            fi
        fi
        
        log "WARNING" "Package manager is locked or installation failed, retrying in $delay seconds..."
        sleep "$delay"
        (( retry++ ))
        (( delay *= 2 ))
    done
    
    error_exit "Failed to install required packages after $max_retries attempts"
}

# Function to configure PAM for 2FA
configure_pam_2fa() {
    local pam_file="/etc/pam.d/sshd"
    local pam_backup="${pam_file}.pre2fa"
    
    log "INFO" "Configuring PAM for 2FA..."
    
    # Create backup if it doesn't exist
    if [[ ! -f "$pam_backup" ]]; then
        cp -p "$pam_file" "$pam_backup"
    fi
    
    # Remove any existing Google Authenticator configuration
    sed -i '/^auth.*pam_google_authenticator.so/d' "$pam_file"
    
    # Add new configuration at the beginning
    sed -i '1i auth required pam_google_authenticator.so' "$pam_file"
    
    # Verify PAM configuration
    if ! pam-auth-update --verify >/dev/null 2>&1; then
        log "ERROR" "Invalid PAM configuration"
        restore_from_backup "$pam_file" "$pam_backup"
        return 1
    fi
    
    return 0
}

# Function to configure SSH for 2FA
configure_ssh_2fa() {
    local sshd_config="/etc/ssh/sshd_config"
    local config_backup="${sshd_config}.pre2fa"
    
    log "INFO" "Configuring SSH for 2FA..."
    
    # Create backup if it doesn't exist
    if [[ ! -f "$config_backup" ]]; then
        cp -p "$sshd_config" "$config_backup"
    fi
    
    # Update SSH configuration with proper options
    local settings=(
        "ChallengeResponseAuthentication yes"
        "AuthenticationMethods publickey,keyboard-interactive"
        "KbdInteractiveAuthentication yes"
        "UsePAM yes"
    )
    
    # Apply settings
    for setting in "${settings[@]}"; do
        local key="${setting%% *}"
        sed -i "/^${key}/d" "$sshd_config"
        echo "$setting" >> "$sshd_config"
    done
    
    # Verify SSH configuration
    if ! sshd -t; then
        log "ERROR" "Invalid SSH configuration"
        restore_from_backup "$sshd_config" "$config_backup"
        return 1
    fi
    
    return 0
}

# Function to set up Google Authenticator for a user
setup_google_auth() {
    local username="$1"
    local ga_file="/home/${username}/.google_authenticator"
    
    log "INFO" "Setting up Google Authenticator for $username..."
    
    # Generate Google Authenticator configuration
    local ga_options=(
        "--time-based"                     # TOTP instead of HOTP
        "--disallow-reuse"                 # Prevent token reuse
        "--force"                          # Don't prompt for confirmation
        "--rate-limit=${GA_RATE_LIMIT}"    # Rate limiting attempts
        "--rate-time=${GA_RATE_TIME}"      # Rate limiting window
        "--window-size=${GA_WINDOW_SIZE}"  # Allow some clock skew
        "--emergency-codes=${GA_TOKENS_LAG}" # Emergency scratch codes
    )
    
    if ! su -c "google-authenticator ${ga_options[*]}" - "$username"; then
        error_exit "Failed to set up Google Authenticator for $username"
    fi
    
    # Set proper permissions
    chmod 400 "$ga_file"
    chown "${username}:${username}" "$ga_file"
    
    return 0
}

# Function to verify 2FA setup
verify_2fa_setup() {
    local username="$1"
    local ga_file="/home/${username}/.google_authenticator"
    
    # Check file existence and permissions
    if [[ ! -f "$ga_file" ]]; then
        return 1
    fi
    
    # Verify file permissions
    local perms
    perms=$(stat -c "%a" "$ga_file")
    if [[ "$perms" != "400" ]]; then
        return 1
    fi
    
    # Check PAM configuration
    if ! grep -q "^auth.*pam_google_authenticator.so" /etc/pam.d/sshd; then
        return 1
    fi
    
    # Check SSH configuration
    if ! grep -q "^AuthenticationMethods.*keyboard-interactive" /etc/ssh/sshd_config; then
        return 1
    fi
    
    return 0
}

# Function to test 2FA configuration
test_2fa_config() {
    local username="$1"
    local test_command="ssh -o PreferredAuthentications=keyboard-interactive -o BatchMode=no ${username}@localhost echo 'Test successful'"
    
    log "INFO" "Testing 2FA configuration..."
    
    if timeout 5 "$test_command" >/dev/null 2>&1; then
        log "ERROR" "2FA test failed - connection succeeded without 2FA"
        return 1
    elif [[ $? -eq 124 ]]; then
        # Timeout means we got a 2FA prompt, which is good
        log "SUCCESS" "2FA prompt verified"
        return 0
    else
        log "SUCCESS" "2FA configuration verified"
        return 0
    fi
}

# Main function
main() {
    local admin_user=""
    local force_setup=0
    
    # Parse command line options
    while getopts "u:f" opt; do
        case $opt in
            u) admin_user="$OPTARG" ;;
            f) force_setup=1 ;;
            *) error_exit "Usage: $0 -u <username> [-f]" ;;
        esac
    done
    
    if [[ -z "$admin_user" ]]; then
        error_exit "Username is required. Usage: $0 -u <username> [-f]"
    fi
    
    # Verify root access
    check_root
    
    # Validate user
    if ! validate_username "$admin_user"; then
        error_exit "Invalid username format: $admin_user"
    fi
    
    if ! id "$admin_user" >/dev/null 2>&1; then
        error_exit "User $admin_user does not exist"
    fi
    
    if ! is_user_admin "$admin_user"; then
        error_exit "User $admin_user is not an admin user"
    fi
    
    # Check if 2FA is already configured
    if [[ $force_setup -eq 0 ]] && verify_2fa_setup "$admin_user"; then
        log "WARNING" "2FA is already configured for $admin_user"
        if ! prompt_yes_no "Would you like to reconfigure 2FA" "no"; then
            exit 0
        fi
    fi
    
    # Install dependencies
    if ! command -v google-authenticator >/dev/null 2>&1; then
        install_dependencies
    fi
    
    # Configure PAM and SSH with rollback on failure
    if ! configure_pam_2fa || ! configure_ssh_2fa; then
        log "ERROR" "Failed to configure 2FA"
        exit 1
    fi
    
    # Set up Google Authenticator
    if ! setup_google_auth "$admin_user"; then
        log "ERROR" "Failed to set up Google Authenticator"
        exit 1
    fi
    
    # Restart SSH service
    systemctl restart sshd || error_exit "Failed to restart SSH service"
    
    # Verify setup
    if ! verify_2fa_setup "$admin_user"; then
        log "ERROR" "2FA verification failed"
        exit 1
    fi
    
    # Test configuration
    if ! test_2fa_config("$admin_user"); then
        log "ERROR" "2FA testing failed"
        exit 1
    fi
    
    log "SUCCESS" "2FA setup completed successfully for user: $admin_user"
    echo -e "\n${COLOR_YELLOW}Important: Test 2FA login in a new terminal before closing this session!${COLOR_RESET}"
    echo "Command to test: ssh ${admin_user}@localhost"
    
    return 0
}

# Run main function with all arguments
main "$@"