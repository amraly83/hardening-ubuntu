#!/bin/bash
# Setup 2FA (Google Authenticator) for the newly created admin user
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_RESET='\033[0m'

# Source common functions
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    sed -i 's/\r$//' "${SCRIPT_DIR}/common.sh"
    source "${SCRIPT_DIR}/common.sh"
fi

# Function to configure PAM for 2FA
configure_pam_2fa() {
    local pam_file="/etc/pam.d/sshd"
    backup_file "$pam_file"
    
    # Add Google Authenticator PAM configuration
    sed -i '/^auth.*pam_google_authenticator.so/d' "$pam_file"
    sed -i '1i auth required pam_google_authenticator.so' "$pam_file"
    
    return 0
}

# Function to configure SSH for 2FA
configure_ssh_2fa() {
    local sshd_config="/etc/ssh/sshd_config"
    backup_file "$sshd_config"
    
    # Update SSH configuration
    sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$sshd_config"
    sed -i 's/^AuthenticationMethods.*/AuthenticationMethods publickey,keyboard-interactive/' "$sshd_config"
    
    if ! grep -q "^ChallengeResponseAuthentication" "$sshd_config"; then
        echo "ChallengeResponseAuthentication yes" >> "$sshd_config"
    fi
    if ! grep -q "^AuthenticationMethods" "$sshd_config"; then
        echo "AuthenticationMethods publickey,keyboard-interactive" >> "$sshd_config"
    fi
    
    # Verify configuration
    if ! sshd -t; then
        log "ERROR" "Invalid SSH configuration"
        return 1
    fi
    
    return 0
}

# Main function
main() {
    check_root
    
    if [[ $# -ne 1 ]]; then
        log "ERROR" "Usage: $0 <admin_username>"
        exit 1
    fi
    
    local admin_user="$1"
    
    # Validate admin user
    if ! id "$admin_user" >/dev/null 2>&1; then
        log "ERROR" "Admin user $admin_user does not exist"
        exit 1
    fi
    
    if ! is_user_admin "$admin_user"; then
        log "ERROR" "User $admin_user is not an admin user"
        exit 1
    fi
    
    echo -e "\n${COLOR_CYAN}Setting up 2FA for admin user: $admin_user${COLOR_RESET}"
    
    # Check if 2FA is already configured
    if [[ -f "/home/${admin_user}/.google_authenticator" ]]; then
        log "WARNING" "2FA is already configured for $admin_user"
        if ! prompt_yes_no "Would you like to reconfigure 2FA" "no"; then
            exit 0
        fi
    fi
    
    # Install Google Authenticator if needed
    if ! command -v google-authenticator >/dev/null 2>&1; then
        log "INFO" "Installing Google Authenticator PAM module..."
        apt-get update && apt-get install -y libpam-google-authenticator
    fi
    
    # Configure PAM
    log "INFO" "Configuring PAM for 2FA..."
    if ! configure_pam_2fa; then
        log "ERROR" "Failed to configure PAM"
        exit 1
    fi
    
    # Configure SSH
    log "INFO" "Configuring SSH for 2FA..."
    if ! configure_ssh_2fa; then
        log "ERROR" "Failed to configure SSH"
        exit 1
    fi
    
    # Set up Google Authenticator for the admin user
    echo -e "\n${COLOR_CYAN}Setting up Google Authenticator for $admin_user...${COLOR_RESET}"
    echo "Please follow the prompts to configure your 2FA device"
    
    # Run google-authenticator as the admin user
    if ! su -c "google-authenticator -t -d -f -r 3 -R 30 -w 3" - "$admin_user"; then
        log "ERROR" "Failed to set up Google Authenticator"
        exit 1
    fi
    
    # Set proper permissions
    chmod 400 "/home/${admin_user}/.google_authenticator"
    chown "${admin_user}:${admin_user}" "/home/${admin_user}/.google_authenticator"
    
    # Restart SSH service
    systemctl restart sshd
    
    echo -e "\n${COLOR_GREEN}2FA setup completed successfully for admin user: $admin_user${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Important: Test 2FA login in a new terminal before closing this session!${COLOR_RESET}"
    echo "Command to test: ssh -o PreferredAuthentications=keyboard-interactive ${admin_user}@localhost"
    
    return 0
}

# Run main function
main "$@"