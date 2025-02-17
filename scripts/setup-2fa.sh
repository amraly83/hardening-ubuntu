#!/bin/bash
# Setup 2FA (Google Authenticator) for a user
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions after fixing line endings
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    sed -i 's/\r$//' "${SCRIPT_DIR}/common.sh"
    source "${SCRIPT_DIR}/common.sh"
fi

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_RESET='\033[0m'

# Function to backup PAM configuration
backup_pam_config() {
    local file="/etc/pam.d/sshd"
    local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
    
    if [[ -f "$file" ]]; then
        cp -p "$file" "$backup" || return 1
        chmod --reference="$file" "$backup" 2>/dev/null || chmod 644 "$backup"
    fi
    return 0
}

# Function to configure PAM for 2FA
configure_pam_2fa() {
    local pam_file="/etc/pam.d/sshd"
    local temp_file
    temp_file=$(mktemp)
    
    # Create new configuration
    {
        echo "#%PAM-1.0"
        echo "auth required pam_google_authenticator.so"
        echo "auth include common-auth"
        echo "account include common-account"
        echo "session include common-session"
    } > "$temp_file"
    
    # Validate syntax
    if ! pam-syntax-check "$temp_file" 2>/dev/null; then
        rm -f "$temp_file"
        return 1
    fi
    
    # Backup and install new configuration
    backup_pam_config
    mv "$temp_file" "$pam_file"
    chmod 644 "$pam_file"
    
    return 0
}

# Function to configure SSH for 2FA
configure_ssh_2fa() {
    local sshd_config="/etc/ssh/sshd_config"
    local temp_config
    temp_config=$(mktemp)
    
    # Backup existing config
    cp -p "$sshd_config" "${sshd_config}.$(date +%Y%m%d_%H%M%S).bak"
    
    # Update SSH configuration
    sed '/^ChallengeResponseAuthentication/d; /^AuthenticationMethods/d' "$sshd_config" > "$temp_config"
    {
        echo "ChallengeResponseAuthentication yes"
        echo "AuthenticationMethods publickey,keyboard-interactive"
    } >> "$temp_config"
    
    # Validate configuration
    if ! sshd -t -f "$temp_config" >/dev/null 2>&1; then
        rm -f "$temp_config"
        return 1
    fi
    
    # Install new configuration
    mv "$temp_config" "$sshd_config"
    chmod 600 "$sshd_config"
    
    return 0
}

# Function to set up Google Authenticator for a user
setup_google_auth() {
    local username="$1"
    local ga_file="/home/${username}/.google_authenticator"
    
    # Generate configuration
    if ! su -c "google-authenticator -t -d -f -r 3 -R 30 -w 3" - "$username"; then
        return 1
    fi
    
    # Verify file exists and has correct permissions
    if [[ ! -f "$ga_file" ]]; then
        return 1
    fi
    
    chmod 400 "$ga_file"
    chown "$username:$username" "$ga_file"
    
    return 0
}

# Main function
main() {
    # Verify arguments
    if [[ $# -ne 1 ]]; then
        echo -e "${COLOR_RED}Usage: $0 username${COLOR_RESET}"
        exit 1
    fi
    
    local username="$1"
    
    # Clean username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Error: User $username does not exist${COLOR_RESET}"
        exit 1
    fi
    
    echo -e "${COLOR_CYAN}Setting up 2FA for user: $username${COLOR_RESET}"
    
    # Check if 2FA is already configured
    if [[ -f "/home/${username}/.google_authenticator" ]]; then
        echo -e "${COLOR_YELLOW}Warning: 2FA already configured for $username${COLOR_RESET}"
        echo -n "Would you like to reconfigure? [y/N] "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
    
    # Configure PAM
    echo "Configuring PAM for 2FA..."
    if ! configure_pam_2fa; then
        echo -e "${COLOR_RED}Failed to configure PAM${COLOR_RESET}"
        exit 1
    fi
    
    # Configure SSH
    echo "Configuring SSH for 2FA..."
    if ! configure_ssh_2fa; then
        echo -e "${COLOR_RED}Failed to configure SSH${COLOR_RESET}"
        exit 1
    fi
    
    # Set up Google Authenticator
    echo -e "\n${COLOR_CYAN}Setting up Google Authenticator...${COLOR_RESET}"
    echo "Please follow the prompts to configure your 2FA device"
    if ! setup_google_auth "$username"; then
        echo -e "${COLOR_RED}Failed to set up Google Authenticator${COLOR_RESET}"
        exit 1
    fi
    
    # Restart SSH service
    systemctl restart sshd
    
    echo -e "\n${COLOR_GREEN}2FA setup completed successfully${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Important: Test 2FA login in a new terminal before closing this session!${COLOR_RESET}"
    echo "Command to test: ssh -o PreferredAuthentications=keyboard-interactive ${username}@localhost"
    
    return 0
}

# Run main function
main "$@"