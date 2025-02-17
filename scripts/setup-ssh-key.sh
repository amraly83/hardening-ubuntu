#!/bin/bash
# Setup SSH keys for a user with cross-platform compatibility
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

# Function to validate SSH key
validate_ssh_key() {
    local key="$1"
    
    # Remove any carriage returns and leading/trailing whitespace
    key=$(echo "$key" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Check if key is non-empty
    if [[ -z "$key" ]]; then
        return 1
    fi
    
    # Validate key format using ssh-keygen
    if ! echo "$key" | ssh-keygen -l -f - >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

# Function to setup SSH directory with proper permissions
setup_ssh_dir() {
    local username="$1"
    local home_dir
    home_dir=$(getent passwd "$username" | cut -d: -f6)
    
    if [[ ! -d "$home_dir" ]]; then
        echo -e "${COLOR_RED}Error: Home directory not found for $username${COLOR_RESET}"
        return 1
    fi
    
    local ssh_dir="${home_dir}/.ssh"
    
    # Create .ssh directory if it doesn't exist
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$username:$username" "$ssh_dir"
    
    # Create authorized_keys file if it doesn't exist
    touch "${ssh_dir}/authorized_keys"
    chmod 600 "${ssh_dir}/authorized_keys"
    chown "$username:$username" "${ssh_dir}/authorized_keys"
    
    return 0
}

# Function to add SSH key
add_ssh_key() {
    local username="$1"
    local key="$2"
    local home_dir
    home_dir=$(getent passwd "$username" | cut -d: -f6)
    local auth_keys="${home_dir}/.ssh/authorized_keys"
    
    # Clean up the key (remove carriage returns and extra whitespace)
    key=$(echo "$key" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Check if key already exists
    if grep -Fq "$key" "$auth_keys" 2>/dev/null; then
        echo -e "${COLOR_YELLOW}Warning: SSH key already exists${COLOR_RESET}"
        return 0
    fi
    
    # Add the key
    echo "$key" >> "$auth_keys"
    chmod 600 "$auth_keys"
    chown "$username:$username" "$auth_keys"
    
    return 0
}

# Function to verify SSH configuration
verify_ssh_config() {
    # Check sshd configuration
    if ! sshd -t >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Error: Invalid SSH server configuration${COLOR_RESET}"
        return 1
    fi
    
    # Check if SSH service is running
    if ! systemctl is-active --quiet sshd; then
        echo -e "${COLOR_RED}Error: SSH service is not running${COLOR_RESET}"
        return 1
    fi
    
    return 0
}

# Main function
main() {
    # Check arguments
    if [[ $# -ne 1 ]]; then
        echo -e "${COLOR_RED}Usage: $0 username${COLOR_RESET}"
        exit 1
    fi
    
    local username="$1"
    
    # Clean username
    username=$(echo "$username" | tr -cd 'a-z0-9_-')
    
    # Verify user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Error: User $username does not exist${COLOR_RESET}"
        exit 1
    fi
    
    echo -e "${COLOR_CYAN}Setting up SSH keys for user: $username${COLOR_RESET}"
    
    # Setup SSH directory
    if ! setup_ssh_dir "$username"; then
        echo -e "${COLOR_RED}Failed to setup SSH directory${COLOR_RESET}"
        exit 1
    fi
    
    # Get SSH key from user
    echo -e "\n${COLOR_CYAN}Please paste your SSH public key (from ~/.ssh/id_ed25519.pub or similar):${COLOR_RESET}"
    read -r ssh_key
    
    # Validate SSH key
    if ! validate_ssh_key "$ssh_key"; then
        echo -e "${COLOR_RED}Error: Invalid SSH key format${COLOR_RESET}"
        exit 1
    fi
    
    # Add SSH key
    if ! add_ssh_key "$username" "$ssh_key"; then
        echo -e "${COLOR_RED}Failed to add SSH key${COLOR_RESET}"
        exit 1
    fi
    
    # Verify SSH configuration
    echo "Verifying SSH configuration..."
    if ! verify_ssh_config; then
        echo -e "${COLOR_YELLOW}Warning: SSH configuration verification failed${COLOR_RESET}"
        echo "Please check SSH server configuration manually"
    fi
    
    echo -e "\n${COLOR_GREEN}SSH key setup completed successfully${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Important: Test SSH access in a new terminal before closing this session!${COLOR_RESET}"
    echo "Command to test: ssh ${username}@localhost"
    
    return 0
}

# Run main function
main "$@"
