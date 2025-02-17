#!/bin/bash

# Set strict mode
set -euo pipefail

# Get absolute path of script directory and common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/common.sh"

# Define color codes
readonly COLOR_PROMPT='\033[1;36m'    # Bright Cyan for prompts
readonly COLOR_ERROR='\033[1;31m'     # Bright Red for errors
readonly COLOR_RESET='\033[0m'

# Set log file first (before sourcing common.sh)
LOG_FILE="/var/log/server-hardening.log"

# Convert line endings in common.sh if needed
sed -i 's/\r$//' "$COMMON_SH"

# Source common functions
source "$COMMON_SH" || { echo -e "${COLOR_ERROR}Error: Failed to source $COMMON_SH${COLOR_RESET}"; exit 1; }

# Initialize script (after sourcing common.sh)
init_script || { echo "Error: Failed to initialize script"; exit 1; }

setup_sudo_access() {
    local username="$1"
    
    # Ensure sudo group exists
    if ! getent group sudo >/dev/null 2>&1; then
        groupadd sudo
    fi
    
    # Add to sudo group
    log "INFO" "Adding '$username' to sudo group"
    usermod -aG sudo "$username"
    
    # Create initial sudo configuration
    mkdir -p /etc/sudoers.d
    chmod 750 /etc/sudoers.d
    
    # Set up initial NOPASSWD access
    log "DEBUG" "Setting up initial sudo access"
    echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Quick verification
    if timeout 5 su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        # Switch to password-required configuration
        echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
        chmod 440 "/etc/sudoers.d/$username"
        log "SUCCESS" "Sudo access configured successfully"
        return 0
    fi
    
    log "ERROR" "Failed to verify sudo access"
    return 1
}

# Get username with retry logic
get_valid_username() {
    local username
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if [ -z "${1:-}" ]; then
            printf "${COLOR_PROMPT}Enter new admin username${COLOR_RESET}: "
            read -r username
        else
            username="$1"
        fi
        
        # Basic validation before calling validate_username
        if [[ -z "$username" ]]; then
            echo -e "${COLOR_ERROR}Error: Username cannot be empty${COLOR_RESET}"
            if [ -n "${1:-}" ]; then
                return 1
            fi
            ((attempt++))
            continue
        fi
        
        # Call validate_username
        if validate_username "$username"; then
            printf "%s" "$username"
            return 0
        fi
        
        if [ -n "${1:-}" ]; then
            return 1
        fi
        ((attempt++))
    done
    
    return 1
}

handle_existing_user() {
    local username="$1"
    
    if is_user_admin "$username"; then
        if [ -t 0 ]; then  # Only prompt if running interactively
            if prompt_yes_no "User '$username' is already an admin. Would you like to verify/update their configuration" "yes"; then
                return 0
            else
                return 1
            fi
        else
            log "INFO" "User '$username' is already an admin user"
            return 0
        fi
    else
        log "WARNING" "User '$username' exists but is not an admin"
        if [ -t 0 ]; then  # Only prompt if running interactively
            if prompt_yes_no "Would you like to add this user to sudo group" "no"; then
                if usermod -aG sudo "$username"; then
                    log "INFO" "Added '$username' to sudo group"
                    return 0
                else
                    error_exit "Failed to add user to sudo group"
                fi
            fi
        fi
        return 1
    fi
}

main() {
    local USERNAME
    
    # Get and validate username
    USERNAME=$(get_valid_username "${1:-}") || error_exit "Failed to get valid username"
    
    # Handle existing user
    if id "$USERNAME" >/dev/null 2>&1; then
        if is_user_admin "$USERNAME"; then
            log "INFO" "User '$USERNAME' already exists and is already an admin"
            if prompt_yes_no "Would you like to use this existing admin user" "yes"; then
                printf "%s" "$USERNAME"
                return 0
            fi
            error_exit "Operation cancelled. Please try again with a different username"
        else
            log "WARNING" "User '$USERNAME' exists but is not an admin"
            if prompt_yes_no "Would you like to grant admin privileges to this user" "no"; then
                if usermod -aG sudo "$USERNAME"; then
                    log "INFO" "Added '$USERNAME' to sudo group"
                    printf "%s" "$USERNAME"
                    return 0
                else
                    error_exit "Failed to add user to sudo group"
                fi
            fi
            error_exit "Operation cancelled. Please try again with a different username"
        fi
    fi
    
    # Create new user
    log "INFO" "Creating new admin user: $USERNAME"
    if ! adduser --gecos "" "$USERNAME"; then
        error_exit "Failed to create user '$USERNAME'"
    fi
    
    # Add to sudo group and configure sudo access
    if ! setup_sudo_access "$USERNAME"; then
        error_exit "Failed to configure sudo access"
    fi
    
    # Set up .ssh directory
    SSH_DIR="/home/${USERNAME}/.ssh"
    if [[ ! -d "$SSH_DIR" ]]; then
        mkdir -p "$SSH_DIR"
        chown "${USERNAME}:${USERNAME}" "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    
    log "INFO" "Successfully configured admin user: $USERNAME"
    printf "%s" "$USERNAME"
}

main "$@"