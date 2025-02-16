#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

# Get username with retry logic
get_valid_username() {
    local username
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if [ -z "${1:-}" ]; then
            read -r -p "Enter new admin username: " username
        else
            username="$1"
        fi
        
        # Trim whitespace
        username=$(echo "$username" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        
        # Basic validation before calling validate_username
        if [[ -z "$username" ]]; then
            log "ERROR" "Username cannot be empty"
            if [ -n "${1:-}" ]; then
                return 1
            fi
            ((attempt++))
            continue
        fi
        
        # Call validate_username without redirecting stderr
        if ! validate_username "$username"; then
            if [ -n "${1:-}" ]; then
                return 1
            fi
            ((attempt++))
            continue
        fi
        
        echo "$username"
        return 0
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
        if ! handle_existing_user "$USERNAME"; then
            error_exit "Operation cancelled. Please try again with a different username"
        fi
    else
        # Create new user
        log "INFO" "Creating new admin user: $USERNAME"
        if ! adduser --gecos "" "$USERNAME"; then
            error_exit "Failed to create user '$USERNAME'"
        fi
        
        # Add to sudo group
        log "INFO" "Adding '$USERNAME' to sudo group"
        if ! usermod -aG sudo "$USERNAME"; then
            error_exit "Failed to add '$USERNAME' to sudo group"
        fi
    fi
    
    # Set up .ssh directory
    SSH_DIR="/home/${USERNAME}/.ssh"
    if [[ ! -d "$SSH_DIR" ]]; then
        mkdir -p "$SSH_DIR"
        chown "${USERNAME}:${USERNAME}" "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    
    log "INFO" "Successfully configured admin user: $USERNAME"
    echo "================================================================"
    echo "Admin user $USERNAME has been configured"
    echo
    echo "Next steps:"
    echo "1. Set up SSH keys for this user:"
    echo "   ./setup-ssh-key.sh $USERNAME"
    echo
    echo "2. Test sudo access:"
    echo "   su - $USERNAME"
    echo "   sudo whoami  # Should output 'root'"
    echo
    echo "3. If using 2FA, set it up:"
    echo "   ./setup-2fa.sh $USERNAME"
    echo "================================================================"
}

main "$@"