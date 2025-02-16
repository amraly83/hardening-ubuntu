#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

# Main script logic starts here
if [ -z "${1:-}" ]; then
    read -p "Enter new admin username: " USERNAME
else
    USERNAME="$1"
fi

# Validate username
validate_username "$USERNAME"

# Check if user exists
if id "$USERNAME" >/dev/null 2>&1; then
    if is_user_admin "$USERNAME"; then
        error_exit "User '$USERNAME' already exists and is already an admin user"
    else
        log "WARNING" "User '$USERNAME' already exists but is not an admin"
        if prompt_yes_no "Would you like to add this user to sudo group" "no"; then
            usermod -aG sudo "$USERNAME"
            log "INFO" "Added '$USERNAME' to sudo group"
        else
            error_exit "Operation cancelled by user"
        fi
    fi
else
    # Create new user
    log "INFO" "Creating new admin user: $USERNAME"
    if ! adduser --gecos "" "$USERNAME"; then
        error_exit "Failed to create user '$USERNAME'"
    fi
    
    # Add to sudo group
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