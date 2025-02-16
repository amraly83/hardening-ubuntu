#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

# Get username
if [ -z "${1:-}" ]; then
    read -p "Enter username to setup SSH key for: " USERNAME
else
    USERNAME="$1"
fi

# Check if user exists
check_user_exists "$USERNAME"

# Create .ssh directory if it doesn't exist
SSH_DIR="/home/${USERNAME}/.ssh"
if [[ ! -d "$SSH_DIR" ]]; then
    mkdir -p "$SSH_DIR"
    chown "${USERNAME}:${USERNAME}" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
fi

# Path for the authorized_keys file
AUTH_KEYS="${SSH_DIR}/authorized_keys"

# Check if authorized_keys already exists
if [[ -f "$AUTH_KEYS" ]]; then
    backup_file "$AUTH_KEYS"
fi

# Get the SSH public key
while true; do
    echo "Please paste the SSH public key (starts with ssh-rsa or ssh-ed25519):"
    read -r PUBKEY
    
    if [[ -z "$PUBKEY" ]]; then
        error_exit "No SSH key provided"
    fi
    
    if validate_ssh_key "$PUBKEY"; then
        break
    else
        log "ERROR" "Invalid SSH public key. Please try again."
    fi
done

# Add the key to authorized_keys
echo "$PUBKEY" >> "$AUTH_KEYS"
chown "${USERNAME}:${USERNAME}" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# Verify SSH access works
log "INFO" "Verifying SSH key setup..."
if ! verify_ssh_access "$USERNAME"; then
    log "WARNING" "Could not verify SSH access automatically"
    echo "Please test SSH access manually"
fi

log "INFO" "SSH key has been added for user ${USERNAME}"
echo "================================================================"
echo "SSH key setup complete for ${USERNAME}"
echo
echo "To test the SSH key access:"
echo "1. Try logging in from another terminal:"
echo "   ssh -i ~/.ssh/id_ed25519 ${USERNAME}@hostname"
echo
echo "2. If using 2FA, set it up now:"
echo "   ./setup-2fa.sh ${USERNAME}"
echo "================================================================"