#!/bin/bash
set -euo pipefail

# Check if run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Get username
if [ -z "$1" ]; then
    read -p "Enter username to setup SSH key for: " USERNAME
else
    USERNAME="$1"
fi

# Check if user exists
if ! id "$USERNAME" >/dev/null 2>&1; then
    echo "User $USERNAME does not exist"
    exit 1
fi

# Create .ssh directory if it doesn't exist
SSH_DIR="/home/${USERNAME}/.ssh"
if [[ ! -d "$SSH_DIR" ]]; then
    mkdir -p "$SSH_DIR"
    chown "${USERNAME}:${USERNAME}" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
fi

# Path for the authorized_keys file
AUTH_KEYS="${SSH_DIR}/authorized_keys"

# Function to validate SSH public key
validate_ssh_key() {
    local key="$1"
    ssh-keygen -l -f <(echo "$key") >/dev/null 2>&1
}

# Get the SSH public key
while true; do
    echo "Please paste the SSH public key (starts with ssh-rsa or ssh-ed25519):"
    read -r PUBKEY
    
    if validate_ssh_key "$PUBKEY"; then
        break
    else
        echo "Invalid SSH public key. Please try again."
    fi
done

# Add the key to authorized_keys
echo "$PUBKEY" >> "$AUTH_KEYS"
chown "${USERNAME}:${USERNAME}" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

echo "SSH key has been added for user ${USERNAME}"
echo "Please verify SSH key access before running the hardening script!"