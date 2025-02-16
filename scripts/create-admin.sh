#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Get username
if [ -z "$1" ]; then
    read -p "Enter new admin username: " USERNAME
else
    USERNAME="$1"
fi

# Validate username
if [[ ! "$USERNAME" =~ ^[a-z][-a-z0-9]*$ ]]; then
    echo "Invalid username. Use only lowercase letters, numbers, and hyphens."
    echo "Username must start with a letter."
    exit 1
fi

# Check if user exists
if id "$USERNAME" >/dev/null 2>&1; then
    echo "User $USERNAME already exists"
    exit 1
fi

# Create user
echo "Creating new admin user: $USERNAME"
adduser "$USERNAME"

# Add to sudo group
usermod -aG sudo "$USERNAME"

# Set up .ssh directory
SSH_DIR="/home/${USERNAME}/.ssh"
if [[ ! -d "$SSH_DIR" ]]; then
    mkdir -p "$SSH_DIR"
    chown "${USERNAME}:${USERNAME}" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
fi

# Path for the authorized_keys file
AUTH_KEYS="${SSH_DIR}/authorized_keys"
touch "$AUTH_KEYS"
chown "${USERNAME}:${USERNAME}" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

echo "================================================================"
echo "Admin user $USERNAME has been created and added to sudo group"
echo "Before running the hardening script, you MUST:"
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