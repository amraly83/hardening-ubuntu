#!/bin/bash

# Helper script for initializing sudo access
set -euo pipefail

username="$1"
if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Clean username
username=$(echo "$username" | tr -cd 'a-z0-9_-')

# Reset sudo state
sudo -K -u "$username" 2>/dev/null || true
rm -f /run/sudo/ts/* 2>/dev/null || true

# Ensure sudo group exists and user is a member
if ! getent group sudo >/dev/null 2>&1; then
    groupadd sudo
fi

usermod -aG sudo "$username"
sg sudo -c "id" || true

# Create NOPASSWD sudoers entry
echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
chmod 440 "/etc/sudoers.d/$username"

# Test sudo access
if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
    # Success - switch to password-required configuration
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    exit 0
fi

exit 1