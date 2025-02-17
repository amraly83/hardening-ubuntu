#!/bin/bash

# Initialize sudo access in a clean environment
set -euo pipefail

# Get username from argument
username="$1"
if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Clean username
username=$(echo "$username" | tr -cd 'a-z0-9_-')

# Reset sudo state
sudo -K
rm -f /run/sudo/ts/* 2>/dev/null || true

# Create initial sudoers.d entry with NOPASSWD
mkdir -p /etc/sudoers.d
chmod 750 /etc/sudoers.d
echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
chmod 440 "/etc/sudoers.d/$username"

# Verify sudo access works
if timeout 5 su -s /bin/bash - "$username" -c "sudo -n true"; then
    # Switch to password-required configuration
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    exit 0
fi

exit 1