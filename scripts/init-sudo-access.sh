#!/bin/bash
# Initialize sudo access in a clean environment
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions if available
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    sed -i 's/\r$//' "${SCRIPT_DIR}/common.sh"
    source "${SCRIPT_DIR}/common.sh"
fi

# Get username from argument
username="$1"
if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Clean username and validate format
username=$(echo "$username" | tr -cd 'a-z0-9_-')
if [[ ! "$username" =~ ^[a-z][a-z0-9_-]*$ ]]; then
    echo "Invalid username format" >&2
    exit 1
fi

# Verify user exists
if ! id "$username" >/dev/null 2>&1; then
    echo "User does not exist: $username" >&2
    exit 1
fi

# Reset sudo state for clean initialization
sudo -K
rm -f /run/sudo/ts/* 2>/dev/null || true

# Ensure sudo group exists and user is a member
if ! getent group sudo >/dev/null 2>&1; then
    groupadd sudo
fi

# Add user to sudo group if not already a member
if ! groups "$username" | grep -q '\bsudo\b'; then
    usermod -aG sudo "$username"
    # Force group update
    sg sudo -c "id" || true
fi

# Create initial sudoers.d entry with NOPASSWD for testing
mkdir -p /etc/sudoers.d
chmod 750 /etc/sudoers.d
echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
chmod 440 "/etc/sudoers.d/$username"

# Verify sudo access works with multiple attempts
max_attempts=3
attempt=1
success=false

while [ $attempt -le $max_attempts ]; do
    if timeout 5 su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        success=true
        break
    fi
    sleep 1
    ((attempt++))
done

if [ "$success" = true ]; then
    # Switch to password-required configuration
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    exit 0
fi

echo "Failed to verify sudo access after $max_attempts attempts" >&2
exit 1