#!/bin/bash
# Initialize sudo access with proper cross-platform handling
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RESET='\033[0m'

# Clean and validate username
username="$1"
if [ -z "$username" ]; then
    echo -e "${COLOR_RED}Usage: $0 username${COLOR_RESET}" >&2
    exit 1
fi

# Clean username to prevent concatenation issues
username=$(echo "$username" | tr -cd 'a-z0-9_-')

# Verify user exists
if ! id "$username" >/dev/null 2>&1; then
    echo -e "${COLOR_RED}Error: User $username does not exist${COLOR_RESET}" >&2
    exit 1
fi

# Clear sudo state
sudo -K -u "$username" 2>/dev/null || true
rm -f /run/sudo/ts/* 2>/dev/null || true

# Ensure sudo group exists
if ! getent group sudo >/dev/null 2>&1; then
    groupadd sudo
fi

# Add to sudo group if needed
if ! groups "$username" | grep -q '\bsudo\b'; then
    usermod -aG sudo "$username"
    # Force group update
    sg sudo -c "id" || true
fi

# Create or update sudoers entry
mkdir -p /etc/sudoers.d
chmod 750 /etc/sudoers.d

# Start with NOPASSWD for testing
echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
chmod 440 "/etc/sudoers.d/$username"

# Test sudo access with retries
max_attempts=3
attempt=1
success=false

while [ $attempt -le $max_attempts ]; do
    echo -n "Testing sudo access (attempt $attempt/$max_attempts)... "
    if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
        success=true
        break
    fi
    echo -e "${COLOR_RED}Failed${COLOR_RESET}"
    sleep 1
    ((attempt++))
done

if [ "$success" = true ]; then
    # Switch to password-required configuration
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    echo -e "${COLOR_GREEN}Sudo access configured successfully${COLOR_RESET}"
    exit 0
fi

echo -e "${COLOR_RED}Failed to verify sudo access after $max_attempts attempts${COLOR_RESET}" >&2
exit 1