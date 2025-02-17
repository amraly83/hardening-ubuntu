#!/bin/bash
# Simple wrapper script for sudo verification with reliable timeout
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fix line endings in common.sh if it exists
COMMON_SH="${SCRIPT_DIR}/common.sh"
if [[ -f "$COMMON_SH" ]]; then
    sed -i 's/\r$//' "$COMMON_SH"
    source "$COMMON_SH"
fi

# Get and clean username
username="$1"
if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Clean the username to prevent any concatenation issues
username=$(echo "$username" | tr -cd 'a-z0-9_-')

# Reset sudo state first
sudo -K -u "$username" 2>/dev/null || true
rm -f /run/sudo/ts/* 2>/dev/null || true

# Run sudo test as a single inline script with proper error handling
timeout 10 bash -c "
    # First try with -n (non-interactive)
    if su -s /bin/bash - \"$username\" -c 'sudo -n true' >/dev/null 2>&1; then
        exit 0
    fi
    
    # Try standard sudo if non-interactive fails
    if su -s /bin/bash - \"$username\" -c 'sudo true' >/dev/null 2>&1; then
        exit 0
    fi
    
    # If we get here, both attempts failed
    exit 1
" || exit 1