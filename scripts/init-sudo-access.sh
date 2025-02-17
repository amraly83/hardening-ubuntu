#!/bin/bash
# Initialize sudo access in a clean environment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Validate input and user existence
if [ $# -lt 1 ]; then
    log "ERROR" "Usage: $0 username"
    exit 1
fi

username="$1"
username=$(echo "$username" | tr -cd 'a-z0-9_-')

if ! validate_username "$username"; then
    exit 1
fi

if ! id "$username" >/dev/null 2>&1; then
    log "ERROR" "User does not exist: $username"
    exit 1
fi

# Clean environment
clean_sudo_env "$username"

# Setup sudo with NOPASSWD first for testing
if ! setup_sudo_access "$username" true; then
    log "ERROR" "Failed to setup initial sudo access"
    exit 1
fi

# Test sudo access
if ! test_sudo_access "$username" 3; then
    log "ERROR" "Failed to verify sudo access"
    exit 1
fi

# Switch to password-required configuration
if ! setup_sudo_access "$username" false; then
    log "ERROR" "Failed to setup final sudo configuration"
    exit 1
fi

log "SUCCESS" "Sudo access initialized successfully"
exit 0