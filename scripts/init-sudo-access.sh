#!/bin/bash
# Initialize sudo access in a clean environment
set -euo pipefail

# Fix line endings and setup
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Validate input
if [ $# -lt 1 ]; then
    log "ERROR" "Usage: $0 username"
    exit 1
fi

username="$1"
username=$(echo "$username" | tr -cd 'a-z0-9_-')

# Validate username and existence
if ! validate_username "$username"; then
    exit 1
fi

if ! id "$username" >/dev/null 2>&1; then
    log "ERROR" "User does not exist: $username"
    exit 1
fi

# Clean sudo environment
log "DEBUG" "Cleaning sudo environment..."
sudo -K
rm -f /run/sudo/ts/* 2>/dev/null || true

# Setup sudo group
if ! getent group sudo >/dev/null 2>&1; then
    log "INFO" "Creating sudo group"
    groupadd sudo
fi

# Add user to sudo group
if ! groups "$username" | grep -q '\bsudo\b'; then
    log "INFO" "Adding $username to sudo group"
    usermod -aG sudo "$username"
    # Force group update
    sg sudo -c "id" || true
fi

# Setup sudoers directory
mkdir -p /etc/sudoers.d
chmod 750 /etc/sudoers.d

# Configure sudo access
log "INFO" "Configuring sudo access for $username"

# First test with NOPASSWD
echo "$username ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$username"
chmod 440 "/etc/sudoers.d/$username"

# Verify sudo access with retries
max_attempts=3
attempt=1
success=false

while [ $attempt -le $max_attempts ]; do
    log "DEBUG" "Verifying sudo access (attempt $attempt/$max_attempts)"
    
    if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n true'" >/dev/null 2>&1; then
        success=true
        break
    fi
    
    # Try alternative verification method
    if timeout 5 bash -c "su -s /bin/bash - '$username' -c 'sudo -n id'" >/dev/null 2>&1; then
        success=true
        break
    fi
    
    sleep 2
    ((attempt++))
done

if [ "$success" = true ]; then
    log "SUCCESS" "Sudo access verified successfully"
    
    # Switch to password-required configuration
    echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
    chmod 440 "/etc/sudoers.d/$username"
    
    # Verify final configuration
    if visudo -c &>/dev/null; then
        log "SUCCESS" "Sudo configuration is valid"
        exit 0
    else
        log "ERROR" "Final sudo configuration validation failed"
        exit 1
    fi
fi

log "ERROR" "Failed to verify sudo access after $max_attempts attempts"
exit 1