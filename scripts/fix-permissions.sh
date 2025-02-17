#!/bin/bash
# Fix critical directory permissions before installation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log "INFO" "Fixing critical directory permissions..."

# Fix /etc/sudoers.d permissions
if [ -d "/etc/sudoers.d" ]; then
    chmod 750 /etc/sudoers.d
    log "INFO" "Fixed /etc/sudoers.d permissions to 750"
fi

# Fix /var/log permissions
if [ -d "/var/log" ]; then
    chmod 755 /var/log
    log "INFO" "Fixed /var/log permissions to 755"
fi

# Verify permissions were set correctly
verify_permissions() {
    local dir="$1"
    local expected="$2"
    local current
    
    current=$(stat -c '%a' "$dir")
    if [ "$current" != "$expected" ]; then
        log "ERROR" "Failed to set permissions on $dir (current: $current, expected: $expected)"
        return 1
    fi
    return 0
}

# Verify all fixes
verify_permissions "/etc/sudoers.d" "750" || exit 1
verify_permissions "/var/log" "755" || exit 1

log "SUCCESS" "Critical directory permissions have been fixed"