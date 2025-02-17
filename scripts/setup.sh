#!/bin/bash
# Main setup script for server hardening
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root"
fi

log "INFO" "Starting server hardening setup..."

# Initialize progress tracking
"${SCRIPT_DIR}/progress.sh" init

# Install dependencies
log "INFO" "Installing required dependencies..."
if ! "${SCRIPT_DIR}/install-deps.sh" install required; then
    error_exit "Failed to install required dependencies"
fi

# Verify dependency installation
log "INFO" "Verifying dependencies..."
if ! "${SCRIPT_DIR}/install-deps.sh" verify; then
    error_exit "Dependency verification failed"
fi

# Run the main installation
log "INFO" "Running main installation..."
if ! "${SCRIPT_DIR}/install.sh"; then
    error_exit "Installation failed"
fi

# Update progress
"${SCRIPT_DIR}/progress.sh" update "installation" "complete"

# Run final verification
log "INFO" "Running final verification..."
if ! "${SCRIPT_DIR}/verify-complete.sh" "${NEW_USER:-root}"; then
    log "WARNING" "Some verification checks failed. Please review the logs."
fi

# Display final status dashboard
"${SCRIPT_DIR}/security-dashboard.sh" --once

log "SUCCESS" "Server hardening setup completed"
echo
echo "=== Setup Complete ==="
echo "Please review the following:"
echo "1. Security Dashboard Output"
echo "2. Logs in /var/log/server-hardening.log"
echo "3. Verification Report"
echo
echo "IMPORTANT: Test your access before logging out!"