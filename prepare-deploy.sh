#!/bin/bash

# Set strict mode
set -euo pipefail

# Configuration
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/server-hardening.log"

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

echo "Preparing deployment environment..."

# Check if running as root on Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root on Linux"
        exit 1
    fi
    
    # Run install-deps.sh first to ensure all required tools are available
    echo "Installing dependencies..."
    if ! "${DEPLOY_DIR}/scripts/install-deps.sh"; then
        echo "Error: Failed to install dependencies"
        exit 1
    fi
fi

# Create required directories
echo "Creating required directories..."
mkdir -p "${DEPLOY_DIR}/logs"
chmod 750 "${DEPLOY_DIR}/logs"

# Fix script permissions and line endings
echo "Fixing script permissions and line endings..."
find "${DEPLOY_DIR}/scripts" -type f -name "*.sh" -exec chmod +x {} \;

# Run script-preloader for each script in correct order
cd "${DEPLOY_DIR}/scripts"
./script-preloader.sh || {
    echo "Error: Script preparation failed"
    exit 1
}

# Validate all scripts
./validate.sh || {
    echo "Error: Script validation failed"
    exit 1
}

# Create log file with proper permissions
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
fi

echo "Deployment preparation completed successfully"
echo "Run setup.sh to begin the hardening process"