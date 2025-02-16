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

# Function to install required tools
install_required_tools() {
    local os_type="$1"
    case "$os_type" in
        ubuntu|debian)
            apt-get update
            apt-get install -y file dos2unix jq
            ;;
        centos|rhel|fedora)
            yum install -y file dos2unix jq
            ;;
        *)
            echo "Warning: Unknown OS type. Please install 'file', 'dos2unix', and 'jq' manually."
            ;;
    esac
}

echo "Preparing deployment environment..."

# Check if running as root on Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root on Linux"
        exit 1
    fi
    
    # Install required tools
    OS_TYPE=$(detect_os)
    install_required_tools "$OS_TYPE"
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