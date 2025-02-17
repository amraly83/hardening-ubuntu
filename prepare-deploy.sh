#!/bin/bash
# Deployment preparation script
set -euo pipefail

# Configuration
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/server-hardening.log"
BACKUP_DIR="${DEPLOY_DIR}/backups/$(date +%Y%m%d_%H%M%S)"

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

# Function to validate script encoding
validate_encoding() {
    local file="$1"
    if file "$file" | grep -q "CRLF"; then
        echo "Converting CRLF to LF for $file"
        sed -i 's/\r$//' "$file"
    fi
}

echo "=== Starting Deployment Preparation ==="

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Check if running on Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Verify root privileges
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root on Linux"
        exit 1
    fi
    
    # Detect Ubuntu version
    if [ "$(detect_os)" != "ubuntu" ]; then
        echo "Warning: This script is designed for Ubuntu Server"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Install required dependencies
    echo "Installing dependencies..."
    if ! "${DEPLOY_DIR}/scripts/install-deps.sh"; then
        echo "Error: Failed to install dependencies"
        exit 1
    fi
fi

# Create required directories with proper permissions
echo "Creating required directories..."
mkdir -p "${DEPLOY_DIR}/logs"
chmod 750 "${DEPLOY_DIR}/logs"

# Backup existing configuration if it exists
if [[ -d "/etc/server-hardening" ]]; then
    echo "Backing up existing configuration..."
    cp -r "/etc/server-hardening" "$BACKUP_DIR/"
fi

# Process all shell scripts
echo "Processing shell scripts..."
while IFS= read -r -d '' script; do
    # Backup original
    cp "$script" "$BACKUP_DIR/$(basename "$script").orig"
    
    # Fix line endings and validate encoding
    validate_encoding "$script"
    
    # Make executable
    chmod +x "$script"
    
    echo "✓ Processed: $(basename "$script")"
done < <(find "${DEPLOY_DIR}/scripts" -type f -name "*.sh" -print0)

# Run script-preloader with proper error handling
echo "Running script preparation..."
if ! "${DEPLOY_DIR}/scripts/script-preloader.sh"; then
    echo "Error: Script preparation failed"
    echo "Check ${DEPLOY_DIR}/logs/script-preloader.log for details"
    exit 1
fi

# Validate all scripts
echo "Validating scripts..."
if ! "${DEPLOY_DIR}/scripts/validate.sh"; then
    echo "Error: Script validation failed"
    echo "Check ${DEPLOY_DIR}/logs/validate.log for details"
    exit 1
fi

# Set up logging
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Setting up logging..."
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
fi

echo "=== Deployment Preparation Complete ==="
echo "All scripts have been prepared and validated."
echo "Backups stored in: $BACKUP_DIR"
echo "You can now run setup.sh to begin the hardening process."