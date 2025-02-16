#!/bin/bash

# Set strict mode
set -euo pipefail

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script with Windows-compatible paths
LOG_FILE="${TEMP:-/tmp}/server-hardening.log"
init_script

# Early environment check
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log "WARNING" "Not running on Linux. Dependencies will not be installed."
    exit 0
fi

# Required packages list
PACKAGES=(
    "jq"              # For progress tracking JSON handling
    "dos2unix"        # For line ending fixes
    "openssh-server"  # For SSH configuration
    "ufw"            # For firewall management
    "fail2ban"       # For intrusion prevention
    "auditd"         # For system auditing
    "libpam-google-authenticator" # For 2FA
)

# Function to check if package is installed
is_package_installed() {
    dpkg -l "$1" &>/dev/null
}

# Function to install missing packages
install_missing_packages() {
    local missing_packages=()
    
    echo "Checking required packages..."
    for package in "${PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        echo "Installing missing packages: ${missing_packages[*]}"
        apt-get update
        apt-get install -y "${missing_packages[@]}"
    else
        echo "All required packages are already installed"
    fi
}

# Main installation function
main() {
    log "INFO" "Starting dependency check..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 
        exit 1
    fi
    
    # Check if we're on a Debian-based system
    if [[ ! -f /etc/debian_version ]]; then
        log "WARNING" "Not running on a Debian-based system, skipping package installation"
        return 0
    }
    
    # Update package lists if possible
    if command -v apt-get >/dev/null 2>&1; then
        log "INFO" "Updating package lists..."
        apt-get update || log "WARNING" "Failed to update package lists"
    else
        log "WARNING" "apt-get not found, skipping package operations"
        return 0
    fi
    
    # Create required directories
    mkdir -p /var/log/hardening
    chmod 750 /var/log/hardening
    
    # Install packages
    install_missing_packages
    
    # Verify installations
    local failed_packages=()
    for package in "${PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            failed_packages+=("$package")
        fi
    done
    
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        echo "Failed to install packages: ${failed_packages[*]}"
        exit 1
    fi
    
    log "INFO" "Dependency check completed"
    return 0
}

main "$@"