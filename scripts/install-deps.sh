#!/bin/bash

# Set strict mode
set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set log file before sourcing common.sh
LOG_FILE="${TEMP:-/tmp}/server-hardening.log"

# Fix line endings in common.sh
sed -i 's/\r$//' "${SCRIPT_DIR}/common.sh"

# Source common functions
source "${SCRIPT_DIR}/common.sh" || {
    echo "Error: Failed to source common.sh"
    exit 1
}

# Initialize script
init_script || {
    echo "Error: Failed to initialize script"
    exit 1
}

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
    
    log "INFO" "Checking required packages..."
    for package in "${PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log "INFO" "Installing missing packages: ${missing_packages[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}"
    else
        log "INFO" "All required packages are already installed"
    fi
}

# Main installation function
main() {
    log "INFO" "Starting dependency check..."
    
    # Early environment check
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log "WARNING" "Not running on Linux. Dependencies will not be installed."
        exit 0
    fi
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
    
    # Check if we're on a Debian-based system
    if [[ ! -f /etc/debian_version ]]; then
        log "WARNING" "Not running on a Debian-based system, skipping package installation"
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
        error_exit "Failed to install packages: ${failed_packages[*]}"
    fi
    
    log "INFO" "Dependency check completed successfully"
    return 0
}

main "$@"