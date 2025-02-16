#!/bin/bash

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
REQUIRED_PACKAGES=(
    "openssh-server"
    "libpam-google-authenticator"
    "ufw"
    "fail2ban"
    "sudo"
    "git"
    "bc"
    "unattended-upgrades"
    "apt-listchanges"
    "postfix"
    "apparmor"
    "auditd"
)

# Function to check if package is installed
is_package_installed() {
    local package="$1"
    if ! command -v dpkg >/dev/null 2>&1; then
        log "WARNING" "dpkg not found, cannot check package installation"
        return 0
    }
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    return $?
}

# Function to install packages
install_package() {
    local package="$1"
    log "INFO" "Installing $package..."
    
    if ! command -v apt-get >/dev/null 2>&1; then
        log "WARNING" "apt-get not found, skipping package installation"
        return 0
    }
    
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
        log "WARNING" "Failed to install $package"
        return 1
    fi
}

# Function to configure postfix if needed
configure_postfix() {
    if ! is_package_installed "postfix"; then
        log "INFO" "Configuring postfix..."
        # Set up postfix in non-interactive mode
        debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
        debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
        install_package "postfix"
    fi
}

# Main installation function
main() {
    log "INFO" "Starting dependency check..."
    
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
    }
    
    # Check installed packages
    local missing_packages=()
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            missing_packages+=("$package")
        fi
    done
    
    if [ ${#missing_packages[@]} -eq 0 ]; then
        log "INFO" "All required packages are already installed"
        return 0
    fi
    
    # Report missing packages
    log "INFO" "Missing packages: ${missing_packages[*]}"
    if ! prompt_yes_no "Would you like to install missing packages" "yes"; then
        log "WARNING" "Skipping package installation"
        return 0
    fi
    
    # Try to install missing packages
    local failed=0
    for package in "${missing_packages[@]}"; do
        if ! install_package "$package"; then
            ((failed++))
        fi
    done
    
    if [ "$failed" -gt 0 ]; then
        log "WARNING" "$failed package(s) failed to install"
        if ! prompt_yes_no "Continue despite package installation failures" "no"; then
            error_exit "Package installation failed"
        fi
    fi
    
    log "INFO" "Dependency check completed"
    return 0
}

main "$@"