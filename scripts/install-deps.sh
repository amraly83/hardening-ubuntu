#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

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
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    return $?
}

# Function to install packages
install_package() {
    local package="$1"
    log "INFO" "Installing $package..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
        error_exit "Failed to install $package"
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
    log "INFO" "Starting dependency installation..."
    
    # Update package lists
    log "INFO" "Updating package lists..."
    if ! apt-get update; then
        error_exit "Failed to update package lists"
    fi
    
    # Install packages
    local missing_packages=()
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            missing_packages+=("$package")
        fi
    done
    
    if [ ${#missing_packages[@]} -eq 0 ]; then
        log "INFO" "All required packages are already installed"
    else
        log "INFO" "Installing missing packages: ${missing_packages[*]}"
        for package in "${missing_packages[@]}"; do
            install_package "$package"
        done
    fi
    
    # Special handling for postfix configuration
    configure_postfix
    
    # Enable and start required services
    local services=("ufw" "fail2ban" "apparmor" "auditd")
    for service in "${services[@]}"; do
        log "INFO" "Enabling and starting $service..."
        systemctl enable "$service"
        systemctl start "$service"
    done
    
    # Verify installations
    log "INFO" "Verifying installations..."
    local failed=0
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            log "ERROR" "Package $package installation verification failed"
            ((failed++))
        fi
    done
    
    if [ "$failed" -gt 0 ]; then
        error_exit "$failed package(s) failed to install correctly"
    fi
    
    log "INFO" "All dependencies installed successfully"
    echo "================================================================"
    echo "Dependencies installation complete"
    echo "You can now proceed with the hardening setup"
    echo "Run: sudo ./setup.sh"
    echo "================================================================"
}

main "$@"