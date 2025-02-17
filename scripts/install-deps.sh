#!/bin/bash
# Package dependency management and installation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Set error handling for apt operations
export DEBIAN_FRONTEND=noninteractive
APT_OPTS="-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

# Load package lists from requirements
if [[ -f "${SCRIPT_DIR}/../docs/REQUIREMENTS.md" ]]; then
    REQUIRED_PACKAGES=(
        openssh-server
        libpam-google-authenticator
        ufw
        fail2ban
        sudo
        git
        bc
        jq
    )
    
    OPTIONAL_PACKAGES=(
        unattended-upgrades
        apt-listchanges
        postfix
        apparmor
        auditd
    )
else
    error_exit "Requirements file not found"
fi

install_dependencies() {
    local mode="${1:-required}"
    local install_log="/var/log/hardening-install.log"
    local success=true
    
    log "INFO" "Installing dependencies (mode: $mode)..."
    
    # Ensure apt is not locked
    check_apt_lock || error_exit "APT is locked. Please try again later."
    
    # Update package lists
    log "INFO" "Updating package lists..."
    if ! apt-get update >> "$install_log" 2>&1; then
        error_exit "Failed to update package lists"
    fi
    
    # Install required packages
    log "INFO" "Installing required packages..."
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        log "INFO" "Installing $pkg..."
        if ! apt-get install $APT_OPTS "$pkg" >> "$install_log" 2>&1; then
            log "ERROR" "Failed to install $pkg"
            success=false
            continue
        fi
    done
    
    # Install optional packages if requested
    if [[ "$mode" == "full" ]]; then
        log "INFO" "Installing optional packages..."
        for pkg in "${OPTIONAL_PACKAGES[@]}"; do
            log "INFO" "Installing $pkg..."
            if ! apt-get install $APT_OPTS "$pkg" >> "$install_log" 2>&1; then
                log "WARNING" "Failed to install optional package $pkg"
                continue
            fi
        done
    fi
    
    # Verify installations
    verify_installations || success=false
    
    if [[ "$success" != "true" ]]; then
        log "ERROR" "Some package installations failed"
        return 1
    fi
    
    log "SUCCESS" "Package installation completed successfully"
    return 0
}

verify_installations() {
    local failed=false
    
    log "INFO" "Verifying package installations..."
    
    # Check required packages
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l "$pkg" | grep -q "^ii"; then
            log "ERROR" "Required package not installed: $pkg"
            failed=true
        fi
    done
    
    # Configure and verify services
    verify_service_configuration || failed=true
    
    return $([ "$failed" == "false" ])
}

verify_service_configuration() {
    local failed=false
    
    # Check and enable essential services
    local services=(
        "ssh"
        "fail2ban"
        "ufw"
    )
    
    for service in "${services[@]}"; do
        log "INFO" "Configuring service: $service..."
        
        # Enable service if not enabled
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl enable "$service" || {
                log "ERROR" "Failed to enable $service"
                failed=true
                continue
            }
        fi
        
        # Start service if not running
        if ! systemctl is-active --quiet "$service"; then
            systemctl start "$service" || {
                log "ERROR" "Failed to start $service"
                failed=true
            }
        fi
    done
    
    # Special handling for UFW
    if ! ufw status | grep -q "Status: active"; then
        log "INFO" "Enabling UFW..."
        ufw --force enable || failed=true
    fi
    
    return $([ "$failed" == "false" ])
}

check_apt_lock() {
    # Check for apt/dpkg locks
    if lsof /var/lib/dpkg/lock >/dev/null 2>&1 || \
       lsof /var/lib/apt/lists/lock >/dev/null 2>&1 || \
       lsof /var/cache/apt/archives/lock >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

cleanup_packages() {
    log "INFO" "Cleaning up package installation..."
    
    # Remove unnecessary packages
    apt-get autoremove -y
    
    # Clean apt cache
    apt-get clean
    
    # Remove old config files
    dpkg --purge "$(dpkg -l | awk '/^rc/ {print $2}')"
}

show_package_status() {
    echo "=== Package Installation Status ==="
    echo
    echo "Required Packages:"
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if dpkg -l "$pkg" | grep -q "^ii"; then
            echo "✓ $pkg (Installed)"
        else
            echo "✗ $pkg (Not installed)"
        fi
    done
    
    echo
    echo "Optional Packages:"
    for pkg in "${OPTIONAL_PACKAGES[@]}"; do
        if dpkg -l "$pkg" | grep -q "^ii"; then
            echo "✓ $pkg (Installed)"
        else
            echo "- $pkg (Not installed)"
        fi
    done
    
    echo
    echo "Service Status:"
    for service in ssh fail2ban ufw; do
        if systemctl is-active --quiet "$service"; then
            echo "✓ $service (Running)"
        else
            echo "✗ $service (Not running)"
        fi
    done
}

# Main execution
case "${1:-}" in
    "install")
        install_dependencies "${2:-required}"
        ;;
    "verify")
        verify_installations
        ;;
    "cleanup")
        cleanup_packages
        ;;
    "status")
        show_package_status
        ;;
    *)
        echo "Usage: $0 <install|verify|cleanup|status> [mode]"
        echo "Modes:"
        echo "  required  Install only required packages (default)"
        echo "  full      Install all packages including optional ones"
        exit 1
        ;;
esac