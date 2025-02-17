#!/bin/bash
# Package dependency management and installation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Required package definitions with versions
declare -A REQUIRED_PACKAGES=(
    ["openssh-server"]="latest"
    ["libpam-google-authenticator"]="latest"
    ["ufw"]="latest"
    ["fail2ban"]="latest"
    ["sudo"]="latest"
    ["git"]="latest"
    ["bc"]="latest"
    ["jq"]="latest"
)

# Optional but recommended packages
declare -A OPTIONAL_PACKAGES=(
    ["unattended-upgrades"]="latest"
    ["apt-listchanges"]="latest"
    ["postfix"]="latest"
    ["apparmor"]="latest"
    ["auditd"]="latest"
)

install_dependencies() {
    local mode="${1:-required}"
    local install_log="/var/log/hardening-install.log"
    
    log "INFO" "Installing dependencies (mode: $mode)..."
    
    # Check if apt is locked
    if check_apt_lock; then
        error_exit "APT is locked. Please try again later."
    fi
    
    # Update package lists
    if ! DEBIAN_FRONTEND=noninteractive apt-get update >> "$install_log" 2>&1; then
        error_exit "Failed to update package lists"
    fi
    
    # Install required packages
    install_package_group "Required" REQUIRED_PACKAGES[@] "$install_log"
    
    # Install optional packages if requested
    if [[ "$mode" == "full" ]]; then
        install_package_group "Optional" OPTIONAL_PACKAGES[@] "$install_log"
    fi
    
    # Verify installations
    verify_installations
    
    log "SUCCESS" "Package installation completed successfully"
}

install_package_group() {
    local group_name="$1"
    local -n packages="$2"
    local log_file="$3"
    
    log "INFO" "Installing $group_name packages..."
    
    for pkg in "${!packages[@]}"; do
        local version="${packages[$pkg]}"
        local install_cmd="DEBIAN_FRONTEND=noninteractive apt-get install -y"
        
        if [[ "$version" != "latest" ]]; then
            install_cmd+=" $pkg=$version"
        else
            install_cmd+=" $pkg"
        fi
        
        log "INFO" "Installing $pkg..."
        if ! eval "$install_cmd" >> "$log_file" 2>&1; then
            log "ERROR" "Failed to install $pkg"
            continue
        fi
    done
}

verify_installations() {
    local failed=false
    
    log "INFO" "Verifying package installations..."
    
    # Check required packages
    for pkg in "${!REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l "$pkg" | grep -q "^ii"; then
            log "ERROR" "Required package not installed: $pkg"
            failed=true
        fi
    done
    
    # Configure and verify services
    verify_service_configuration || failed=true
    
    if [[ "$failed" == "true" ]]; then
        error_exit "Package verification failed"
    fi
}

verify_service_configuration() {
    local failed=false
    
    # Check SSH service
    if ! systemctl is-enabled ssh >/dev/null 2>&1; then
        systemctl enable ssh
    fi
    if ! systemctl is-active --quiet ssh; then
        systemctl start ssh || failed=true
    fi
    
    # Check fail2ban
    if ! systemctl is-enabled fail2ban >/dev/null 2>&1; then
        systemctl enable fail2ban
    fi
    if ! systemctl is-active --quiet fail2ban; then
        systemctl start fail2ban || failed=true
    fi
    
    # Check UFW
    if ! systemctl is-enabled ufw >/dev/null 2>&1; then
        systemctl enable ufw
    fi
    if ! ufw status | grep -q "Status: active"; then
        ufw --force enable || failed=true
    fi
    
    # Check unattended-upgrades if installed
    if dpkg -l unattended-upgrades | grep -q "^ii"; then
        if ! systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
            systemctl enable unattended-upgrades
        fi
        if ! systemctl is-active --quiet unattended-upgrades; then
            systemctl start unattended-upgrades || failed=true
        fi
    fi
    
    return $([ "$failed" == "false" ])
}

check_apt_lock() {
    # Check for apt/dpkg locks
    lsof /var/lib/dpkg/lock >/dev/null 2>&1 || \
    lsof /var/lib/apt/lists/lock >/dev/null 2>&1 || \
    lsof /var/cache/apt/archives/lock >/dev/null 2>&1
}

cleanup_packages() {
    log "INFO" "Cleaning up package installation..."
    
    # Remove unused packages
    apt-get autoremove -y
    
    # Clean apt cache
    apt-get clean
    
    # Remove old config files
    dpkg --purge $(dpkg -l | awk '/^rc/ {print $2}')
}

show_package_status() {
    echo "=== Package Installation Status ==="
    echo
    echo "Required Packages:"
    for pkg in "${!REQUIRED_PACKAGES[@]}"; do
        if dpkg -l "$pkg" | grep -q "^ii"; then
            echo "✓ $pkg (Installed)"
        else
            echo "✗ $pkg (Not installed)"
        fi
    done
    
    echo
    echo "Optional Packages:"
    for pkg in "${!OPTIONAL_PACKAGES[@]}"; do
        if dpkg -l "$pkg" | grep -q "^ii"; then
            echo "✓ $pkg (Installed)"
        else
            echo "- $pkg (Not installed)"
        fi
    done
    
    echo
    echo "Service Status:"
    services=("ssh" "fail2ban" "ufw" "unattended-upgrades")
    for service in "${services[@]}"; do
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