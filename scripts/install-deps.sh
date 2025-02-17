#!/bin/bash
# Install required dependencies for hardening scripts
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[1;34m'
readonly COLOR_RESET='\033[0m'

# Required packages
REQUIRED_PACKAGES=(
    "sudo"
    "openssh-server"
    "ufw"
    "fail2ban"
    "unattended-upgrades"
    "dos2unix"
    "libpam-google-authenticator"
    "jq"
    "expect"
    "timeout"
    "file"
    "bc"
    "curl"
)

# Function to check if package is installed
is_package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Function to install a package with progress
install_package() {
    local package="$1"
    echo -n "Installing ${package}... "
    
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
        return 0
    else
        echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
        return 1
    fi
}

# Main installation function
main() {
    local failed=0
    local installed=0
    local skipped=0
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_RED}Error: This script must be run as root${COLOR_RESET}"
        exit 1
    fi
    
    # Check if running on Ubuntu
    if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        echo -e "${COLOR_YELLOW}Warning: This script is designed for Ubuntu${COLOR_RESET}"
        echo "Continue anyway? [y/N] "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    echo -e "${COLOR_BLUE}=== Installing Required Dependencies ===${COLOR_RESET}"
    
    # Update package lists first
    echo "Updating package lists..."
    if ! apt-get update >/dev/null 2>&1; then
        echo -e "${COLOR_RED}Failed to update package lists${COLOR_RESET}"
        exit 1
    fi
    
    # Install packages
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if is_package_installed "$package"; then
            echo -e "Package $package is ${COLOR_GREEN}already installed${COLOR_RESET}"
            ((skipped++))
            continue
        fi
        
        if install_package "$package"; then
            ((installed++))
        else
            ((failed++))
            echo -e "${COLOR_RED}Failed to install $package${COLOR_RESET}"
        fi
    done
    
    # Fix any potential dependency issues
    echo "Fixing potential dependency issues..."
    apt-get install -f -y >/dev/null 2>&1 || true
    
    # Print summary
    echo -e "\n${COLOR_BLUE}=== Installation Summary ===${COLOR_RESET}"
    echo -e "Packages installed: ${COLOR_GREEN}$installed${COLOR_RESET}"
    echo -e "Packages skipped: ${COLOR_YELLOW}$skipped${COLOR_RESET}"
    if [[ $failed -gt 0 ]]; then
        echo -e "Packages failed: ${COLOR_RED}$failed${COLOR_RESET}"
        echo -e "\n${COLOR_RED}Some packages failed to install. Please check the errors above.${COLOR_RESET}"
        return 1
    fi
    
    echo -e "\n${COLOR_GREEN}All required dependencies installed successfully${COLOR_RESET}"
    return 0
}

# Run main function
main "$@"