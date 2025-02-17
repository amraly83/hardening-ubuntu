#!/bin/bash
# Initialize PAM configuration with proper cross-platform handling
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RESET='\033[0m'

# Function to safely backup PAM files
backup_pam_file() {
    local file="$1"
    local backup="${file}.$(date +%Y%m%d_%H%M%S).bak"
    
    if [[ -f "$file" ]]; then
        echo "Backing up ${file}..."
        cp -p "$file" "$backup" || {
            echo -e "${COLOR_RED}Failed to backup ${file}${COLOR_RESET}"
            return 1
        }
        chmod --reference="$file" "$backup" 2>/dev/null || chmod 644 "$backup"
    fi
    return 0
}

# Function to safely write PAM configuration
write_pam_config() {
    local file="$1"
    local temp_file
    temp_file=$(mktemp)
    
    # Write to temporary file first
    cat > "$temp_file" || return 1
    chmod 644 "$temp_file" || return 1
    
    # Move to final location
    mv "$temp_file" "$file" || return 1
    
    return 0
}

# Initialize basic PAM configuration
init_basic_pam() {
    # Backup existing configurations
    backup_pam_file "/etc/pam.d/sudo"
    backup_pam_file "/etc/pam.d/su"
    
    # Create basic sudo PAM configuration
    write_pam_config "/etc/pam.d/sudo" << 'EOF' || return 1
#%PAM-1.0
auth       include      common-auth
account    include      common-account
password   include      common-password
session    required     pam_env.so readenv=1 user_readenv=0
session    required     pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
session    required     pam_unix.so
session    include      common-session
EOF
    
    # Create basic su PAM configuration
    write_pam_config "/etc/pam.d/su" << 'EOF' || return 1
#%PAM-1.0
auth       sufficient   pam_rootok.so
auth       required     pam_unix.so
account    required     pam_unix.so
session    required     pam_unix.so
session    include      common-session
EOF
    
    # Ensure common-auth exists with basic configuration
    if [[ ! -f "/etc/pam.d/common-auth" ]]; then
        write_pam_config "/etc/pam.d/common-auth" << 'EOF' || return 1
#%PAM-1.0
auth    [success=1 default=ignore]  pam_unix.so nullok_secure
auth    requisite                   pam_deny.so
auth    required                    pam_permit.so
EOF
    fi
    
    return 0
}

# Verify PAM configuration
verify_pam_config() {
    local errors=0
    
    # Check file permissions
    for file in /etc/pam.d/{sudo,su,common-auth}; do
        if [[ -f "$file" ]]; then
            local perms
            perms=$(stat -c "%a" "$file")
            if [[ "$perms" != "644" ]]; then
                echo -e "${COLOR_YELLOW}Warning: Incorrect permissions on ${file} (${perms})${COLOR_RESET}"
                chmod 644 "$file" || ((errors++))
            fi
        else
            echo -e "${COLOR_RED}Error: Required PAM file ${file} not found${COLOR_RESET}"
            ((errors++))
        fi
    done
    
    # Verify basic authentication works
    if ! pamtester sudo root authenticate 2>/dev/null; then
        echo -e "${COLOR_YELLOW}Warning: Basic PAM authentication test failed${COLOR_RESET}"
        ((errors++))
    fi
    
    return $errors
}

# Main function
main() {
    local status=0
    
    echo "Initializing PAM configuration..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_RED}Error: This script must be run as root${COLOR_RESET}"
        exit 1
    fi
    
    # Initialize basic PAM configuration
    if ! init_basic_pam; then
        echo -e "${COLOR_RED}Failed to initialize PAM configuration${COLOR_RESET}"
        status=1
    fi
    
    # Verify configuration
    echo "Verifying PAM configuration..."
    if ! verify_pam_config; then
        echo -e "${COLOR_YELLOW}Warning: PAM configuration verification had issues${COLOR_RESET}"
        status=1
    fi
    
    if [[ $status -eq 0 ]]; then
        echo -e "${COLOR_GREEN}PAM initialization completed successfully${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}PAM initialization completed with warnings${COLOR_RESET}"
    fi
    
    return $status
}

# Run main function
main "$@"