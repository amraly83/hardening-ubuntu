#!/bin/bash

# Configure PAM for sudo
# This script is called by harden.sh to set up proper PAM configuration

set -euo pipefail

# Backup current PAM config if it exists
if [[ -f /etc/pam.d/sudo ]]; then
    cp /etc/pam.d/sudo "/etc/pam.d/sudo.$(date +%Y%m%d_%H%M%S).bak"
fi

# Create a clean PAM configuration for sudo
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0

# Standard Unix authentication
auth       sufficient   pam_unix.so try_first_pass
auth       required     pam_deny.so

# Account management
account    required     pam_unix.so
account    include      common-account

# Session management
session    required     pam_env.so readenv=1 user_readenv=0
session    required     pam_limits.so
session    required     pam_unix.so
session    include      common-session

# Password management
password   include      common-password
EOF

chmod 644 /etc/pam.d/sudo

# Test configuration
if ! pamtester sudo root authenticate 2>/dev/null; then
    # If test fails, create minimal working configuration
    cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth       required     pam_unix.so
account    required     pam_unix.so
session    required     pam_unix.so
EOF
    chmod 644 /etc/pam.d/sudo
fi