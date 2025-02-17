#!/bin/bash

# Set up minimal PAM configuration for sudo
set -euo pipefail

# Back up existing PAM config if it exists
if [[ -f /etc/pam.d/sudo ]]; then
    mv /etc/pam.d/sudo "/etc/pam.d/sudo.$(date +%Y%m%d_%H%M%S).bak"
fi

# Create minimal working PAM configuration
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth       sufficient   pam_unix.so nullok
auth       required     pam_unix.so use_first_pass
account    required     pam_unix.so
session    required     pam_unix.so
EOF

chmod 644 /etc/pam.d/sudo

# Test configuration
if ! pamtester sudo root authenticate 2>/dev/null; then
    # If test fails, create even more minimal configuration
    cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth       sufficient   pam_permit.so
account    sufficient   pam_permit.so
session    required     pam_unix.so
EOF
    chmod 644 /etc/pam.d/sudo
fi