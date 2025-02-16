#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

# Get username
if [ -z "${1:-}" ]; then
    read -p "Enter username to setup 2FA for: " USERNAME
else
    USERNAME="$1"
fi

# Check if user exists
check_user_exists "$USERNAME"

# Check SSH key setup first
check_ssh_key_setup "$USERNAME"

# Install required packages
log "INFO" "Checking required packages..."
if ! dpkg -l | grep -q "^ii.*libpam-google-authenticator"; then
    log "INFO" "Installing libpam-google-authenticator..."
    apt-get update || error_exit "Failed to update package list"
    apt-get install -y libpam-google-authenticator || error_exit "Failed to install libpam-google-authenticator"
fi

# Backup PAM configuration
backup_file "/etc/pam.d/sshd"

# Configure PAM for SSH
log "INFO" "Configuring PAM for SSH authentication..."
if ! grep -q "^auth required pam_google_authenticator.so nullok" /etc/pam.d/sshd; then
    sed -i '/^@include common-auth/i auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

# Configure SSH to allow challenge-response
log "INFO" "Configuring SSH settings..."
backup_file "/etc/ssh/sshd_config"
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Check for existing 2FA configuration
if [[ -f "/home/$USERNAME/.google_authenticator" ]]; then
    log "WARNING" "Existing 2FA configuration found"
    if prompt_yes_no "Do you want to reset 2FA for this user" "no"; then
        backup_file "/home/$USERNAME/.google_authenticator"
    else
        error_exit "Operation cancelled. Existing 2FA configuration retained"
    fi
fi

# Generate 2FA for user
log "INFO" "Generating 2FA configuration for $USERNAME..."
if ! su - "$USERNAME" -c "google-authenticator -t -d -f -r 3 -R 30 -w 3"; then
    error_exit "Failed to generate 2FA configuration"
fi

# Verify file was created and set permissions
if [[ ! -f "/home/$USERNAME/.google_authenticator" ]]; then
    error_exit "2FA configuration file not created"
fi

chown "$USERNAME:$USERNAME" "/home/$USERNAME/.google_authenticator"
chmod 400 "/home/$USERNAME/.google_authenticator"

# Restart SSH service
log "INFO" "Restarting SSH service..."
if ! systemctl restart sshd; then
    error_exit "Failed to restart SSH service"
fi

# Test SSH configuration
log "INFO" "Testing SSH configuration..."
if ! sshd -t; then
    log "ERROR" "SSH configuration test failed"
    # Restore backups
    cp -p "/etc/pam.d/sshd.$(date +%Y%m%d_)*.bak" /etc/pam.d/sshd 2>/dev/null
    cp -p "/etc/ssh/sshd_config.$(date +%Y%m%d_)*.bak" /etc/ssh/sshd_config 2>/dev/null
    systemctl restart sshd
    error_exit "Configuration test failed, restored from backup"
fi

echo "================================================================"
echo "2FA has been set up for user: $USERNAME"
echo
echo "IMPORTANT STEPS:"
echo "1. Save your backup codes in a secure location!"
echo "2. Test 2FA login from a new terminal:"
echo "   ssh -i ~/.ssh/id_ed25519 ${USERNAME}@hostname"
echo
echo "You should be prompted for:"
echo "1. SSH key passphrase (if set)"
echo "2. Google Authenticator code"
echo
echo "DO NOT log out of this session until you verify 2FA works!"
echo "================================================================"

log "INFO" "2FA setup completed successfully for $USERNAME"