#!/bin/bash
set -euo pipefail

# Check if run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Get username
if [ -z "$1" ]; then
    read -p "Enter username to setup 2FA for: " USERNAME
else
    USERNAME="$1"
fi

# Check if user exists
if ! id "$USERNAME" >/dev/null 2>&1; then
    echo "User $USERNAME does not exist"
    exit 1
fi

# Install required packages
echo "Checking required packages..."
if ! dpkg -l | grep -q "^ii.*libpam-google-authenticator"; then
    echo "Installing libpam-google-authenticator..."
    apt-get update
    apt-get install -y libpam-google-authenticator
fi

# Create home directory if it doesn't exist
if [[ ! -d "/home/$USERNAME" ]]; then
    echo "Creating home directory for $USERNAME..."
    mkdir -p "/home/$USERNAME"
    chown "$USERNAME:$USERNAME" "/home/$USERNAME"
    chmod 750 "/home/$USERNAME"
fi

# Backup PAM configuration
echo "Backing up PAM configuration..."
if [[ -f /etc/pam.d/sshd ]]; then
    cp -p /etc/pam.d/sshd "/etc/pam.d/sshd.$(date +%Y%m%d_%H%M%S).bak"
fi

# Configure PAM for SSH
echo "Configuring PAM for SSH authentication..."
if ! grep -q "^auth required pam_google_authenticator.so nullok" /etc/pam.d/sshd; then
    sed -i '/^@include common-auth/i auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

# Configure SSH to allow challenge-response
echo "Configuring SSH settings..."
if ! grep -q "^ChallengeResponseAuthentication yes" /etc/ssh/sshd_config; then
    sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
fi

# Generate 2FA for user
echo "Generating 2FA configuration for $USERNAME..."
if ! su - "$USERNAME" -c "which google-authenticator" >/dev/null 2>&1; then
    echo "Error: google-authenticator command not found even after installation"
    echo "Try running: sudo apt-get install --reinstall libpam-google-authenticator"
    exit 1
fi

# Make sure the user's .google_authenticator file doesn't exist
if [[ -f "/home/$USERNAME/.google_authenticator" ]]; then
    echo "Warning: Existing 2FA configuration found. Making backup..."
    mv "/home/$USERNAME/.google_authenticator" "/home/$USERNAME/.google_authenticator.$(date +%Y%m%d_%H%M%S).bak"
fi

# Generate new 2FA configuration
echo "Initializing Google Authenticator for $USERNAME..."
su - "$USERNAME" -c "google-authenticator -t -d -f -r 3 -R 30 -w 3"

# Verify file was created
if [[ ! -f "/home/$USERNAME/.google_authenticator" ]]; then
    echo "Error: Failed to create 2FA configuration file"
    exit 1
fi

# Set proper permissions
echo "Setting correct permissions..."
chown "$USERNAME:$USERNAME" "/home/$USERNAME/.google_authenticator"
chmod 400 "/home/$USERNAME/.google_authenticator"

# Restart SSH service
echo "Restarting SSH service..."
if ! systemctl restart sshd; then
    echo "Error: Failed to restart SSH service"
    exit 1
fi

echo "==============================================="
echo "2FA has been set up for $USERNAME"
echo "Please save these backup codes in a secure location!"
echo "-----------------------------------------------"
echo "Testing SSH configuration..."
if sshd -t; then
    echo "SSH configuration test passed"
else
    echo "Error: SSH configuration test failed"
    echo "Restoring backup..."
    if [[ -f "/etc/pam.d/sshd.$(date +%Y%m%d_%H%M%S).bak" ]]; then
        cp -p "/etc/pam.d/sshd.$(date +%Y%m%d_%H%M%S).bak" /etc/pam.d/sshd
    fi
    systemctl restart sshd
    exit 1
fi
echo "==============================================="
echo "IMPORTANT: Keep your backup codes safe!"
echo "If you lose access to your authenticator app,"
echo "you'll need these codes to regain access."
echo "Test 2FA login from a new terminal BEFORE logging out!"