# Server Hardening Guide
# Last updated: 2024

## Quick Start
For automated setup, simply run:
```bash
chmod +x setup.sh
sudo ./setup.sh
```
This will guide you through all steps automatically.

## Manual Setup (if automated setup fails)
If you prefer to run steps manually or the automated setup fails, follow these steps:

## Prerequisites
- Ubuntu Server 20.04 or later
- Root access to the server
- Google Authenticator app installed on your mobile device
- SSH client on your local machine
- Backup of your current server configuration

## Step 0: Safety Check (CRITICAL)
If you're logged in as root, you MUST create at least one additional admin user before running the hardening script:

1. Make scripts executable:
   ```bash
   chmod +x *.sh
   ```

2. Create a new admin user:
   ```bash
   sudo ./create-admin.sh newusername
   ```
   - Follow the prompts to set up the user
   - Make sure to remember the password

## Step 1: Initial Setup
1. Transfer all scripts to your server:
   - harden.sh
   - setup-ssh-key.sh
   - setup-2fa.sh

2. Make all scripts executable:
   ```bash
   chmod +x harden.sh setup-ssh-key.sh setup-2fa.sh
   ```

## Step 2: SSH Key Setup (CRITICAL - DO THIS FIRST)
1. For each user that needs SSH access:
   ```bash
   # On your LOCAL machine
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```
   - Save the key in the default location
   - Use a strong passphrase
   - Copy your public key:
     ```bash
     cat ~/.ssh/id_ed25519.pub
     ```

2. On the SERVER, run for each user:
   ```bash
   sudo ./setup-ssh-key.sh username
   ```
   - Paste the public key when prompted
   - Test SSH access BEFORE proceeding:
     ```bash
     ssh -i ~/.ssh/id_ed25519 username@server
     ```

## Step 3: Configure 2FA (If Using)
1. For each user that needs SSH access:
   ```bash
   sudo ./setup-2fa.sh username
   ```
   - Scan the QR code with Google Authenticator app
   - Save the backup codes securely
   - Test 2FA login BEFORE proceeding:
     ```bash
     ssh -i ~/.ssh/id_ed25519 username@server
     ```
   - You should be prompted for:
     1. SSH key passphrase
     2. Google Authenticator code

## Step 4: Server Hardening
1. Review and modify default values in harden.sh:
   - SSH_PORT="3333"
   - SSH_ALLOW_USERS="user1 user2"
   - ADMIN_EMAIL="admin@example.com"
   - FIREWALL_ADDITIONAL_PORTS="80,443,..."

2. Run the hardening script:
   ```bash
   sudo ./harden.sh
   ```

3. During script execution, you'll be prompted for:
   - SSH configuration
   - GRUB bootloader password
   - Network/IPv6 settings
   - Automatic updates preferences
   - Email notification settings

## Step 5: Post-Hardening Verification
1. Check the generated documentation:
   - Review system-configuration.md
   - Save recovery-procedures.md securely
   - Test all configured services

2. Verify SSH access:
   ```bash
   # From a NEW terminal
   ssh -p 3333 -i ~/.ssh/id_ed25519 username@server
   ```

3. Check security services:
   ```bash
   sudo systemctl status sshd
   sudo systemctl status fail2ban
   sudo ufw status verbose
   sudo systemctl status unattended-upgrades
   ```

4. Review logs:
   ```bash
   sudo tail -f /var/log/server-hardening.log
   sudo tail -f /var/log/auth.log
   ```

## Emergency Recovery
If you get locked out:
1. Access the server console through your provider's management interface
2. Login as root
3. Run:
   ```bash
   ./harden.sh --restore
   ```

## Important Safety Notes
- The hardening script will NOT proceed if:
  1. You're running as root with no other user accounts that can login
  2. You're running as root with no other users having sudo privileges
  3. SSH keys haven't been set up for allowed users
- Always keep at least one terminal session open while testing changes
- Test sudo access for the new admin user before proceeding
- Verify SSH key authentication works before disabling password login

## Important Notes
- NEVER proceed to the next step until you've verified the current step works
- Keep multiple SSH sessions open while testing changes
- Save all backup codes and passwords securely
- Document any custom changes you make
- Regular testing of the restore procedure is recommended

## Maintenance Tasks
Weekly:
- Check /var/log/server-hardening.log
- Review failed login attempts in auth.log
- Verify backup integrity
- Test SSH access with keys and 2FA

Monthly:
- Review and update allowed users
- Check for failed automatic updates
- Test restore procedure
- Update documentation if needed