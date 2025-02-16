# Server Hardening Guide
# Last updated: 2024

## Getting Started

Before you begin:
1. Download docs/CHECKLIST.md and keep it handy
2. Mark off each step as you complete it
3. Document your configurations in the Notes section
4. Save the completed checklist for your records

## Quick Start
The safest and recommended way to harden your server:

```bash
# Clone the repository
git clone https://github.com/amraly83/hardening-ubuntu.git
cd hardening-ubuntu

# Make scripts executable
chmod +x scripts/*.sh

# Run the automated setup
sudo ./scripts/setup.sh
```

## Pre-Flight Checks
The setup script will automatically verify:
- Minimum system requirements (1GB RAM, 1GB free disk space)
- Ubuntu version compatibility (20.04+)
- Required packages availability
- Network connectivity
- Backup space availability
- Running services status
- Current user sessions

## Installation Process
Follow these steps in order, checking off each item in your CHECKLIST.md:

1. Initial Setup
   - System Readiness Check
     - Validates system requirements
     - Checks for required commands
     - Verifies script integrity

   - Admin User Creation
     - Creates a new admin user if needed
     - Validates username requirements
     - Sets up proper sudo access
     - Prevents common username mistakes

   - SSH Key Setup
     - Creates .ssh directory with proper permissions
     - Validates SSH public key format
     - Tests key-based authentication
     - Creates backup of existing configuration

   - Two-Factor Authentication (Optional)
     - Installs Google Authenticator
     - Configures PAM modules
     - Sets up user-specific 2FA
     - Tests authentication flow

   - System Hardening
     - Configures SSH security settings
     - Sets up firewall rules
     - Enables automatic updates
     - Configures fail2ban
     - Sets up system auditing

## Safety Features
The scripts include several safety measures:

1. Root Account Protection
   - Prevents disabling root login without a working admin account
   - Validates sudo access before proceeding
   - Maintains system accessibility

2. SSH Access Safety
   - Requires successful key verification before disabling passwords
   - Keeps existing sessions active during changes
   - Creates backups of all configurations

3. Configuration Validation
   - Tests all changes before applying
   - Provides automatic rollback on failure
   - Validates service status after changes

4. Backup and Recovery
   - Creates timestamped backups
   - Provides restore procedures
   - Maintains backup manifests

## Manual Setup (if needed)
If you prefer to run steps manually or need to troubleshoot:

### Step 1: Pre-Flight Check
```bash
sudo ./scripts/preflight.sh
```
Resolve any issues reported before proceeding.

### Step 2: Create Admin User
```bash
sudo ./scripts/create-admin.sh username
```
Verify:
- User creation successful
- Sudo access works
- Home directory permissions correct

### Step 3: SSH Key Setup
On your local machine:
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

On the server:
```bash
sudo ./scripts/setup-ssh-key.sh username
```
Test before proceeding:
```bash
ssh -i ~/.ssh/id_ed25519 username@server
```

### Step 4: 2FA Setup (Optional)
```bash
sudo ./scripts/setup-2fa.sh username
```
Important:
- Save backup codes securely
- Test login with 2FA before logout
- Keep existing session open while testing

### Step 5: System Hardening
```bash
sudo ./scripts/harden.sh
```

## Post-Installation
After setup completes:

1. Review Documentation
   - Check generated configuration docs
   - Save recovery procedures
   - Store backup codes securely

2. Verify Access
   ```bash
   # New terminal
   ssh -p 3333 -i ~/.ssh/id_ed25519 username@server
   ```

3. Check Services
   ```bash
   sudo systemctl status sshd
   sudo systemctl status fail2ban
   sudo ufw status verbose
   ```

4. Monitor Logs
   ```bash
   sudo tail -f /var/log/server-hardening.log
   sudo tail -f /var/log/auth.log
   ```

## Emergency Recovery
If you get locked out:

1. Access server console via provider's interface
2. Login as root
3. Run:
   ```bash
   ./scripts/harden.sh --restore
   ```

## Maintaining Documentation
Keep these documents updated and secure:
1. Your completed CHECKLIST.md
2. Generated configuration documentation
3. Recovery procedures
4. Backup codes and passwords
5. Emergency contact information

## Maintenance Schedule
Daily:
- Monitor /var/log/server-hardening.log
- Check auth.log for unauthorized attempts
- Verify service status

Weekly:
- Test SSH key access
- Review failed login attempts
- Check automatic updates status

Monthly:
- Review and update allowed users
- Test restore procedure
- Update documentation if needed
- Verify backup integrity

## Troubleshooting
Common issues and solutions in docs/troubleshooting.md