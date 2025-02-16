# Setup Checklist

Use this checklist to track your progress through the hardening setup process.

## Pre-Installation
- [ ] Read REQUIREMENTS.md
- [ ] Backed up current system configuration
- [ ] Have root/sudo access
- [ ] Have console access available
- [ ] Generated SSH key pair locally
- [ ] Installed Google Authenticator app (if using 2FA)
- [ ] Documented emergency contact information

## Installation Steps

### 1. Initial Setup
- [ ] Cloned repository
- [ ] Made scripts executable
- [ ] Ran install-deps.sh successfully
- [ ] All dependencies installed
- [ ] Preflight checks passed

### 2. User Management
- [ ] Created new admin user
- [ ] Added user to sudo group
- [ ] Tested sudo access
- [ ] Documented username and password

### 3. SSH Configuration
- [ ] Added SSH public key
- [ ] Tested SSH key access
- [ ] Noted new SSH port number
- [ ] Kept backup of SSH configuration

### 4. Two-Factor Authentication
- [ ] Set up Google Authenticator
- [ ] Saved backup codes securely
- [ ] Tested 2FA login
- [ ] Documented recovery procedures

### 5. System Hardening
- [ ] Firewall configured
- [ ] Automatic updates set up
- [ ] Fail2ban configured
- [ ] System auditing enabled

### 6. Verification
- [ ] SSH access working
- [ ] 2FA working (if enabled)
- [ ] Sudo access working
- [ ] All services running
- [ ] Firewall rules correct
- [ ] Logs being generated

## Post-Installation
- [ ] Reviewed all documentation
- [ ] Saved all backup codes
- [ ] Tested recovery procedures
- [ ] Set up monitoring
- [ ] Scheduled regular maintenance
- [ ] Updated emergency contacts

## Notes
Use this section to document any custom configurations or important information:

SSH Port: _______
Admin Username: _______
Backup Codes Location: _______
Emergency Contact: _______
Custom Firewall Rules: _______

## Validation
Date Completed: _______
Validated By: _______
Next Review Date: _______