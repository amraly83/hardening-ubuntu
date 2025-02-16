# System Requirements and Dependencies

## Required Packages
The following packages must be installed for the hardening scripts to work:

```bash
# Core Requirements
- openssh-server            # SSH server
- libpam-google-authenticator  # 2FA support
- ufw                      # Firewall
- fail2ban                # Brute force protection
- sudo                    # Privilege escalation
- git                     # Version control (for cloning)
- bc                      # Basic calculator (for version checks)

# Optional but Recommended
- unattended-upgrades     # Automatic security updates
- apt-listchanges         # Update notifications
- postfix                 # Email notifications
- apparmor               # Application security
- auditd                 # System auditing
```

## System Requirements
- Ubuntu Server 20.04 LTS or later
- Minimum 1GB RAM
- Minimum 1GB free disk space in /var
- Working internet connection
- Access to the server console (in case of lockout)

## Network Requirements
The following ports should be accessible:
- Default SSH port (22) - Will be changed during setup
- New SSH port (default: 3333) - Configurable
- HTTP/HTTPS (80/443) - If running web services
- Custom ports as needed

## User Requirements
- Root access or sudo privileges
- Understanding of SSH key-based authentication
- Google Authenticator app installed on mobile device (if using 2FA)
- Backup email address for notifications

## Pre-Installation Checklist
Before running the setup:

1. System Access
   - [ ] Root password available
   - [ ] Console access verified
   - [ ] Network connectivity confirmed

2. Backups
   - [ ] Current SSH configuration backed up
   - [ ] User data backed up
   - [ ] System configuration backed up

3. Security
   - [ ] SSH key pair generated locally
   - [ ] Google Authenticator app installed (if using 2FA)
   - [ ] Emergency contact information documented

4. Documentation
   - [ ] Server IP address noted
   - [ ] All required passwords documented
   - [ ] Recovery procedures reviewed

## Post-Installation Requirements
After setup, maintain:

1. Regular Backups
   - SSH keys and 2FA backup codes
   - System configuration files
   - User data

2. Monitoring
   - System logs
   - Failed login attempts
   - Security updates

3. Documentation
   - Changed passwords and configurations
   - Custom firewall rules
   - Added users and their access levels

## Environment Compatibility
Tested and supported on:
- Ubuntu Server 20.04 LTS
- Ubuntu Server 22.04 LTS

Other environments may work but are not officially supported.

## Support and Updates
- Regular testing on latest Ubuntu LTS releases
- Security patches applied as needed
- Community support via GitHub issues
- Documentation updates based on user feedback