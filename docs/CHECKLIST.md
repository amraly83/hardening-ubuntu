# Ubuntu Server Hardening Checklist

## Pre-Installation Requirements
- [ ] System Requirements
  - [ ] Ubuntu 20.04 LTS or higher
  - [ ] Minimum 1GB RAM
  - [ ] Minimum 1GB free disk space
  - [ ] Root/sudo access available
  - [ ] Console access available as backup

- [ ] Security Prerequisites
  - [ ] Generated SSH key pair locally (`ssh-keygen -t ed25519`)
  - [ ] Installed Google Authenticator app (if using 2FA)
  - [ ] Backed up current system configuration
  - [ ] Documented emergency contact information

## Installation Process

### 1. Initial Setup
- [ ] Repository Preparation
  - [ ] Cloned repository
  - [ ] Fixed script permissions: `chmod +x scripts/*.sh`
  - [ ] Fixed line endings: `sed -i 's/\r$//' scripts/*.sh`
  - [ ] Ran `install-deps.sh` successfully

- [ ] System Checks
  - [ ] All dependencies installed correctly
  - [ ] Preflight checks passed
  - [ ] No syntax errors in scripts
  - [ ] Log directory writable

### 2. User Management
- [ ] Admin User Setup
  - [ ] Created new admin user successfully
  - [ ] Added user to sudo group
  - [ ] Tested sudo access verification
  - [ ] Documented username securely
  - [ ] Verified no duplicate user issues

### 3. SSH Configuration
- [ ] Key Setup
  - [ ] SSH directory permissions correct (700)
  - [ ] Added SSH public key properly
  - [ ] authorized_keys permissions correct (600)
  - [ ] Tested SSH key access before proceeding
  - [ ] Backed up SSH configuration

- [ ] SSH Hardening
  - [ ] Noted new SSH port (default: 3333)
  - [ ] Disabled password authentication
  - [ ] Limited login attempts
  - [ ] Root login disabled
  - [ ] Protocol 2 enforced

### 4. Two-Factor Authentication
- [ ] 2FA Setup
  - [ ] Google Authenticator configured correctly
  - [ ] PAM modules properly configured
  - [ ] Saved backup codes securely
  - [ ] Tested 2FA login in separate session
  - [ ] Documented recovery procedures

### 5. System Hardening
- [ ] Security Controls
  - [ ] UFW firewall configured and enabled
  - [ ] Automatic updates configured
  - [ ] Fail2ban installed and configured
  - [ ] System auditing enabled
  - [ ] Core dumps disabled

- [ ] Service Hardening
  - [ ] Unnecessary services disabled
  - [ ] Required ports documented
  - [ ] Service configurations backed up
  - [ ] SELinux/AppArmor configured

### 6. Verification Steps
- [ ] Access Testing
  - [ ] SSH access working on new port
  - [ ] 2FA working (if enabled)
  - [ ] Sudo access verified
  - [ ] Recovery procedures tested

- [ ] System Checks
  - [ ] All critical services running
  - [ ] Firewall rules verified
  - [ ] Logging working correctly
  - [ ] Monitoring set up

## Post-Installation
- [ ] Documentation
  - [ ] All configurations documented
  - [ ] Backup codes stored securely
  - [ ] Recovery procedures documented
  - [ ] Emergency contacts updated

- [ ] Monitoring Setup
  - [ ] Log rotation configured
  - [ ] Disk space monitoring
  - [ ] Service monitoring
  - [ ] Security alerts configured

## Critical Information
```plaintext
SSH Port: _______
Admin Username: _______
Backup Files Location: _______
Recovery Codes Location: _______
Emergency Contact: _______

Custom Configurations:
Firewall Rules: _______
Allowed Services: _______
Modified Files: _______
```

## Validation
```plaintext
Installation Date: _______
Completed By: _______
Verified By: _______
Next Review Date: _______
```

## Notes
Use this section for any special configurations or important observations:

```plaintext
Additional Notes:
1. 
2. 
3. 