# Troubleshooting Guide

## Common Issues and Solutions

### 1. Pre-Flight Check Failures

#### Insufficient Disk Space
**Problem**: "Insufficient disk space" error during preflight checks
**Solution**:
- Clean up /var/log directory
- Remove old packages: `sudo apt-get autoremove`
- Clear apt cache: `sudo apt-get clean`

#### Low Memory Warning
**Problem**: "Low memory detected" warning
**Solution**:
- Close unnecessary processes
- Check for memory leaks: `ps aux --sort=-%mem | head`
- Consider adding swap space

### 2. User Management Issues

#### User Already Exists
**Problem**: "User already exists"
**Solutions**:
1. If user is already an admin:
   - Choose "yes" to use the existing admin user
   - The script will verify their configuration
   - SSH keys and 2FA can be reconfigured if needed

2. If user exists but is not an admin:
   - Choose "yes" to grant admin privileges
   - The user will be added to the sudo group
   - Existing home directory and files will be preserved

3. If you want a different user:
   - Choose "no" when prompted
   - Enter a different username
   - You have 3 attempts before the script exits

**Example Scenarios**:
```
Scenario 1: Existing admin user
Q: "User 'admin' is already an admin. Would you like to use this existing admin user?"
- Yes: Continues with existing user
- No: Prompts for a different username

Scenario 2: Existing regular user
Q: "User 'user1' exists but is not an admin. Would you like to grant admin privileges?"
- Yes: Adds user to sudo group
- No: Prompts for a different username
```

#### Using Existing Admin User
**Problem**: Script stops after confirming existing admin user
**Solutions**:
1. Wait for sudo verification:
   - The script performs up to 3 verification attempts
   - Each attempt has a built-in delay to handle system load
   - Total verification can take up to 30 seconds

2. If sudo verification fails:
   - Choose "yes" when prompted to fix sudo access
   - The script will attempt to repair group membership
   - A new verification cycle will start

3. Common sudo verification failures:
   - User not in sudo group despite admin status
   - Stale group membership (needs session refresh)
   - PAM configuration issues
   - sudo configuration corruption

**Verification Process**:
```
Step 1: Initial Check
- Script checks if user exists
- Verifies admin status (sudo group or sudoers entry)

Step 2: Sudo Verification
- Attempts non-interactive sudo command
- Uses timeout to prevent hanging
- Retries with exponential backoff

Step 3: Auto-Recovery
- Offers to fix common sudo issues
- Re-adds user to sudo group if needed
- Verifies fix was successful
```

#### Sudo Access Fails
**Problem**: "Failed to verify sudo access"
**Solution**:
- Check /etc/sudoers.d/ permissions
- Verify user is in sudo group: `groups username`
- Reset sudo configuration: `pkexec visudo`

### 3. SSH Key Setup Problems

#### Invalid SSH Key
**Problem**: "Invalid SSH public key"
**Solution**:
- Ensure you're copying the .pub file content
- Key should start with 'ssh-rsa' or 'ssh-ed25519'
- Check for copy/paste errors

#### SSH Access Verification Fails
**Problem**: "Could not verify SSH access automatically"
**Solution**:
- Check SSH service status: `systemctl status sshd`
- Verify key permissions: `chmod 600 ~/.ssh/authorized_keys`
- Check SSH logs: `tail -f /var/log/auth.log`

### 4. 2FA Configuration Issues

#### Google Authenticator Installation Fails
**Problem**: "Failed to install libpam-google-authenticator"
**Solution**:
- Update package lists: `sudo apt-get update`
- Check internet connectivity
- Try alternative repository: `sudo add-apt-repository universe`

#### PAM Configuration Errors
**Problem**: "SSH configuration test failed"
**Solution**:
- Check PAM syntax: `sudo pam-auth-update`
- Verify /etc/pam.d/sshd permissions
- Restore from backup if needed

### 5. System Hardening Issues

#### Firewall Configuration Fails
**Problem**: "Failed to configure UFW"
**Solution**:
- Reset UFW: `sudo ufw --force reset`
- Check rule syntax
- Verify port numbers are valid

#### Automatic Updates Issues
**Problem**: "Failed to configure automatic updates"
**Solution**:
- Check disk space
- Verify internet connectivity
- Check dpkg locks: `sudo lsof /var/lib/dpkg/lock-frontend`

### 6. Recovery Procedures

#### Locked Out of SSH
1. Access server through console
2. Check SSH configuration:
   ```bash
   sudo cat /etc/ssh/sshd_config
   ```
3. Reset to backup:
   ```bash
   sudo cp /etc/ssh/sshd_config.TIMESTAMP.bak /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

#### Failed 2FA
1. Access server through console
2. Remove 2FA requirement temporarily:
   ```bash
   sudo sed -i '/pam_google_authenticator.so/d' /etc/pam.d/sshd
   sudo systemctl restart sshd
   ```
3. Reconfigure 2FA:
   ```bash
   sudo ./scripts/setup-2fa.sh username
   ```

### 7. Log Analysis

#### Important Log Locations
- Server Hardening: `/var/log/server-hardening.log`
- SSH Access: `/var/log/auth.log`
- System Messages: `/var/log/syslog`
- Fail2ban: `/var/log/fail2ban.log`

#### Common Log Messages
- "Failed password": Someone trying password auth
- "Invalid user": Attempted login with non-existent user
- "Accepted publickey": Successful key-based login
- "error: maximum authentication attempts exceeded": Too many failed attempts

### 8. Maintenance Issues

#### Backup Restoration Fails
**Problem**: "No valid backup found for restoration"
**Solution**:
- Check backup directory permissions
- Verify backup manifest integrity
- Try specific backup date: `./scripts/harden.sh --restore YYYY-MM-DD`

#### Service Verification Fails
**Problem**: "Critical service is not running"
**Solution**:
- Check service status: `systemctl status service_name`
- Review service logs: `journalctl -u service_name`
- Restart service: `sudo systemctl restart service_name`

### Getting Help
If you encounter an issue not covered here:
1. Check the server-hardening.log file
2. Review relevant service logs
3. Open an issue on GitHub with:
   - Full error message
   - Relevant log entries
   - System information
   - Steps to reproduce