# Ubuntu Server Hardening Scripts

A comprehensive set of scripts for hardening Ubuntu Server security configurations.

This repository contains scripts for hardening Ubuntu servers. The scripts can be developed and tested on Windows but are designed to run on Ubuntu Server.

## Features
- Automated server hardening process
- SSH key-based authentication setup
- Two-factor authentication (2FA) with Google Authenticator
- Firewall configuration with UFW
- Automatic security updates
- Fail2ban setup
- System backup and restore functionality
- User management with proper sudo access

## Quick Start
```bash
# Clone the repository
git clone https://github.com/amraly83/hardening-ubuntu.git
cd hardening-ubuntu

# Make all scripts executable
chmod +x scripts/*.sh

# Run the automated setup
sudo ./scripts/setup.sh
```

## Development Setup

If you're developing these scripts on Windows:

1. Install Git for Windows with Git Bash
2. Configure Git to handle line endings:
   ```bash
   git config --global core.autocrlf input
   ```
3. Use Git Bash to run and test scripts during development
4. Install WSL (Windows Subsystem for Linux) for local testing

## Deployment

To deploy these scripts to your Ubuntu server:

1. Run `prepare-deploy.sh` using Git Bash:
   ```bash
   ./prepare-deploy.sh
   ```
2. Copy the contents of the `deploy` directory to your Ubuntu server:
   ```bash
   scp -r deploy/* user@your-server:/path/to/destination/
   ```
3. On the Ubuntu server, verify permissions:
   ```bash
   chmod +x /path/to/destination/scripts/*.sh
   ```

## Installation Tracking
We provide a detailed checklist to help you track your progress through the installation:
1. Copy docs/CHECKLIST.md to your local workspace
2. Follow each section and check off completed items
3. Document your specific configuration details
4. Save for future reference and auditing

## What the Setup Does
1. Performs pre-flight system checks
2. Creates a new admin user with sudo privileges
3. Sets up SSH key authentication
4. Configures Google Authenticator 2FA (optional)
5. Applies system hardening measures
6. Generates documentation and backup procedures

## Safety Features
- Prevents root lockout by requiring a secondary admin user
- Tests SSH access before disabling password authentication
- Creates backups before making system changes
- Validates all configurations before applying
- Provides rollback capabilities if something goes wrong

## Directory Structure
```
hardening-ubuntu/
├── scripts/
│   ├── setup.sh           # Main setup script
│   ├── preflight.sh      # System readiness checks
│   ├── common.sh         # Shared functions library
│   ├── create-admin.sh   # Admin user creation
│   ├── setup-ssh-key.sh  # SSH key setup
│   ├── setup-2fa.sh      # 2FA configuration
│   ├── harden.sh        # Core hardening script
│   └── validate.sh      # Script validation
├── docs/
│   ├── GUIDE.md         # Detailed setup guide
│   └── templates/       # Documentation templates
├── examples/
│   └── config/         # Example configurations
└── .github/
    └── workflows/      # CI/CD configurations
```

## Requirements
- Ubuntu Server 20.04 or later
- Root access to the server
- At least 1GB RAM and 1GB free disk space
- Internet access for package installation
- Google Authenticator app for 2FA (optional)
- SSH client on your local machine

## Manual Setup
See [GUIDE.md](docs/GUIDE.md) for detailed instructions and manual setup steps.

## Security Features
- SSH hardening with key-based authentication
- Optional 2FA using Google Authenticator
- UFW firewall configuration
- Fail2ban for brute force protection
- Automatic security updates
- GRUB password protection
- System backup and restore
- Comprehensive logging
- Documentation generation

## Scripts Overview

- `scripts/setup.sh`: Main setup script that guides through the hardening process
- `scripts/common.sh`: Common functions used by all scripts
- `scripts/create-admin.sh`: Creates and configures admin user
- `scripts/setup-ssh-key.sh`: Configures SSH key authentication
- `scripts/setup-2fa.sh`: Sets up two-factor authentication
- `scripts/harden.sh`: Applies system hardening configurations

## Testing

Always test scripts in a safe environment first:
1. Test locally using WSL
2. Test on a development server
3. Finally deploy to production

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](LICENSE)

## Author
[Amr Aly](https://github.com/amraly83)