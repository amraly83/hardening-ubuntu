# Ubuntu Server Hardening Scripts

A comprehensive set of scripts for hardening Ubuntu Server security configurations.

## Features
- Automated server hardening process
- SSH key-based authentication setup
- Two-factor authentication (2FA) with Google Authenticator
- Firewall configuration with UFW
- Automatic security updates
- Fail2ban setup
- System backup and restore functionality
- User management with proper sudo access

## Requirements
- Ubuntu Server 20.04 or later
- Root access to the server
- Google Authenticator app for 2FA
- SSH client

## Quick Start
```bash
git clone https://github.com/amraly83/hardening-ubuntu.git
cd hardening-ubuntu
chmod +x *.sh
sudo ./setup.sh
```

## Manual Setup
See [GUIDE.md](GUIDE.md) for detailed instructions.

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

## Directory Structure
```
hardening-ubuntu/
├── scripts/
│   ├── setup.sh           # Main setup script
│   ├── harden.sh         # Core hardening script
│   ├── setup-2fa.sh      # 2FA configuration
│   ├── setup-ssh-key.sh  # SSH key setup
│   └── create-admin.sh   # Admin user creation
├── docs/
│   ├── GUIDE.md          # Detailed setup guide
│   └── templates/        # Documentation templates
└── examples/
    └── config/           # Example configurations
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](LICENSE)

## Author
[Amr Aly](https://github.com/amraly83)