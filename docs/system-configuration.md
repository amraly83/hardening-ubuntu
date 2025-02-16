# System Hardening Documentation
Generated: Sun Feb 16 09:16:36 AM UTC 2025
Script Version: 1.0.0

## System Information
Ubuntu Version: Ubuntu 22.04.1 LTS
Kernel Version: 5.15.0-46-generic

## Security Configurations
### SSH Configuration
```
Port 3333
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
AllowUsers amraly web
AuthenticationMethods publickey,keyboard-interactive
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
```