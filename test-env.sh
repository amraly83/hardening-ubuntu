#!/bin/bash
# Test environment setup script for Windows development
set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_USER="testadmin"
TEST_EMAIL="test@localhost"
LOG_FILE="/tmp/hardening-test.log"

# Check if running in Git Bash
if [[ ! "$OSTYPE" == "msys" ]]; then
    echo "This script must be run in Git Bash"
    exit 1
fi

# Check if WSL is installed and Ubuntu is available
if ! wsl.exe --status >/dev/null 2>&1; then
    echo "WSL is not installed. Please install WSL and Ubuntu from Microsoft Store"
    exit 1
fi

# Create test environment
echo "Setting up test environment in WSL..."
wsl.exe bash -c "
    # Cleanup previous test environment
    sudo rm -rf ~/hardening-test
    mkdir -p ~/hardening-test
    
    # Install required packages
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        openssh-server \
        libpam-google-authenticator \
        ufw \
        fail2ban \
        sudo \
        git \
        bc \
        jq \
        unattended-upgrades \
        apt-listchanges
"

# Copy files to WSL with proper permissions
echo "Copying files to WSL test environment..."
./prepare-deploy.sh
wsl.exe bash -c "
    cp -r deploy/* ~/hardening-test/
    chmod +x ~/hardening-test/scripts/*.sh
"

# Setup test configuration
echo "Creating test configuration..."
wsl.exe bash -c "
    cd ~/hardening-test
    mkdir -p /etc/server-hardening
    cat > /etc/server-hardening/hardening.conf << EOF
SSH_PORT=3333
SSH_ALLOW_USERS=$TEST_USER
ADMIN_EMAIL=$TEST_EMAIL
FIREWALL_ADDITIONAL_PORTS=80,443
MFA_ENABLED=yes
ENABLE_AUTO_UPDATES=yes
ENABLE_IPV6=no
EOF
"

# Run validation suite
echo "Running validation suite..."
wsl.exe bash -c "
    cd ~/hardening-test
    
    # Syntax check all scripts
    echo 'Checking script syntax...'
    for script in scripts/*.sh; do
        bash -n \"\$script\" || exit 1
    done
    
    # Run preflight checks
    echo 'Running preflight checks...'
    sudo ./scripts/preflight.sh || exit 1
    
    # Prepare test SSH key
    echo 'Generating test SSH key...'
    ssh-keygen -t ed25519 -f ~/.ssh/test_key -N '' || exit 1
    
    # Run automated tests
    echo 'Running automated tests...'
    export AUTOMATED_TESTING=1
    sudo ./scripts/test_user_handling.sh || exit 1
    sudo ./scripts/test-2fa.sh || exit 1
    
    # Verify system configuration
    echo 'Verifying system configuration...'
    sudo ./scripts/verify-system.sh \$TEST_USER || exit 1
"

echo "=== Test Environment Ready ==="
echo "To access the test environment:"
echo "1. Run: wsl.exe"
echo "2. Navigate to: cd ~/hardening-test"
echo "3. Start setup: sudo ./scripts/setup.sh"
echo
echo "Test SSH key location: ~/.ssh/test_key"
echo "Test user: $TEST_USER"
echo "Logs available at: $LOG_FILE"