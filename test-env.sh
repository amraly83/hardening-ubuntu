#!/bin/bash
# Test environment setup script for Windows development

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

# Create test directory in WSL
echo "Setting up test environment in WSL..."
wsl.exe bash -c "
    mkdir -p ~/hardening-test
    rm -rf ~/hardening-test/*
"

# Copy files to WSL
echo "Copying files to WSL test environment..."
./prepare-deploy.sh
wsl.exe bash -c "cp -r deploy/* ~/hardening-test/"

# Run basic validation
echo "Running basic validation..."
wsl.exe bash -c "
    cd ~/hardening-test
    for script in scripts/*.sh; do
        echo \"Checking \$script...\"
        bash -n \"\$script\" || exit 1
    done
"

echo "Test environment ready!"
echo "To test in WSL, run: wsl.exe"
echo "Then navigate to: cd ~/hardening-test"
echo "Run scripts with: sudo ./scripts/setup.sh"