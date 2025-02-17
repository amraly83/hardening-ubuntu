#!/bin/bash

# Simple wrapper script for sudo verification with reliable timeout
username="$1"

if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Try sudo test without requiring terminal
sudo_test() {
    # First try with -n (non-interactive)
    if su -s /bin/bash - "$username" -c "sudo -n true" >/dev/null 2>&1; then
        return 0
    fi
    
    # If that fails, try with basic command
    if su -s /bin/bash - "$username" -c "sudo true" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Run the test with a timeout
timeout 10 bash -c "sudo_test" || exit 1