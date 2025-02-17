#!/bin/bash

# Simple wrapper script for sudo verification with reliable timeout
username="$1"

if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Run sudo test as a single inline script
timeout 10 bash -c "
    if su -s /bin/bash - \"$username\" -c 'sudo -n true' >/dev/null 2>&1; then
        exit 0
    fi
    
    if su -s /bin/bash - \"$username\" -c 'sudo true' >/dev/null 2>&1; then
        exit 0
    fi
    
    exit 1
" || exit 1