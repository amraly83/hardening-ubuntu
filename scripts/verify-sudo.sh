#!/bin/bash

# Simple wrapper script for sudo verification with reliable timeout
username="$1"

if [ -z "$username" ]; then
    echo "Usage: $0 username" >&2
    exit 1
fi

# Try sudo with -n (non-interactive) flag
timeout 10 su - "$username" -c "sudo -n true"
exit $?