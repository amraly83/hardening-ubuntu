#!/bin/bash
set -euo pipefail

echo "Fixing permission issues..."

# Fix /etc/sudoers.d permissions
if [ -d "/etc/sudoers.d" ]; then
    chmod 750 /etc/sudoers.d
    echo "Fixed permissions on /etc/sudoers.d to 750"
fi

# Fix /var/log permissions
if [ -d "/var/log" ]; then
    chmod 755 /var/log
    echo "Fixed permissions on /var/log to 755"
fi

# Check system load and provide recommendations
load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
if [[ $(echo "$load_avg > 0.8" | bc) -eq 1 ]]; then
    echo ""
    echo "System load is still high ($load_avg). Recommendations:"
    echo "1. Check running processes: 'top' or 'htop'"
    echo "2. Consider terminating non-essential processes"
    echo "3. Wait for system load to decrease before proceeding"
fi

echo ""
echo "Run preflight checks again to verify fixes: ./preflight.sh"