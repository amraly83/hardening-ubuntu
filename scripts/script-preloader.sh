#!/bin/bash
# Script preloader - fixes line endings and permissions after git clone
set -euo pipefail

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# First fix this script's line endings and make it executable
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

echo "Preparing scripts for execution..."

# Initialize variables for tracking
fixed_count=0
error_count=0

# Function to fix a script
fix_script() {
    local script="$1"
    local relative_path="${script#$SCRIPT_DIR/}"
    
    echo -n "Processing $relative_path... "
    
    # Fix line endings
    if sed -i 's/\r$//' "$script" 2>/dev/null; then
        # Make executable
        if chmod +x "$script" 2>/dev/null; then
            echo "✓ OK"
            ((fixed_count++))
            return 0
        fi
    fi
    
    echo "✗ FAILED"
    ((error_count++))
    return 1
}

# Process all shell scripts in the scripts directory and subdirectories
while IFS= read -r -d '' script; do
    fix_script "$script"
done < <(find "$SCRIPT_DIR" -type f -name "*.sh" -print0)

echo "================================================================"
echo "Script preparation complete:"
echo "Fixed: $fixed_count scripts"
if [[ $error_count -gt 0 ]]; then
    echo "Errors: $error_count scripts failed to process"
    exit 1
fi

# Create initial directories if they don't exist
mkdir -p "/var/log/server-hardening" "/etc/server-hardening" 2>/dev/null || true

echo "All scripts prepared successfully"
exit 0