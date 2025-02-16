#!/bin/bash

# Script preloader to ensure proper formatting and dependencies
set -euo pipefail

# Function to validate script syntax
validate_script() {
    local script="$1"
    if ! bash -n "$script" 2>/dev/null; then
        echo "Syntax error in $script"
        return 1
    fi
    return 0
}

# Function to fix script formatting
fix_script_formatting() {
    local script="$1"
    
    # Fix line endings
    sed -i.bak 's/\r$//' "$script"
    
    # Remove backup file if it exists
    rm -f "${script}.bak"
    
    # Make script executable
    chmod +x "$script"
    
    # Validate script syntax
    validate_script "$script"
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Process all shell scripts
echo "Preparing shell scripts..."
for script in "${SCRIPT_DIR}"/*.sh; do
    if [[ -f "$script" ]]; then
        echo "Processing: $(basename "$script")"
        if ! fix_script_formatting "$script"; then
            echo "Error processing: $script"
            exit 1
        fi
    fi
done

# Verify common.sh can be sourced
echo "Verifying common.sh..."
if ! source "${SCRIPT_DIR}/common.sh" 2>/dev/null; then
    echo "Error: common.sh cannot be sourced"
    exit 1
fi

echo "Script preparation complete"