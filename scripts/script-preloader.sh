#!/bin/bash

# Script preloader to ensure proper formatting and dependencies
set -euo pipefail

# Check for required commands
check_required_commands() {
    local missing=()
    local commands=("file" "tr" "sed" "grep" "bash")
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Missing required commands: ${missing[*]}"
        echo "Please install the missing packages and try again"
        return 1
    fi
    return 0
}

# Check required commands before proceeding
if ! check_required_commands; then
    exit 1
fi

# Function to validate script syntax
validate_script() {
    local script="$1"
    if ! bash -n "$script" 2>/dev/null; then
        echo "Syntax error in $script"
        return 1
    fi
    # Check for CRLF line endings
    if file "$script" | grep -q "CRLF"; then
        echo "Warning: CRLF line endings found in $script"
        # Try to fix CRLF endings more aggressively
        tr -d '\r' < "$script" > "${script}.tmp" && mv "${script}.tmp" "$script"
        if file "$script" | grep -q "CRLF"; then
            echo "Error: Failed to fix CRLF line endings in $script"
            return 1
        fi
    fi
    return 0
}

# Function to check script dependencies
check_dependencies() {
    local script="$1"
    # Look for source commands
    if grep -q "source.*common.sh" "$script"; then
        # This script depends on common.sh, ensure it's processed first
        if [[ "$script" != *"common.sh" ]]; then
            fix_script_formatting "${SCRIPT_DIR}/common.sh" || return 1
        fi
    fi
    return 0
}

# Function to fix script formatting
fix_script_formatting() {
    local script="$1"
    
    echo "Processing: $(basename "$script")"
    
    # Check dependencies first
    check_dependencies "$script" || {
        echo "Error: Failed to process dependencies for $script"
        return 1
    }
    
    # Fix line endings
    sed -i.bak 's/\r$//' "$script"
    
    # Remove backup file if it exists
    rm -f "${script}.bak"
    
    # Make script executable
    chmod +x "$script"
    
    # Validate script syntax
    if ! validate_script "$script"; then
        return 1
    fi
    
    return 0
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Process common.sh first
echo "Preparing shell scripts..."
if ! fix_script_formatting "${SCRIPT_DIR}/common.sh"; then
    echo "Error: Failed to process common.sh"
    exit 1
fi

# Then process all other shell scripts
for script in "${SCRIPT_DIR}"/*.sh; do
    if [[ -f "$script" && "$script" != *"common.sh" ]]; then
        if ! fix_script_formatting "$script"; then
            echo "Error processing: $script"
            exit 1
        fi
    fi
done

echo "Verifying scripts can be sourced..."
# Try to source common.sh first
if ! source "${SCRIPT_DIR}/common.sh" 2>/dev/null; then
    echo "Error: common.sh cannot be sourced"
    exit 1
fi

# Verify other scripts that need to be sourced
for script in progress.sh; do
    if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
        if ! source "${SCRIPT_DIR}/${script}" 2>/dev/null; then
            echo "Error: ${script} cannot be sourced"
            exit 1
        fi
    fi
done

echo "Script preparation complete"