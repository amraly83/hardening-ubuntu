#!/bin/bash

# Script preloader to ensure proper formatting and dependencies
set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Keep track of processed files
declare -A PROCESSED_FILES

# Function to validate script syntax
validate_script() {
    local script="$1"
    if ! bash -n "$script" 2>/dev/null; then
        echo "Syntax error in $script"
        return 1
    fi
    # Check for CRLF line endings and fix if needed
    if file "$script" | grep -q "CRLF"; then
        echo "Warning: CRLF line endings found in $script"
        tr -d '\r' < "$script" > "${script}.tmp" && mv "${script}.tmp" "$script"
        if file "$script" | grep -q "CRLF"; then
            echo "Error: Failed to fix CRLF line endings in $script"
            return 1
        fi
    fi
    return 0
}

# Function to fix script formatting
fix_script_formatting() {
    local script="$1"
    
    # Skip if already processed
    [[ -n "${PROCESSED_FILES[$script]:-}" ]] && return 0
    
    echo "Processing: $(basename "$script")"
    
    # Special handling for common.sh - process it first but don't modify after initial processing
    if [[ "$script" == *"common.sh" ]]; then
        if [[ ! -n "${PROCESSED_FILES[${SCRIPT_DIR}/common.sh]:-}" ]]; then
            # Only fix common.sh once, at the very start
            validate_script "$script" || return 1
            PROCESSED_FILES[$script]=1
        fi
        return 0
    fi
    
    # For other scripts, process common.sh dependency first
    if grep -q "source.*common.sh" "$script"; then
        if [[ ! -n "${PROCESSED_FILES[${SCRIPT_DIR}/common.sh]:-}" ]]; then
            fix_script_formatting "${SCRIPT_DIR}/common.sh" || {
                echo "Error: Failed to process dependency common.sh for $script"
                return 1
            }
        fi
    fi
    
    # Fix line endings
    sed -i.bak 's/\r$//' "$script"
    rm -f "${script}.bak"
    
    # Make script executable
    chmod +x "$script"
    
    # Validate script syntax
    validate_script "$script" || return 1
    
    # Mark as processed
    PROCESSED_FILES[$script]=1
    
    return 0
}

# Main script
main() {
    # Check required commands
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
        exit 1
    fi
    
    echo "Preparing shell scripts..."
    
    # Process common.sh first and only once
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
    
    echo "Script preparation complete"
}

# Run main function
main "$@"