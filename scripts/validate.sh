#!/bin/bash

check_scripts() {
    local script="$1"
    # Check for shebang
    if ! head -n 1 "$script" | grep -q "^#!/bin/bash"; then
        echo "Error: $script is missing shebang (#!/bin/bash)"
        return 1
    fi
    
    # Check permissions
    if [[ ! -x "$script" ]]; then
        echo "Error: $script is not executable"
        return 1
    fi
    
    # Basic syntax check
    if ! bash -n "$script"; then
        echo "Error: $script has syntax errors"
        return 1
    }
    
    return 0
}

# Check all shell scripts
for script in *.sh; do
    echo "Checking $script..."
    if ! check_scripts "$script"; then
        exit 1
    fi
done

echo "All scripts passed validation"