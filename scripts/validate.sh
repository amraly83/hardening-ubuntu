#!/bin/bash

# Script validator to ensure all dependencies and scripts are properly configured
set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to validate script requirements
validate_requirements() {
    local script="$1"
    local result=0
    
    # Check for DOS line endings
    if file "$script" | grep -q "CRLF"; then
        echo "Error: $script has DOS line endings"
        result=1
    fi
    
    # Check for proper shebang
    if ! head -n 1 "$script" | grep -q '^#!/bin/bash'; then
        echo "Error: $script missing or incorrect shebang"
        result=1
    fi
    
    # Check for execution permission
    if [[ ! -x "$script" ]]; then
        echo "Error: $script is not executable"
        result=1
    fi
    
    return $result
}

# Function to test script sourcing
test_script_source() {
    local script="$1"
    local temp_script
    temp_script=$(mktemp)
    
    cat > "$temp_script" << EOF
#!/bin/bash
set -euo pipefail
source '$script'
echo 'Script sourced successfully'
EOF
    
    chmod +x "$temp_script"
    if ! bash "$temp_script" > /dev/null 2>&1; then
        rm -f "$temp_script"
        return 1
    fi
    
    rm -f "$temp_script"
    return 0
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    # Required commands
    local commands=("sed" "awk" "grep" "file" "mktemp" "chmod" "bash")
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required commands: ${missing[*]}"
        return 1
    fi
    
    return 0
}

# Main validation function
main() {
    local exit_code=0
    
    echo "Checking dependencies..."
    if ! check_dependencies; then
        echo "Error: Missing required dependencies"
        exit 1
    fi
    
    echo "Validating scripts..."
    for script in "${SCRIPT_DIR}"/*.sh; do
        echo "Checking: $(basename "$script")"
        
        if ! validate_requirements "$script"; then
            echo "Error: Script format validation failed for: $script"
            exit_code=1
            continue
        fi
        
        if [[ "$script" != "${BASH_SOURCE[0]}" ]] && grep -q "^source.*common.sh" "$script"; then
            if ! test_script_source "$script"; then
                echo "Error: Script sourcing failed for: $script"
                exit_code=1
            fi
        fi
    done
    
    if [[ $exit_code -eq 0 ]]; then
        echo "All scripts validated successfully"
    fi
    
    return $exit_code
}

# Run main function
main "$@"