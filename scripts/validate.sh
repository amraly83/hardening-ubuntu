#!/bin/bash
# Script validator to ensure all dependencies and scripts are properly configured
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Get absolute path of script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
readonly COLOR_RED='\033[1;31m'
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RESET='\033[0m'

# Function to validate script requirements
validate_script() {
    local script="$1"
    local result=0
    local relative_path="${script#$SCRIPT_DIR/}"
    
    echo -n "Validating $relative_path... "
    
    # Check if file exists and is readable
    if [[ ! -f "$script" ]] || [[ ! -r "$script" ]]; then
        echo -e "${COLOR_RED}ERROR: File not found or not readable${COLOR_RESET}"
        return 1
    }
    
    # Check for DOS line endings
    if file "$script" | grep -q "CRLF"; then
        echo -e "${COLOR_YELLOW}WARNING: Found CRLF line endings, fixing...${COLOR_RESET}"
        sed -i 's/\r$//' "$script"
        result=1
    fi
    
    # Check for proper shebang
    if ! head -n 1 "$script" | grep -q '^#!/bin/bash'; then
        echo -e "${COLOR_RED}ERROR: Missing or incorrect shebang${COLOR_RESET}"
        result=1
    fi
    
    # Check for execution permission
    if [[ ! -x "$script" ]]; then
        echo -e "${COLOR_YELLOW}WARNING: Missing execute permission, fixing...${COLOR_RESET}"
        chmod +x "$script"
        result=1
    fi
    
    # Check for common syntax errors
    if ! bash -n "$script" >/dev/null 2>&1; then
        echo -e "${COLOR_RED}ERROR: Syntax error detected${COLOR_RESET}"
        bash -n "$script" 2>&1 | sed 's/^/  /'
        result=1
    fi
    
    # Check for common.sh sourcing if script uses it
    if grep -q "source.*common.sh" "$script"; then
        if ! grep -q "sed -i 's/\r\$//' .*common.sh" "$script"; then
            echo -e "${COLOR_YELLOW}WARNING: Script sources common.sh but doesn't fix its line endings${COLOR_RESET}"
            result=1
        fi
    fi
    
    if [[ $result -eq 0 ]]; then
        echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
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
# Fix line endings first
sed -i 's/\r$//' "$script"
source '$script'
echo 'Script sourced successfully'
EOF
    
    chmod +x "$temp_script"
    if ! timeout 5 bash "$temp_script" > /dev/null 2>&1; then
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
    local commands=(
        "sed"
        "awk"
        "grep"
        "file"
        "mktemp"
        "chmod"
        "bash"
        "timeout"
        "tr"
    )
    
    echo "Checking required commands..."
    for cmd in "${commands[@]}"; do
        echo -n "  $cmd... "
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${COLOR_RED}MISSING${COLOR_RESET}"
            missing+=("$cmd")
        else
            echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "\n${COLOR_RED}Missing required commands: ${missing[*]}${COLOR_RESET}"
        return 1
    fi
    
    return 0
}

# Main validation function
main() {
    local exit_code=0
    local validated=0
    local failed=0
    
    echo "=== Starting Script Validation ==="
    
    # Check dependencies first
    echo -e "\nChecking dependencies..."
    if ! check_dependencies; then
        echo -e "\n${COLOR_RED}Error: Missing required dependencies${COLOR_RESET}"
        exit 1
    fi
    
    # Process all shell scripts
    echo -e "\nValidating scripts..."
    while IFS= read -r -d '' script; do
        if ! validate_script "$script"; then
            ((failed++))
            exit_code=1
        fi
        ((validated++))
        
        # Test sourcing if script is meant to be sourced
        if [[ "$script" != "${BASH_SOURCE[0]}" ]] && grep -q "^source.*common.sh" "$script"; then
            echo -n "Testing source compatibility for $(basename "$script")... "
            if ! test_script_source "$script"; then
                echo -e "${COLOR_RED}FAILED${COLOR_RESET}"
                ((failed++))
                exit_code=1
            else
                echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
            fi
        fi
    done < <(find "$SCRIPT_DIR" -type f -name "*.sh" -print0)
    
    # Print summary
    echo -e "\n=== Validation Summary ==="
    echo "Scripts validated: $validated"
    if [[ $failed -eq 0 ]]; then
        echo -e "${COLOR_GREEN}All scripts passed validation${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}Failed validations: $failed${COLOR_RESET}"
    fi
    
    return $exit_code
}

# Run main function
main "$@"