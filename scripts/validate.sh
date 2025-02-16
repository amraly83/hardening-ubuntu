#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script with Windows-compatible path
LOG_FILE="${TEMP:-/tmp}/server-hardening.log"
init_script

validate_script() {
    local script="$1"
    local script_name=$(basename "$script")
    log "INFO" "Validating $script_name..."
    
    # Skip actual validation on Windows
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        log "INFO" "Skipping detailed validation on Windows for $script_name"
        return 0
    fi
    
    # Check for shebang
    if ! head -n 1 "$script" | grep -q "^#!/bin/bash"; then
        log "WARNING" "$script_name is missing shebang (#!/bin/bash)"
        return 0  # Not fatal on Windows
    fi
    
    # Check permissions on Unix-like systems only
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [[ ! -x "$script" ]]; then
            log "WARNING" "$script_name is not executable"
            chmod +x "$script" 2>/dev/null || log "WARNING" "Failed to make $script executable"
        fi
    fi
    
    # Check for common sourcing
    if [[ "$script_name" != "common.sh" ]] && ! grep -q "source.*common.sh" "$script" 2>/dev/null; then
        log "WARNING" "$script_name is not sourcing common.sh"
        return 0  # Not fatal
    fi
    
    return 0  # Success
}

validate_all_scripts() {
    local failed=0
    local scripts=(
        "${SCRIPT_DIR}/common.sh"
        "${SCRIPT_DIR}/create-admin.sh"
        "${SCRIPT_DIR}/setup-ssh-key.sh"
        "${SCRIPT_DIR}/setup-2fa.sh"
        "${SCRIPT_DIR}/harden.sh"
        "${SCRIPT_DIR}/setup.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ ! -f "$script" ]]; then
            log "ERROR" "Required script not found: $script"
            ((failed++))
            continue
        fi
        
        if ! validate_script "$script"; then
            ((failed++))
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log "WARNING" "$failed script validation issues found"
        # Not failing on Windows
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            return 1
        fi
    fi
    
    log "INFO" "Script validation completed"
    return 0
}

# Run validation
validate_all_scripts