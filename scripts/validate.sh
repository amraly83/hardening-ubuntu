#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

validate_script() {
    local script="$1"
    local script_name=$(basename "$script")
    log "INFO" "Validating $script_name..."
    
    # Check for shebang
    if ! head -n 1 "$script" | grep -q "^#!/bin/bash"; then
        log "ERROR" "$script_name is missing shebang (#!/bin/bash)"
        return 1
    fi
    
    # Check permissions
    if [[ ! -x "$script" ]]; then
        log "WARNING" "$script_name is not executable"
        chmod +x "$script" || {
            log "ERROR" "Failed to make $script_name executable"
            return 1
        }
    fi
    
    # Check for common sourcing
    if [[ "$script_name" != "common.sh" ]] && ! grep -q "source.*common.sh" "$script"; then
        log "ERROR" "$script_name is not sourcing common.sh"
        return 1
    fi
    
    # Basic syntax check
    if ! bash -n "$script"; then
        log "ERROR" "$script_name has syntax errors"
        return 1
    fi
    
    # Check for common security practices
    if grep -q "eval.*\$" "$script"; then
        log "WARNING" "$script_name contains potentially unsafe eval usage"
    fi
    
    if grep -q "sudo.*-E" "$script"; then
        log "WARNING" "$script_name uses sudo with -E flag which might be unsafe"
    fi
    
    return 0
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
        log "ERROR" "$failed script(s) failed validation"
        return 1
    fi
    
    log "INFO" "All scripts passed validation"
    return 0
}

# Run validation
if ! validate_all_scripts; then
    error_exit "Script validation failed"
fi