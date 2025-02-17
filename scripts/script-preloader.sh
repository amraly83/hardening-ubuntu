#!/bin/bash
# Script preloader and validator
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
PRELOAD_LOG="/var/log/script-preloader.log"

# Source common functions if available
if [[ -f "${SCRIPT_DIR}/common.sh" ]]; then
    source "${SCRIPT_DIR}/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

preload_scripts() {
    local success=true
    
    # Create log directory
    mkdir -p "$(dirname "$PRELOAD_LOG")"
    
    log "INFO" "Starting script preloader..."
    
    # Verify script permissions
    check_script_permissions || success=false
    
    # Validate script dependencies
    validate_dependencies || success=false
    
    # Check script syntax
    check_script_syntax || success=false
    
    # Verify required files exist
    verify_required_files || success=false
    
    # Initialize configuration if needed
    initialize_configuration || success=false
    
    if [[ "$success" == "true" ]]; then
        log "SUCCESS" "Script preloader completed successfully"
        return 0
    else
        log "ERROR" "Script preloader encountered errors"
        return 1
    fi
}

check_script_permissions() {
    local failed=false
    
    log "INFO" "Checking script permissions..."
    
    # Find all shell scripts
    while IFS= read -r -d '' script; do
        # Check if script is executable
        if [[ ! -x "$script" ]]; then
            log "WARNING" "Making script executable: $script"
            chmod +x "$script" || {
                log "ERROR" "Failed to set executable permission on $script"
                failed=true
            }
        fi
        
        # Check ownership
        if [[ -n "${SUDO_USER:-}" ]]; then
            chown "$SUDO_USER:$SUDO_USER" "$script" || {
                log "ERROR" "Failed to set ownership on $script"
                failed=true
            }
        fi
    done < <(find "$SCRIPT_DIR" -type f -name "*.sh" -print0)
    
    return $([ "$failed" == "false" ])
}

validate_dependencies() {
    local failed=false
    
    log "INFO" "Validating script dependencies..."
    
    # Check for required commands
    local required_commands=(
        "ssh"
        "ufw"
        "fail2ban-client"
        "google-authenticator"
        "jq"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "ERROR" "Required command not found: $cmd"
            failed=true
        fi
    done
    
    # Check for required directories
    local required_dirs=(
        "/etc/ssh"
        "/etc/pam.d"
        "/etc/fail2ban"
        "/etc/ufw"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log "ERROR" "Required directory not found: $dir"
            failed=true
        fi
    done
    
    return $([ "$failed" == "false" ])
}

check_script_syntax() {
    local failed=false
    
    log "INFO" "Checking script syntax..."
    
    # Check all shell scripts for syntax errors
    while IFS= read -r -d '' script; do
        if ! bash -n "$script" 2>/dev/null; then
            log "ERROR" "Syntax error in script: $script"
            failed=true
        fi
    done < <(find "$SCRIPT_DIR" -type f -name "*.sh" -print0)
    
    return $([ "$failed" == "false" ])
}

verify_required_files() {
    local failed=false
    
    log "INFO" "Verifying required files..."
    
    # Required configuration templates
    local required_files=(
        "${PARENT_DIR}/docs/REQUIREMENTS.md"
        "${PARENT_DIR}/examples/config/hardening.conf.example"
        "${SCRIPT_DIR}/common.sh"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log "ERROR" "Required file not found: $file"
            failed=true
        fi
    done
    
    return $([ "$failed" == "false" ])
}

initialize_configuration() {
    log "INFO" "Initializing configuration..."
    
    # Create configuration directory
    mkdir -p "/etc/server-hardening"
    
    # Copy example configuration if none exists
    if [[ ! -f "/etc/server-hardening/hardening.conf" ]]; then
        cp "${PARENT_DIR}/examples/config/hardening.conf.example" "/etc/server-hardening/hardening.conf" || {
            log "ERROR" "Failed to initialize configuration"
            return 1
        }
    fi
    
    # Set proper permissions
    chmod 600 "/etc/server-hardening/hardening.conf"
    
    return 0
}

generate_preload_report() {
    local report_file="/var/log/hardening-preload-report.txt"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    {
        echo "=== Script Preloader Report ==="
        echo "Generated: $timestamp"
        echo
        echo "=== Script Status ==="
        find "$SCRIPT_DIR" -type f -name "*.sh" -exec bash -n {} \; -exec echo "✓ {}" \; 2>&1
        echo
        echo "=== Dependencies ==="
        for cmd in ssh ufw fail2ban-client google-authenticator jq; do
            if command -v "$cmd" >/dev/null 2>&1; then
                echo "✓ $cmd: $(command -v "$cmd")"
            else
                echo "✗ $cmd: Not found"
            fi
        done
        echo
        echo "=== Configuration ==="
        if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
            echo "✓ Configuration file exists"
            stat "/etc/server-hardening/hardening.conf"
        else
            echo "✗ Configuration file missing"
        fi
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Preload report generated: $report_file"
}

# Main execution
preload_scripts
generate_preload_report