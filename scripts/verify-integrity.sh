#!/bin/bash
# Script integrity verification system
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

CHECKSUM_FILE="/etc/server-hardening/script-checksums.sha256"
VERIFY_LOG="/var/log/script-integrity.log"

verify_script_integrity() {
    local mode="${1:-verify}"
    local success=true
    
    case "$mode" in
        "init")
            initialize_checksums
            ;;
        "verify")
            verify_checksums
            ;;
        "update")
            update_checksums
            ;;
        *)
            error_exit "Invalid mode: $mode"
            ;;
    esac
}

initialize_checksums() {
    log "INFO" "Initializing script checksums..."
    
    # Create checksums directory if it doesn't exist
    mkdir -p "$(dirname "$CHECKSUM_FILE")"
    
    # Generate checksums for all scripts
    {
        echo "# Script integrity checksums"
        echo "# Generated: $(date --iso-8601=seconds)"
        echo "# System: $(hostname)"
        echo
        
        find "$SCRIPT_DIR" -type f -name "*.sh" -print0 | while IFS= read -r -d '' script; do
            # Calculate checksum
            sha256sum "$script"
        done
    } > "$CHECKSUM_FILE"
    
    # Secure the checksum file
    chmod 400 "$CHECKSUM_FILE"
    
    log "SUCCESS" "Checksums initialized successfully"
}

verify_checksums() {
    local fail_count=0
    
    if [[ ! -f "$CHECKSUM_FILE" ]]; then
        error_exit "Checksum file not found. Run with 'init' first"
    }
    
    log "INFO" "Verifying script integrity..."
    
    # Verify each script
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        
        # Extract checksum and filename
        read -r expected_sum filename <<< "$line"
        
        if [[ -f "$filename" ]]; then
            # Calculate current checksum
            current_sum=$(sha256sum "$filename" | awk '{print $1}')
            
            if [[ "$current_sum" != "$expected_sum" ]]; then
                log "ERROR" "Integrity check failed for: $filename"
                log "ERROR" "Expected: $expected_sum"
                log "ERROR" "Got:      $current_sum"
                ((fail_count++))
                
                # Log the failure details
                log_integrity_failure "$filename" "$expected_sum" "$current_sum"
            fi
        else
            log "ERROR" "Script not found: $filename"
            ((fail_count++))
        fi
    done < "$CHECKSUM_FILE"
    
    if [[ $fail_count -eq 0 ]]; then
        log "SUCCESS" "All script integrity checks passed"
        return 0
    else
        log "ERROR" "$fail_count script(s) failed integrity check"
        return 1
    fi
}

update_checksums() {
    local backup_suffix=".$(date +%Y%m%d_%H%M%S).bak"
    
    # Backup existing checksums
    if [[ -f "$CHECKSUM_FILE" ]]; then
        cp -p "$CHECKSUM_FILE" "${CHECKSUM_FILE}${backup_suffix}"
    fi
    
    # Generate new checksums
    initialize_checksums
    
    # Verify the new checksums
    if ! verify_checksums; then
        log "ERROR" "Verification of new checksums failed"
        if [[ -f "${CHECKSUM_FILE}${backup_suffix}" ]]; then
            mv "${CHECKSUM_FILE}${backup_suffix}" "$CHECKSUM_FILE"
            log "INFO" "Restored previous checksums"
        fi
        return 1
    fi
    
    log "SUCCESS" "Checksums updated successfully"
    return 0
}

log_integrity_failure() {
    local script="$1"
    local expected="$2"
    local actual="$3"
    local timestamp
    timestamp=$(date --iso-8601=seconds)
    
    {
        echo "=== Integrity Failure Report ==="
        echo "Timestamp: $timestamp"
        echo "Script: $script"
        echo "Expected checksum: $expected"
        echo "Actual checksum: $actual"
        echo
        echo "File permissions: $(stat -c '%A (%a)' "$script")"
        echo "Owner/Group: $(stat -c '%U:%G' "$script")"
        echo "Last modified: $(stat -c '%y' "$script")"
        echo
        echo "Recent modifications:"
        find "$SCRIPT_DIR" -type f -mtime -7 -ls
        echo
        echo "=== End Report ==="
        echo
    } >> "$VERIFY_LOG"
}

verify_single_script() {
    local script="$1"
    
    if [[ ! -f "$script" ]]; then
        error_exit "Script not found: $script"
    }
    
    if [[ ! -f "$CHECKSUM_FILE" ]]; then
        error_exit "Checksum file not found. Run with 'init' first"
    }
    
    log "INFO" "Verifying single script: $script"
    
    # Get expected checksum
    local expected_sum
    expected_sum=$(grep "$script" "$CHECKSUM_FILE" | awk '{print $1}')
    
    if [[ -z "$expected_sum" ]]; then
        error_exit "No checksum found for script: $script"
    fi
    
    # Calculate current checksum
    local current_sum
    current_sum=$(sha256sum "$script" | awk '{print $1}')
    
    if [[ "$current_sum" == "$expected_sum" ]]; then
        log "SUCCESS" "Script integrity verified: $script"
        return 0
    else
        log "ERROR" "Script integrity check failed: $script"
        log_integrity_failure "$script" "$expected_sum" "$current_sum"
        return 1
    fi
}

# Main execution
case "${1:-}" in
    "init")
        verify_script_integrity "init"
        ;;
    "verify")
        if [[ $# -gt 1 ]]; then
            verify_single_script "$2"
        else
            verify_script_integrity "verify"
        fi
        ;;
    "update")
        verify_script_integrity "update"
        ;;
    *)
        echo "Usage: $0 <init|verify|update> [script_path]"
        echo "Examples:"
        echo "  $0 init              # Initialize checksums"
        echo "  $0 verify            # Verify all scripts"
        echo "  $0 verify script.sh  # Verify single script"
        echo "  $0 update            # Update checksums"
        exit 1
        ;;
esac