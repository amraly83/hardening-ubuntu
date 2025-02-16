#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

check_disk_space() {
    local required_mb=1024  # 1GB minimum
    local available=$(df -m /var | awk 'NR==2 {print $4}')
    
    if [[ $available -lt $required_mb ]]; then
        error_exit "Insufficient disk space. Required: ${required_mb}MB, Available: ${available}MB"
    fi
}

check_memory() {
    local required_mb=1024  # 1GB minimum
    local available=$(free -m | awk '/^Mem:/{print $2}')
    
    if [[ $available -lt $required_mb ]]; then
        log "WARNING" "Low memory detected. Recommended: ${required_mb}MB, Available: ${available}MB"
        if ! prompt_yes_no "Continue with low memory" "no"; then
            error_exit "Operation cancelled due to low memory"
        fi
    fi
}

check_running_services() {
    local critical_services=(
        "sshd"
        "systemd-journald"
    )
    
    for service in "${critical_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            error_exit "Critical service $service is not running"
        fi
    done
}

check_network() {
    # Check if we can reach important services
    local urls=(
        "security.ubuntu.com"
        "archive.ubuntu.com"
    )
    
    for url in "${urls[@]}"; do
        if ! ping -c 1 "$url" >/dev/null 2>&1; then
            log "WARNING" "Cannot reach $url. Package updates might fail"
        fi
    done
}

check_backup_space() {
    local backup_dir="/var/backups/server-hardening"
    local required_mb=512
    
    # Create backup directory if it doesn't exist
    mkdir -p "$backup_dir" || error_exit "Cannot create backup directory"
    
    local available=$(df -m "$backup_dir" | awk 'NR==2 {print $4}')
    if [[ $available -lt $required_mb ]]; then
        error_exit "Insufficient space for backups. Required: ${required_mb}MB, Available: ${available}MB"
    fi
}

check_open_sessions() {
    local session_count=$(who | wc -l)
    if [[ $session_count -gt 1 ]]; then
        log "WARNING" "Multiple sessions detected ($session_count). This might indicate other users are logged in"
        if ! prompt_yes_no "Continue with multiple sessions" "no"; then
            error_exit "Operation cancelled due to multiple sessions"
        fi
    fi
}

main() {
    log "INFO" "Running pre-flight checks..."
    
    # System checks
    check_disk_space
    check_memory
    check_running_services
    check_network
    check_backup_space
    check_open_sessions
    
    # Validate all scripts
    if ! "${SCRIPT_DIR}/validate.sh"; then
        error_exit "Script validation failed"
    fi
    
    log "INFO" "All pre-flight checks passed"
    echo "================================================================"
    echo "Pre-flight checks completed successfully"
    echo "The system is ready for hardening"
    echo "================================================================"
}

main "$@"