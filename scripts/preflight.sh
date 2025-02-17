#!/bin/bash
# System readiness and preflight checks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Minimum system requirements
MIN_RAM_MB=1024
MIN_DISK_MB=1024
MIN_UBUNTU_VERSION="20.04"

run_preflight_checks() {
    local success=true
    
    log "INFO" "Running preflight checks..."
    
    # Check system resources
    check_system_resources || success=false
    
    # Check OS compatibility
    check_os_compatibility || success=false
    
    # Check network connectivity
    check_network_connectivity || success=false
    
    # Check file system permissions
    check_fs_permissions || success=false
    
    # Check existing services
    check_existing_services || success=false
    
    # Check backup space
    check_backup_space || success=false
    
    # Generate preflight report
    generate_preflight_report "$success"
    
    return $([ "$success" == "true" ])
}

check_system_resources() {
    local success=true
    
    # Check RAM
    local total_ram
    total_ram=$(free -m | awk '/^Mem:/ {print $2}')
    if [[ $total_ram -lt $MIN_RAM_MB ]]; then
        log "ERROR" "Insufficient RAM: ${total_ram}MB (minimum ${MIN_RAM_MB}MB required)"
        success=false
    fi
    
    # Check disk space
    local free_space
    free_space=$(df -m /var | awk 'NR==2 {print $4}')
    if [[ $free_space -lt $MIN_DISK_MB ]]; then
        log "ERROR" "Insufficient disk space: ${free_space}MB free (minimum ${MIN_DISK_MB}MB required)"
        success=false
    fi
    
    # Check CPU load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    if [[ $(echo "$load_avg > 0.8" | bc) -eq 1 ]]; then
        log "WARNING" "High system load detected: $load_avg"
    fi
    
    return $([ "$success" == "true" ])
}

check_os_compatibility() {
    # Check if running on Ubuntu
    if [[ ! -f /etc/lsb-release ]] || ! grep -q "Ubuntu" /etc/lsb-release; then
        log "ERROR" "System is not running Ubuntu"
        return 1
    fi
    
    # Check Ubuntu version
    local current_version
    current_version=$(lsb_release -rs)
    if [[ $(echo "$current_version < $MIN_UBUNTU_VERSION" | bc) -eq 1 ]]; then
        log "ERROR" "Unsupported Ubuntu version: $current_version (minimum $MIN_UBUNTU_VERSION required)"
        return 1
    fi
    
    return 0
}

check_network_connectivity() {
    local success=true
    
    # Check DNS resolution
    if ! host -t A ubuntu.com >/dev/null 2>&1; then
        log "ERROR" "DNS resolution failed"
        success=false
    fi
    
    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log "ERROR" "No internet connectivity"
        success=false
    fi
    
    # Check APT sources
    if ! apt-get update --print-uris >/dev/null 2>&1; then
        log "ERROR" "Unable to reach APT repositories"
        success=false
    fi
    
    return $([ "$success" == "true" ])
}

check_fs_permissions() {
    local success=true
    
    # Check critical directories
    local dirs=(
        "/etc/ssh:755"
        "/etc/pam.d:755"
        "/etc/sudoers.d:750"
        "/var/log:755"
    )
    
    for entry in "${dirs[@]}"; do
        local dir="${entry%:*}"
        local expected_perm="${entry#*:}"
        local current_perm
        
        if [[ -d "$dir" ]]; then
            current_perm=$(stat -c '%a' "$dir")
            if [[ "$current_perm" != "$expected_perm" ]]; then
                log "ERROR" "Invalid permissions on $dir: $current_perm (expected $expected_perm)"
                success=false
            fi
        else
            log "ERROR" "Required directory not found: $dir"
            success=false
        fi
    done
    
    return $([ "$success" == "true" ])
}

check_existing_services() {
    local success=true
    
    # Check for running services that might conflict
    local services=("sshd" "fail2ban" "ufw")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "INFO" "Service $service is running"
            # Backup existing configuration
            backup_service_config "$service"
        fi
    done
    
    # Check for existing user sessions
    local active_sessions
    active_sessions=$(who | wc -l)
    if [[ $active_sessions -gt 1 ]]; then
        log "WARNING" "Multiple user sessions detected: $active_sessions"
    fi
    
    return $([ "$success" == "true" ])
}

check_backup_space() {
    local backup_path="/var/backups/server-hardening"
    local required_space_mb=500
    
    # Create backup directory if it doesn't exist
    mkdir -p "$backup_path"
    
    # Check available space
    local available_space
    available_space=$(df -m "$backup_path" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt $required_space_mb ]]; then
        log "ERROR" "Insufficient backup space: ${available_space}MB (minimum ${required_space_mb}MB required)"
        return 1
    fi
    
    return 0
}

backup_service_config() {
    local service="$1"
    local backup_dir="/var/backups/server-hardening/services"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$backup_dir/$service"
    
    case "$service" in
        "sshd")
            cp -p /etc/ssh/sshd_config "$backup_dir/$service/sshd_config.$timestamp"
            ;;
        "fail2ban")
            cp -p /etc/fail2ban/jail.local "$backup_dir/$service/jail.local.$timestamp" 2>/dev/null || true
            ;;
        "ufw")
            cp -p /etc/ufw/user.rules "$backup_dir/$service/user.rules.$timestamp"
            ;;
    esac
}

generate_preflight_report() {
    local success="$1"
    local report_file="/var/log/hardening-preflight.report"
    
    {
        echo "=== System Preflight Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Status: $([ "$success" == "true" ] && echo "PASSED" || echo "FAILED")"
        echo
        echo "=== System Information ==="
        echo "Ubuntu Version: $(lsb_release -d | cut -f2)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo
        echo "=== Resource Status ==="
        echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}') total, $(free -h | grep '^Mem:' | awk '{print $7}') available"
        echo "Disk Space: $(df -h /var | awk 'NR==2 {print $4}') available"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo
        echo "=== Network Status ==="
        echo "DNS Resolution: $(host -t A ubuntu.com >/dev/null 2>&1 && echo "OK" || echo "FAILED")"
        echo "Internet Connectivity: $(ping -c 1 8.8.8.8 >/dev/null 2>&1 && echo "OK" || echo "FAILED")"
        echo "APT Sources: $(apt-get update --print-uris >/dev/null 2>&1 && echo "OK" || echo "FAILED")"
        echo
        echo "=== Service Status ==="
        systemctl list-units --type=service --state=running | grep -E 'sshd|fail2ban|ufw'
        echo
        echo "=== Active Sessions ==="
        who
        echo
        echo "=== Recommendations ==="
        if [[ "$success" != "true" ]]; then
            echo "- Review error messages in system logs"
            echo "- Ensure minimum system requirements are met"
            echo "- Verify network connectivity"
            echo "- Check service configurations"
        else
            echo "- Proceed with hardening installation"
            echo "- Monitor system resources during installation"
            echo "- Keep terminal session active"
            echo "- Follow installation progress"
        fi
    } > "$report_file"
    
    chmod 600 "$report_file"
    log "INFO" "Preflight report generated: $report_file"
}

# Main execution
run_preflight_checks