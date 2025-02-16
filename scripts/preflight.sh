#!/bin/bash

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Initialize script
LOG_FILE="/var/log/server-hardening.log"
init_script

check_critical_services() {
    log "INFO" "Checking critical services..."
    
    # List of critical services that must be running
    local critical_services=(
        "ssh"       # SSH server
        "cron"      # Cron daemon
        "systemd"   # System and service manager
    )
    
    local failed=0
    for service in "${critical_services[@]}"; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            log "ERROR" "Critical service $service is not running"
            ((failed++))
        fi
    done
    
    if [[ "$failed" -gt 0 ]]; then
        error_exit "$failed critical services are not running"
    fi
}

check_system_resources() {
    log "INFO" "Checking system resources..."
    
    # Check CPU load
    local load=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F, '{ print $1 }')
    if [[ $(echo "$load > 5" | bc 2>/dev/null) -eq 1 ]]; then
        log "WARNING" "High system load detected: $load"
    fi
    
    # Check memory
    local mem_available=$(free -m | awk '/^Mem:/ {print $7}')
    if [[ "$mem_available" -lt 512 ]]; then
        error_exit "Insufficient memory available: ${mem_available}MB (minimum 512MB required)"
    fi
    
    # Check disk space
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    if [[ "$disk_free" -lt 1024 ]]; then
        error_exit "Insufficient disk space: ${disk_free}MB (minimum 1GB required)"
    fi
}

check_network() {
    log "INFO" "Checking network configuration..."
    
    # Check if network is up
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        error_exit "No network connectivity detected"
    fi
    
    # Check if DNS resolution works
    if ! host -W 5 ubuntu.com >/dev/null 2>&1; then
        error_exit "DNS resolution not working"
    fi
    
    # Check SSH port availability
    if ! netstat -tuln | grep -q ':22\s'; then
        error_exit "SSH port 22 is not available"
    fi
}

check_security_status() {
    log "INFO" "Checking security status..."
    
    # Check for pending security updates
    if [[ -x /usr/lib/update-notifier/apt-check ]]; then
        local updates=$(/usr/lib/update-notifier/apt-check 2>&1)
        local security_updates=$(echo "$updates" | cut -d';' -f2)
        if [[ "$security_updates" -gt 0 ]]; then
            log "WARNING" "$security_updates security updates pending"
        fi
    fi
    
    # Check if firewall is active
    if ! ufw status | grep -q "Status: active"; then
        log "WARNING" "Firewall is not enabled"
    fi
}

main() {
    log "INFO" "Starting server pre-flight checks..."
    
    # Run all checks
    check_critical_services
    check_system_resources
    check_network
    check_security_status
    
    log "SUCCESS" "All pre-flight checks passed"
    echo "================================================================"
    echo "Pre-flight checks completed successfully."
    echo "The server meets all minimum requirements for hardening."
    echo "================================================================"
}

main "$@"