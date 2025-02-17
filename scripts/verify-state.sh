#!/bin/bash
# Create a script to handle user sessions and system state verification
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Check active sessions and processes
check_active_sessions() {
    local max_allowed_sessions=1
    local active_sessions
    
    # Get number of active sessions excluding the current one
    active_sessions=$(who | grep -v "$(whoami)" | wc -l)
    
    if [[ $active_sessions -gt 0 ]]; then
        log "WARNING" "Found $active_sessions additional active user sessions"
        echo "Active sessions:"
        who
        
        if ! prompt_yes_no "Continue with active sessions present?" "no"; then
            log "ERROR" "Installation aborted due to active sessions"
            exit 1
        fi
    else
        log "INFO" "No additional active sessions found"
    fi
}

# Verify system state
verify_system_state() {
    local proceed=true
    
    # Check system load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    if [[ $(echo "$load_avg > 0.8" | bc) -eq 1 ]]; then
        log "WARNING" "High system load detected: $load_avg"
        if ! prompt_yes_no "Continue with high system load?" "no"; then
            proceed=false
        fi
    fi
    
    # Check available resources
    local mem_avail
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    if [[ $mem_avail -lt 512 ]]; then
        log "WARNING" "Low available memory: ${mem_avail}MB"
        if ! prompt_yes_no "Continue with low memory?" "no"; then
            proceed=false
        fi
    fi
    
    if [[ "$proceed" != "true" ]]; then
        log "ERROR" "System state verification failed"
        exit 1
    fi
}

# Main execution
check_active_sessions
verify_system_state