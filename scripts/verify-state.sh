#!/bin/bash
# System state verification and readiness check
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Constants
readonly REQUIRED_SPACE_MB=1024
readonly MIN_MEMORY_MB=512
readonly MAX_LOAD=0.8
readonly REQUIRED_PACKAGES=(
    "openssh-server"
    "ufw"
    "fail2ban"
    "sudo"
    "libpam-google-authenticator"
)

# Track verification results
declare -A STATE_CHECKS

verify_resources() {
    log "INFO" "Verifying system resources..."
    local status=0

    # Check disk space
    local available_space
    available_space=$(df -m / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt $REQUIRED_SPACE_MB ]]; then
        log "ERROR" "Insufficient disk space: ${available_space}MB available, ${REQUIRED_SPACE_MB}MB required"
        status=1
    fi

    # Check memory
    local mem_available
    mem_available=$(free -m | awk '/^Mem:/ {print $7}')
    if [[ $mem_available -lt $MIN_MEMORY_MB ]]; then
        log "ERROR" "Insufficient memory: ${mem_available}MB available, ${MIN_MEMORY_MB}MB required"
        status=1
    fi

    # Check CPU load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    if [[ $(echo "$load_avg > $MAX_LOAD" | bc) -eq 1 ]]; then
        log "ERROR" "System load too high: $load_avg (max: $MAX_LOAD)"
        status=1
    fi

    STATE_CHECKS["resources"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_package_state() {
    log "INFO" "Verifying package state..."
    local status=0

    # Check package manager state
    if fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        log "ERROR" "Package manager is locked"
        status=1
    fi

    # Check required packages
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            log "ERROR" "Required package not installed: $pkg"
            status=1
        fi
    done

    # Verify no pending updates that could interfere
    if [[ -f /var/run/reboot-required ]]; then
        log "ERROR" "System reboot required before proceeding"
        status=1
    fi

    STATE_CHECKS["packages"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_process_state() {
    log "INFO" "Verifying process state..."
    local status=0

    # Check for active users
    local active_sessions
    active_sessions=$(who | grep -v "$(whoami)" | wc -l)
    if [[ $active_sessions -gt 0 ]]; then
        log "ERROR" "Found $active_sessions active user sessions"
        who | while read -r line; do
            log "INFO" "Active session: $line"
        done
        status=1
    fi

    # Check for crucial system processes
    local required_processes=("sshd" "systemd" "udevd")
    for proc in "${required_processes[@]}"; do
        if ! pgrep -x "$proc" >/dev/null; then
            log "ERROR" "Required process not running: $proc"
            status=1
        fi
    done

    STATE_CHECKS["processes"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_network_state() {
    log "INFO" "Verifying network state..."
    local status=0

    # Check network connectivity
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "ERROR" "No internet connectivity"
        status=1
    fi

    # Check DNS resolution
    if ! host -W 5 google.com >/dev/null 2>&1; then
        log "ERROR" "DNS resolution not working"
        status=1
    fi

    # Check if SSH port is available
    local ssh_port=22
    if [[ -f "/etc/server-hardening/hardening.conf" ]]; then
        # shellcheck source=/dev/null
        source "/etc/server-hardening/hardening.conf"
        ssh_port="${SSH_PORT:-22}"
    fi
    
    if netstat -ln | grep -q ":${ssh_port}[[:space:]]"; then
        if ! systemctl is-active --quiet sshd; then
            log "ERROR" "SSH port ${ssh_port} in use by another process"
            status=1
        fi
    fi

    STATE_CHECKS["network"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

verify_filesystem_state() {
    log "INFO" "Verifying filesystem state..."
    local status=0

    # Check filesystem mounts
    local required_mounts=("/" "/home")
    for mount in "${required_mounts[@]}"; do
        if ! mountpoint -q "$mount"; then
            log "ERROR" "Required mount point not mounted: $mount"
            status=1
        fi
    done

    # Check filesystem usage
    local max_usage=90
    df -h | awk 'NR>1 && $5 ~ /%/ {sub(/%/,"",$5); if ($5 > '"$max_usage"') print $6,$5"%"}' | \
    while read -r fs usage; do
        log "ERROR" "Filesystem usage too high on $fs: $usage"
        status=1
    done

    # Check inode usage
    df -i | awk 'NR>1 && $5 ~ /%/ {sub(/%/,"",$5); if ($5 > '"$max_usage"') print $6,$5"%"}' | \
    while read -r fs usage; do
        log "ERROR" "Inode usage too high on $fs: $usage"
        status=1
    done

    STATE_CHECKS["filesystem"]=$([[ $status -eq 0 ]] && echo "PASS" || echo "FAIL")
    return $status
}

generate_state_report() {
    local report_file="/var/log/system-state-report.txt"
    local total=0
    local passed=0

    {
        echo "=== System State Verification Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "System: $(uname -a)"
        echo

        echo "=== Resource Status ==="
        echo "Memory Available: $(free -h | awk '/^Mem:/ {print $7}')"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Disk Space: $(df -h / | awk 'NR==2 {print $4}') available"
        echo

        echo "=== Verification Results ==="
        for check in "${!STATE_CHECKS[@]}"; do
            echo "${check}: ${STATE_CHECKS[$check]}"
            ((total++))
            [[ "${STATE_CHECKS[$check]}" == "PASS" ]] && ((passed++))
        done
        echo

        echo "=== Summary ==="
        echo "Total Checks: $total"
        echo "Passed: $passed"
        echo "Failed: $((total - passed))"
        echo "Success Rate: $(( (passed * 100) / total ))%"
        echo

        if [[ $passed -lt $total ]]; then
            echo "=== Required Actions ==="
            [[ "${STATE_CHECKS[resources]:-FAIL}" == "FAIL" ]] && \
                echo "- Free up system resources (memory/disk space)"
            [[ "${STATE_CHECKS[packages]:-FAIL}" == "FAIL" ]] && \
                echo "- Install missing packages and resolve package manager issues"
            [[ "${STATE_CHECKS[processes]:-FAIL}" == "FAIL" ]] && \
                echo "- Terminate conflicting processes and user sessions"
            [[ "${STATE_CHECKS[network]:-FAIL}" == "FAIL" ]] && \
                echo "- Resolve network connectivity issues"
            [[ "${STATE_CHECKS[filesystem]:-FAIL}" == "FAIL" ]] && \
                echo "- Address filesystem space and mount issues"
        fi

    } > "$report_file"

    chmod 600 "$report_file"
    log "INFO" "State verification report generated: $report_file"
}

main() {
    local exit_status=0

    # Check root access
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi

    log "INFO" "Starting system state verification..."

    # Run all verifications
    verify_resources || exit_status=1
    verify_package_state || exit_status=1
    verify_process_state || exit_status=1
    verify_network_state || exit_status=1
    verify_filesystem_state || exit_status=1

    # Generate verification report
    generate_state_report

    if [[ $exit_status -eq 0 ]]; then
        log "SUCCESS" "System state verification passed"
    else
        log "ERROR" "System state verification failed"
    fi

    return $exit_status
}

# Run main function
main "$@"