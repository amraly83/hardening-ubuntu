#!/bin/bash
# Security log monitoring and analysis script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Configuration
LOG_DIR="/var/log"
REPORT_DIR="/var/log/security-reports"
ALERT_LOG="${REPORT_DIR}/security-alerts.log"
MAX_AUTH_FAILURES=5
SCAN_INTERVAL=3600  # 1 hour in seconds

monitor_security_logs() {
    mkdir -p "$REPORT_DIR"
    chmod 750 "$REPORT_DIR"

    while true; do
        check_auth_logs
        check_sudo_logs
        check_ssh_logs
        check_fail2ban_logs
        check_ufw_logs
        
        # Generate hourly report
        generate_security_report

        sleep "$SCAN_INTERVAL"
    done
}

check_auth_logs() {
    local auth_log="${LOG_DIR}/auth.log"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Check for authentication failures
    local auth_failures
    auth_failures=$(grep "authentication failure\|Failed password" "$auth_log" | wc -l)
    
    if [[ $auth_failures -gt $MAX_AUTH_FAILURES ]]; then
        log_alert "High number of authentication failures detected: $auth_failures"
    fi

    # Check for suspicious root access attempts
    if grep -q "authentication failure.*root" "$auth_log"; then
        log_alert "Suspicious root authentication attempts detected"
    fi

    # Check for unusual login times
    if [[ $(date +%H) -lt 6 || $(date +%H) -gt 22 ]]; then
        if grep -q "session opened" "$auth_log"; then
            log_alert "Login activity detected during unusual hours"
        fi
    fi
}

check_sudo_logs() {
    local sudo_log="${LOG_DIR}/sudo.log"
    
    # Check for unauthorized sudo attempts
    if grep -q "NOT in sudoers" "$sudo_log" 2>/dev/null; then
        log_alert "Unauthorized sudo access attempts detected"
    fi

    # Check for suspicious sudo commands
    local suspicious_commands=("chmod 777" "rm -rf /" "wget http" "curl http" "nc -l")
    for cmd in "${suspicious_commands[@]}"; do
        if grep -q "COMMAND=$cmd" "$sudo_log" 2>/dev/null; then
            log_alert "Suspicious sudo command detected: $cmd"
        fi
    done
}

check_ssh_logs() {
    local auth_log="${LOG_DIR}/auth.log"
    
    # Check for invalid users
    local invalid_users
    invalid_users=$(grep "Invalid user" "$auth_log" | awk '{print $8}' | sort | uniq -c | sort -nr)
    if [[ -n "$invalid_users" ]]; then
        log_alert "Invalid SSH login attempts detected:\n$invalid_users"
    fi

    # Check for successful logins from unexpected IPs
    local allowed_networks=("192.168." "10." "172.16.")
    while read -r line; do
        if [[ "$line" =~ Accepted\ .+\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            local ip="${BASH_REMATCH[1]}"
            local matched=false
            for network in "${allowed_networks[@]}"; do
                if [[ "$ip" == "$network"* ]]; then
                    matched=true
                    break
                fi
            done
            if ! $matched; then
                log_alert "SSH login from unexpected IP: $ip"
            fi
        fi
    done < <(grep "Accepted" "$auth_log")
}

check_fail2ban_logs() {
    local f2b_log="${LOG_DIR}/fail2ban.log"
    
    # Check for banned IPs
    local bans
    bans=$(grep "Ban " "$f2b_log" 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -nr)
    if [[ -n "$bans" ]]; then
        log_alert "Recent IP bans by fail2ban:\n$bans"
    fi

    # Check for repeated bans
    local repeat_offenders
    repeat_offenders=$(grep "Ban " "$f2b_log" 2>/dev/null | awk '{print $NF}' | sort | uniq -c | awk '$1 >= 3 {print}')
    if [[ -n "$repeat_offenders" ]]; then
        log_alert "Repeat offenders detected:\n$repeat_offenders"
    fi
}

check_ufw_logs() {
    local ufw_log="${LOG_DIR}/ufw.log"
    
    # Check for blocked connection attempts
    local blocks
    blocks=$(grep "UFW BLOCK" "$ufw_log" 2>/dev/null | awk '{print $12}' | sort | uniq -c | sort -nr | head -5)
    if [[ -n "$blocks" ]]; then
        log_alert "Top 5 blocked IPs by UFW:\n$blocks"
    fi

    # Check for port scans
    local port_scans
    port_scans=$(grep "UFW BLOCK" "$ufw_log" 2>/dev/null | awk '{print $12}' | sort | uniq -c | awk '$1 >= 10 {print}')
    if [[ -n "$port_scans" ]]; then
        log_alert "Possible port scan detected from:\n$port_scans"
    fi
}

log_alert() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] ALERT: $message" >> "$ALERT_LOG"
    log "WARNING" "$message"

    # Rotate log if too large
    if [[ $(stat -f%z "$ALERT_LOG") -gt 1048576 ]]; then  # 1MB
        mv "$ALERT_LOG" "${ALERT_LOG}.1"
        touch "$ALERT_LOG"
        chmod 600 "$ALERT_LOG"
    fi
}

generate_security_report() {
    local report_file="${REPORT_DIR}/security-report-$(date +%Y%m%d-%H).txt"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "=== Security Status Report ==="
        echo "Generated: $timestamp"
        echo
        echo "=== Authentication Summary ==="
        echo "Failed login attempts: $(grep "authentication failure\|Failed password" "${LOG_DIR}/auth.log" | wc -l)"
        echo "Successful logins: $(grep "session opened" "${LOG_DIR}/auth.log" | wc -l)"
        echo
        echo "=== SSH Activity ==="
        echo "Invalid users: $(grep "Invalid user" "${LOG_DIR}/auth.log" | wc -l)"
        echo "Root login attempts: $(grep "authentication failure.*root" "${LOG_DIR}/auth.log" | wc -l)"
        echo
        echo "=== Firewall Activity ==="
        echo "Blocked connections: $(grep "UFW BLOCK" "${LOG_DIR}/ufw.log" 2>/dev/null | wc -l)"
        echo
        echo "=== Fail2ban Status ==="
        if command -v fail2ban-client >/dev/null 2>&1; then
            fail2ban-client status
        else
            echo "fail2ban not installed"
        fi
        echo
        echo "=== System Status ==="
        echo "Load average: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Memory usage: $(free -h | grep Mem)"
        echo "Disk usage: $(df -h /)"
        echo
        echo "=== Recent Alerts ==="
        tail -n 10 "$ALERT_LOG" 2>/dev/null || echo "No recent alerts"
    } > "$report_file"

    chmod 600 "$report_file"
}

# Main execution
if [[ "${1:-}" == "--daemon" ]]; then
    monitor_security_logs
else
    # One-time check
    check_auth_logs
    check_sudo_logs
    check_ssh_logs
    check_fail2ban_logs
    check_ufw_logs
    generate_security_report
fi