#!/bin/bash
# Real-time security monitoring dashboard
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Configuration
REFRESH_INTERVAL=5
LOG_FILES=(
    "/var/log/auth.log"
    "/var/log/fail2ban.log"
    "/var/log/ufw.log"
    "/var/log/sudo.log"
)

show_dashboard() {
    local iteration=0
    
    while true; do
        clear
        print_header
        
        # Show real-time security status
        print_system_status
        print_service_status
        print_security_metrics
        print_recent_alerts
        print_active_connections
        
        # Update footer with last refresh time
        print_footer "$iteration"
        
        sleep "$REFRESH_INTERVAL"
        ((iteration++))
    done
}

print_header() {
    local datetime
    datetime=$(date '+%Y-%m-%d %H:%M:%S')
    echo "=== Security Monitoring Dashboard ==="
    echo "Server: $(hostname) | Time: $datetime"
    echo "----------------------------------------"
}

print_system_status() {
    echo "System Status:"
    echo "- Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "- Memory: $(free -h | grep Mem | awk '{print "Used: " $3 "/" $2}')"
    echo "- Disk: $(df -h / | tail -1 | awk '{print $5 " used"}')"
    echo "----------------------------------------"
}

print_service_status() {
    echo "Security Services:"
    services=("sshd" "fail2ban" "ufw" "security-monitor")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "✓ $service: Running"
        else
            echo "✗ $service: Stopped"
        fi
    done
    echo "----------------------------------------"
}

print_security_metrics() {
    echo "Security Metrics (Last Hour):"
    
    # Failed login attempts
    local failed_logins
    failed_logins=$(grep -c "Failed password" /var/log/auth.log)
    echo "- Failed Logins: $failed_logins"
    
    # Banned IPs
    local banned_ips
    banned_ips=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
    echo "- Banned IPs: ${banned_ips:-0}"
    
    # Firewall blocks
    local fw_blocks
    fw_blocks=$(grep -c "UFW BLOCK" /var/log/ufw.log 2>/dev/null || echo "0")
    echo "- Firewall Blocks: $fw_blocks"
    
    # Sudo usage
    local sudo_cmds
    sudo_cmds=$(grep -c "COMMAND=" /var/log/sudo.log 2>/dev/null || echo "0")
    echo "- Sudo Commands: $sudo_cmds"
    echo "----------------------------------------"
}

print_recent_alerts() {
    echo "Recent Security Alerts:"
    if [[ -f "/var/log/security-alerts.log" ]]; then
        tail -n 5 "/var/log/security-alerts.log" | while read -r line; do
            echo "! $line"
        done
    else
        echo "No recent alerts"
    fi
    echo "----------------------------------------"
}

print_active_connections() {
    echo "Active SSH Connections:"
    who | grep -i pts | while read -r line; do
        echo "- $line"
    done
    echo "----------------------------------------"
}

print_footer() {
    local iteration="$1"
    local uptime
    uptime=$(uptime -p)
    echo "Dashboard Refresh: $iteration | System Uptime: $uptime"
    echo "Press Ctrl+C to exit"
}

# Command-line options
case "${1:-}" in
    "--once")
        # Single run mode
        print_header
        print_system_status
        print_service_status
        print_security_metrics
        print_recent_alerts
        print_active_connections
        ;;
    "--csv")
        # Output metrics in CSV format
        echo "timestamp,failed_logins,banned_ips,fw_blocks,sudo_cmds"
        datetime=$(date '+%Y-%m-%d %H:%M:%S')
        failed_logins=$(grep -c "Failed password" /var/log/auth.log)
        banned_ips=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        fw_blocks=$(grep -c "UFW BLOCK" /var/log/ufw.log 2>/dev/null || echo "0")
        sudo_cmds=$(grep -c "COMMAND=" /var/log/sudo.log 2>/dev/null || echo "0")
        echo "$datetime,$failed_logins,${banned_ips:-0},$fw_blocks,$sudo_cmds"
        ;;
    "--help")
        echo "Usage: $0 [OPTION]"
        echo "Options:"
        echo "  --once    Run once and exit"
        echo "  --csv     Output metrics in CSV format"
        echo "  --help    Show this help message"
        ;;
    *)
        # Interactive dashboard mode
        show_dashboard
        ;;
esac