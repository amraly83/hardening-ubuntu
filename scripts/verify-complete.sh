#!/bin/bash
# Final system verification script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

verify_complete_system() {
    local username="$1"
    local success=true
    local report_file="/var/log/hardening-final-verification.log"
    
    # Start verification process
    {
        echo "=== Final System Verification Report ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Server: $(hostname)"
        echo "Ubuntu Version: $(lsb_release -d 2>/dev/null | cut -f2)"
        echo

        # Verify all components sequentially
        components=(
            "verify-system.sh:System Security"
            "verify-network.sh:Network Security"
            "verify-admin-setup.sh:Admin Configuration"
            "verify-sudo.sh:Sudo Access"
            "verify-2fa.sh:2FA Setup"
            "verify-deployment.sh:Deployment Status"
        )

        for component in "${components[@]}"; do
            script="${component%%:*}"
            desc="${component#*:}"
            
            echo "=== Verifying $desc ==="
            if [[ -x "${SCRIPT_DIR}/$script" ]]; then
                if "${SCRIPT_DIR}/$script" "$username"; then
                    echo "✓ $desc: PASSED"
                else
                    echo "✗ $desc: FAILED"
                    success=false
                fi
            else
                echo "! $desc: SKIPPED (Script not found)"
                success=false
            fi
            echo
        done

        # Additional security checks
        echo "=== Additional Security Checks ==="
        
        # Check critical file permissions
        echo "Checking critical file permissions..."
        files_to_check=(
            "/etc/shadow:0:0:400"
            "/etc/ssh/sshd_config:0:0:600"
            "/etc/sudoers:0:0:440"
        )
        
        for entry in "${files_to_check[@]}"; do
            IFS=: read -r file owner group perm <<< "$entry"
            if ! check_file_permission "$file" "$owner" "$group" "$perm"; then
                echo "✗ Invalid permissions on $file"
                success=false
            else
                echo "✓ Correct permissions on $file"
            fi
        done
        
        # Check running services
        echo -e "\nChecking security services..."
        services=("sshd" "fail2ban" "ufw" "security-monitor")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                echo "✓ $service is running"
            else
                echo "✗ $service is not running"
                success=false
            fi
        done
        
        # Check monitoring setup
        echo -e "\nVerifying monitoring configuration..."
        if [[ -f "/var/log/security-alerts.log" ]] && \
           [[ -f "/etc/systemd/system/security-monitor.service" ]] && \
           systemctl is-enabled --quiet security-monitor.service; then
            echo "✓ Security monitoring is properly configured"
        else
            echo "✗ Security monitoring configuration incomplete"
            success=false
        fi
        
        # Final status
        echo -e "\n=== Final Status ==="
        if [[ "$success" == "true" ]]; then
            echo "✓ All security components verified successfully"
        else
            echo "✗ Some security components failed verification"
            echo "  Please check the detailed logs above"
        fi
        
    } | tee "$report_file"
    
    chmod 600 "$report_file"
    
    return $([ "$success" == "true" ])
}

check_file_permission() {
    local file="$1"
    local owner="$2"
    local group="$3"
    local perm="$4"
    
    [[ -f "$file" ]] && \
    [[ "$(stat -c '%u' "$file")" == "$owner" ]] && \
    [[ "$(stat -c '%g' "$file")" == "$group" ]] && \
    [[ "$(stat -c '%a' "$file")" == "$perm" ]]
}

# Main execution
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 username"
    exit 1
fi

verify_complete_system "$1"