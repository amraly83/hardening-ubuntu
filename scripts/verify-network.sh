#!/bin/bash
# Network security validation script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

verify_network_security() {
    local success=true

    # Check kernel network parameters
    echo "Checking kernel network security parameters..."
    check_sysctl_params || success=false

    # Check open ports
    echo "Checking open ports..."
    check_open_ports || success=false

    # Verify firewall rules
    echo "Verifying firewall configuration..."
    check_firewall_rules || success=false

    # Check network services
    echo "Checking network services..."
    check_network_services || success=false

    # Verify fail2ban
    echo "Verifying fail2ban configuration..."
    check_fail2ban || success=false

    if [[ "$success" == "true" ]]; then
        log "SUCCESS" "Network security verification passed"
        return 0
    else
        log "ERROR" "Network security verification failed"
        return 1
    fi
}

check_sysctl_params() {
    local params=(
        "net.ipv4.conf.all.accept_redirects:0"
        "net.ipv4.conf.all.secure_redirects:0"
        "net.ipv4.conf.all.accept_source_route:0"
        "net.ipv4.conf.all.log_martians:1"
        "net.ipv4.icmp_echo_ignore_broadcasts:1"
        "net.ipv4.tcp_syncookies:1"
        "net.ipv4.conf.all.rp_filter:1"
        "net.ipv6.conf.all.disable_ipv6:1"
    )

    local failed=false
    for param in "${params[@]}"; do
        local key="${param%:*}"
        local expected="${param#*:}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "NOT_SET")
        
        if [[ "$actual" != "$expected" ]]; then
            log "ERROR" "Kernel parameter $key is set to $actual (expected $expected)"
            failed=true
        fi
    done

    ! "$failed"
}

check_open_ports() {
    local allowed_ports=(22 3333 80 443)  # Default allowed ports
    local config_file="/etc/server-hardening/hardening.conf"
    
    # Load custom ports from config if available
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        IFS=',' read -ra custom_ports <<< "${FIREWALL_ADDITIONAL_PORTS:-}"
        allowed_ports+=("${custom_ports[@]}")
    fi

    # Check for unexpected open ports
    local open_ports
    open_ports=$(netstat -tuln | grep 'LISTEN' | awk '{print $4}' | awk -F: '{print $NF}')
    
    local failed=false
    for port in $open_ports; do
        if [[ ! " ${allowed_ports[@]} " =~ " ${port} " ]]; then
            log "ERROR" "Unexpected open port: $port"
            failed=true
        fi
    done

    ! "$failed"
}

check_firewall_rules() {
    # Verify UFW is active
    if ! ufw status | grep -q "Status: active"; then
        log "ERROR" "UFW firewall is not active"
        return 1
    fi

    # Verify default policies
    local policies
    policies=$(ufw status verbose | grep "Default")
    if ! echo "$policies" | grep -q "deny (incoming)"; then
        log "ERROR" "UFW default incoming policy is not deny"
        return 1
    fi

    # Verify required rules exist
    local config_file="/etc/server-hardening/hardening.conf"
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        local ssh_port="${SSH_PORT:-3333}"
        if ! ufw status | grep -q "$ssh_port/tcp"; then
            log "ERROR" "SSH port $ssh_port not found in firewall rules"
            return 1
        fi
    fi

    return 0
}

check_network_services() {
    local dangerous_services=(
        "telnet"
        "rsh"
        "rlogin"
        "rexec"
        "finger"
        "ypserv"
        "tftp"
        "talk"
        "ntalk"
    )

    local failed=false
    for service in "${dangerous_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "ERROR" "Dangerous service $service is running"
            failed=true
        fi
    done

    ! "$failed"
}

check_fail2ban() {
    # Verify fail2ban is running
    if ! systemctl is-active --quiet fail2ban; then
        log "ERROR" "fail2ban service is not running"
        return 1
    fi

    # Check jail configuration
    local jail_conf="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_conf" ]]; then
        log "ERROR" "fail2ban jail configuration not found"
        return 1
    fi

    # Verify SSH jail is enabled
    if ! fail2ban-client status sshd >/dev/null 2>&1; then
        log "ERROR" "SSH jail not configured in fail2ban"
        return 1
    fi

    return 0
}

# Main execution
verify_network_security