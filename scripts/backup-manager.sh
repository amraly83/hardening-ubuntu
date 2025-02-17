#!/bin/bash
# Comprehensive backup management system
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

BACKUP_ROOT="/var/backups/server-hardening"
BACKUP_LOG="/var/log/hardening-backup.log"
MANIFEST_FILE="backup-manifest.json"
RETENTION_DAYS=30

create_backup() {
    local backup_type="$1"
    local description="${2:-Automated backup}"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="${BACKUP_ROOT}/${timestamp}"
    local success=true
    
    log "INFO" "Creating $backup_type backup: $description"
    
    # Create backup directory structure
    mkdir -p "$backup_dir"/{config,users,services,system}
    
    case "$backup_type" in
        "full")
            backup_all_components "$backup_dir" || success=false
            ;;
        "config")
            backup_configuration "$backup_dir" || success=false
            ;;
        "users")
            backup_user_data "$backup_dir" || success=false
            ;;
        "services")
            backup_service_config "$backup_dir" || success=false
            ;;
        *)
            error_exit "Invalid backup type: $backup_type"
            ;;
    esac
    
    if [[ "$success" == "true" ]]; then
        # Create backup manifest
        create_backup_manifest "$backup_dir" "$backup_type" "$description" "$timestamp"
        
        # Cleanup old backups
        cleanup_old_backups
        
        log "SUCCESS" "Backup completed successfully: $backup_dir"
        return 0
    else
        log "ERROR" "Backup failed"
        rm -rf "$backup_dir"
        return 1
    fi
}

backup_all_components() {
    local backup_dir="$1"
    
    # System Configuration
    cp -p /etc/ssh/sshd_config "$backup_dir/config/"
    cp -p /etc/pam.d/sshd "$backup_dir/config/"
    cp -p /etc/fail2ban/jail.local "$backup_dir/config/"
    cp -p /etc/ufw/user.rules "$backup_dir/config/"
    
    # User Data
    tar -czf "$backup_dir/users/home_dirs.tar.gz" -C /home .
    cp -rp /etc/sudoers.d "$backup_dir/users/"
    
    # Service Configuration
    systemctl list-unit-files --state=enabled --no-pager > "$backup_dir/services/enabled_services.txt"
    
    # Security Settings
    sysctl -a > "$backup_dir/system/sysctl_settings.txt"
    
    # Our custom configurations
    cp -rp /etc/server-hardening "$backup_dir/config/"
    
    # Backup logs
    mkdir -p "$backup_dir/logs"
    cp -p /var/log/auth.log "$backup_dir/logs/"
    cp -p /var/log/fail2ban.log "$backup_dir/logs/"
    cp -p "$BACKUP_LOG" "$backup_dir/logs/"
    
    return 0
}

backup_configuration() {
    local backup_dir="$1"
    
    # Core configuration files
    for file in /etc/ssh/sshd_config \
                /etc/pam.d/sshd \
                /etc/fail2ban/jail.local \
                /etc/ufw/user.rules \
                /etc/server-hardening/*; do
        if [[ -f "$file" ]]; then
            cp -p "$file" "$backup_dir/config/"
        fi
    done
    
    return 0
}

backup_user_data() {
    local backup_dir="$1"
    
    # SSH keys and configurations
    find /home -maxdepth 2 -name ".ssh" -type d -exec cp -rp {} "$backup_dir/users/" \;
    
    # Sudo configurations
    cp -rp /etc/sudoers.d "$backup_dir/users/"
    
    # User specific configurations
    cp -p /etc/passwd "$backup_dir/users/"
    cp -p /etc/group "$backup_dir/users/"
    cp -p /etc/shadow "$backup_dir/users/"
    
    return 0
}

backup_service_config() {
    local backup_dir="$1"
    
    # Service states
    systemctl list-unit-files --state=enabled --no-pager > "$backup_dir/services/enabled_services.txt"
    
    # Service configurations
    for service in sshd fail2ban ufw security-monitor; do
        if systemctl is-active --quiet "$service"; then
            systemctl status "$service" > "$backup_dir/services/${service}_status.txt"
        fi
    done
    
    return 0
}

create_backup_manifest() {
    local backup_dir="$1"
    local backup_type="$2"
    local description="$3"
    local timestamp="$4"
    
    cat > "${backup_dir}/${MANIFEST_FILE}" << EOF
{
    "backup_id": "${timestamp}",
    "type": "${backup_type}",
    "description": "${description}",
    "created": "$(date --iso-8601=seconds)",
    "system": {
        "hostname": "$(hostname)",
        "os_version": "$(lsb_release -d 2>/dev/null | cut -f2)",
        "kernel": "$(uname -r)"
    },
    "components": {
        "files_backed_up": $(find "$backup_dir" -type f ! -name "$MANIFEST_FILE" | wc -l),
        "total_size_bytes": $(du -sb "$backup_dir" | cut -f1)
    }
}
EOF
}

restore_backup() {
    local backup_id="$1"
    local component="${2:-all}"
    local backup_dir="${BACKUP_ROOT}/${backup_id}"
    
    if [[ ! -d "$backup_dir" ]]; then
        error_exit "Backup not found: $backup_id"
    fi
    
    # Verify backup manifest
    if [[ ! -f "${backup_dir}/${MANIFEST_FILE}" ]]; then
        error_exit "Invalid backup: manifest file missing"
    fi
    
    log "INFO" "Restoring backup: $backup_id ($component)"
    
    # Create restore point before proceeding
    create_backup "full" "Pre-restore backup" || error_exit "Failed to create restore point"
    
    case "$component" in
        "all")
            restore_all_components "$backup_dir"
            ;;
        "config")
            restore_configuration "$backup_dir"
            ;;
        "users")
            restore_user_data "$backup_dir"
            ;;
        "services")
            restore_service_config "$backup_dir"
            ;;
        *)
            error_exit "Invalid restore component: $component"
            ;;
    esac
    
    log "SUCCESS" "Backup restored successfully"
}

restore_all_components() {
    local backup_dir="$1"
    
    # Restore configurations
    cp -p "$backup_dir"/config/* /etc/ssh/
    cp -p "$backup_dir"/config/sshd /etc/pam.d/
    cp -p "$backup_dir"/config/jail.local /etc/fail2ban/
    cp -p "$backup_dir"/config/user.rules /etc/ufw/
    
    # Restore user data
    tar -xzf "$backup_dir/users/home_dirs.tar.gz" -C /home
    cp -rp "$backup_dir"/users/sudoers.d/* /etc/sudoers.d/
    
    # Restart services
    systemctl restart sshd fail2ban ufw
}

cleanup_old_backups() {
    local cutoff_date
    cutoff_date=$(date -d "$RETENTION_DAYS days ago" +%s)
    
    find "$BACKUP_ROOT" -maxdepth 1 -type d -mtime +"$RETENTION_DAYS" | while read -r backup_dir; do
        if [[ -f "${backup_dir}/${MANIFEST_FILE}" ]]; then
            backup_date=$(jq -r '.created' "${backup_dir}/${MANIFEST_FILE}" | date -d - +%s)
            if [[ $backup_date -lt $cutoff_date ]]; then
                log "INFO" "Removing old backup: $(basename "$backup_dir")"
                rm -rf "$backup_dir"
            fi
        fi
    done
}

list_backups() {
    echo "Available Backups:"
    echo "ID                  Type     Description"
    echo "----------------------------------------"
    
    find "$BACKUP_ROOT" -maxdepth 1 -type d -name "202*" | sort -r | while read -r backup_dir; do
        if [[ -f "${backup_dir}/${MANIFEST_FILE}" ]]; then
            id=$(basename "$backup_dir")
            type=$(jq -r '.type' "${backup_dir}/${MANIFEST_FILE}")
            desc=$(jq -r '.description' "${backup_dir}/${MANIFEST_FILE}")
            printf "%-20s %-8s %s\n" "$id" "$type" "$desc"
        fi
    done
}

# Main execution
case "${1:-}" in
    "create")
        if [[ $# -lt 2 ]]; then
            echo "Usage: $0 create <full|config|users|services> [description]"
            exit 1
        fi
        create_backup "$2" "${3:-}"
        ;;
    "restore")
        if [[ $# -lt 2 ]]; then
            echo "Usage: $0 restore <backup_id> [component]"
            exit 1
        fi
        restore_backup "$2" "${3:-all}"
        ;;
    "list")
        list_backups
        ;;
    *)
        echo "Usage: $0 <create|restore|list> [options]"
        echo "Examples:"
        echo "  $0 create full \"Pre-update backup\""
        echo "  $0 restore 20240101_120000 config"
        echo "  $0 list"
        exit 1
        ;;
esac