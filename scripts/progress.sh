#!/bin/bash
# Progress tracking and state management system
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

PROGRESS_FILE="/var/lib/server-hardening/progress.json"
PROGRESS_LOG="/var/log/hardening-progress.log"

# Progress stages and their dependencies
declare -A STAGES=(
    ["preflight"]=""
    ["backup"]="preflight"
    ["user_setup"]="backup"
    ["ssh_config"]="user_setup"
    ["2fa_setup"]="ssh_config"
    ["firewall"]="preflight"
    ["system_hardening"]="firewall"
    ["monitoring"]="system_hardening"
    ["verification"]="monitoring"
)

# Initialize progress tracking
init_progress() {
    mkdir -p "$(dirname "$PROGRESS_FILE")"
    
    # Create initial progress state
    cat > "$PROGRESS_FILE" << EOF
{
    "start_time": "$(date --iso-8601=seconds)",
    "hostname": "$(hostname)",
    "stages": {
        "preflight": {"status": "pending", "timestamp": null},
        "backup": {"status": "pending", "timestamp": null},
        "user_setup": {"status": "pending", "timestamp": null},
        "ssh_config": {"status": "pending", "timestamp": null},
        "2fa_setup": {"status": "pending", "timestamp": null},
        "firewall": {"status": "pending", "timestamp": null},
        "system_hardening": {"status": "pending", "timestamp": null},
        "monitoring": {"status": "pending", "timestamp": null},
        "verification": {"status": "pending", "timestamp": null}
    },
    "current_stage": null,
    "completed": false,
    "error": null
}
EOF
    
    chmod 600 "$PROGRESS_FILE"
}

# Update stage status
update_stage() {
    local stage="$1"
    local status="$2"
    local timestamp
    timestamp=$(date --iso-8601=seconds)
    
    # Validate stage
    if [[ ! " ${!STAGES[@]} " =~ " $stage " ]]; then
        error_exit "Invalid stage: $stage"
    }
    
    # Check dependencies
    local deps="${STAGES[$stage]}"
    if [[ -n "$deps" ]]; then
        for dep in $deps; do
            if ! check_stage_complete "$dep"; then
                error_exit "Dependency not met: $stage requires $dep"
            }
        done
    fi
    
    # Update progress file
    local temp_file
    temp_file=$(mktemp)
    jq --arg stage "$stage" \
       --arg status "$status" \
       --arg time "$timestamp" \
       '.stages[$stage].status = $status |
        .stages[$stage].timestamp = $time |
        if $status == "in_progress" then .current_stage = $stage else . end' \
        "$PROGRESS_FILE" > "$temp_file"
    mv "$temp_file" "$PROGRESS_FILE"
    
    # Log progress
    log_progress "$stage" "$status"
}

# Check if stage is complete
check_stage_complete() {
    local stage="$1"
    local status
    
    status=$(jq -r --arg stage "$stage" '.stages[$stage].status' "$PROGRESS_FILE")
    [[ "$status" == "complete" ]]
}

# Log progress update
log_progress() {
    local stage="$1"
    local status="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] Stage '$stage' - $status" >> "$PROGRESS_LOG"
}

# Display progress summary
show_progress() {
    local total_stages=${#STAGES[@]}
    local completed_stages=0
    local current_stage
    
    echo "=== Hardening Progress ==="
    
    for stage in "${!STAGES[@]}"; do
        local status
        status=$(jq -r --arg stage "$stage" '.stages[$stage].status' "$PROGRESS_FILE")
        local timestamp
        timestamp=$(jq -r --arg stage "$stage" '.stages[$stage].timestamp // "N/A"' "$PROGRESS_FILE")
        
        case "$status" in
            "complete")
                echo "[✓] $stage"
                ((completed_stages++))
                ;;
            "in_progress")
                echo "[*] $stage (Current)"
                current_stage="$stage"
                ;;
            "failed")
                echo "[✗] $stage"
                ;;
            *)
                echo "[ ] $stage"
                ;;
        esac
        
        if [[ "$timestamp" != "N/A" ]]; then
            echo "    Last update: $timestamp"
        fi
    done
    
    # Show progress percentage
    local progress=$((completed_stages * 100 / total_stages))
    echo
    echo "Overall Progress: $progress% ($completed_stages/$total_stages stages complete)"
    
    if [[ -n "${current_stage:-}" ]]; then
        echo "Current Stage: $current_stage"
    fi
}

# Check if all stages are complete
is_hardening_complete() {
    local completed
    completed=$(jq -r '.completed' "$PROGRESS_FILE")
    [[ "$completed" == "true" ]]
}

# Save error state
save_error() {
    local error_msg="$1"
    local stage="${2:-}"
    local timestamp
    timestamp=$(date --iso-8601=seconds)
    
    local temp_file
    temp_file=$(mktemp)
    
    jq --arg error "$error_msg" \
       --arg time "$timestamp" \
       --arg stage "$stage" \
       '. * {
           "error": {
               "message": $error,
               "timestamp": $time,
               "stage": $stage
           }
       }' "$PROGRESS_FILE" > "$temp_file"
    mv "$temp_file" "$PROGRESS_FILE"
    
    log "ERROR" "Error in stage $stage: $error_msg"
}

# Reset progress tracking
reset_progress() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        local backup_file="${PROGRESS_FILE}.$(date +%Y%m%d_%H%M%S).bak"
        mv "$PROGRESS_FILE" "$backup_file"
        log "INFO" "Previous progress backed up to: $backup_file"
    fi
    
    init_progress
    log "INFO" "Progress tracking reset"
}

# Export stage completion status
export_progress() {
    local export_file="${1:-/var/lib/server-hardening/progress-export.json}"
    
    jq '{
        summary: {
            start_time: .start_time,
            completed_stages: [.stages | to_entries[] | select(.value.status == "complete") | .key],
            current_stage: .current_stage,
            total_progress: (.stages | to_entries | map(select(.value.status == "complete")) | length) * 100 / (.stages | length)
        },
        stages: .stages,
        error: .error
    }' "$PROGRESS_FILE" > "$export_file"
    
    chmod 644 "$export_file"
}

# Main execution
case "${1:-}" in
    "init")
        init_progress
        ;;
    "update")
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 update <stage> <status>"
            exit 1
        fi
        update_stage "$2" "$3"
        ;;
    "show")
        show_progress
        ;;
    "reset")
        reset_progress
        ;;
    "export")
        export_progress "${2:-}"
        ;;
    *)
        echo "Usage: $0 <init|update|show|reset|export> [args...]"
        echo "Examples:"
        echo "  $0 init                    # Initialize progress tracking"
        echo "  $0 update preflight complete  # Update stage status"
        echo "  $0 show                    # Show current progress"
        echo "  $0 reset                   # Reset progress tracking"
        echo "  $0 export output.json      # Export progress data"
        exit 1
        ;;
esac