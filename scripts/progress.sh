#!/bin/bash

# Configuration tracking file
PROGRESS_FILE="/var/log/hardening-progress.json"

track_progress() {
    local step="$1"
    local status="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Create progress file if it doesn't exist
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        echo '{"steps":[]}' > "$PROGRESS_FILE"
        chmod 640 "$PROGRESS_FILE"
    fi
    
    # Add progress entry
    local temp_file
    temp_file=$(mktemp)
    jq --arg step "$step" \
       --arg status "$status" \
       --arg time "$timestamp" \
       '.steps += [{"step": $step, "status": $status, "timestamp": $time}]' \
       "$PROGRESS_FILE" > "$temp_file" && mv "$temp_file" "$PROGRESS_FILE"
}

show_progress() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        echo "Setup Progress:"
        jq -r '.steps[] | "[\(.timestamp)] \(.step): \(.status)"' "$PROGRESS_FILE"
    else
        echo "No progress recorded yet."
    fi
}

resume_from_last() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        local last_step
        last_step=$(jq -r '.steps[-1].step' "$PROGRESS_FILE")
        echo "Last completed step: $last_step"
        return 0
    fi
    return 1
}