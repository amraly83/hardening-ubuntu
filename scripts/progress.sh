#!/bin/bash

# Configuration tracking file
PROGRESS_FILE="/var/log/hardening-progress.json"

# Function to check if jq is available
has_jq() {
    command -v jq >/dev/null 2>&1
}

# Fallback function for when jq is not available
update_progress_fallback() {
    local step="$1"
    local status="$2"
    local timestamp="$3"
    local temp_file
    temp_file=$(mktemp)
    
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        echo "{\"steps\":[]}" > "$PROGRESS_FILE"
        chmod 640 "$PROGRESS_FILE"
    fi
    
    # Simple text-based approach when jq is not available
    cp "$PROGRESS_FILE" "$temp_file"
    sed -i 's/}]}$//' "$temp_file"
    if grep -q '"steps":\[\]' "$temp_file"; then
        echo "{\"step\":\"$step\",\"status\":\"$status\",\"timestamp\":\"$timestamp\"}" >> "$temp_file"
    else
        echo ",{\"step\":\"$step\",\"status\":\"$status\",\"timestamp\":\"$timestamp\"}" >> "$temp_file"
    fi
    echo "]}" >> "$temp_file"
    mv "$temp_file" "$PROGRESS_FILE"
}

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
    
    if has_jq; then
        # Use jq if available
        local temp_file
        temp_file=$(mktemp)
        if ! jq --arg step "$step" \
               --arg status "$status" \
               --arg time "$timestamp" \
               '.steps += [{"step": $step, "status": $status, "timestamp": $time}]' \
               "$PROGRESS_FILE" > "$temp_file"; then
            echo "Warning: jq command failed, using fallback method" >&2
            update_progress_fallback "$step" "$status" "$timestamp"
        else
            mv "$temp_file" "$PROGRESS_FILE"
        fi
    else
        # Use fallback if jq is not available
        echo "Warning: jq not found, using fallback progress tracking method" >&2
        update_progress_fallback "$step" "$status" "$timestamp"
    fi
}

show_progress() {
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        echo "No progress recorded yet."
        return
    fi
    
    echo "Setup Progress:"
    if has_jq; then
        jq -r '.steps[] | "[\(.timestamp)] \(.step): \(.status)"' "$PROGRESS_FILE"
    else
        # Simple fallback display using grep and sed
        echo "Note: jq not available, showing simplified progress" >&2
        grep -o '"step":"[^"]*","status":"[^"]*","timestamp":"[^"]*"' "$PROGRESS_FILE" | \
            sed 's/"step":"\([^"]*\)","status":"\([^"]*\)","timestamp":"\([^"]*\)"/[\3] \1: \2/'
    fi
}

resume_from_last() {
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        return 1
    fi
    
    if has_jq; then
        local last_step
        last_step=$(jq -r '.steps[-1].step' "$PROGRESS_FILE")
        echo "Last completed step: $last_step"
        return 0
    else
        # Simple fallback using grep and sed
        local last_step
        last_step=$(grep -o '"step":"[^"]*"' "$PROGRESS_FILE" | tail -n1 | sed 's/"step":"\([^"]*\)"/\1/')
        if [[ -n "$last_step" ]]; then
            echo "Last completed step: $last_step"
            return 0
        fi
    fi
    return 1
}