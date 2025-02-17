#!/bin/bash
# Track setup progress with cross-platform compatibility
set -euo pipefail

# Fix line endings for this script first
sed -i 's/\r$//' "${BASH_SOURCE[0]}"
chmod +x "${BASH_SOURCE[0]}"

# Progress tracking file
PROGRESS_FILE="/var/lib/server-hardening/progress.json"

# Colors for output
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[1;34m'
readonly COLOR_RESET='\033[0m'

# Initialize progress tracking
init_progress() {
    mkdir -p "$(dirname "$PROGRESS_FILE")"
    
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        cat > "$PROGRESS_FILE" << EOF
{
    "steps": {
        "prerequisites": "pending",
        "admin_user": "pending",
        "ssh_keys": "pending",
        "2fa": "pending",
        "system_hardening": "pending"
    },
    "current_step": "prerequisites",
    "last_updated": "",
    "username": ""
}
EOF
        chmod 600 "$PROGRESS_FILE"
    fi
}

# Update progress for a step
track_progress() {
    local step="$1"
    local status="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    
    # Ensure temp file inherits permissions
    local temp_file
    temp_file=$(mktemp)
    chmod 600 "$temp_file"
    
    jq --arg step "$step" \
       --arg status "$status" \
       --arg time "$timestamp" \
       '.steps[$step] = $status | .last_updated = $time' \
       "$PROGRESS_FILE" > "$temp_file" && mv "$temp_file" "$PROGRESS_FILE"
}

# Update current step
set_current_step() {
    local step="$1"
    local temp_file
    temp_file=$(mktemp)
    chmod 600 "$temp_file"
    
    jq --arg step "$step" \
       '.current_step = $step' \
       "$PROGRESS_FILE" > "$temp_file" && mv "$temp_file" "$PROGRESS_FILE"
}

# Set username in progress
set_username() {
    local username="$1"
    local temp_file
    temp_file=$(mktemp)
    chmod 600 "$temp_file"
    
    jq --arg username "$username" \
       '.username = $username' \
       "$PROGRESS_FILE" > "$temp_file" && mv "$temp_file" "$PROGRESS_FILE"
}

# Get current progress
get_progress() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        cat "$PROGRESS_FILE"
    else
        echo "{}"
    fi
}

# Check if we should resume from last step
resume_from_last() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        local current_step
        current_step=$(jq -r '.current_step' "$PROGRESS_FILE")
        if [[ "$current_step" != "null" && "$current_step" != "prerequisites" ]]; then
            return 0
        fi
    fi
    return 1
}

# Display progress nicely
show_progress() {
    echo -e "\n${COLOR_BLUE}=== Setup Progress ===${COLOR_RESET}"
    
    local status
    while IFS="=" read -r step status; do
        status="${status//\"/}"
        printf "%-20s" "$step"
        case "$status" in
            "completed") echo -e "${COLOR_GREEN}✓ Completed${COLOR_RESET}" ;;
            "failed") echo -e "${COLOR_RED}✗ Failed${COLOR_RESET}" ;;
            "pending") echo -e "${COLOR_YELLOW}⋯ Pending${COLOR_RESET}" ;;
            "verifying") echo -e "${COLOR_BLUE}⟳ Verifying${COLOR_RESET}" ;;
            *) echo -e "? Unknown" ;;
        esac
    done < <(jq -r '.steps | to_entries | .[] | "\(.key)=\(.value)"' "$PROGRESS_FILE")
    
    local last_updated
    last_updated=$(jq -r '.last_updated' "$PROGRESS_FILE")
    if [[ -n "$last_updated" && "$last_updated" != "null" ]]; then
        echo -e "\nLast updated: $last_updated"
    fi
    
    echo
}

# Clear progress (for testing or reset)
clear_progress() {
    rm -f "$PROGRESS_FILE"
    init_progress
}

# Check if a step is completed
is_step_completed() {
    local step="$1"
    local status
    
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        return 1
    fi
    
    status=$(jq -r ".steps[\"$step\"]" "$PROGRESS_FILE")
    [[ "$status" == "completed" ]]
}

# Get username from progress
get_username() {
    if [[ -f "$PROGRESS_FILE" ]]; then
        jq -r '.username' "$PROGRESS_FILE"
    fi
}

# Verify step completion
verify_step_completion() {
    local step="$1"
    local username="$2"
    
    case "$step" in
        "admin_user")
            # Verify admin user setup
            if ! id "$username" >/dev/null 2>&1; then
                return 1
            fi
            if ! groups "$username" | grep -q '\bsudo\b'; then
                return 1
            fi
            ;;
        "ssh_keys")
            # Verify SSH key setup
            if [[ ! -f "/home/${username}/.ssh/authorized_keys" ]]; then
                return 1
            fi
            ;;
        "2fa")
            # Verify 2FA setup if enabled
            if [[ -f "/home/${username}/.google_authenticator" ]]; then
                if ! grep -q "auth.*pam_google_authenticator.so" /etc/pam.d/sshd 2>/dev/null; then
                    return 1
                fi
            fi
            ;;
        *)
            # Unknown step
            return 1
            ;;
    esac
    
    return 0
}

# Export functions
export -f track_progress
export -f show_progress
export -f set_current_step
export -f set_username
export -f get_progress
export -f resume_from_last
export -f is_step_completed
export -f get_username
export -f verify_step_completion

# Initialize progress file if it doesn't exist
init_progress