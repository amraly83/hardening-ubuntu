#!/bin/bash

# Set strict mode
set -euo pipefail

# Configuration
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/server-hardening.log"

echo "Preparing scripts for deployment..."

# Function to validate script syntax
validate_script() {
    local script="$1"
    bash -n "$script" || {
        echo "Syntax error in $script"
        return 1
    }
}

# Function to fix file permissions and line endings
fix_file_attributes() {
    local file="$1"
    # Remove Windows line endings
    sed -i 's/\r$//' "$file"
    # Make executable
    chmod +x "$file"
    # Validate script syntax
    validate_script "$file"
}

# Prepare all shell scripts
echo "Fixing permissions and line endings..."
find "$DEPLOY_DIR" -type f -name "*.sh" | while read -r script; do
    echo "Processing: $script"
    fix_file_attributes "$script"
done

# Verify common.sh can be sourced
if ! source "${DEPLOY_DIR}/scripts/common.sh" 2>/dev/null; then
    echo "Error: Failed to source common.sh"
    exit 1
fi

# Verify critical files exist
REQUIRED_FILES=(
    "scripts/setup.sh"
    "scripts/create-admin.sh"
    "scripts/setup-ssh-key.sh"
    "scripts/setup-2fa.sh"
    "scripts/harden.sh"
    "scripts/common.sh"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "${DEPLOY_DIR}/${file}" ]]; then
        echo "Error: Required file ${file} not found"
        exit 1
    fi
done

echo "Verifying script permissions and syntax..."
for file in "${REQUIRED_FILES[@]}"; do
    full_path="${DEPLOY_DIR}/${file}"
    echo "Checking: $file"
    validate_script "$full_path"
done

# Create necessary directories
echo "Creating required directories..."
mkdir -p "${DEPLOY_DIR}/logs"
chmod 750 "${DEPLOY_DIR}/logs"

# Verify log file permissions
if [[ -f "$LOG_FILE" ]]; then
    chmod 640 "$LOG_FILE"
fi

echo "Deployment preparation completed successfully"
echo "Run setup.sh to begin the hardening process"