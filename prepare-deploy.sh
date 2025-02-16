#!/bin/bash
# Deployment preparation script

# Create a deployment directory
DEPLOY_DIR="deploy"
rm -rf "$DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR"

# Copy all files preserving directory structure
cp -r scripts docs examples LICENSE README.md "$DEPLOY_DIR/"

# Set correct permissions for all shell scripts
find "$DEPLOY_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# Verify line endings are correct
echo "Verifying line endings..."
if command -v dos2unix >/dev/null 2>&1; then
    find "$DEPLOY_DIR" -type f -name "*.sh" -exec dos2unix {} \;
else
    echo "Warning: dos2unix not found. Please install it for line ending conversion"
fi

echo "Files are ready in the $DEPLOY_DIR directory"
echo "You can now copy these files to your Ubuntu server"