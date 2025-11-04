#!/bin/bash
#
# Netwarden WordPress Plugin Build Script
#
# Creates a distributable ZIP file for WordPress plugin installation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/netwarden"
OUTPUT_DIR="$SCRIPT_DIR/dist"
PLUGIN_NAME="netwarden"
VERSION=$(grep "Version:" "$PLUGIN_DIR/netwarden.php" | awk '{print $3}')

echo "Building Netwarden WordPress Plugin v$VERSION"
echo "=============================================="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Clean previous builds
echo "Cleaning previous builds..."
rm -f "$OUTPUT_DIR/${PLUGIN_NAME}.zip"
rm -f "$OUTPUT_DIR/${PLUGIN_NAME}-${VERSION}.zip"

# Create ZIP file
echo "Creating ZIP archive..."
cd "$SCRIPT_DIR"
zip -r "$OUTPUT_DIR/${PLUGIN_NAME}.zip" "$PLUGIN_NAME/" \
    -x "*.git*" \
    -x "*.DS_Store" \
    -x "*/.DS_Store" \
    -x "*.gitignore" \
    -x "*/__pycache__/*" \
    -x "*.pyc" \
    -x "${PLUGIN_NAME}/assets/*"

# Create versioned copy
cp "$OUTPUT_DIR/${PLUGIN_NAME}.zip" "$OUTPUT_DIR/${PLUGIN_NAME}-${VERSION}.zip"

echo ""
echo "Build complete!"
echo "Output: $OUTPUT_DIR/${PLUGIN_NAME}.zip"
echo "Versioned: $OUTPUT_DIR/${PLUGIN_NAME}-${VERSION}.zip"
echo ""
echo "File size: $(du -h "$OUTPUT_DIR/${PLUGIN_NAME}.zip" | cut -f1)"
echo ""

# Copy to agent-repo pod for distribution via get.netwarden.com
echo "Copying to agent repository..."
AGENT_REPO_POD="agent-repo-0"
AGENT_REPO_NAMESPACE="netwarden"

if kubectl get pod "$AGENT_REPO_POD" -n "$AGENT_REPO_NAMESPACE" &>/dev/null; then
    echo "Found agent-repo pod: $AGENT_REPO_POD"

    # Copy the ZIP file to the agent-repo pod
    if kubectl cp "$OUTPUT_DIR/${PLUGIN_NAME}.zip" \
        "$AGENT_REPO_NAMESPACE/$AGENT_REPO_POD:/var/www/html/netwarden-wordpress-latest.zip"; then
        echo "✓ Successfully copied to agent repository"
        echo "  Available at: https://get.netwarden.com/netwarden-wordpress-latest.zip"
    else
        echo "✗ Failed to copy to agent repository"
        exit 1
    fi
else
    echo "⚠ Warning: agent-repo pod not found in $AGENT_REPO_NAMESPACE namespace"
    echo "  Skipping deployment to get.netwarden.com"
fi

echo ""
echo "To install:"
echo "1. Upload $OUTPUT_DIR/${PLUGIN_NAME}.zip to WordPress"
echo "2. Go to Plugins → Add New → Upload Plugin"
echo "3. Choose the ZIP file and click Install Now"
echo "4. Activate the plugin"
