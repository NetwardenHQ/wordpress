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

# Publish to the agent repository (Cloudflare R2) for get.netwarden.com.
#
# 2026-09-10: this used to `kubectl cp` into an `agent-repo-0` pod serving
# /var/www/html. That pod no longer exists, and the old code treated a missing
# pod as a warning and carried on — so the build reported success while
# publishing nothing. The zip on get.netwarden.com had been stale since
# 2026-06-24 as a result. get.netwarden.com is now served straight from R2.
#
# R2 speaks the S3 API; the `aws` CLI here talks to Cloudflare, not Amazon.
echo "Publishing to the agent repository..."

R2_BUCKET="${NETWARDEN_AGENT_REPO_BUCKET:-netwarden-agent-repo}"
DEST_KEY="netwarden-wordpress-latest.zip"

if [ -z "${R2_ACCESS_KEY_ID:-}" ] || [ -z "${R2_SECRET_ACCESS_KEY:-}" ] || [ -z "${R2_ACCOUNT_ID:-}" ]; then
    echo "✗ Missing R2 credentials — nothing was published."
    echo "  Export R2_ACCOUNT_ID, R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY"
    echo "  (values live in the netwarden repo's secrets/release.env), then re-run."
    exit 1
fi

# AWS_PROFILE is cleared on purpose: sibling scripts export AWS_PROFILE=epistles,
# and an inherited AWS profile would send this upload at Amazon instead of R2.
unset AWS_PROFILE
export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export AWS_ENDPOINT_URL="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
# R2 rejects the CRC32 trailers botocore adds by default since early 2025.
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

if aws s3 cp "$OUTPUT_DIR/${PLUGIN_NAME}.zip" "s3://${R2_BUCKET}/${DEST_KEY}" \
        --region auto --content-type application/zip; then
    echo "✓ Published to s3://${R2_BUCKET}/${DEST_KEY}"
    echo "  Available at: https://get.netwarden.com/${DEST_KEY}"
else
    echo "✗ Failed to publish to the agent repository"
    exit 1
fi

echo ""
echo "To install:"
echo "1. Upload $OUTPUT_DIR/${PLUGIN_NAME}.zip to WordPress"
echo "2. Go to Plugins → Add New → Upload Plugin"
echo "3. Choose the ZIP file and click Install Now"
echo "4. Activate the plugin"
