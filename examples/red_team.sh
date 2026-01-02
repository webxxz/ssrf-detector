#!/bin/bash

# Red Team Internal Assessment
# Requires full authorization

OOB_DOMAIN="callbacks.redteam.local"
TARGET="https://internal.corp.com"
OUTPUT_DIR="./redteam-assessment"
mkdir -p "$OUTPUT_DIR"

echo "=== Red Team SSRF Assessment ==="
echo "Target: $TARGET"
echo "Authorization: FULL (Internal Assessment)"
echo ""

# Comprehensive scan with all techniques enabled
./ssrfdetect \
    -u "$TARGET/api/fetch?url=" \
    -p url \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level full \
    --allow-internal \
    --allow-cloud-metadata \
    --allow-protocol-escalation \
    -f json \
    -o "$OUTPUT_DIR/full-assessment.json" \
    -v

# Extract critical findings
echo ""
echo "=== Critical Findings Summary ==="
jq '.findings[] | select(.severity == "Critical")' "$OUTPUT_DIR/full-assessment.json"

echo ""
echo "Assessment complete. Review: $OUTPUT_DIR/full-assessment.json"