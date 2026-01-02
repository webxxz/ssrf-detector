#!/bin/bash

# Bug Bounty Hunting with SSRF Detector
# This script demonstrates various bug bounty scenarios

OOB_DOMAIN="your-oob-domain.com"
OUTPUT_DIR="./bug-bounty-reports"
mkdir -p "$OUTPUT_DIR"

echo "=== Bug Bounty SSRF Detection Suite ==="

# Scenario 1: URL Import Feature
echo "[1] Testing URL import feature..."
./ssrfdetect \
    -u "https://target.com/api/import?source=" \
    -p source \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    --allow-cloud-metadata \
    -f markdown \
    -o "$OUTPUT_DIR/import-feature.md" \
    -v

# Scenario 2: Webhook Registration
echo "[2] Testing webhook registration..."
./ssrfdetect \
    -u "https://target.com/webhooks/create?callback_url=" \
    -p callback_url \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    --allow-cloud-metadata \
    -f json \
    -o "$OUTPUT_DIR/webhook-ssrf.json" \
    -v

# Scenario 3: PDF Generator
echo "[3] Testing PDF generator..."
./ssrfdetect \
    -u "https://target.com/generate-pdf?url=" \
    -p url \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    -f markdown \
    -o "$OUTPUT_DIR/pdf-generator.md" \
    -v

# Scenario 4: Image Proxy/Fetcher
echo "[4] Testing image proxy..."
./ssrfdetect \
    -u "https://target.com/proxy/image?src=" \
    -p src \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    --allow-cloud-metadata \
    -f json \
    -o "$OUTPUT_DIR/image-proxy.json" \
    -v

# Scenario 5: OAuth Redirect
echo "[5] Testing OAuth redirect..."
./ssrfdetect \
    -u "https://target.com/oauth/authorize?redirect_uri=" \
    -p redirect_uri \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    -f markdown \
    -o "$OUTPUT_DIR/oauth-redirect.md" \
    -v

# Scenario 6: Link Preview
echo "[6] Testing link preview..."
./ssrfdetect \
    -u "https://target.com/preview?link=" \
    -p link \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    --allow-cloud-metadata \
    -f json \
    -o "$OUTPUT_DIR/link-preview.json" \
    -v

echo ""
echo "=== Scan Complete ==="
echo "Reports saved to: $OUTPUT_DIR"
echo ""
echo "Next steps:"
echo "1. Review findings in $OUTPUT_DIR"
echo "2. Validate critical findings manually"
echo "3. Prepare HackerOne/Bugcrowd report"
echo "4. Include POC from markdown reports"