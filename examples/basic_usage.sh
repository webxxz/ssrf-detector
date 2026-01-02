#!/bin/bash

# Basic usage examples for SSRF Detector

OOB_DOMAIN="oob.example.com"

# Example 1: Simplest scan (external only, safest)
echo "=== Example 1: Basic External Scan ==="
./ssrfdetect \
    -u "https://example.com/fetch?url=test" \
    -p url \
    --oob-domain "$OOB_DOMAIN" \
    -v

# Example 2: With JSON output
echo ""
echo "=== Example 2: JSON Output ==="
./ssrfdetect \
    -u "https://example.com/api/import" \
    -p source \
    --oob-domain "$OOB_DOMAIN" \
    -f json \
    -o report.json

# Example 3: Verbose mode for debugging
echo ""
echo "=== Example 3: Verbose Debugging ==="
./ssrfdetect \
    -u "https://example.com/redirect?next=" \
    -p next \
    --oob-domain "$OOB_DOMAIN" \
    -v

# Example 4: Cloud metadata detection (requires auth-level basic)
echo ""
echo "=== Example 4: Cloud Metadata Detection ==="
./ssrfdetect \
    -u "https://aws-app.example.com/fetch" \
    -p url \
    --oob-domain "$OOB_DOMAIN" \
    --auth-level basic \
    --allow-cloud-metadata \
    -f markdown \
    -o aws-metadata.md \
    -v

# Example 5: CSV output for bulk testing
echo ""
echo "=== Example 5: CSV Bulk Testing ==="
./ssrfdetect \
    -u "https://example.com/proxy" \
    -p target \
    --oob-domain "$OOB_DOMAIN" \
    -f csv \
    -o results.csv