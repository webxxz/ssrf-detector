#!/bin/bash

# SSRF Detector - OOB Server Setup Script
# This script helps setup your own out-of-band callback server

set -e

echo "=== SSRF Detector OOB Server Setup ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Don't run this script as root${NC}"
   exit 1
fi

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check prerequisites
print_status "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_warning "docker-compose not found. Will use 'docker compose' instead."
fi

# Get domain configuration
echo ""
echo "OOB Server Configuration"
echo "========================"
echo ""

read -p "Enter your OOB domain (e.g., oob.yourdomain.com): " OOB_DOMAIN

if [ -z "$OOB_DOMAIN" ]; then
    print_error "Domain is required"
    exit 1
fi

print_status "OOB Domain: $OOB_DOMAIN"

# DNS setup instructions
echo ""
echo "DNS Configuration Required:"
echo "============================"
echo ""
echo "Please add the following DNS records:"
echo ""
echo "1. A Record:"
echo "   $OOB_DOMAIN    →    $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo ""
echo "2. Wildcard A Record:"
echo "   *.$OOB_DOMAIN  →    $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo ""
read -p "Have you configured DNS? (y/n): " dns_configured

if [ "$dns_configured" != "y" ]; then
    print_warning "Please configure DNS before continuing"
    exit 0
fi

# Create OOB server directory
OOB_DIR="$HOME/ssrf-oob-server"
mkdir -p "$OOB_DIR"
cd "$OOB_DIR"

print_status "Created OOB server directory: $OOB_DIR"

# Create simple HTTP callback server
cat > callback_server.py << 'EOF'
#!/usr/bin/env python3
"""
Simple OOB Callback Server for SSRF Detection
Logs all HTTP and DNS requests
"""

import http.server
import socketserver
import json
import datetime
import os
from urllib.parse import urlparse, parse_qs

PORT = 8080
LOG_FILE = "/var/log/oob-callbacks.log"

class CallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.log_callback("GET")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        self.log_callback("POST", body)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_callback(self, method, body=None):
        callback_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "method": method,
            "path": self.path,
            "client_address": self.client_address[0],
            "headers": dict(self.headers),
            "body": body.decode('utf-8', errors='ignore') if body else None
        }
        
        # Log to console
        print(f"\n{'='*80}")
        print(f"[{callback_data['timestamp']}] Callback received!")
        print(f"From: {callback_data['client_address']}")
        print(f"Method: {method} {self.path}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        if body:
            print(f"Body: {body.decode('utf-8', errors='ignore')[:200]}")
        print('='*80)
        
        # Log to file
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(callback_data) + '\n')
        except Exception as e:
            print(f"Error writing to log: {e}")

if __name__ == "__main__":
    print(f"OOB Callback Server starting on port {PORT}")
    print(f"Logging to: {LOG_FILE}")
    
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    with socketserver.TCPServer(("0.0.0.0", PORT), CallbackHandler) as httpd:
        print(f"Server ready. Listening for callbacks...")
        httpd.serve_forever()
EOF

chmod +x callback_server.py

print_status "Created callback server script"

# Create Dockerfile for OOB server
cat > Dockerfile << 'EOF'
FROM python:3.11-alpine

WORKDIR /app

COPY callback_server.py /app/

RUN mkdir -p /var/log && \
    chmod 777 /var/log

EXPOSE 8080

CMD ["python3", "/app/callback_server.py"]
EOF

print_status "Created Dockerfile"

# Create docker-compose.yml
cat > docker-compose.yml << EOF
version: '3.8'

services:
  oob-server:
    build: .
    container_name: ssrf-oob-server
    ports:
      - "80:8080"
      - "443:8080"
    volumes:
      - ./logs:/var/log
    restart: unless-stopped
    environment:
      - OOB_DOMAIN=${OOB_DOMAIN}
    networks:
      - oob-network

networks:
  oob-network:
    driver: bridge
EOF

print_status "Created docker-compose.yml"

# Create log directory
mkdir -p logs

# Build and start
echo ""
print_status "Building OOB server container..."
docker build -t ssrf-oob-server .

echo ""
print_status "Starting OOB server..."
docker-compose up -d

# Wait for server to start
sleep 3

# Test server
echo ""
print_status "Testing OOB server..."
if curl -s http://localhost/test > /dev/null; then
    print_status "OOB server is running!"
else
    print_error "OOB server test failed"
fi

# Setup instructions
echo ""
echo "=== Setup Complete ==="
echo ""
print_status "OOB Server Status:"
docker-compose ps
echo ""
print_status "View logs:"
echo "  docker-compose logs -f"
echo ""
print_status "View callbacks:"
echo "  tail -f logs/oob-callbacks.log"
echo ""
print_status "Stop server:"
echo "  docker-compose down"
echo ""
print_status "Test callback:"
echo "  curl http://$OOB_DOMAIN/test"
echo ""
echo "=== Next Steps ==="
echo ""
echo "1. Ensure firewall allows ports 80 and 443"
echo "2. (Optional) Setup SSL with Let's Encrypt"
echo "3. Test DNS resolution: nslookup test.$OOB_DOMAIN"
echo "4. Use in SSRF detector: --oob-domain $OOB_DOMAIN"
echo ""
print_status "All done!"