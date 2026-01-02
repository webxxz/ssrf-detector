# SSRF Detector - Production-Grade SSRF Detection Framework

A comprehensive, production-quality Server-Side Request Forgery (SSRF) and Open Redirect detection tool designed for bug bounty hunters, red teams, and security professionals.

## Features

### Detection Capabilities

- **SSRF Detection**
  - Classic SSRF with OOB verification
  - Blind SSRF via timing analysis
  - Internal network access detection
  - Cloud metadata access (AWS, GCP, Azure)
  
- **Open Redirect Detection**
  - Client-side redirects
  - Server-side redirect following
  - Redirect → SSRF escalation
  
- **Advanced Techniques**
  - Parser differential detection
  - Encoding boundary analysis
  - Protocol escalation testing
  - Trust boundary mapping

### Safety Features

- Authorization level controls
- Scope management
- False positive elimination
- Statistical validation
- Safe-by-default configuration

### Output Formats

- JSON (machine-readable)
- Markdown (bug bounty submissions)
- CSV (tracking/analysis)

## Installation

```bash
# Build from source
go build -o ssrfdetect cmd/ssrfdetect/main.go

# Or using Make
make build