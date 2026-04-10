# ssrf-detector

`ssrf-detector` is a Go-based SSRF and Open Redirect testing framework for authorized security assessments. It targets server-side URL fetch paths and redirect flows, correlates multiple evidence signals, and produces reports suitable for bug bounty and red team workflows.

The scanner combines direct callback verification, blind inference, parser/encoding differential checks, and internal service probing behind explicit authorization controls. Output is structured for both automation (JSON/CSV) and platform-ready markdown submissions.

## Features

- Classic SSRF with OOB callback verification
- Blind SSRF via timing analysis and signal fusion
- Cloud metadata probing (AWS, GCP, Azure)
- Protocol escalation testing (`http` → `file`/`gopher`/`dict`)
- Parser differential and encoding boundary analysis
- Open Redirect detection and Redirect → SSRF chaining
- Injection-point discovery from query/path/header/body/json contexts
- Multi-format reporting (JSON, Markdown templates, CSV)
- Scope and authorization guardrails (safe-by-default)

## Installation

### Build with Go

```bash
git clone https://github.com/webxxz/ssrf-detector.git
cd ssrf-detector
go build -o build/ssrfdetect cmd/ssrfdetect/main.go
```

### Build and run with Docker

```bash
docker build -t ssrf-detector:latest .
docker run --rm ssrf-detector:latest --help
```

## Usage

### Basic scan

```bash
./build/ssrfdetect \
  -u "https://target.tld/api/fetch" \
  -p url \
  --oob-domain oob.yourdomain.tld
```

### HackerOne markdown report

```bash
./build/ssrfdetect \
  -u "https://target.tld/import" \
  -p source \
  --oob-domain oob.yourdomain.tld \
  --auth-level basic \
  --allow-cloud-metadata \
  -f markdown \
  --platform hackerone \
  -o hackerone-report.md
```

### QNAP markdown report

```bash
./build/ssrfdetect \
  -u "https://target.tld/redirect" \
  -p next \
  --oob-domain oob.yourdomain.tld \
  --auth-level full \
  --allow-internal \
  --allow-protocol-escalation \
  -f markdown \
  --platform qnap \
  -o qnap-report.md
```

### Batch targets with auto discovery

```bash
./build/ssrfdetect \
  --targets-file targets.txt \
  --auto-discover \
  --oob-domain oob.yourdomain.tld \
  -f json \
  -o findings.json
```

## Architecture Overview

- `cmd/ssrfdetect`: CLI entrypoint, argument parsing, scan orchestration
- `internal/core`: core types, config, evidence interfaces, scan state
- `internal/detection`: phase-based detection engines and SSRF heuristics
- `internal/oob`: callback identifier generation, listener/server, attribution
- `internal/http`: HTTP client wrapper with timing and redirect telemetry
- `internal/surface`: injection-point extraction/discovery from request surfaces
- `internal/payloads`: payload generation for SSRF and protocol variants
- `internal/chain`: attack-chain reasoning and escalation mapping
- `internal/scoring`: confidence scoring, false-positive controls, CVSS logic
- `internal/waf`: WAF fingerprinting utilities
- `internal/report`: JSON/CSV/Markdown rendering and platform templates
- `pkg/ssrfdetect`: library-facing package for embedding scanner APIs

## OOB Self-Hosted Server

The self-hosted OOB flow uses per-test correlation IDs embedded in generated callback URLs. During scanning, payloads are issued with those IDs, and the OOB service records inbound DNS/HTTP interactions keyed by identifier. Matching callback events are then attributed to individual tests/finding evidence.

Operationally, this enables deterministic proof for classic SSRF paths and supports fusion with other signals (timing, inclusion, internal reachability). Self-hosting keeps callback logs under operator control and avoids dependency on third-party interaction services.

## Confidence Scoring

Confidence levels are evidence-driven and normalized into four classes:

- `CONFIRMED`: strongest evidence profile (high-confidence multi-signal SSRF proof)
- `HIGH`: strong multi-signal evidence with low false-positive risk
- `MEDIUM`: partial but meaningful correlation requiring analyst review
- `NOISE`: weak/inconclusive signal set or disqualified evidence pattern

Scoring incorporates evidence quality, correlation bonuses (e.g., OOB + timing), and false-positive rejection gates such as reflection-only or client-side-only behavior.

## Contributing

1. Fork and create a feature branch.
2. Keep changes scoped and add/adjust tests for modified behavior.
3. Run local validation (`make build`, `make test`, `make lint` when available).
4. Submit a pull request with clear technical rationale and reproduction context.

## License

This project is licensed under the terms in [LICENSE](LICENSE).
