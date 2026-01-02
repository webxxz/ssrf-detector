package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"ssrf-detector/internal/core"
	"ssrf-detector/pkg/ssrfdetect"
)

func main() {
	// Create configuration
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"
	config.AuthLevel = core.AuthLevelBasic
	config.Scope.AllowCloudMetadata = true
	config.Verbose = true

	// Create scanner
	scanner, err := ssrfdetect.NewScanner(config)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Perform scan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	findings, err := scanner.Scan(ctx, "https://example.com/fetch", "url")
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Process findings
	fmt.Printf("Found %d vulnerabilities\n", len(findings))
	for i, finding := range findings {
		fmt.Printf("\n[%d] %s - %s\n", i+1, finding.Type, finding.Severity)
		fmt.Printf("    Confidence: %s (%d)\n", finding.Confidence, finding.ConfidenceScore)
		fmt.Printf("    Impact: %s\n", finding.Impact)
	}
}
