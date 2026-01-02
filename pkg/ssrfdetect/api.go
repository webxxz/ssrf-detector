// Package ssrfdetect provides a public API for using SSRF detector as a library.
package ssrfdetect

import (
	"context"
	"net/url"

	"ssrf-detector/internal/core"
	"ssrf-detector/internal/detection"
	"ssrf-detector/internal/http"
	"ssrf-detector/internal/oob"
	"ssrf-detector/internal/scoring"
)

// Scanner represents the SSRF detection scanner
type Scanner struct {
	config     *core.Config
	oobManager core.OOBManager
	httpClient core.HTTPClient
	pipeline   *detection.Pipeline
}

// NewScanner creates a new scanner instance
func NewScanner(config *core.Config) (*Scanner, error) {
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Initialize OOB manager
	oobManager, err := oob.NewManager(config)
	if err != nil {
		return nil, err
	}

	// Initialize HTTP client
	httpClient := http.NewClient(config)

	// Initialize pipeline
	pipeline, err := detection.NewPipeline(config, oobManager, httpClient)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		config:     config,
		oobManager: oobManager,
		httpClient: httpClient,
		pipeline:   pipeline,
	}, nil
}

// Scan performs SSRF detection on a target
func (s *Scanner) Scan(ctx context.Context, targetURL string, paramName string) ([]*core.Finding, error) {
	// Parse URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Create target
	target := &core.Target{
		URL:    parsedURL,
		Method: "GET",
		InjectionPoint: core.InjectionPoint{
			Type: core.InjectionQuery,
			Name: paramName,
		},
	}

	// Execute scan
	state, err := s.pipeline.Execute(ctx, target)
	if err != nil {
		return nil, err
	}

	// Build findings
	scorer := scoring.NewScorer(s.config)
	fpChecker := scoring.NewFalsePositiveChecker(s.config)

	findings := make([]*core.Finding, 0)

	if finding, err := scorer.BuildFinding(state); err == nil {
		if err := fpChecker.Check(finding, state); err == nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// Close cleans up scanner resources
func (s *Scanner) Close() error {
	// Cleanup if needed
	return nil
}
