// Package detection implements phase-based SSRF detection engines.
package detection

import (
	"context"
	"fmt"
	"time"

	"ssrf-detector/internal/core"
)

// Pipeline orchestrates detection phases
type Pipeline struct {
	config  *core.Config
	engines map[core.DetectionPhase]core.DetectionEngine
	order   []core.DetectionPhase
}

// NewPipeline creates a new detection pipeline
func NewPipeline(config *core.Config, oobManager core.OOBManager, httpClient core.HTTPClient) (*Pipeline, error) {
	p := &Pipeline{
		config:  config,
		engines: make(map[core.DetectionPhase]core.DetectionEngine),
	}

	// Initialize engines in dependency order
	engines := []core.DetectionEngine{
		NewReachabilityEngine(config, httpClient),
		NewCapabilityEngine(config, httpClient, oobManager),
		NewFetchAnalysisEngine(config, httpClient, oobManager),
		NewRedirectAnalysisEngine(config, httpClient, oobManager),
		NewTrustBoundaryEngine(config, httpClient, oobManager),
		NewParserDifferentialEngine(config, httpClient, oobManager),
		NewEncodingBoundaryEngine(config, httpClient, oobManager),
		NewProtocolEscalationEngine(config, httpClient, oobManager),
		NewInternalAccessEngine(config, httpClient, oobManager),
		NewVerificationEngine(config, httpClient, oobManager),
	}

	for _, engine := range engines {
		p.engines[engine.Name()] = engine
		p.order = append(p.order, engine.Name())
	}

	return p, nil
}

// Execute runs the detection pipeline
func (p *Pipeline) Execute(ctx context.Context, target *core.Target) (*core.ScanState, error) {
	state := &core.ScanState{
		Target:       target,
		Config:       p.config,
		PhaseResults: make(map[core.DetectionPhase]*core.PhaseResult),
		Capabilities: make(map[string]bool),
		Metadata:     make(map[string]interface{}),
		StartTime:    time.Now(),
	}

	// Execute phases in order
	for _, phaseName := range p.order {
		engine := p.engines[phaseName]

		// Check authorization level
		if engine.RequiredAuthLevel() > p.config.AuthLevel {
			if p.config.Verbose {
				fmt.Printf("[SKIP] Phase %s requires auth level %d (current: %d)\n",
					phaseName, engine.RequiredAuthLevel(), p.config.AuthLevel)
			}
			continue
		}

		// Check dependencies
		if !p.dependenciesSatisfied(engine, state) {
			if p.config.Verbose {
				fmt.Printf("[SKIP] Phase %s dependencies not satisfied\n", phaseName)
			}
			continue
		}

		// Execute phase
		if p.config.Verbose {
			fmt.Printf("[PHASE] Executing %s\n", phaseName)
		}

		result, err := engine.Execute(ctx, target, state)
		if err != nil {
			return state, fmt.Errorf("phase %s failed: %w", phaseName, err)
		}

		// Store result
		state.PhaseResults[phaseName] = result

		// Accumulate evidence
		state.Evidence = append(state.Evidence, result.Evidence...)

		// Check if should stop
		if result.ShouldStop {
			if p.config.Verbose {
				fmt.Printf("[STOP] Phase %s requested stop\n", phaseName)
			}
			break
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		default:
		}
	}

	return state, nil
}

// dependenciesSatisfied checks if phase dependencies are met
func (p *Pipeline) dependenciesSatisfied(engine core.DetectionEngine, state *core.ScanState) bool {
	deps := engine.DependsOn()
	if len(deps) == 0 {
		return true // No dependencies
	}

	for _, dep := range deps {
		result, exists := state.PhaseResults[dep]
		if !exists || !result.Success {
			return false
		}
	}

	return true
}
