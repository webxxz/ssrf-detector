package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"ssrf-detector/internal/core"
)

// CSVReporter generates CSV reports
type CSVReporter struct {
	config *core.Config
}

// NewCSVReporter creates a new CSV reporter
func NewCSVReporter(config *core.Config) *CSVReporter {
	return &CSVReporter{
		config: config,
	}
}

func (r *CSVReporter) Format() string {
	return "csv"
}

// Generate creates a CSV report
func (r *CSVReporter) Generate(findings []*core.Finding, state *core.ScanState) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"ID",
		"Type",
		"Severity",
		"Confidence",
		"Confidence Score",
		"Vulnerable Parameter",
		"Impact Summary",
		"Evidence Count",
		"Internal IPs",
		"Cloud Provider",
		"Detected At",
	}

	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write findings
	for _, finding := range findings {
		record := []string{
			finding.ID,
			string(finding.Type),
			string(finding.Severity),
			string(finding.Confidence),
			fmt.Sprintf("%d", finding.ConfidenceScore),
			finding.VulnerableParameter,
			r.truncate(finding.Impact, 100),
			fmt.Sprintf("%d", len(finding.Evidence)),
			strings.Join(finding.InternalIPsReached, "; "),
			finding.CloudProvider,
			finding.DetectedAt.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.Bytes(), nil
}

// truncate truncates string to max length
func (r *CSVReporter) truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
