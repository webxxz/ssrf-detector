package scoring

import (
	"fmt"
	"math"
	"time"
)

// StatisticalAnalyzer performs statistical analysis on timing data
type StatisticalAnalyzer struct{}

// NewStatisticalAnalyzer creates a new analyzer
func NewStatisticalAnalyzer() *StatisticalAnalyzer {
	return &StatisticalAnalyzer{}
}

// AnalyzeTiming performs statistical analysis on timing samples
func (a *StatisticalAnalyzer) AnalyzeTiming(baseline []time.Duration, test []time.Duration) (*TimingAnalysisResult, error) {
	if len(baseline) == 0 || len(test) == 0 {
		return nil, fmt.Errorf("baseline and test samples required")
	}

	// Calculate baseline statistics
	baselineMean := a.calculateMean(baseline)
	baselineStdDev := a.calculateStdDev(baseline, baselineMean)

	// Calculate test statistics
	testMean := a.calculateMean(test)
	testStdDev := a.calculateStdDev(test, testMean)

	// Calculate Z-score
	zScore := a.calculateZScore(testMean, baselineMean, baselineStdDev)

	// Determine significance
	significant := math.Abs(zScore) >= 3.0 // 3-sigma threshold

	result := &TimingAnalysisResult{
		BaselineMean:   baselineMean,
		BaselineStdDev: baselineStdDev,
		TestMean:       testMean,
		TestStdDev:     testStdDev,
		ZScore:         zScore,
		Significant:    significant,
		Samples:        len(test),
	}

	return result, nil
}

// calculateMean computes average of durations
func (a *StatisticalAnalyzer) calculateMean(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}

	var sum time.Duration
	for _, s := range samples {
		sum += s
	}

	return sum / time.Duration(len(samples))
}

// calculateStdDev computes standard deviation
func (a *StatisticalAnalyzer) calculateStdDev(samples []time.Duration, mean time.Duration) time.Duration {
	if len(samples) <= 1 {
		return 0
	}

	var sumSquares float64
	for _, s := range samples {
		diff := float64(s - mean)
		sumSquares += diff * diff
	}

	variance := sumSquares / float64(len(samples))
	return time.Duration(math.Sqrt(variance))
}

// calculateZScore computes Z-score for test vs baseline
func (a *StatisticalAnalyzer) calculateZScore(testMean, baselineMean, baselineStdDev time.Duration) float64 {
	if baselineStdDev == 0 {
		return 0
	}

	diff := float64(testMean - baselineMean)
	stdDev := float64(baselineStdDev)

	return diff / stdDev
}

// TimingAnalysisResult contains timing analysis results
type TimingAnalysisResult struct {
	BaselineMean   time.Duration
	BaselineStdDev time.Duration
	TestMean       time.Duration
	TestStdDev     time.Duration
	ZScore         float64
	Significant    bool
	Samples        int
}

// String returns human-readable analysis
func (r *TimingAnalysisResult) String() string {
	return fmt.Sprintf(
		"Timing Analysis:\n"+
			"  Baseline: %.2fms ± %.2fms\n"+
			"  Test: %.2fms ± %.2fms\n"+
			"  Z-Score: %.2f\n"+
			"  Significant: %v (n=%d)",
		float64(r.BaselineMean.Milliseconds()),
		float64(r.BaselineStdDev.Milliseconds()),
		float64(r.TestMean.Milliseconds()),
		float64(r.TestStdDev.Milliseconds()),
		r.ZScore,
		r.Significant,
		r.Samples,
	)
}
