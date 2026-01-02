// Package main implements the SSRF detection CLI.
package main

import (
    "context"
    "fmt"
    "log"
    "net/url"
    "os"
    "os/signal"
    "syscall"
    "time"

    "ssrf-detector/internal/core"
    "ssrf-detector/internal/detection"
    "ssrf-detector/internal/http"
    "ssrf-detector/internal/oob"
    "ssrf-detector/internal/report"
    "ssrf-detector/internal/scoring"
)

const version = "1.0.0"

func main() {
    // Parse command line arguments
    config, target, err := parseArgs(os.Args[1:])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        printUsage()
        os.Exit(1)
    }
    
    // Validate configuration
    if err := config.Validate(); err != nil {
        fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
        os.Exit(1)
    }
    
    // Print banner
    if config.Verbose {
        printBanner()
    }
    
    // Setup signal handling for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    
    go func() {
        <-sigChan
        fmt.Println("\n[!] Interrupt received, shutting down...")
        cancel()
    }()
    
    // Run scanner
    if err := run(ctx, config, target); err != nil {
        fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
        os.Exit(1)
    }
}

// run executes the scan
func run(ctx context.Context, config *core.Config, target *core.Target) error {
    // Initialize OOB manager
    oobManager, err := oob.NewManager(config)
    if err != nil {
        return fmt.Errorf("failed to initialize OOB manager: %w", err)
    }
    
    // Start OOB server if configured
    if config.OOBServerURL != "" {
        oobServer := oob.NewServer(oobManager, config)
        if err := oobServer.Start(ctx); err != nil {
            return fmt.Errorf("failed to start OOB server: %w", err)
        }
        defer oobServer.Stop(ctx)
        
        if config.Verbose {
            fmt.Printf("[+] OOB server started\n")
        }
    }
    
    // Initialize HTTP client
    httpClient := http.NewClient(config)
    
    // Initialize detection pipeline
    pipeline, err := detection.NewPipeline(config, oobManager, httpClient)
    if err != nil {
        return fmt.Errorf("failed to initialize detection pipeline: %w", err)
    }
    
    // Execute scan
    if config.Verbose {
        fmt.Printf("[+] Starting scan of %s\n", target.URL.String())
        fmt.Printf("[+] Authorization level: %s\n", config.AuthLevel)
        fmt.Printf("[+] Injection point: %s (%s)\n", target.InjectionPoint.Name, target.InjectionPoint.Type)
    }
    
    state, err := pipeline.Execute(ctx, target)
    if err != nil {
        return fmt.Errorf("scan execution failed: %w", err)
    }
    
    if config.Verbose {
        fmt.Printf("[+] Scan completed in %s\n", time.Since(state.StartTime))
        fmt.Printf("[+] Total evidence collected: %d\n", len(state.Evidence))
    }
    
    // Score and build findings
    scorer := scoring.NewScorer(config)
    fpChecker := scoring.NewFalsePositiveChecker(config)
    
    findings := make([]*core.Finding, 0)
    
    // Attempt to build finding from collected evidence
    finding, err := scorer.BuildFinding(state)
    if err != nil {
        if config.Verbose {
            fmt.Printf("[!] No valid finding: %v\n", err)
        }
    } else {
        // Check for false positives
        if err := fpChecker.Check(finding, state); err != nil {
            if config.Verbose {
                fmt.Printf("[!] Finding rejected as false positive: %v\n", err)
            }
        } else {
            findings = append(findings, finding)
        }
    }
    
    // Generate report
    if err := generateReport(config, findings, state); err != nil {
        return fmt.Errorf("failed to generate report: %w", err)
    }
    
    // Print summary
    printSummary(findings, config.Verbose)
    
    return nil
}

// generateReport creates and saves the report
func generateReport(config *core.Config, findings []*core.Finding, state *core.ScanState) error {
    var reporter core.Reporter
    
    switch config.ReportFormat {
    case "json":
        reporter = report.NewJSONReporter(config)
    case "markdown", "md":
        reporter = report.NewMarkdownReporter(config)
    case "csv":
        reporter = report.NewCSVReporter(config)
    default:
        return fmt.Errorf("unsupported report format: %s", config.ReportFormat)
    }
    
    data, err := reporter.Generate(findings, state)
    if err != nil {
        return fmt.Errorf("failed to generate report: %w", err)
    }
    
    // Write to file or stdout
    if config.OutputFile != "" {
        if err := os.WriteFile(config.OutputFile, data, 0644); err != nil {
            return fmt.Errorf("failed to write report file: %w", err)
        }
        fmt.Printf("[+] Report saved to: %s\n", config.OutputFile)
    } else {
        fmt.Println(string(data))
    }
    
    return nil
}

// printSummary prints scan summary
func printSummary(findings []*core.Finding, verbose bool) {
    fmt.Println("\n=== Scan Summary ===")
    fmt.Printf("Total findings: %d\n", len(findings))
    
    if len(findings) > 0 {
        // Count by severity
        severityCounts := make(map[core.Severity]int)
        for _, f := range findings {
            severityCounts[f.Severity]++
        }
        
        if count := severityCounts[core.SeverityCritical]; count > 0 {
            fmt.Printf("  Critical: %d\n", count)
        }
        if count := severityCounts[core.SeverityHigh]; count > 0 {
            fmt.Printf("  High: %d\n", count)
        }
        if count := severityCounts[core.SeverityMedium]; count > 0 {
            fmt.Printf("  Medium: %d\n", count)
        }
        if count := severityCounts[core.SeverityLow]; count > 0 {
            fmt.Printf("  Low: %d\n", count)
        }
    }
}

// parseArgs parses command line arguments
func parseArgs(args []string) (*core.Config, *core.Target, error) {
    config := core.DefaultConfig()
    
    // Simple argument parsing (in production, use flag package or cobra)
    if len(args) == 0 {
        return nil, nil, fmt.Errorf("no arguments provided")
    }
    
    var targetURL string
    var paramName string
    
    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "-u", "--url":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            targetURL = args[i+1]
            i++
            
        case "-p", "--param":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            paramName = args[i+1]
            i++
            
        case "--oob-domain":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            config.OOBDomain = args[i+1]
            i++
            
        case "--auth-level":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            level, err := parseAuthLevel(args[i+1])
            if err != nil {
                return nil, nil, err
            }
            config.AuthLevel = level
            i++
            
        case "-o", "--output":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            config.OutputFile = args[i+1]
            i++
            
        case "-f", "--format":
            if i+1 >= len(args) {
                return nil, nil, fmt.Errorf("missing value for %s", args[i])
            }
            config.ReportFormat = args[i+1]
            i++
            
        case "-v", "--verbose":
            config.Verbose = true
            
        case "--allow-internal":
            config.Scope.AllowInternalIPs = true
            
        case "--allow-cloud-metadata":
            config.Scope.AllowCloudMetadata = true
            
        case "--allow-protocol-escalation":
            config.Scope.AllowProtocolEscalation = true
            
        case "-h", "--help":
            printUsage()
            os.Exit(0)
            
        case "--version":
            fmt.Printf("SSRF Detector v%s\n", version)
            os.Exit(0)
            
        default:
            return nil, nil, fmt.Errorf("unknown flag: %s", args[i])
        }
    }
    
    // Validate required arguments
    if targetURL == "" {
        return nil, nil, fmt.Errorf("target URL is required (-u)")
    }
    
    if paramName == "" {
        return nil, nil, fmt.Errorf("parameter name is required (-p)")
    }
    
    if config.OOBDomain == "" {
        return nil, nil, fmt.Errorf("OOB domain is required (--oob-domain)")
    }
    
    // Parse target URL
    parsedURL, err := url.Parse(targetURL)
    if err != nil {
        return nil, nil, fmt.Errorf("invalid target URL: %w", err)
    }
    
    // Build target
    target := &core.Target{
        URL:    parsedURL,
        Method: "GET",
        InjectionPoint: core.InjectionPoint{
            Type: core.InjectionQuery,
            Name: paramName,
        },
    }
    
    return config, target, nil
}

// parseAuthLevel parses authorization level string
func parseAuthLevel(s string) (core.AuthorizationLevel, error) {
    switch s {
    case "none", "0":
        return core.AuthLevelNone, nil
    case "basic", "1":
        return core.AuthLevelBasic, nil
    case "full", "2":
        return core.AuthLevelFull, nil
    case "exploit", "3":
        return core.AuthLevelExploit, nil
    default:
        return core.AuthLevelNone, fmt.Errorf("invalid auth level: %s (use: none, basic, full, exploit)", s)
    }
}

// printBanner prints the tool banner
func printBanner() {
    banner := `
   _____ _____ _____  ______   _____       _            _             
  / ____/ ____|  __ \|  ____| |  __ \     | |          | |            
 | (___| (___ | |__) | |__    | |  | | ___| |_ ___  ___| |_ ___  _ __ 
  \___ \\___ \|  _  /|  __|   | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ____) |___) | | \ \| |____  | |__| |  __/ ||  __/ (__| || (_) | |   
 |_____/_____/|_|  \_\______| |_____/ \___|\__\___|\___|\__\___/|_|   
                                                                       
                Professional SSRF Detection Framework
                              Version %s
`
    fmt.Printf(banner, version)
    fmt.Println()
}

// printUsage prints usage information
func printUsage() {
    usage := `
SSRF Detector - Production-Grade SSRF and Open Redirect Detection

Usage:
  ssrfdetect -u <URL> -p <param> --oob-domain <domain> [options]

Required Arguments:
  -u, --url <URL>              Target URL to test
  -p, --param <name>           Parameter name to inject into
  --oob-domain <domain>        Out-of-band callback domain

Optional Arguments:
  --auth-level <level>         Authorization level: none|basic|full|exploit (default: none)
  --allow-internal             Allow internal IP testing (requires auth-level >= basic)
  --allow-cloud-metadata       Allow cloud metadata testing (requires auth-level >= basic)
  --allow-protocol-escalation  Allow protocol escalation (requires auth-level >= full)
  
  -o, --output <file>          Output file (default: stdout)
  -f, --format <format>        Report format: json|markdown|csv (default: json)
  -v, --verbose                Verbose output
  
  -h, --help                   Show this help message
  --version                    Show version

Authorization Levels:
  none     - External scanner-controlled resources only (safest)
  basic    - Bug bounty / external assessment (cloud metadata, public files)
  full     - Red team / internal assessment (internal services, protocol escalation)
  exploit  - Controlled environment (service manipulation)

Examples:
  # Basic SSRF detection (external only)
  ssrfdetect -u "https://example.com/fetch" -p url --oob-domain scanner.yourdomain.com

  # Bug bounty scan with cloud metadata detection
  ssrfdetect -u "https://target.com/api/import" -p source \
    --oob-domain oob.example.com \
    --auth-level basic \
    --allow-cloud-metadata \
    -o report.json -v

  # Full red team assessment
  ssrfdetect -u "https://internal.app/redirect" -p next \
    --oob-domain callbacks.redteam.com \
    --auth-level full \
    --allow-internal \
    --allow-cloud-metadata \
    --allow-protocol-escalation \
    -f markdown -o findings.md

  # Generate CSV for tracking
  ssrfdetect -u "https://app.example.com/fetch?url=test" -p url \
    --oob-domain oob.scanner.io \
    -f csv -o results.csv

Safety Notice:
  This tool performs active security testing. Ensure you have proper authorization
  before scanning any target. Unauthorized testing may be illegal.

Documentation:
  https://github.com/example/ssrf-detector
`
    fmt.Println(usage)
}