#!/bin/bash

# SSRF Detector - Test Runner Script

set -e

echo "=== SSRF Detector Test Suite ==="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed"
    exit 1
fi

# Parse arguments
RUN_INTEGRATION=false
RUN_COVERAGE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--integration)
            RUN_INTEGRATION=true
            shift
            ;;
        -c|--coverage)
            RUN_COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-i|--integration] [-c|--coverage] [-v|--verbose]"
            exit 1
            ;;
    esac
done

# Unit tests
print_status "Running unit tests..."
echo ""

if [ "$VERBOSE" = true ]; then
    go test -v -race ./internal/... ./pkg/...
else
    go test -race ./internal/... ./pkg/...
fi

UNIT_TEST_STATUS=$?

if [ $UNIT_TEST_STATUS -eq 0 ]; then
    print_status "Unit tests passed ✓"
else
    print_error "Unit tests failed ✗"
    exit 1
fi

echo ""

# Integration tests
if [ "$RUN_INTEGRATION" = true ]; then
    print_status "Running integration tests..."
    echo ""
    
    if [ "$VERBOSE" = true ]; then
        go test -v -tags=integration ./test/integration/...
    else
        go test -tags=integration ./test/integration/...
    fi
    
    INTEGRATION_TEST_STATUS=$?
    
    if [ $INTEGRATION_TEST_STATUS -eq 0 ]; then
        print_status "Integration tests passed ✓"
    else
        print_error "Integration tests failed ✗"
        exit 1
    fi
    
    echo ""
fi

# Coverage
if [ "$RUN_COVERAGE" = true ]; then
    print_status "Generating coverage report..."
    echo ""
    
    go test -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -html=coverage.out -o coverage.html
    
    # Calculate coverage percentage
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
    
    print_status "Coverage: $COVERAGE"
    print_status "Report: coverage.html"
    
    # Open in browser if available
    if command -v xdg-open &> /dev/null; then
        xdg-open coverage.html &>/dev/null &
    elif command -v open &> /dev/null; then
        open coverage.html
    fi
    
    echo ""
fi

# Static analysis
print_status "Running static analysis..."
echo ""

# go vet
print_status "Running go vet..."
go vet ./...

if [ $? -eq 0 ]; then
    print_status "go vet passed ✓"
else
    print_error "go vet found issues ✗"
fi

echo ""

# golangci-lint if available
if command -v golangci-lint &> /dev/null; then
    print_status "Running golangci-lint..."
    golangci-lint run ./...
    
    if [ $? -eq 0 ]; then
        print_status "golangci-lint passed ✓"
    else
        print_warning "golangci-lint found issues"
    fi
else
    print_warning "golangci-lint not installed (optional)"
    echo "  Install: https://golangci-lint.run/usage/install/"
fi

echo ""

# Summary
print_status "Test Summary:"
echo "  Unit tests: ✓"
if [ "$RUN_INTEGRATION" = true ]; then
    echo "  Integration tests: ✓"
fi
if [ "$RUN_COVERAGE" = true ]; then
    echo "  Coverage: $COVERAGE"
fi
echo "  Static analysis: ✓"
echo ""

print_status "All tests passed!"