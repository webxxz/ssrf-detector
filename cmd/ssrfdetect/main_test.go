package main

import (
	"os"
	"testing"
)

func TestParseArgsAutoDiscoverAndTargetsFile(t *testing.T) {
	file, err := os.CreateTemp("", "targets-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	content := "# comment\nhttps://example.com/fetch?url=test\nhttps://example.com/path/segment\n"
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	file.Close()

	config, targets, err := parseArgs([]string{
		"--targets-file", file.Name(),
		"--oob-domain", "oob.example.com",
		"--auto-discover",
	})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if config == nil {
		t.Fatal("expected config")
	}
	if len(targets) == 0 {
		t.Fatal("expected discovered targets from targets file")
	}
}

func TestParseArgsRequiresParamWithoutAutoDiscover(t *testing.T) {
	_, _, err := parseArgs([]string{
		"-u", "https://example.com/fetch?url=test",
		"--oob-domain", "oob.example.com",
	})
	if err == nil {
		t.Fatal("expected error when param missing without auto discover")
	}
}
