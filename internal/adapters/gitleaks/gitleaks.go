// Package gitleaks adapts the external Gitleaks CLI to Shinigami findings.
package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Finding deliberately excludes secret-bearing Gitleaks fields such as Secret,
// Match and line content.
type Finding struct {
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Fingerprint string `json:"fingerprint"`
}

type rawFinding struct {
	RuleID      string `json:"RuleID"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Description string `json:"Description"`
	Fingerprint string `json:"Fingerprint"`
}

// ParseReport parses a bounded Gitleaks JSON report and drops sensitive fields.
func ParseReport(data []byte) ([]Finding, error) {
	if len(data) > 16<<20 {
		return nil, errors.New("gitleaks report exceeds 16 MiB")
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("empty gitleaks report")
	}
	var raw []rawFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid gitleaks report: %w", err)
	}
	findings := make([]Finding, 0, len(raw))
	for _, r := range raw {
		findings = append(findings, Finding{RuleID: r.RuleID, File: r.File, Line: r.StartLine, Description: r.Description, Fingerprint: r.Fingerprint})
	}
	return findings, nil
}

// Scan requires Gitleaks v8. It inspects the working tree, not Git history.
// Missing tools and unexpected exit codes fail closed; no repository scripts run.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	binary, err := exec.LookPath("gitleaks")
	if err != nil {
		return nil, errors.New("gitleaks executable not found in PATH")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("scan target must be a directory")
	}
	dir, err := os.MkdirTemp("", "shinigami-report-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	report := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "dir", "--no-banner", "--no-color", "--report-format", "json", "--report-path", report, root)
	// Never surface subprocess stdout/stderr: it may contain discovered secrets.
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("gitleaks scan cancelled or timed out: %w", ctx.Err())
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return nil, errors.New("gitleaks execution failed (output redacted)")
		}
	}
	data, readErr := os.ReadFile(report)
	if readErr != nil {
		if err == nil && os.IsNotExist(readErr) {
			return []Finding{}, nil
		}
		return nil, errors.New("gitleaks report missing or unreadable")
	}
	return ParseReport(data)
}
