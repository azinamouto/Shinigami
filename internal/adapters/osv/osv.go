// Package osv adapts OSV-Scanner v2 JSON reports into metadata-only findings.
package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Finding contains advisory and dependency metadata, not source code.
type Finding struct {
	VulnerabilityID string
	Package         string
	Version         string
	Ecosystem       string
	File            string
}

type report struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
			Groups []struct {
				IDs []string `json:"ids"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ParseReport accepts OSV-Scanner v2 JSON and rejects malformed or oversized reports.
// Both per-package vulnerabilities and grouped IDs are supported; duplicates are removed.
func ParseReport(data []byte) ([]Finding, error) {
	if len(data) > 16<<20 {
		return nil, errors.New("osv report exceeds 16 MiB")
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("empty osv report")
	}
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid osv JSON: %w", err)
	}
	// Do not treat unexpected schemas (or empty objects) as clean scans.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return nil, errors.New("invalid osv report object")
	}
	if _, ok := top["results"]; !ok {
		return nil, errors.New("osv report missing results")
	}
	if string(top["results"]) == "null" {
		return nil, errors.New("osv report has null results")
	}
	findings := make([]Finding, 0)
	seen := make(map[string]bool)
	for _, result := range r.Results {
		for _, p := range result.Packages {
			ids := make([]string, 0, len(p.Vulnerabilities))
			for _, v := range p.Vulnerabilities {
				ids = append(ids, v.ID)
			}
			for _, group := range p.Groups {
				if len(group.IDs) > 0 {
					ids = append(ids, group.IDs[0])
				}
			}
			for _, id := range ids {
				if id == "" || p.Package.Name == "" {
					continue
				}
				f := Finding{VulnerabilityID: id, Package: p.Package.Name, Version: p.Package.Version, Ecosystem: p.Package.Ecosystem, File: result.Source.Path}
				key := f.VulnerabilityID + "\x00" + f.Package + "\x00" + f.Version + "\x00" + f.Ecosystem + "\x00" + f.File
				if !seen[key] {
					findings = append(findings, f)
					seen[key] = true
				}
			}
		}
	}
	return findings, nil
}

// Scan uses the OSV-Scanner v2 source scan command. This adapter can make
// network requests through OSV-Scanner; do not use it as an offline guarantee.
func Scan(ctx context.Context, root string) ([]Finding, error) {
	binary, err := exec.LookPath("osv-scanner")
	if err != nil {
		return nil, errors.New("osv-scanner executable not found in PATH (v2 required)")
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
	dir, err := os.MkdirTemp("", "shinigami-osv-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	reportPath := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	// Avoid call-analysis of source projects: toolchains/build scripts are not run by this adapter.
	cmd := exec.CommandContext(ctx, binary, "scan", "source", "--recursive", "--no-call-analysis=go", "--format=json", "--output-file", reportPath, root)
	// No stdout/stderr forwarding: paths and dependency metadata can be sensitive.
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("osv scan cancelled or timed out: %w", ctx.Err())
	}
	if err != nil {
		var exit *exec.ExitError
		// OSV-Scanner v2 exits 1 when vulnerabilities are present.
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return nil, errors.New("osv scanner execution failed (output redacted)")
		}
	}
	f, readErr := os.Open(reportPath)
	if readErr != nil {
		return nil, errors.New("osv report missing or unreadable")
	}
	defer f.Close()
	data, readErr := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if readErr != nil {
		return nil, errors.New("osv report read failed")
	}
	return ParseReport(data)
}
