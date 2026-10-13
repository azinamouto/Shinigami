package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/azinamouto/shinigami/internal/adapters/gitleaks"
	"github.com/azinamouto/shinigami/internal/adapters/osv"
	"github.com/azinamouto/shinigami/internal/scanner"
	"github.com/azinamouto/shinigami/internal/report/sarif"
	"os"
	"path/filepath"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("shinigami", version)
	case "rules":
		for _, r := range scanner.Rules {
			fmt.Printf("%s  %-6s %s\n", r.ID, r.Severity, r.Message)
		}
	case "scan":
		cmd := flag.NewFlagSet("scan", flag.ExitOnError)
		format := cmd.String("format", "terminal", "terminal, json, or sarif")
		engine := cmd.String("scanner", "native", "native, gitleaks, osv, or all")
		failOn := cmd.Bool("fail-on-findings", false, "exit 1 if any findings are detected")
		cmd.Parse(os.Args[2:])
		if *format != "terminal" && *format != "json" && *format != "sarif" {
			fmt.Fprintln(os.Stderr, "unsupported format")
			os.Exit(2)
		}
		target := "."
		if cmd.NArg() > 0 {
			target = cmd.Arg(0)
		}
		if *engine != "native" && *engine != "gitleaks" && *engine != "osv" && *engine != "all" {
			fmt.Fprintln(os.Stderr, "unsupported scanner")
			os.Exit(2)
		}
		var findings []scanner.Finding
		var err error
		if *engine == "native" || *engine == "all" {
			findings, err = scanner.Scan(target)
		}
		if err == nil && (*engine == "gitleaks" || *engine == "all") {
			var external []gitleaks.Finding
			external, err = gitleaks.Scan(context.Background(), target)
			if err == nil {
				for _, f := range external {
					rel := f.File
					if r, e := filepath.Rel(target, f.File); e == nil && r != "." && r != ".." && !filepath.IsAbs(r) && len(r) >= 2 && r[:2] != ".." {
						rel = r
					}
					fingerprint := sha256.Sum256([]byte("gitleaks:" + f.RuleID + ":" + rel + ":" + f.Fingerprint))
					findings = append(findings, scanner.Finding{ID: hex.EncodeToString(fingerprint[:8]), Rule: "GITLEAKS/" + f.RuleID, Severity: "HIGH", File: rel, Line: f.Line, Message: "Potential exposed credential", Remediation: "Rotate the credential if real, remove it from tracked files, and review history."})
				}
			}
		}
		if err == nil && (*engine == "osv" || *engine == "all") {
			var external []osv.Finding
			external, err = osv.Scan(context.Background(), target)
			if err == nil {
				for _, f := range external {
					fingerprint := sha256.Sum256([]byte("osv:" + f.VulnerabilityID + ":" + f.Ecosystem + ":" + f.Package + ":" + f.Version + ":" + f.File))
					findings = append(findings, scanner.Finding{ID: hex.EncodeToString(fingerprint[:8]), Rule: "OSV/" + f.VulnerabilityID, Severity: "UNKNOWN", File: f.File, Line: 0, Message: "Known vulnerability in " + f.Ecosystem + " dependency " + f.Package + "@" + f.Version, Remediation: "Review the advisory at https://osv.dev/vulnerability/" + f.VulnerabilityID + " and update or replace the affected dependency."})
				}
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan failed:", err)
			os.Exit(2)
		}
		if *format == "sarif" {
			data, encodeErr := sarif.Encode(findings, version)
			if encodeErr != nil {
				fmt.Fprintln(os.Stderr, "SARIF encoding failed:", encodeErr)
				os.Exit(2)
			}
			fmt.Println(string(data))
		} else if *format == "json" {
			out := struct {
				Version  string            `json:"version"`
				Findings []scanner.Finding `json:"findings"`
				Count    int               `json:"count"`
			}{version, findings, len(findings)}
			if out.Findings == nil {
				out.Findings = []scanner.Finding{}
			}
			_ = json.NewEncoder(os.Stdout).Encode(out)
		} else {
			fmt.Printf("Shinigami %s — %d potential finding(s)\n", version, len(findings))
			for _, f := range findings {
				fmt.Printf("[%s] %s:%d %s — %s\n", f.Severity, f.File, f.Line, f.Rule, f.Message)
			}
		}
		if *failOn && len(findings) > 0 {
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "Usage: shinigami <scan|rules|version> [options]\n  scan [-scanner native|gitleaks|osv|all] [-format terminal|json] [-fail-on-findings] [directory]")
}
