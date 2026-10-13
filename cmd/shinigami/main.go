package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/azinamouto/shinigami/internal/scanner"
	"os"
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
		format := cmd.String("format", "terminal", "terminal or json")
		failOn := cmd.Bool("fail-on-findings", false, "exit 1 if any findings are detected")
		cmd.Parse(os.Args[2:])
		if *format != "terminal" && *format != "json" {
			fmt.Fprintln(os.Stderr, "unsupported format")
			os.Exit(2)
		}
		target := "."
		if cmd.NArg() > 0 {
			target = cmd.Arg(0)
		}
		findings, err := scanner.Scan(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan failed:", err)
			os.Exit(2)
		}
		if *format == "json" {
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
	fmt.Fprintln(os.Stderr, "Usage: shinigami <scan|rules|version> [options]\n  scan [-format terminal|json] [-fail-on-findings] [directory]")
}
