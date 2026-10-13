package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Finding struct {
	ID          string `json:"id"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}
type Rule struct {
	ID, Severity, Message, Remediation string
	Pattern                            *regexp.Regexp
}

var Rules = []Rule{
	{"SHI001", "HIGH", "Potentially unsafe TLS verification bypass", "Remove insecure TLS verification overrides and validate certificates.", regexp.MustCompile(`(?i)\binsecureSkipVerify\s*:\s*true\b`)},
	{"SHI002", "MEDIUM", "Debug mode explicitly enabled", "Disable debug mode in production configurations.", regexp.MustCompile(`(?i)\b(?:DEBUG|APP_DEBUG)\s*[:=]\s*(?:true|1)\b`)},
	{"SHI003", "HIGH", "Potentially permissive CORS configuration", "Restrict allowed origins to trusted domains.", regexp.MustCompile(`(?i)(?:access-control-allow-origin\s*[:=]\s*["']?\*|allow_origins\s*[:=]\s*\[\s*["']\*["']\s*\])`)},
	{"SHI004", "HIGH", "Potentially unsafe shell invocation", "Avoid shell execution with untrusted inputs; use argument arrays.", regexp.MustCompile(`(?i)\b(?:exec|spawn)\s*\([^\n]*\bshell\s*:\s*true\b`)},
}
var excluded = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".next": true, "coverage": true, ".venv": true}

func Scan(root string) ([]Finding, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "scan", Path: root, Err: fs.ErrInvalid}
	}
	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && (excluded[d.Name()] || strings.HasPrefix(d.Name(), ".git")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		reader := bufio.NewScanner(file)
		reader.Buffer(make([]byte, 64*1024), 1024*1024)
		line := 0
		for reader.Scan() {
			line++
			s := reader.Text()
			if strings.ContainsRune(s, '\x00') {
				break
			}
			for _, r := range Rules {
				if r.Pattern.MatchString(s) {
					sum := sha256.Sum256([]byte(r.ID + ":" + rel + ":" + strings.TrimSpace(s)))
					findings = append(findings, Finding{ID: hex.EncodeToString(sum[:8]), Rule: r.ID, Severity: r.Severity, File: rel, Line: line, Message: r.Message, Remediation: r.Remediation})
				}
			}
		}
		return reader.Err()
	})
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})
	return findings, err
}
