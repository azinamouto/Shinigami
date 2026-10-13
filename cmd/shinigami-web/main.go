// Shinigami local-only dashboard API. Start with: go run ./cmd/shinigami-web
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/azinamouto/shinigami/internal/adapters/gitleaks"
	"github.com/azinamouto/shinigami/internal/adapters/osv"
	"github.com/azinamouto/shinigami/internal/report/sarif"
	"github.com/azinamouto/shinigami/internal/scanner"
)

const version = "0.2.0-dev"

type scanRequest struct {
	Path   string `json:"path"`
	Engine string `json:"engine"`
}
type scanResponse struct {
	Path     string            `json:"path"`
	Engine   string            `json:"engine"`
	At       string            `json:"at"`
	Count    int               `json:"count"`
	Findings []scanner.Finding `json:"findings"`
}
type api struct {
	mu      sync.Mutex
	running bool
	latest  *scanResponse
}

func (a *api) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (a *api) fail(w http.ResponseWriter, status int, msg string) {
	a.json(w, status, map[string]string{"error": msg})
}
func (a *api) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.fail(w, 405, "method not allowed")
		return
	}
	var req scanRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.fail(w, 400, "invalid scan request")
		return
	}
	switch req.Engine {
	case "native", "gitleaks", "osv", "all":
	default:
		a.fail(w, 400, "unsupported scanner")
		return
	}
	if req.Path == "" {
		a.fail(w, 400, "repository path is required")
		return
	}
	path, err := filepath.Abs(req.Path)
	if err != nil {
		a.fail(w, 400, "invalid repository path")
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		a.fail(w, 400, "repository directory not found")
		return
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		a.fail(w, 409, "a scan is already running")
		return
	}
	a.running = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.running = false; a.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	findings := make([]scanner.Finding, 0)
	if req.Engine == "native" || req.Engine == "all" {
		var f []scanner.Finding
		f, err = scanner.Scan(path)
		if err == nil {
			findings = append(findings, f...)
		}
	}
	if err == nil && (req.Engine == "gitleaks" || req.Engine == "all") {
		var fs []gitleaks.Finding
		fs, err = gitleaks.Scan(ctx, path)
		if err == nil {
			for _, f := range fs {
				rel := relative(path, f.File)
				id := sha256.Sum256([]byte("gitleaks:" + f.RuleID + ":" + rel + ":" + f.Fingerprint))
				findings = append(findings, scanner.Finding{ID: hex.EncodeToString(id[:8]), Rule: "GITLEAKS/" + f.RuleID, Severity: "HIGH", File: rel, Line: f.Line, Message: "Potential exposed credential", Remediation: "Rotate the credential if real, remove it from tracked files, and review history."})
			}
		}
	}
	if err == nil && (req.Engine == "osv" || req.Engine == "all") {
		var fs []osv.Finding
		fs, err = osv.Scan(ctx, path)
		if err == nil {
			for _, f := range fs {
				rel := relative(path, f.File)
				id := sha256.Sum256([]byte("osv:" + f.VulnerabilityID + ":" + f.Ecosystem + ":" + f.Package + ":" + f.Version + ":" + rel))
				findings = append(findings, scanner.Finding{ID: hex.EncodeToString(id[:8]), Rule: "OSV/" + f.VulnerabilityID, Severity: "UNKNOWN", File: rel, Line: 0, Message: "Known vulnerability in " + f.Ecosystem + " dependency " + f.Package + "@" + f.Version, Remediation: "Review https://osv.dev/vulnerability/" + f.VulnerabilityID + " and update the dependency."})
			}
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			a.fail(w, 504, "scan cancelled or timed out")
		} else {
			a.fail(w, 500, "scan failed; check scanner installation and target")
		}
		return
	}
	result := &scanResponse{Path: path, Engine: req.Engine, At: time.Now().UTC().Format(time.RFC3339), Count: len(findings), Findings: findings}
	a.mu.Lock()
	a.latest = result
	a.mu.Unlock()
	a.json(w, 200, result)
}
func relative(root, path string) string {
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		return filepath.ToSlash(filepath.Clean(path))
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}
func (a *api) latestScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.fail(w, 405, "method not allowed")
		return
	}
	a.mu.Lock()
	v := a.latest
	a.mu.Unlock()
	if v == nil {
		a.json(w, 200, map[string]any{"scan": nil})
		return
	}
	a.json(w, 200, map[string]any{"scan": v})
}
func (a *api) export(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.fail(w, 405, "method not allowed")
		return
	}
	format := r.URL.Query().Get("format")
	if format != "json" && format != "sarif" {
		a.fail(w, 400, "invalid report format")
		return
	}
	a.mu.Lock()
	v := a.latest
	a.mu.Unlock()
	if v == nil {
		a.fail(w, 404, "no completed scan")
		return
	}
	var b []byte
	var err error
	if format == "sarif" {
		b, err = sarif.Encode(v.Findings, version)
	} else {
		b, err = json.MarshalIndent(v, "", "  ")
	}
	if err != nil {
		a.fail(w, 500, "report encoding failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=shinigami-results.%s", map[string]string{"json": "json", "sarif": "sarif"}[format]))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
func (a *api) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.fail(w, 405, "method not allowed")
		return
	}
	a.mu.Lock()
	running := a.running
	a.mu.Unlock()
	a.json(w, 200, map[string]any{"version": version, "running": running, "mode": "localhost"})
}
func main() {
	a := &api{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", a.status)
	mux.HandleFunc("/api/scan", a.scan)
	mux.HandleFunc("/api/latest", a.latestScan)
	mux.HandleFunc("/api/export", a.export)
	// Explicitly deny cross-origin browser requests. Vite forwards same-origin /api requests.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://127.0.0.1:5173" && origin != "http://localhost:5173" {
			a.fail(w, 403, "cross-origin requests are not allowed")
			return
		}
		mux.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:8787")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Shinigami local API listening at http://127.0.0.1:8787")
	log.Fatal(http.Serve(ln, handler))
}
