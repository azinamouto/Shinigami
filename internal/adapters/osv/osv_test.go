package osv

import (
	"strings"
	"testing"
)

func TestParseReport(t *testing.T) {
	raw := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"example.com/unsafe","version":"1.0.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GHSA-example-1234"}]}]}]}`
	got, err := ParseReport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VulnerabilityID != "GHSA-example-1234" || got[0].File != "go.mod" {
		t.Fatalf("unexpected findings: %+v", got)
	}
}
func TestParseReportRejectsInvalid(t *testing.T) {
	for _, s := range []string{"", `{}`, `{"results":null}`, `not-json`} {
		if _, err := ParseReport([]byte(s)); err == nil {
			t.Errorf("accepted invalid report %q", s)
		}
	}
	if _, err := ParseReport([]byte(strings.Repeat(" ", 16<<20+1))); err == nil {
		t.Error("accepted oversized report")
	}
}
func TestParseReportEmpty(t *testing.T) {
	got, err := ParseReport([]byte(`{"results":[]}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("expected clean scan, got %v, %v", got, err)
	}
}
