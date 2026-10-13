package gitleaks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRedactsSecret(t *testing.T) {
	data := []byte(`[{"RuleID":"generic-api-key","File":"a.env","StartLine":4,"Description":"Credential","Fingerprint":"abc","Secret":"SYNTHETIC_PRIVATE_TOKEN","Match":"SYNTHETIC_PRIVATE_TOKEN"}]`)
	findings, err := ParseReport(data)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
	if strings.Contains(strings.TrimSpace(findings[0].Description), "SYNTHETIC_PRIVATE_TOKEN") {
		t.Fatal("secret leaked")
	}
	if strings.Contains(toJSON(t, findings), "SYNTHETIC_PRIVATE_TOKEN") {
		t.Fatal("serialized secret leaked")
	}
}
func TestMalformedReport(t *testing.T) {
	if _, err := ParseReport([]byte(`oops`)); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := ParseReport([]byte(``)); err == nil {
		t.Fatal("expected empty report error")
	}
}
func TestMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := Scan(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("missing tool must not count as clean")
	}
}
func TestScanFakeExecutable(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX fake executable fixture")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "gitleaks")
	source := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 if [ "$1" = "--report-path" ]; then shift; printf '[{"RuleID":"test","File":"file","StartLine":1,"Secret":"SYNTHETIC_PRIVATE_TOKEN"}]' > "$1"; fi
 shift
done
exit 1
`
	if err := os.WriteFile(script, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	found, err := Scan(context.Background(), t.TempDir())
	if err != nil || len(found) != 1 {
		t.Fatalf("findings=%v err=%v", found, err)
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
