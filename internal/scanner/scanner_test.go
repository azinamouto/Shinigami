package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.txt"), []byte("DEBUG=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "ignored.js"), []byte("DEBUG=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rule != "SHI002" {
		t.Fatalf("unexpected findings: %+v", got)
	}
}
func TestEmpty(t *testing.T) {
	got, err := Scan(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}
