//go:build darwin

package walker

import (
	"os"
	"testing"
)

// These tests exercise the real libproc + Security.framework path. They
// verify the CGo bindings work and produce sensible output for the current
// process. They do not assert on specific TeamID/Authority values because
// those vary by who built the test binary.

func TestDarwinPlatform_LookupSelf(t *testing.T) {
	p := darwinPlatform{}
	ppid, path, err := p.Lookup(os.Getpid())
	if err != nil {
		t.Fatalf("Lookup(self): %v", err)
	}
	if ppid <= 0 {
		t.Fatalf("expected positive parent PID, got %d", ppid)
	}
	if path == "" {
		t.Fatal("expected non-empty binary path from kernel")
	}
}

func TestDarwinPlatform_LookupNonexistent(t *testing.T) {
	p := darwinPlatform{}
	_, _, err := p.Lookup(999999)
	if err == nil {
		t.Fatal("expected error for nonexistent PID, got nil")
	}
}

func TestDarwinPlatform_CodesignAdHocBinary(t *testing.T) {
	// /bin/ls is platform-signed (ad-hoc) on every Mac. Identifier is
	// reliably populated; TeamID may be empty (ad-hoc has no team).
	p := darwinPlatform{}
	team, bundle, auth := p.Codesign("/bin/ls")
	if bundle == "" && auth == "" && team == "" {
		t.Skipf("Security.framework returned no fields for /bin/ls (sandbox/TCC?): team=%q bundle=%q auth=%q", team, bundle, auth)
	}
}

func TestDarwinPlatform_CodesignNonexistentPath(t *testing.T) {
	p := darwinPlatform{}
	team, bundle, auth := p.Codesign("/nonexistent/binary")
	if team != "" || bundle != "" || auth != "" {
		t.Fatalf("expected empty fields for nonexistent path, got %q %q %q", team, bundle, auth)
	}
}

func TestDarwinPlatform_CodesignEmptyPath(t *testing.T) {
	p := darwinPlatform{}
	team, bundle, auth := p.Codesign("")
	if team != "" || bundle != "" || auth != "" {
		t.Fatalf("expected empty fields for empty path, got %q %q %q", team, bundle, auth)
	}
}
