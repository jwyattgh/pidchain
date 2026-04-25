//go:build darwin

package walker

import (
	"errors"
	"os"
	"testing"
)

func TestDarwinPlatform_NewReturnsDarwinPlatform(t *testing.T) {
	orig := New
	t.Cleanup(func() { New = orig })
	New = orig
	if _, ok := New().(darwinPlatform); !ok {
		t.Fatalf("New() returned %T, want darwinPlatform", New())
	}
}

// TestDarwinPlatform_CodesignDeveloperIDBinary exercises the TeamID-populated
// branch of Codesign. Ad-hoc platform binaries like /bin/ls leave TeamID
// empty; this test probes a short list of paths where Developer-ID signed
// binaries typically live. Skips if none are present — the branch stays
// uncovered in that environment, not a failure.
func TestDarwinPlatform_CodesignDeveloperIDBinary(t *testing.T) {
	candidates := []string{
		"/usr/local/bin/node",
		"/opt/homebrew/bin/node",
		"/opt/homebrew/bin/go",
		"/usr/local/go/bin/go",
		"/opt/homebrew/bin/brew",
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
	}
	p := darwinPlatform{}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		team, _, _ := p.Codesign(path)
		if team != "" {
			return
		}
	}
	t.Skip("no Developer-ID signed binary found at known paths; TeamID branch not exercised")
}

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

// TestDarwinPlatform_LookupKernelTerminator exercises the proc_pidinfo
// failure branch of Lookup. On macOS, an unprivileged caller's
// proc_pidpath(1) succeeds (returns "/sbin/launchd") but proc_pidinfo
// returns 0 because it can't read another process's bsdinfo without
// privilege. Skips when running as root.
func TestDarwinPlatform_LookupKernelTerminator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; proc_pidinfo(1) succeeds and the failure branch isn't exercised")
	}
	p := darwinPlatform{}
	_, _, err := p.Lookup(1)
	if !errors.Is(err, ErrProcessDead) {
		t.Fatalf("want ErrProcessDead from unprivileged Lookup(1), got %v", err)
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
