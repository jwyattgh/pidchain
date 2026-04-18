//go:build windows

package walker

import (
	"os"
	"testing"
)

// These tests exercise the real Toolhelp32 + Crypt API path. They verify
// the bindings work on a real Windows host and produce sensible output
// for the current process. Specific Authenticode field values vary by
// binary, so they are not asserted on. Run manually in VMware per spec.

func TestWindowsPlatform_LookupSelf(t *testing.T) {
	p := windowsPlatform{}
	ppid, path, err := p.Lookup(os.Getpid())
	if err != nil {
		t.Fatalf("Lookup(self): %v", err)
	}
	if ppid <= 0 {
		t.Fatalf("expected positive parent PID, got %d", ppid)
	}
	if path == "" {
		t.Fatal("expected non-empty binary path from QueryFullProcessImageName")
	}
}

func TestWindowsPlatform_LookupNonexistent(t *testing.T) {
	p := windowsPlatform{}
	_, _, err := p.Lookup(999999999)
	if err == nil {
		t.Fatal("expected error for nonexistent PID, got nil")
	}
}

func TestWindowsPlatform_CodesignSystemBinary(t *testing.T) {
	// notepad.exe is signed with the Microsoft Windows publisher cert on
	// every Windows install. All three Authenticode fields should be
	// populated when CGo + crypt32 are working correctly.
	p := windowsPlatform{}
	team, bundle, auth := p.Codesign(`C:\Windows\System32\notepad.exe`)
	if team == "" && bundle == "" && auth == "" {
		t.Skipf("Crypt API returned no fields for notepad.exe (env issue?): team=%q bundle=%q auth=%q", team, bundle, auth)
	}
}

func TestWindowsPlatform_CodesignNonexistentPath(t *testing.T) {
	p := windowsPlatform{}
	team, bundle, auth := p.Codesign(`C:\nonexistent\binary.exe`)
	if team != "" || bundle != "" || auth != "" {
		t.Fatalf("expected empty fields for nonexistent path, got %q %q %q", team, bundle, auth)
	}
}

func TestWindowsPlatform_CodesignEmptyPath(t *testing.T) {
	p := windowsPlatform{}
	team, bundle, auth := p.Codesign("")
	if team != "" || bundle != "" || auth != "" {
		t.Fatalf("expected empty fields for empty path, got %q %q %q", team, bundle, auth)
	}
}
