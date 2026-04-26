//go:build windows

package walker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPlatform_NewReturnsWindowsPlatform(t *testing.T) {
	orig := New
	t.Cleanup(func() { New = orig })
	New = orig
	if _, ok := New().(windowsPlatform); !ok {
		t.Fatalf("New() returned %T, want windowsPlatform", New())
	}
}

// TestWindowsPlatform_CodesignPathWithNullByte exercises the
// UTF16PtrFromString error branch. A Go string containing a null byte
// cannot round-trip to a null-terminated UTF-16 buffer, so Codesign must
// return empty fields without calling into the Crypt API.
func TestWindowsPlatform_CodesignPathWithNullByte(t *testing.T) {
	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: "C:\\Windows\\notepad\x00.exe"})
	if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
		t.Fatalf("expected empty fields for null-byte path, got %q %q %q",
			info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
	}
}

// TestWindowsPlatform_CodesignProbeSignedBinary covers the cTeam/cBundle/
// cAuth populated branches of Codesign by probing a few paths where
// Authenticode-signed binaries with embedded (not catalog) signatures are
// commonly present. Skips if none produce a non-empty signature field on
// this runner — the branches stay uncovered in that environment.
func TestWindowsPlatform_CodesignProbeSignedBinary(t *testing.T) {
	candidates := []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\calc.exe`,
		`C:\Windows\System32\notepad.exe`,
		`C:\Windows\explorer.exe`,
		`C:\Program Files\Git\bin\git.exe`,
	}
	p := windowsPlatform{}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		info := p.Codesign(ProcessInfo{BinaryPath: path})
		if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
			return
		}
	}
	t.Skip("no probed binary produced Authenticode fields on this runner; populated branches not exercised")
}

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

// TestWindowsPlatform_LookupSystemProcess exercises fullImagePath's
// OpenProcess-failure branch. PID 4 (System) always exists on Windows
// and is unprivileged-inaccessible, so OpenProcess fails for a normal
// caller and fullImagePath returns "". Lookup itself succeeds because
// Toolhelp32 enumerates System without needing the OpenProcess handle.
func TestWindowsPlatform_LookupSystemProcess(t *testing.T) {
	p := windowsPlatform{}
	_, path, err := p.Lookup(4)
	if err != nil {
		t.Fatalf("expected no error for System PID 4, got %v", err)
	}
	// Empty path is the documented signal that OpenProcess failed
	// (SYSTEM-owned ancestor, unprivileged caller). If running as
	// Administrator the path may be populated; either way exercises a
	// real path through fullImagePath.
	if path != "" {
		t.Logf("running with elevated access; PID 4 path=%q", path)
	}
}

func TestWindowsPlatform_CodesignSystemBinary(t *testing.T) {
	const path = `C:\Windows\System32\notepad.exe`

	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not present at %s: %v", path, err)
	}

	diag := codesignDiag(path)

	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: path})

	allEmpty := info.TeamID == "" && info.BundleIdentifier == "" && info.AuthorityLeaf == ""

	switch diag {
	case 0, 5:
		if allEmpty {
			t.Fatalf("diag reports success (%d) but Codesign returned empty fields: team=%q bundle=%q auth=%q",
				diag, info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
		}
	case 1:
		t.Fatalf("file disappeared between os.Stat and CGo call (race): %s", path)
	case 2:
		t.Fatalf("notepad.exe has no embedded Authenticode signature and no catalog match. diag=2")
	case 3:
		t.Fatalf("notepad.exe signer info is unreadable. diag=3")
	case 4:
		t.Fatalf("notepad.exe signer cert not found in store. diag=4")
	default:
		t.Fatalf("unknown diag code: %d", diag)
	}
}

func TestWindowsPlatform_CodesignNonexistentPath(t *testing.T) {
	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: `C:\nonexistent\binary.exe`})
	if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
		t.Fatalf("expected empty fields for nonexistent path, got %q %q %q",
			info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
	}
}

func TestWindowsPlatform_CodesignEmptyPath(t *testing.T) {
	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: ""})
	if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
		t.Fatalf("expected empty fields for empty path, got %q %q %q",
			info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
	}
}

// TestWindowsPlatform_CodesignUnsignedExistingFile exercises the
// catalog-no-match branch of pidchain_authenticode. The file exists on
// disk (so CryptQueryObject can open it and CreateFileW for the catalog
// hash succeeds), has no embedded Authenticode signature (it's not a PE),
// and won't match any installed catalog. This drives the embedded-failure
// path through find_catalog_file's success-through-hash-then-enum-fail
// branch and back out via rc != 0.
func TestWindowsPlatform_CodesignUnsignedExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "unsigned.bin")
	if err := os.WriteFile(path, []byte("not a binary"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: path})
	if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
		t.Fatalf("expected empty fields for unsigned file, got %q %q %q",
			info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
	}
}

// TestWindowsPlatform_CodesignDiag_UnsignedExistingFile asserts that
// pidchain_codesign_diag returns 2 (no embedded, no catalog) for a file
// that exists but is unsigned. Distinguishes "file missing" (diag=1) from
// "no signature found anywhere" (diag=2) explicitly.
func TestWindowsPlatform_CodesignDiag_UnsignedExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "unsigned.bin")
	if err := os.WriteFile(path, []byte("not a binary"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if diag := codesignDiag(path); diag != 2 {
		t.Fatalf("expected diag=2 (no embedded, no catalog), got %d", diag)
	}
}

// TestWindowsPlatform_CodesignDiag_NullBytePath exercises codesignDiag's
// UTF16PtrFromString error branch. A Go string with embedded null bytes
// cannot round-trip to a null-terminated UTF-16 buffer, so codesignDiag
// must return -1 without calling into CGo.
func TestWindowsPlatform_CodesignDiag_NullBytePath(t *testing.T) {
	if diag := codesignDiag("path\x00with\x00nulls"); diag != -1 {
		t.Fatalf("expected diag=-1 from invalid UTF-16 path, got %d", diag)
	}
}
