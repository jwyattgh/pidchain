//go:build windows

package walker

/*
#include <wchar.h>
extern int pidchain_codesign_diag(const wchar_t* path);
*/

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
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

func TestWindowsPlatform_CodesignSystemBinary(t *testing.T) {
	const path = `C:\Windows\System32\notepad.exe`

	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not present at %s: %v", path, err)
	}

	wpath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	diag := int(C.pidchain_codesign_diag((*C.wchar_t)(unsafe.Pointer(wpath))))

	p := windowsPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: path})

	allEmpty := info.TeamID == "" && info.BundleIdentifier == "" && info.AuthorityLeaf == ""

	switch diag {
	case 0:
		if allEmpty {
			t.Fatalf("pidchain_codesign_diag reports success but Codesign returned empty fields: team=%q bundle=%q auth=%q",
				info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
		}
	case 1:
		t.Fatalf("file disappeared between os.Stat and CGo call (race): %s", path)
	case 2:
		t.Fatalf("notepad.exe has no embedded Authenticode signature (likely catalog-signed); pidchain.Codesign cannot extract identity from this binary on this Windows version. diag=2")
	case 3:
		t.Fatalf("notepad.exe has an embedded signature but signer info is unreadable. diag=3")
	case 4:
		t.Fatalf("notepad.exe signer info present but signer cert not found in embedded store. diag=4")
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
