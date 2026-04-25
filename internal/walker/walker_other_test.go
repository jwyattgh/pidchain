//go:build !darwin && !windows

package walker

import (
	"errors"
	"testing"
)

// TestUnsupportedPlatform_NewReturnsUnsupported exercises the New closure
// installed by walker_other.go's init(). On unsupported platforms, calling
// New() must return an unsupportedPlatform value.
func TestUnsupportedPlatform_NewReturnsUnsupported(t *testing.T) {
	orig := New
	t.Cleanup(func() { New = orig })
	New = orig
	if _, ok := New().(unsupportedPlatform); !ok {
		t.Fatalf("New() returned %T, want unsupportedPlatform", New())
	}
}

func TestUnsupportedPlatform_LookupReturnsErrPlatformUnsupported(t *testing.T) {
	p := unsupportedPlatform{}
	_, _, err := p.Lookup(1)
	if !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("want ErrPlatformUnsupported, got %v", err)
	}
}

func TestUnsupportedPlatform_CodesignReturnsEmpty(t *testing.T) {
	p := unsupportedPlatform{}
	info := p.Codesign(ProcessInfo{BinaryPath: "/anything"})
	if info.TeamID != "" || info.BundleIdentifier != "" || info.AuthorityLeaf != "" {
		t.Fatalf("want all empty fields, got team=%q bundle=%q auth=%q",
			info.TeamID, info.BundleIdentifier, info.AuthorityLeaf)
	}
}
