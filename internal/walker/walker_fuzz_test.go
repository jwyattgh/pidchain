package walker

import (
	"errors"
	"fmt"
	"testing"
)

// FuzzComputeFingerprint asserts the SHA256 invariants on arbitrary
// codesign field values: deterministic across calls, 64 lowercase hex
// chars. Fuzzing covers high-entropy strings (NUL bytes, multi-byte
// runes, very long values) that would be hard to enumerate as table
// cases.
func FuzzComputeFingerprint(f *testing.F) {
	f.Add("T1", "com.example.app", "Developer ID Application: Example")
	f.Add("", "", "")
	f.Add("Q6L2SF6YDW", "com.anthropic.claudefordesktop", "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)")
	f.Add("\x00", "\x00\x00", "\x00\x00\x00")

	f.Fuzz(func(t *testing.T, teamID, bundleID, authority string) {
		entries := []ProcessInfo{{
			TeamID:           teamID,
			BundleIdentifier: bundleID,
			AuthorityLeaf:    authority,
		}}
		fp1 := computeFingerprint(entries)
		fp2 := computeFingerprint(entries)
		if fp1 != fp2 {
			t.Fatalf("non-deterministic: %s vs %s", fp1, fp2)
		}
		if len(fp1) != 64 {
			t.Fatalf("length = %d, want 64", len(fp1))
		}
		for _, c := range fp1 {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-hex char %q in %s", c, fp1)
			}
		}
	})
}

// FuzzClassifyStartupErr asserts the classifier holds for arbitrarily
// wrapped errors: any chain containing ErrPlatformUnsupported maps to
// ErrPlatformUnsupported, every other chain maps to ErrProcessDead.
// Fuzzing covers pathological wrap messages (NUL, control chars, very
// long strings).
func FuzzClassifyStartupErr(f *testing.F) {
	f.Add("permission denied")
	f.Add("")
	f.Add("read /proc: input/output error")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, wrapMsg string) {
		plain := errors.New(wrapMsg)
		if got := classifyStartupErr(plain); !errors.Is(got, ErrProcessDead) {
			t.Fatalf("plain error %q: classified as %v, want ErrProcessDead", wrapMsg, got)
		}

		wrappedUnsupported := fmt.Errorf("%s: %w", wrapMsg, ErrPlatformUnsupported)
		if got := classifyStartupErr(wrappedUnsupported); !errors.Is(got, ErrPlatformUnsupported) {
			t.Fatalf("wrapped ErrPlatformUnsupported with %q: classified as %v, want ErrPlatformUnsupported", wrapMsg, got)
		}

		wrappedDead := fmt.Errorf("%s: %w", wrapMsg, ErrProcessDead)
		if got := classifyStartupErr(wrappedDead); !errors.Is(got, ErrProcessDead) {
			t.Fatalf("wrapped ErrProcessDead with %q: classified as %v, want ErrProcessDead", wrapMsg, got)
		}
	})
}
