package pidchain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/jwyattgh/pidchain"
	"github.com/jwyattgh/pidchain/internal/canonical"
)

func TestErrorSentinels_Distinct(t *testing.T) {
	all := []error{
		pidchain.ErrPlatformUnsupported,
		pidchain.ErrProcessDead,
		pidchain.ErrMaxDepthExceeded,
	}
	for i, a := range all {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Fatalf("sentinels %d and %d alias each other: %v / %v", i, j, a, b)
			}
		}
	}
}

func TestFingerprint_NonexistentPID_ReturnsErrProcessDead(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	_, err := pidchain.Fingerprint(999999999)
	if !errors.Is(err, pidchain.ErrProcessDead) {
		t.Fatalf("want ErrProcessDead, got %v", err)
	}
}

func TestChain_NonexistentPID_ReturnsErrProcessDead(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	chain, err := pidchain.Chain(999999999)
	if !errors.Is(err, pidchain.ErrProcessDead) {
		t.Fatalf("want ErrProcessDead, got %v", err)
	}
	if chain != nil {
		t.Fatalf("want nil chain, got %+v", chain)
	}
}

func TestUnsupportedPlatform_ReturnsErrPlatformUnsupported(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("supported platform; nothing to assert")
	}
	_, err := pidchain.Fingerprint(os.Getpid())
	if !errors.Is(err, pidchain.ErrPlatformUnsupported) {
		t.Fatalf("want ErrPlatformUnsupported, got %v", err)
	}
}

func TestFingerprint_Self_Integration(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	fp, err := pidchain.Fingerprint(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatalf("Fingerprint(self): %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64-char hex sha256, got %d chars: %q", len(fp), fp)
	}
	if _, decErr := hex.DecodeString(fp); decErr != nil {
		t.Fatalf("fingerprint is not lowercase hex: %v", decErr)
	}
}

func TestChain_Self_Integration(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	chain, err := pidchain.Chain(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatalf("Chain(self): %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("expected non-empty chain for self")
	}
	if chain[0].PID != os.Getpid() {
		t.Fatalf("first entry PID: got %d want %d", chain[0].PID, os.Getpid())
	}
	if chain[0].BinaryPath == "" {
		t.Fatal("first entry BinaryPath should be non-empty (kernel-attested)")
	}
}

func TestFingerprint_Self_Deterministic(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	a, err := pidchain.Fingerprint(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}
	b, err := pidchain.Fingerprint(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("fingerprint not deterministic across two calls: %s vs %s", a, b)
	}
}

func TestChain_Self_IdentityFieldsStable(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	a, err := pidchain.Chain(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}
	b, err := pidchain.Chain(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("chain length changed across calls: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].TeamID != b[i].TeamID ||
			a[i].BundleIdentifier != b[i].BundleIdentifier ||
			a[i].AuthorityLeaf != b[i].AuthorityLeaf {
			t.Fatalf("identity fields drifted at position %d:\n a=%+v\n b=%+v", i, a[i], b[i])
		}
	}
}

// TestPublicAPIConsistency proves the two public functions are internally
// consistent: Fingerprint(pid) equals hex(sha256(canonical.Bytes(Chain(pid))))
// for the same pid. They walk the same way and use the same canonical
// helper; this test would catch any future divergence.
func TestPublicAPIConsistency(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("requires a supported platform")
	}
	chain, err := pidchain.Chain(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}
	fp, err := pidchain.Fingerprint(os.Getpid())
	if err != nil && !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatal(err)
	}

	ancestors := make([]canonical.Ancestor, len(chain))
	for i, p := range chain {
		ancestors[i] = canonical.Ancestor{
			TeamID:           p.TeamID,
			BundleIdentifier: p.BundleIdentifier,
			AuthorityLeaf:    p.AuthorityLeaf,
		}
	}
	bytes, err := canonical.Bytes(ancestors)
	if err != nil {
		t.Fatalf("canonical.Bytes: %v", err)
	}
	sum := sha256.Sum256(bytes)
	want := hex.EncodeToString(sum[:])

	if fp != want {
		t.Fatalf("Fingerprint != hex(sha256(canonical(Chain))):\n  Fingerprint: %s\n  Computed:    %s", fp, want)
	}
}
