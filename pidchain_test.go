package pidchain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/jwyattgh/pidchain"
	"github.com/jwyattgh/pidchain/internal/walker"
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
	if chain.Entries != nil {
		t.Fatalf("want nil entries on error, got %+v", chain.Entries)
	}
	if chain.Fingerprint != "" {
		t.Fatalf("want empty fingerprint on error, got %q", chain.Fingerprint)
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
	if len(chain.Entries) == 0 {
		t.Fatal("expected non-empty chain for self")
	}
	if chain.Entries[0].PID != os.Getpid() {
		t.Fatalf("first entry PID: got %d want %d", chain.Entries[0].PID, os.Getpid())
	}
	if chain.Entries[0].BinaryPath == "" {
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
	if len(a.Entries) != len(b.Entries) {
		t.Fatalf("chain length changed across calls: %d vs %d", len(a.Entries), len(b.Entries))
	}
	for i := range a.Entries {
		if a.Entries[i].TeamID != b.Entries[i].TeamID ||
			a.Entries[i].BundleIdentifier != b.Entries[i].BundleIdentifier ||
			a.Entries[i].AuthorityLeaf != b.Entries[i].AuthorityLeaf {
			t.Fatalf("identity fields drifted at position %d:\n a=%+v\n b=%+v", i, a.Entries[i], b.Entries[i])
		}
	}
}

// TestPublicAPIConsistency proves the two public functions are internally
// consistent: Fingerprint(pid) equals hex(sha256(concat(Chain(pid) codesign
// fields))) for the same pid. They share one internal build path; this test
// catches any future divergence between the two wrappers.
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

	h := sha256.New()
	for _, p := range chain.Entries {
		h.Write([]byte(p.TeamID))
		h.Write([]byte(p.BundleIdentifier))
		h.Write([]byte(p.AuthorityLeaf))
	}
	want := hex.EncodeToString(h.Sum(nil))

	if fp != want {
		t.Fatalf("Fingerprint != hex(sha256(concat(Chain fields))):\n  Fingerprint: %s\n  Computed:    %s", fp, want)
	}
}

// simpleChainFake produces a short, well-terminated ancestry so tests can
// drive Fingerprint and Chain through their full success-return paths on
// every OS, including Linux where platform-specific integration tests skip.
type simpleChainFake struct{}

func (simpleChainFake) Lookup(pid int) (int, string, error) {
	switch pid {
	case 100:
		return 50, "/bin/app", nil
	case 50:
		return 0, "/sbin/init", nil
	}
	return 0, "", pidchain.ErrProcessDead
}

func (simpleChainFake) Codesign(path string) (string, string, string) {
	return "TEAM", "bundle." + path, "Authority"
}

func TestFingerprint_SuccessPathViaFake(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return simpleChainFake{} }
	t.Cleanup(func() { walker.New = orig })

	fp, err := pidchain.Fingerprint(100)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: got %d want 64", len(fp))
	}
}

func TestChain_SuccessPathViaFake(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return simpleChainFake{} }
	t.Cleanup(func() { walker.New = orig })

	chain, err := pidchain.Chain(100)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(chain.Entries) != 2 {
		t.Fatalf("chain length: got %d want 2", len(chain.Entries))
	}
	if chain.Entries[0].PID != 100 || chain.Entries[1].PID != 50 {
		t.Fatalf("walk order wrong: %+v", chain.Entries)
	}
	if len(chain.Fingerprint) != 64 {
		t.Fatalf("fingerprint length: got %d want 64", len(chain.Fingerprint))
	}
}
