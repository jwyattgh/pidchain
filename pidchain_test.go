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
	if err != nil {
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
	if err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	b, err := pidchain.Fingerprint(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("fingerprint not deterministic across two calls: %s vs %s", a, b)
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
	if err != nil {
		t.Fatal(err)
	}
	fp, err := pidchain.Fingerprint(os.Getpid())
	if err != nil {
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

func (simpleChainFake) Codesign(info pidchain.ProcessInfo) pidchain.ProcessInfo {
	info.TeamID = "TEAM"
	info.BundleIdentifier = "bundle." + info.BinaryPath
	info.AuthorityLeaf = "Authority"
	return info
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

	want := []struct {
		pid       int
		team      string
		bundle    string
		authority string
	}{
		{pid: 100, team: "TEAM", bundle: "bundle./bin/app", authority: "Authority"},
		{pid: 50, team: "TEAM", bundle: "bundle./sbin/init", authority: "Authority"},
	}
	for i, w := range want {
		got := chain.Entries[i]
		if got.PID != w.pid {
			t.Errorf("entry %d PID: got %d want %d", i, got.PID, w.pid)
		}
		if got.TeamID != w.team {
			t.Errorf("entry %d TeamID: got %q want %q", i, got.TeamID, w.team)
		}
		if got.BundleIdentifier != w.bundle {
			t.Errorf("entry %d BundleIdentifier: got %q want %q", i, got.BundleIdentifier, w.bundle)
		}
		if got.AuthorityLeaf != w.authority {
			t.Errorf("entry %d AuthorityLeaf: got %q want %q", i, got.AuthorityLeaf, w.authority)
		}
	}
	if len(chain.Fingerprint) != 64 {
		t.Fatalf("fingerprint length: got %d want 64", len(chain.Fingerprint))
	}
}

// ExampleFingerprint demonstrates the typical server-side usage: obtain
// the peer PID via a kernel-attested mechanism, derive the fingerprint,
// compare against an ACL.
func ExampleFingerprint() {
	// In a real server, peerPID comes from the kernel — cmd.Process.Pid
	// for a spawned child, LOCAL_PEERPID for a UDS peer, etc. Here we
	// use the current process for illustration.
	peerPID := os.Getpid()

	fp, err := pidchain.Fingerprint(peerPID)
	if err != nil {
		// errors.Is(err, pidchain.ErrProcessDead),
		// errors.Is(err, pidchain.ErrPlatformUnsupported)
		_ = err
		return
	}

	// fp is a 64-character lowercase hex SHA256.
	_ = fp
	// Output:
}

// ExampleChain demonstrates the diagnostic / pairing-prompt usage: get
// the structured ancestor list to display to a human (or to log) before
// committing to store the corresponding fingerprint.
func ExampleChain() {
	chain, err := pidchain.Chain(os.Getpid())
	if err != nil {
		_ = err
		return
	}

	// chain.Entries is the ordered ancestry, queried PID first.
	// chain.Fingerprint is the same value Fingerprint() would return.
	for _, e := range chain.Entries {
		_ = e.BinaryPath
		_ = e.TeamID
		_ = e.BundleIdentifier
		_ = e.AuthorityLeaf
	}
	// Output:
}
