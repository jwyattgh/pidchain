package pidchain

import (
	"errors"
	"testing"

	"github.com/jwyattgh/pidchain/internal/walker"
)

// White-box tests for unexported helpers and build() error paths that the
// external public tests cannot reach on every platform.

func TestTranslateWalkerErr_PlatformUnsupported(t *testing.T) {
	if got := translateWalkerErr(walker.ErrPlatformUnsupported); !errors.Is(got, ErrPlatformUnsupported) {
		t.Fatalf("want ErrPlatformUnsupported, got %v", got)
	}
}

func TestTranslateWalkerErr_ProcessDead(t *testing.T) {
	if got := translateWalkerErr(walker.ErrProcessDead); !errors.Is(got, ErrProcessDead) {
		t.Fatalf("want ErrProcessDead, got %v", got)
	}
}

func TestTranslateWalkerErr_PassthroughUnknown(t *testing.T) {
	custom := errors.New("walker: unexpected")
	if got := translateWalkerErr(custom); got != custom {
		t.Fatalf("want passthrough of custom error, got %v", got)
	}
}

// maxDepthFake is a walker.Platform that reports an infinite linear chain
// with fully-populated codesign fields at every position. Used to drive
// walker.Walk past MaxDepth so build() returns ErrMaxDepthExceeded with a
// populated chain and fingerprint.
type maxDepthFake struct{}

func (maxDepthFake) Lookup(pid int) (int, string, error) {
	return pid + 1, "/x", nil
}

func (maxDepthFake) Codesign(string) (string, string, string) {
	return "T", "B", "A"
}

func TestBuild_MaxDepthExceeded_ReturnsChainAndFingerprint(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return maxDepthFake{} }
	t.Cleanup(func() { walker.New = orig })

	chain, fp, err := build(1000)
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("want ErrMaxDepthExceeded, got %v", err)
	}
	if len(chain) != walker.MaxDepth {
		t.Fatalf("chain length: got %d want %d", len(chain), walker.MaxDepth)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: got %d want 64", len(fp))
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
	return 0, "", walker.ErrProcessDead
}

func (simpleChainFake) Codesign(path string) (string, string, string) {
	return "TEAM", "bundle." + path, "Authority"
}

func TestFingerprint_SuccessPathViaFake(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return simpleChainFake{} }
	t.Cleanup(func() { walker.New = orig })

	fp, err := Fingerprint(100)
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

	chain, err := Chain(100)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length: got %d want 2", len(chain))
	}
	if chain[0].PID != 100 || chain[1].PID != 50 {
		t.Fatalf("walk order wrong: %+v", chain)
	}
}
