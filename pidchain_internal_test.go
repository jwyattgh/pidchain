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
