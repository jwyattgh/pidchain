package walker

import (
	"errors"
	"testing"
)

// fakePlatform is a test double satisfying Platform. Lookups and codesign
// data are served from maps; the test installs the fake via withPlatform.
type fakePlatform struct {
	lookups   map[int]lookupResult
	lookupErr map[int]error
	signs     map[string]signResult
}

type lookupResult struct {
	parentPID  int
	binaryPath string
}

type signResult struct {
	teamID, bundleID, authority string
}

func (f *fakePlatform) Lookup(pid int) (int, string, error) {
	if err, ok := f.lookupErr[pid]; ok {
		return 0, "", err
	}
	if l, ok := f.lookups[pid]; ok {
		return l.parentPID, l.binaryPath, nil
	}
	return 0, "", ErrProcessDead
}

func (f *fakePlatform) Codesign(path string) (string, string, string) {
	if s, ok := f.signs[path]; ok {
		return s.teamID, s.bundleID, s.authority
	}
	return "", "", ""
}

func withPlatform(t *testing.T, fake Platform) {
	t.Helper()
	orig := New
	New = func() Platform { return fake }
	t.Cleanup(func() { New = orig })
}

func TestWalk_LinearChainTerminatesAtPID1(t *testing.T) {
	fake := &fakePlatform{
		lookups: map[int]lookupResult{
			100: {parentPID: 50, binaryPath: "/a"},
			50:  {parentPID: 1, binaryPath: "/b"},
			1:   {parentPID: 0, binaryPath: "/sbin/launchd"},
		},
		signs: map[string]signResult{
			"/a":            {teamID: "T1", bundleID: "com.a", authority: "Leaf"},
			"/b":            {teamID: "T2", bundleID: "com.b", authority: "Leaf"},
			"/sbin/launchd": {teamID: "AAPL", bundleID: "com.apple.launchd", authority: "Apple Root CA"},
		},
	}
	withPlatform(t, fake)

	chain, err := Walk(100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length: got %d want 3", len(chain))
	}
	if chain[0].PID != 100 || chain[1].PID != 50 || chain[2].PID != 1 {
		t.Fatalf("walk order wrong: %+v", chain)
	}
	if chain[0].TeamID != "T1" || chain[2].BundleIdentifier != "com.apple.launchd" {
		t.Fatalf("codesign data not stitched in: %+v", chain)
	}
}

func TestWalk_StartPIDDeadReturnsErrProcessDead(t *testing.T) {
	fake := &fakePlatform{lookupErr: map[int]error{42: ErrProcessDead}}
	withPlatform(t, fake)

	chain, err := Walk(42)
	if !errors.Is(err, ErrProcessDead) {
		t.Fatalf("want ErrProcessDead, got %v", err)
	}
	if chain != nil {
		t.Fatalf("want nil chain on start-dead, got %+v", chain)
	}
}

func TestWalk_StartPIDPlatformUnsupportedSurfaces(t *testing.T) {
	fake := &fakePlatform{lookupErr: map[int]error{7: ErrPlatformUnsupported}}
	withPlatform(t, fake)

	chain, err := Walk(7)
	if !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("want ErrPlatformUnsupported, got %v", err)
	}
	if chain != nil {
		t.Fatalf("want nil chain, got %+v", chain)
	}
}

func TestWalk_AncestorDeadReturnsPartialChainNoError(t *testing.T) {
	fake := &fakePlatform{
		lookups:   map[int]lookupResult{10: {parentPID: 5, binaryPath: "/a"}},
		lookupErr: map[int]error{5: ErrProcessDead},
	}
	withPlatform(t, fake)

	chain, err := Walk(10)
	if err != nil {
		t.Fatalf("want nil error for mid-walk truncation, got %v", err)
	}
	if len(chain) != 1 || chain[0].PID != 10 {
		t.Fatalf("want single-entry partial chain, got %+v", chain)
	}
}

func TestWalk_ParentZeroTerminatesWithoutError(t *testing.T) {
	fake := &fakePlatform{
		lookups: map[int]lookupResult{99: {parentPID: 0, binaryPath: "/top"}},
	}
	withPlatform(t, fake)

	chain, err := Walk(99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 || chain[0].PID != 99 {
		t.Fatalf("unexpected chain: %+v", chain)
	}
}

func TestWalk_MaxDepthExceeded(t *testing.T) {
	fake := &fakePlatform{lookups: map[int]lookupResult{}}
	// Build a chain that never terminates: every PID's parent is PID+1.
	for i := 1000; i < 1000+MaxDepth+10; i++ {
		fake.lookups[i] = lookupResult{parentPID: i + 1, binaryPath: "/x"}
	}
	withPlatform(t, fake)

	chain, err := Walk(1000)
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("want ErrMaxDepthExceeded, got %v", err)
	}
	if len(chain) != MaxDepth {
		t.Fatalf("partial chain length: got %d want %d", len(chain), MaxDepth)
	}
}

func TestWalk_KernelTerminatorReachedMidwalk(t *testing.T) {
	// Models macOS's "proc_pidinfo returns 0 at PID 1" behavior: PID 1's
	// lookup fails, but PIDs above it succeed. The walker should return
	// the accumulated chain without an error.
	fake := &fakePlatform{
		lookups: map[int]lookupResult{
			500: {parentPID: 200, binaryPath: "/leaf"},
			200: {parentPID: 1, binaryPath: "/middle"},
		},
		lookupErr: map[int]error{1: ErrProcessDead},
	}
	withPlatform(t, fake)

	chain, err := Walk(500)
	if err != nil {
		t.Fatalf("kernel terminator should not be an error, got %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("want 2-entry partial chain (terminator excluded), got %d", len(chain))
	}
}
