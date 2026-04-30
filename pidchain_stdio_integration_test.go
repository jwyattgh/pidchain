package pidchain_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jwyattgh/pidchain"
)

func TestIntegration_Stdio_ProbeFingerprintsCaller(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("integration test requires a supported platform (darwin or windows)")
	}

	probeBin := buildProbe(t)

	run1 := runProbe(t, probeBin)
	run2 := runProbe(t, probeBin)
	run3 := runProbe(t, probeBin)

	if b, err := json.MarshalIndent(redactChain(run1, filepath.Dir(probeBin)), "", "  "); err == nil {
		t.Logf("chain:\n%s", b)
	}

	for i, c := range []pidchain.ProcessChain{run1, run2, run3} {
		if len(c.Fingerprint) != 64 {
			t.Fatalf("run %d: fingerprint length: got %d want 64", i+1, len(c.Fingerprint))
		}
		if len(c.Entries) == 0 {
			t.Fatalf("run %d: chain has no entries", i+1)
		}
	}

	if run1.Fingerprint != run2.Fingerprint {
		t.Fatalf("fingerprints differ between run 1 and run 2:\n run1=%s\n run2=%s",
			run1.Fingerprint, run2.Fingerprint)
	}
	if run2.Fingerprint != run3.Fingerprint {
		t.Fatalf("fingerprints differ between run 2 and run 3:\n run2=%s\n run3=%s",
			run2.Fingerprint, run3.Fingerprint)
	}

	sawBundle := false
	for _, e := range run1.Entries {
		if e.BundleIdentifier != "" {
			sawBundle = true
			break
		}
	}
	if !sawBundle {
		t.Errorf("no entry has a non-empty BundleIdentifier; codesign path did not fire against any on-disk binary in the ancestry\n entries=%+v", run1.Entries)
	}
}

// buildProbe compiles the shared probe binary into t.TempDir() and
// returns its path. exeSuffix handles Windows .exe.
func buildProbe(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "probe"+exeSuffix())
	cmd := exec.Command("go", "build", "-o", out, "./testdata/integration/probe")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build probe: %v\n%s", err, combined)
	}
	return out
}

// runProbe executes the probe binary and decodes its stdout as a
// pidchain.ProcessChain. The probe calls pidchain.Chain(os.Getpid()),
// so the returned chain is rooted at the probe binary itself and walks
// up through this test process and its ancestors.
func runProbe(t *testing.T, probeBin string) pidchain.ProcessChain {
	t.Helper()
	cmd := exec.Command(probeBin)
	stdout, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("probe exited %d: stderr=%s", ee.ExitCode(), ee.Stderr)
		}
		t.Fatalf("probe run: %v", err)
	}
	var chain pidchain.ProcessChain
	if err := json.Unmarshal(stdout, &chain); err != nil {
		t.Fatalf("decode probe stdout: %v\n stdout=%s", err, stdout)
	}
	return chain
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// redactPath replaces host-specific path prefixes with stable
// placeholders so the chain log can be shared without leaking
// $HOME, $TMPDIR, or the test's per-run temp dir. Longest-match
// first: the test's temp dir is typically a descendant of
// os.TempDir().
func redactPath(p, testTempDir string) string {
	if p == "" {
		return p
	}
	if testTempDir != "" && strings.HasPrefix(p, testTempDir) {
		return "$TEMPDIR" + strings.TrimPrefix(p, testTempDir)
	}
	if td := os.TempDir(); td != "" && strings.HasPrefix(p, td) {
		return "$TMPDIR" + strings.TrimPrefix(p, td)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(p, home) {
		return "$HOME" + strings.TrimPrefix(p, home)
	}
	return p
}

// redactChain returns a copy of c with each entry's BinaryPath
// run through redactPath. The original c is unchanged so the
// existing assertions stay accurate against unredacted data.
func redactChain(c pidchain.ProcessChain, testTempDir string) pidchain.ProcessChain {
	out := pidchain.ProcessChain{
		Entries:     make([]pidchain.ProcessInfo, len(c.Entries)),
		Fingerprint: c.Fingerprint,
	}
	for i, e := range c.Entries {
		e.BinaryPath = redactPath(e.BinaryPath, testTempDir)
		out.Entries[i] = e
	}
	return out
}
