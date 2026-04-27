package pidchain_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jwyattgh/pidchain"
)

type probeOutput struct {
	Channel     string                `json:"channel"`
	CallerPID   int                   `json:"caller_pid"`
	Chain       pidchain.ProcessChain `json:"chain"`
	Fingerprint string                `json:"fingerprint"`
	ChainErr    string                `json:"chain_err,omitempty"`
	FpErr       string                `json:"fingerprint_err,omitempty"`
}

func TestIntegration_Stdio_ProbeFingerprintsCaller(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("integration test requires a supported platform (darwin or windows)")
	}

	probeBin := buildProbe(t)

	run1 := runProbe(t, probeBin)
	run2 := runProbe(t, probeBin)
	run3 := runProbe(t, probeBin)

	for i, r := range []probeOutput{run1, run2, run3} {
		if r.ChainErr != "" {
			t.Fatalf("run %d: probe reported Chain error: %s", i+1, r.ChainErr)
		}
		if r.FpErr != "" {
			t.Fatalf("run %d: probe reported Fingerprint error: %s", i+1, r.FpErr)
		}
		if len(r.Fingerprint) != 64 {
			t.Fatalf("run %d: fingerprint length: got %d want 64", i+1, len(r.Fingerprint))
		}
		if r.Fingerprint != r.Chain.Fingerprint {
			t.Fatalf("run %d: pidchain.Fingerprint(pid)=%s differs from pidchain.Chain(pid).Fingerprint=%s",
				i+1, r.Fingerprint, r.Chain.Fingerprint)
		}
		if len(r.Chain.Entries) == 0 {
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
	for _, e := range run1.Chain.Entries {
		if e.BundleIdentifier != "" {
			sawBundle = true
			break
		}
	}
	if !sawBundle {
		t.Errorf("no entry has a non-empty BundleIdentifier; codesign path did not fire against any on-disk binary in the ancestry\n entries=%+v", run1.Chain.Entries)
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

// runProbe executes the probe binary with --channel=stdio and decodes
// its stdout as probeOutput. Any non-zero exit, stderr, or decode
// failure fails the test. The probe is the spawned child; this test
// process is the caller whose PID the probe will fingerprint via
// os.Getppid().
func runProbe(t *testing.T, probeBin string) probeOutput {
	t.Helper()
	cmd := exec.Command(probeBin, "--channel=stdio")
	stdout, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("probe exited %d: stderr=%s", ee.ExitCode(), ee.Stderr)
		}
		t.Fatalf("probe run: %v", err)
	}
	var out probeOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode probe stdout: %v\n stdout=%s", err, stdout)
	}
	return out
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
