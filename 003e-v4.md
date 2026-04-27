# 003e — Integration test for stdio channel

## Goal

Replace `integration_prototype_test.go` with an integration test that exercises pidchain end-to-end the way Claude Desktop exercises the prototype probe: a caller binary launches a probe binary as a stdio child, the probe binary calls pidchain to fingerprint its launcher, the caller captures the JSON output. The test runs this three times against the same probe binary and asserts the three fingerprints are identical.

The prototype was wrong on two counts: it self-execed a single binary as both sides (so no real on-disk probe binary existed), and v1–v3 of this doc inverted the import direction (parent imported pidchain instead of the spawned child). Both errors are corrected here.

This doc covers stdio only. The probe binary it specifies is shared infrastructure: 003f (Darwin UDS) and 003g (Windows named pipe) reuse the same probe binary with different channel-specific PID-acquisition mechanisms.

## Files

- DELETE: `integration_prototype_test.go`
- CREATE: `pidchain_stdio_integration_test.go`
- CREATE: `testdata/integration/probe/main.go` (the shared probe binary)

The probe binary lives under `testdata/integration/probe/` rather than `testdata/integration/stdio/probe/` because it is the same binary across all three channels. The channel is selected via a `--channel` flag.

The `testdata/` directory is ignored by `go build` and `go list ./...`, so the probe `main` package does not pollute the module's build surface and never ships to consumers. It is a test fixture, not an auxiliary CLI — the 001b "no CLIs, no auxiliary binaries" rule is about shipped artifacts and does not apply to test fixtures under `testdata/`.

## Implementation

### The probe binary

`testdata/integration/probe/main.go` is the on-disk binary the test calls. It imports pidchain. On startup, it identifies the PID it should fingerprint based on the `--channel` flag, calls both `pidchain.Chain(pid)` and `pidchain.Fingerprint(pid)`, and writes the result to stdout as JSON.

For stdio, the PID source is `os.Getppid()` — the binary's parent IS the caller, the same way the prototype probe identifies Claude Desktop via `os.Getppid()`. The 003f and 003g flag handlers will be added when those docs land; for 003e only `--channel=stdio` is implemented.

```go
// Command probe is a test fixture for pidchain integration tests.
// It calls pidchain against a PID acquired via the channel selected by
// --channel, then writes the resulting Chain and Fingerprint to stdout
// as JSON.
//
// For --channel=stdio, the PID is os.Getppid() — the process that
// launched this binary via fork+exec. This mirrors the the prototype probe
// pattern: Claude Desktop launches the prototype probe; the prototype probe calls
// pidchain to identify Claude Desktop.
//
// Exit codes: 0 on success; 2 for any helper-side error (unknown channel,
// JSON encode failure).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

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

func main() {
	channel := flag.String("channel", "stdio", "PID acquisition channel: stdio (003e), uds (003f), namedpipe (003g)")
	flag.Parse()

	var callerPID int
	switch *channel {
	case "stdio":
		callerPID = os.Getppid()
	default:
		fmt.Fprintf(os.Stderr, "probe: unsupported channel %q (003f/003g not yet implemented)\n", *channel)
		os.Exit(2)
	}

	out := probeOutput{Channel: *channel, CallerPID: callerPID}

	chain, chainErr := pidchain.Chain(callerPID)
	out.Chain = chain
	if chainErr != nil {
		out.ChainErr = chainErr.Error()
	}

	fp, fpErr := pidchain.Fingerprint(callerPID)
	out.Fingerprint = fp
	if fpErr != nil {
		out.FpErr = fpErr.Error()
	}

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "probe: encode: %v\n", err)
		os.Exit(2)
	}
}
```

`encoding/json` will use Go field names by default for `pidchain.ProcessChain` and `pidchain.ProcessInfo` — those types carry no struct tags and **must not have any added** (they are public API surface; tagging them is a breaking change). The `probeOutput` wrapper carries its own JSON tags because it is local to this fixture.

The probe calls both `Chain` and `Fingerprint` separately rather than using `Chain(...).Fingerprint`. `Fingerprint` is the public function the relay project-style consumers will actually call; the test exercises it directly so any divergence between `Chain(...).Fingerprint` and `Fingerprint(...)` surfaces as a test failure.

### The integration test

`pidchain_stdio_integration_test.go` builds the probe binary into `t.TempDir()`, runs it three times via `exec.Command` (the same mechanism Claude Desktop uses to launch the prototype probe), captures stdout each run, and asserts the three runs produced identical fingerprints.

Pidchain's existing tests use `runtime.GOOS` checks plus `t.Skip` rather than `//go:build` constraints. The integration test follows the same convention: no `//go:build integration` tag, runs alongside the unit tests, skips at runtime on platforms other than darwin and windows. The `TestIntegration_*` name prefix signals intent. Build-tag rationale is recorded in memory as PC-Decision-2026-04-26-build-tag-deferred and applies project-wide.

```go
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
```

The probe is the spawned child. The test process is its parent. When the probe calls `pidchain.Chain(os.Getppid())`, the PID it passes is the test process's PID. So the fingerprint the probe produces is a fingerprint of the test process's ancestry. Across three runs of the same probe binary in the same test invocation, the test process's ancestry is unchanged, so the fingerprints must be identical. That equality is the headline assertion.

### Why `package pidchain_test` (black-box)

The test verifies the public API only — `pidchain.Chain`, `pidchain.Fingerprint`, `pidchain.ProcessChain`. It does not need access to internals. Per `docs/go-test-patterns.md` and the project's existing `pidchain_test.go`, black-box is the default for public-API tests.

### Why a shared probe binary across channels

The probe binary's job is "identify my caller via the named channel and emit the result." How the caller arrived (stdio fork+exec, UDS connection, named pipe connection) is the test client's concern, but the PID acquisition for that channel and the subsequent pidchain call belong in the probe. Putting them in one binary means:

- One binary to build, sign, and reason about.
- The cross-channel determinism property — "the same caller produces the same fingerprint regardless of channel" — becomes testable in a future doc by running the same probe across two channels and comparing.
- 003f and 003g become small additions: a new `case` in the channel switch and a new test file. No new probe binary.

For 003e the probe only knows `--channel=stdio`. Other values exit 2 with a clear message. 003f adds `--channel=uds --socket=<path>`; 003g adds `--channel=namedpipe --pipe=<name>`.

## Success Criteria

1. `integration_prototype_test.go` no longer exists.
2. `pidchain_stdio_integration_test.go` exists, has no `//go:build` tag, and skips at runtime on platforms other than darwin/windows.
3. `testdata/integration/probe/main.go` exists, imports pidchain, and supports `--channel=stdio` (other channel values exit 2).
4. On macOS: `go test -run TestIntegration_Stdio_ProbeFingerprintsCaller ./...` passes.
5. On Windows: `go test -run TestIntegration_Stdio_ProbeFingerprintsCaller ./...` passes.
6. On Linux: `go test ./...` still passes — the integration test skips at runtime and the existing unit tests' `ErrPlatformUnsupported` coverage is unchanged.
7. The test asserts fingerprint equality across **three** runs of the probe binary launched by the same test process (determinism — the headline contract).
8. The test asserts at least one chain entry has a non-empty `BundleIdentifier` (codesign path fired against on-disk binary).
9. The test asserts `pidchain.Fingerprint(pid)` equals `pidchain.Chain(pid).Fingerprint` for each run (the two public functions agree).

## Out of Scope

- Unix domain socket channel (Darwin, `LOCAL_PEERPID`). Specified in 003f. Will add `--channel=uds` to the same probe binary.
- Windows named pipe channel (`GetNamedPipeClientProcessId`). Specified in 003g. Will add `--channel=namedpipe` to the same probe binary.
- Linux integration test. Linux returns `ErrPlatformUnsupported`; the existing unit tests cover that.
- Cross-channel determinism (asserting the same caller produces the same fingerprint regardless of channel). Possible follow-up once 003f and 003g land.
- Codesigning the probe binary with a real developer certificate. The Go linker produces an adhoc signature on Darwin by default, sufficient to populate `BundleIdentifier` on the probe's own entry and on enough ancestors to satisfy assertion (8).
- Changes to `internal/walker/` or the public API. This is a test-only change.
- Changes to CI workflows. The existing `.github/workflows/ci.yml` runs `go test ./...` on the per-OS matrix established in 002g; the new test runs in that same step without modification.
- JSON struct tags on `pidchain.ProcessInfo` / `pidchain.ProcessChain`. These are part of the public API and must not be modified.
- Adopting `unit`/`integration` build tags repo-wide. See PC-Decision-2026-04-26-build-tag-deferred in memory.
