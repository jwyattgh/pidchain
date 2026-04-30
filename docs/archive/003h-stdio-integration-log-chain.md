# 003h — Stdio integration test: log chain once per test

## Goal

Modify `pidchain_stdio_integration_test.go` so the test logs the `ProcessChain` (which includes its `Fingerprint`) once, viewable when the test is run with `go test -v`. Redact host-specific path prefixes before logging so the output is safe to share.

Save this doc to `docs/003h-stdio-integration-log-chain.md`.

## Files

- MODIFY: `pidchain_stdio_integration_test.go`
- UNCHANGED: everything else, including `testdata/integration/probe/main.go`, `internal/walker/`, `pidchain.go`.

## Implementation

### Redaction rules

Only `pidchain.ProcessInfo.BinaryPath` is redacted. Match prefixes longest-first:

1. `filepath.Dir(probeBin)` (the test's per-run temp dir) → `$TEMPDIR`
2. `os.TempDir()` → `$TMPDIR`
3. `os.UserHomeDir()` → `$HOME`

A path matching none is logged unchanged.

### Helpers

```go
// redactPath replaces host-specific path prefixes with stable
// placeholders. Longest-match-first: the test's temp dir is typically
// a descendant of os.TempDir().
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
// redacted. The original is unchanged so existing assertions still
// run on unredacted data.
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
```

New imports: `os`, `strings`.

`pidchain.ProcessInfo` and `pidchain.ProcessChain` carry no JSON struct tags and **must not have any added** (constraint inherited from 003e — public API surface; tagging is a breaking change). `json.MarshalIndent` will use Go field names, fine for a human-read log.

### Wiring

After `run1` is captured and before the existing assertion loop, log `run1.Chain` once:

```go
probeBin := buildProbe(t)

run1 := runProbe(t, probeBin)
run2 := runProbe(t, probeBin)
run3 := runProbe(t, probeBin)

if b, err := json.MarshalIndent(redactChain(run1.Chain, filepath.Dir(probeBin)), "", "  "); err == nil {
	t.Logf("chain:\n%s", b)
}

for i, r := range []probeOutput{run1, run2, run3} {
	// existing assertions, unchanged
}
```

`buildProbe`'s signature is unchanged. `filepath.Dir(probeBin)` recovers the temp dir.

## Success Criteria

1. `go test -run TestIntegration_Stdio_ProbeFingerprintsCaller -v ./...` on macOS prints exactly one chain log record, indented JSON, including the fingerprint.
2. Without `-v`, the test produces no chain output on success.
3. No path containing `$HOME`, `os.TempDir()`, or the test's temp dir appears in the logged output.
4. Existing assertions still pass and still operate on unredacted data.
5. `go test ./...` on Linux still passes.
6. The probe binary at `testdata/integration/probe/main.go` is unchanged.
7. No new module dependencies. Standard library only.

## Out of Scope

- A unit test for `redactPath`.
- Changing `buildProbe`'s signature.
- Logging more than one run.
- Redacting the probe's own stdout or `go build`'s `CombinedOutput` (failure paths only).
- Username substring redaction outside path prefixes.
- Redacting `TeamID`, `BundleIdentifier`, `AuthorityLeaf`, `PID`, `ParentPID`.
- Verbosity flags on the probe.
- Changes to UDS (003f) or named-pipe (003g) tests.
- Promoting helpers to a separate package.
- JSON struct tags on `pidchain.ProcessInfo` / `pidchain.ProcessChain`.
- Build tags. See `PC-Decision-2026-04-26-build-tag-deferred`.
