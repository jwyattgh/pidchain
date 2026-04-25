# 003b — Tighten pidchain_test.go

## Goal

Apply four changes to `pidchain_test.go` based on review:
- Delete one test that exercises a Go language guarantee, not pidchain code.
- Delete one test that is strictly redundant with another.
- Strengthen one test that asserts shape but not data propagation.
- Add public-API coverage for the `ErrMaxDepthExceeded` path, which today is only covered at the walker level.

## Files

- CHANGE: `pidchain_test.go`

No other files affected.

## Implementation

### Delete `TestErrorSentinels_Distinct`

This test asserts the three sentinels are non-nil and don't alias each other. Go's `var X = errors.New(...)` already guarantees both. The test catches only typos like `ErrFoo = ErrBar`, which code review catches more reliably.

Delete the entire function.

### Delete `TestChain_Self_IdentityFieldsStable`

This test calls `Chain` twice and asserts every entry's `TeamID`, `BundleIdentifier`, and `AuthorityLeaf` is identical across calls. `TestFingerprint_Self_Deterministic` already covers the same regression: the fingerprint is a SHA256 over exactly those fields, so any drift in any field changes the fingerprint and fails that test.

Delete the entire function.

### Strengthen `TestChain_SuccessPathViaFake`

Today the test asserts `len(chain.Entries) == 2`, the two PIDs, and `len(chain.Fingerprint) == 64`. It does not verify that the codesign fields from `simpleChainFake.Codesign` actually reached the entries. A regression where walker dropped `TeamID` would not be caught.

Replace the existing assertions with:

```go
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
```

### Add `maxDepthFake` and two MaxDepth tests

Walker tests cover the MaxDepth path; the public API does not. If `pidchain.Fingerprint` ever regressed to returning `""` on `ErrMaxDepthExceeded` (instead of the partial fingerprint), the existing public tests would not catch it — they all use `&& !errors.Is(err, ErrMaxDepthExceeded)` to skip past that case.

Add a fake that produces an unterminating chain, plus two tests:

```go
// maxDepthFake produces an unterminating chain so the walker hits MaxDepth.
type maxDepthFake struct{}

func (maxDepthFake) Lookup(pid int) (int, string, error) {
	return pid + 1, "/x", nil
}

func (maxDepthFake) Codesign(string) (string, string, string) {
	return "T", "B", "A"
}

func TestFingerprint_MaxDepth_ReturnsPartialFingerprintAndError(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return maxDepthFake{} }
	t.Cleanup(func() { walker.New = orig })

	fp, err := pidchain.Fingerprint(1)
	if !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatalf("want ErrMaxDepthExceeded, got %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("want 64-char partial fingerprint, got %d chars: %q", len(fp), fp)
	}
}

func TestChain_MaxDepth_ReturnsPartialChainAndError(t *testing.T) {
	orig := walker.New
	walker.New = func() walker.Platform { return maxDepthFake{} }
	t.Cleanup(func() { walker.New = orig })

	chain, err := pidchain.Chain(1)
	if !errors.Is(err, pidchain.ErrMaxDepthExceeded) {
		t.Fatalf("want ErrMaxDepthExceeded, got %v", err)
	}
	if len(chain.Entries) != walker.MaxDepth {
		t.Fatalf("want %d entries on MaxDepth, got %d", walker.MaxDepth, len(chain.Entries))
	}
	if len(chain.Fingerprint) != 64 {
		t.Fatalf("want 64-char partial fingerprint, got %d chars", len(chain.Fingerprint))
	}
}
```

## Success Criteria

1. `go test ./...` passes on every supported platform.
2. `pidchain_test.go` no longer contains `TestErrorSentinels_Distinct` or `TestChain_Self_IdentityFieldsStable`.
3. `TestChain_SuccessPathViaFake` asserts every codesign field on every entry.
4. `TestFingerprint_MaxDepth_ReturnsPartialFingerprintAndError` and `TestChain_MaxDepth_ReturnsPartialChainAndError` exist and pass.

## Out of Scope

- Tests for `internal/walker` — already covered.
- Adding tests for any other gap not listed above.
