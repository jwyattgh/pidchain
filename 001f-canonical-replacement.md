# 001f: Replace canonical format with single-walk build

## Context

pidchain's current implementation walks the ancestry once per public call, then serialises the result through `internal/canonical/` into a hand-rolled binary format — length prefix, NUL field separators, record separators, NUL-validation pass — before hashing. The format was lifted from the prototype probe, which is prototype validation code explicitly marked in memory as "scratch validation code slated for deletion" (Project-PidChain, observation #2). It was inherited into the shipped library without being redesigned for pidchain's needs.

Two consequences:

1. **Format overhead.** The `canonical.Bytes` path does more than the library needs. None of the length prefix, NUL separators, NUL-validation, or two-pass structure is load-bearing. A straight concatenation of the three codesign fields per ancestor, in walk order, fed to SHA256, produces a stable fingerprint with the same security properties.

2. **Drift surface between the two public functions.** `Fingerprint(pid)` calls `Chain(pid)`, which calls `walker.Walk`. `Fingerprint` then builds its own `[]canonical.Ancestor` from the chain and hashes it. The two functions do not share a code path — they just happen to call the same walker twice (if a caller uses both) and both happen to use the same canonical helper. The test `TestPublicAPIConsistency` exists to catch drift between them, which is the signal that the design leaves drift possible.

The G115 gosec finding on `uint32(len(chain))` in `canonical.go:54` is a symptom: the conversion exists only because the length prefix exists, the length prefix exists only because the format was copied from prototype code. Fixing the symptom in isolation preserves the disease.

## Goal

Replace the `internal/canonical/` serialisation with a single internal `build` function that does one kernel walk, assembles the hash input directly from `walker.Entry` fields, produces both the chain and the fingerprint, and returns both. `Fingerprint` and `Chain` become thin wrappers over `build`, guaranteeing they can never diverge.

Eliminate `internal/canonical/` entirely. Eliminate the G115 finding as a side effect.

Preserve the existing public API shape and behaviour: same function signatures, same error sentinels, same error semantics (partial chain + `ErrMaxDepthExceeded` pair, `ErrProcessDead` on start-PID failure, `ErrPlatformUnsupported` on unsupported OS).

Preserve the chain-content decision in `PC-Decision-2026-04-17-full-chain-fingerprint`: every ancestor contributes, per-ancestor fields are exactly (TeamID, BundleIdentifier, AuthorityLeaf), no `start_time`, no version tag.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/pidchain.go` |
| EDIT | `/Users/jason/workspace/pidchain/pidchain_test.go` |
| DELETE | `/Users/jason/workspace/pidchain/internal/canonical/canonical.go` |
| DELETE | `/Users/jason/workspace/pidchain/internal/canonical/canonical_test.go` |
| DELETE | `/Users/jason/workspace/pidchain/internal/canonical/` (empty directory) |

No changes to `walker.go`, `walker_darwin.go`, `walker_windows.go`, `walker_other.go`, or `doc.go`. No changes to `go.mod` — the standard library covers everything needed.

## Implementation

### `pidchain.go` — new shape

Replace the current file contents. The new file has:

**Imports.** Drop `"github.com/jwyattgh/pidchain/internal/canonical"`. Keep `crypto/sha256`, `encoding/hex`, `errors`, and `github.com/jwyattgh/pidchain/internal/walker`.

**Exported symbols.** Unchanged: `ErrPlatformUnsupported`, `ErrProcessDead`, `ErrMaxDepthExceeded`, `ProcessChain`, `ProcessInfo`, `Fingerprint`, `Chain`.

**Internal `build` function.**

```go
// build does one kernel walk and returns both the chain and its
// fingerprint. Fingerprint and Chain are thin wrappers that each expose
// one of the two values. Sharing this code path makes divergence between
// the two public functions structurally impossible.
func build(pid int) (ProcessChain, string, error) {
    entries, walkErr := walker.Walk(pid)
    if walkErr != nil && !errors.Is(walkErr, walker.ErrMaxDepthExceeded) {
        return nil, "", translateWalkerErr(walkErr)
    }

    chain := make(ProcessChain, len(entries))
    h := sha256.New()
    for i, e := range entries {
        chain[i] = ProcessInfo{
            PID:              e.PID,
            ParentPID:        e.ParentPID,
            BinaryPath:       e.BinaryPath,
            TeamID:           e.TeamID,
            BundleIdentifier: e.BundleIdentifier,
            AuthorityLeaf:    e.AuthorityLeaf,
        }
        h.Write([]byte(e.TeamID))
        h.Write([]byte(e.BundleIdentifier))
        h.Write([]byte(e.AuthorityLeaf))
    }
    fp := hex.EncodeToString(h.Sum(nil))

    if errors.Is(walkErr, walker.ErrMaxDepthExceeded) {
        return chain, fp, ErrMaxDepthExceeded
    }
    return chain, fp, nil
}
```

**`Fingerprint`.**

```go
func Fingerprint(pid int) (string, error) {
    _, fp, err := build(pid)
    if err != nil && !errors.Is(err, ErrMaxDepthExceeded) {
        return "", err
    }
    return fp, err
}
```

**`Chain`.**

```go
func Chain(pid int) (ProcessChain, error) {
    chain, _, err := build(pid)
    if err != nil && !errors.Is(err, ErrMaxDepthExceeded) {
        return nil, err
    }
    return chain, err
}
```

**`translateWalkerErr`.** Unchanged.

**Doc comments on `Fingerprint` and `Chain`.** Preserve the existing wording verbatim. The comments describe the contract, not the implementation; the contract is unchanged.

### Hash input layout

For a chain of N ancestors, SHA256 is computed over the concatenation, in walk order (index 0 first), of:

```
TeamID[0] || BundleIdentifier[0] || AuthorityLeaf[0] ||
TeamID[1] || BundleIdentifier[1] || AuthorityLeaf[1] ||
...
TeamID[N-1] || BundleIdentifier[N-1] || AuthorityLeaf[N-1]
```

No length prefix, no separators, no validation pass. Empty fields contribute zero bytes.

**Known collision.** Two chains that differ only in how the same total bytes are distributed across field boundaries — e.g. `("AB", "", "C")` at one position versus `("A", "BC", "")` at the same position — produce identical hash input. In the codesign data produced by Security.framework and the Windows Crypt API, this cannot occur in practice: the fields carry structurally distinct content (Team IDs are 10 alphanumeric chars, BundleIdentifiers are reverse-DNS, AuthorityLeaf is a subject-summary string with "Developer ID" or similar prefixes). They do not interchange. Accepting this means not adding separator characters we would otherwise have no reason to introduce.

**Stability guarantee.** The hash input is fully determined by the three-field content of each ancestor in walk order. Any change to any ancestor's codesign data produces a different fingerprint. The same ancestry produces the same fingerprint on every call, across restarts, across library rebuilds (no version tag means no rebuild can change the input format).

### `pidchain_test.go` — update

The existing test file uses `canonical.Ancestor` and `canonical.Bytes` in `TestPublicAPIConsistency` to verify that `Fingerprint(pid)` equals `hex(sha256(canonical.Bytes(Chain(pid))))`. After this change, `canonical` is gone; the consistency test must be rewritten.

**New `TestPublicAPIConsistency`.** Verify that `Fingerprint(pid)` equals the SHA256 of the directly concatenated codesign fields of `Chain(pid)`. Shape:

```go
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
    for _, p := range chain {
        h.Write([]byte(p.TeamID))
        h.Write([]byte(p.BundleIdentifier))
        h.Write([]byte(p.AuthorityLeaf))
    }
    want := hex.EncodeToString(h.Sum(nil))

    if fp != want {
        t.Fatalf("Fingerprint != hex(sha256(concat(Chain fields))):\n Fingerprint: %s\n Computed:    %s", fp, want)
    }
}
```

Drop the `"github.com/jwyattgh/pidchain/internal/canonical"` import from `pidchain_test.go`.

All other tests in `pidchain_test.go` remain unchanged: they test the public surface (error sentinels, self-fingerprint shape, self-chain shape, determinism across calls, identity-field stability), which this change preserves.

### Delete `internal/canonical/`

Remove `canonical.go`, `canonical_test.go`, and the empty directory. The package has no remaining callers once `pidchain.go` is updated.

## Success criteria

1. `go build ./...` succeeds on macOS, Windows, and Linux.
2. `go test ./...` passes on macOS and Windows. Linux legs continue to exercise only the unsupported-platform branch.
3. `TestPublicAPIConsistency` passes with the rewritten assertion.
4. `TestFingerprint_Self_Deterministic` still passes — same PID produces the same fingerprint across two calls within the same test run.
5. `TestChain_Self_IdentityFieldsStable` still passes — two `Chain` calls return identical codesign fields at every position.
6. `golangci-lint run` reports zero findings. The G115 finding at `internal/canonical/canonical.go:54` is gone because the file is gone.
7. `go tool cover -func=coverage.out` on macOS shows total coverage ≥ 88%. Deleting `canonical` removes some denominator; `build` adds less numerator than was removed. Verify locally; if coverage drops below threshold, the fix is more tests on `build`, not lowering the threshold.
8. The `internal/canonical/` directory does not exist in the repo after this change.

## Out of scope

- **The four other CI failures in 001e.** Windows `go build` root cause, coverage-gate OS move, publish-test-results `contents: read`, and standalone-gosec SARIF upload. All of those are addressed in a separate pass. Two of them (G115-related, gosec SARIF) may resolve as side effects of this change; the other two do not depend on this work.
- **Walker changes.** `walker.go` and the per-OS walker files are untouched. The walk already returns exactly the data `build` needs.
- **Public API changes.** Signatures, types, error sentinels, error semantics all remain as currently documented in `doc.go` and as tested by the preserved tests.
- **Fingerprint-format changes that would invalidate stored fingerprints.** Any consumer that has paired against the current format would have its paired fingerprints invalidated by this change. This is unavoidable — the current format and the new format produce different bytes — but there are no paired consumers yet (pidchain has not been adopted). If adoption precedes this change, this becomes a breaking change worth naming in a release note.

## Verification before merging

1. `go build ./...` on macOS.
2. `go test ./...` on macOS — all supported-platform tests pass.
3. `golangci-lint run` — zero findings, in particular no G115.
4. `go tool cover` — coverage ≥ 88% on macOS.
5. Windows build + test in VMware Fusion Pro — confirms the Windows walker continues to work. (This is the same VMware step 001e already needs for a different failure; combining them is fine.)
6. `grep -r "internal/canonical" .` returns no matches outside this doc.
