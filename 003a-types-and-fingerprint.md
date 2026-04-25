# 003a — Move Types and Fingerprint to internal

## Goal

Move all structs and error sentinels into `internal/types/types.go`. Move the SHA256 fingerprint computation from `pidchain.go` into `internal/walker/walker.go`. Extend the chain struct in types.go with a `Fingerprint` field that walker populates. Reduce `pidchain.go` to two functions that call walker and return what walker returns.

## Files

- CREATE: `internal/types/types.go`
- CHANGE: `internal/walker/walker.go`
- CHANGE: `internal/walker/walker_darwin.go`
- CHANGE: `internal/walker/walker_windows.go`
- CHANGE: `internal/walker/walker_other.go`
- CHANGE: `pidchain.go`
- CHANGE: `internal/walker/walker_test.go`
- CHANGE: `pidchain_internal_test.go`

## Implementation

### `internal/types/types.go` (new)

```go
package types

import "errors"

type ProcessInfo struct {
	PID              int
	ParentPID        int
	BinaryPath       string
	TeamID           string
	BundleIdentifier string
	AuthorityLeaf    string
}

type ProcessChain struct {
	Entries     []ProcessInfo
	Fingerprint string
}

var (
	ErrPlatformUnsupported = errors.New("pidchain: platform not supported")
	ErrProcessDead         = errors.New("pidchain: process not found")
	ErrMaxDepthExceeded    = errors.New("pidchain: walk exceeded max depth")
)
```

### `internal/walker/walker.go` (change)

- Delete the local `Entry` struct (lines 21-28).
- Delete the local sentinel declarations (lines 14-18).
- Add import `github.com/jwyattgh/pidchain/internal/types`.
- Replace `Entry` with `types.ProcessInfo` everywhere.
- Replace `ErrPlatformUnsupported`, `ErrProcessDead`, `ErrMaxDepthExceeded` with `types.ErrPlatformUnsupported`, etc.
- Change `Walk`'s signature to `func Walk(startPID int) (types.ProcessChain, error)`.
- Compute SHA256 in the walk loop and write the hex string into the returned `ProcessChain.Fingerprint`.

```go
func Walk(startPID int) (types.ProcessChain, error) {
	p := New()
	result := types.ProcessChain{Entries: make([]types.ProcessInfo, 0, 8)}
	h := sha256.New()
	current := startPID

	for len(result.Entries) < MaxDepth {
		ppid, path, err := p.Lookup(current)
		if err != nil {
			if len(result.Entries) == 0 {
				if errors.Is(err, types.ErrPlatformUnsupported) {
					return types.ProcessChain{}, types.ErrPlatformUnsupported
				}
				return types.ProcessChain{}, types.ErrProcessDead
			}
			result.Fingerprint = hex.EncodeToString(h.Sum(nil))
			return result, nil
		}

		teamID, bundleID, authority := p.Codesign(path)
		result.Entries = append(result.Entries, types.ProcessInfo{
			PID:              current,
			ParentPID:        ppid,
			BinaryPath:       path,
			TeamID:           teamID,
			BundleIdentifier: bundleID,
			AuthorityLeaf:    authority,
		})
		h.Write([]byte(teamID))
		h.Write([]byte(bundleID))
		h.Write([]byte(authority))

		if ppid == 0 || current == 1 {
			result.Fingerprint = hex.EncodeToString(h.Sum(nil))
			return result, nil
		}
		current = ppid
	}

	result.Fingerprint = hex.EncodeToString(h.Sum(nil))
	return result, types.ErrMaxDepthExceeded
}
```

Imports needed in walker.go: `crypto/sha256`, `encoding/hex`, `errors`, `github.com/jwyattgh/pidchain/internal/types`.

### `internal/walker/walker_darwin.go` (change)

Replace unqualified `ErrProcessDead` with `types.ErrProcessDead` at lines 103 and 111. Add `github.com/jwyattgh/pidchain/internal/types` to imports.

### `internal/walker/walker_windows.go` (change)

Replace unqualified `ErrProcessDead` with `types.ErrProcessDead` at lines 149, 156, 163. Add `github.com/jwyattgh/pidchain/internal/types` to imports.

### `internal/walker/walker_other.go` (change)

Replace unqualified `ErrPlatformUnsupported` with `types.ErrPlatformUnsupported` at line 12. Add `github.com/jwyattgh/pidchain/internal/types` to imports.

### `pidchain.go` (change)

Replace the entire file with:

```go
// Package pidchain returns kernel-attested process ancestry and a stable
// fingerprint over the ancestors' code-signing identities.
package pidchain

import (
	"github.com/jwyattgh/pidchain/internal/types"
	"github.com/jwyattgh/pidchain/internal/walker"
)

var (
	ErrPlatformUnsupported = types.ErrPlatformUnsupported
	ErrProcessDead         = types.ErrProcessDead
	ErrMaxDepthExceeded    = types.ErrMaxDepthExceeded
)

func Fingerprint(pid int) (string, error) {
	chain, err := walker.Walk(pid)
	return chain.Fingerprint, err
}

func Chain(pid int) (types.ProcessChain, error) {
	return walker.Walk(pid)
}
```

Removed: `ProcessInfo`, `ProcessChain` (local declarations), `build`, `translateWalkerErr`, all crypto/errors imports.

### `internal/walker/walker_test.go` (change)

- Add import `github.com/jwyattgh/pidchain/internal/types`.
- Replace bare sentinel references (`ErrProcessDead`, `ErrPlatformUnsupported`, `ErrMaxDepthExceeded`) with `types.ErrProcessDead`, etc.
- Update every `chain, err := Walk(...)` to `chain, err := Walk(...)` where `chain` is now `types.ProcessChain`. Tests that read `chain[0].PID` become `chain.Entries[0].PID`. Tests that check `len(chain)` become `len(chain.Entries)`. Tests that compare `chain != nil` become `chain.Entries != nil`.

### `pidchain_internal_test.go` (change)

- Delete `TestTranslateWalkerErr_PlatformUnsupported`, `TestTranslateWalkerErr_ProcessDead`, `TestTranslateWalkerErr_PassthroughUnknown` — `translateWalkerErr` no longer exists.
- Delete `TestBuild_MaxDepthExceeded_ReturnsChainAndFingerprint` and `maxDepthFake` — `build` no longer exists.
- In `simpleChainFake.Lookup`, replace `walker.ErrProcessDead` with `types.ErrProcessDead`. Add `github.com/jwyattgh/pidchain/internal/types` to imports.
- In `TestChain_SuccessPathViaFake`, update field access: `chain[0].PID` becomes `chain.Entries[0].PID`, `len(chain)` becomes `len(chain.Entries)`.

## Success Criteria

1. `go build ./...` succeeds on linux, darwin, windows.
2. `go test ./...` passes on every platform.
3. `Fingerprint(pid)` returns the same hex string for the same ancestry as today.
4. `Chain(pid).Entries` contains the same per-ancestor data as today's `Chain(pid)`.

## Out of Scope

- Renaming `ErrProcessDead` to match its message.
