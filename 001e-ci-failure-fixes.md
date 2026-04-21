# Fix CI failures from first 001d workflow run

## Context

The CI workflows created per doc 001d just ran on a push. Five distinct failures surfaced — each with a clear root cause, none of them a pidchain-source-code bug. The fixes are targeted edits to CI config and one bounds check in canonical.go. No architectural changes.

## Failures and root causes

### 1. Windows `go build` fails: "updates to go.mod needed; go mod tidy"

Go directive was lowered from `1.26.1` to `1.25`, which drifted go.mod/go.sum relative to the cached deps. `go mod tidy` aligns them.

### 2. Coverage gate: 68.9% vs 88% threshold

Gate runs on `ubuntu-latest` / Go 1.26. But on Linux, `walker_other.go` is the only walker implementation exercised — all the Darwin libproc + Security.framework code is excluded by build tags. Coverage drops because the majority of the walker package doesn't run.

The doc's calculation ("80/88 blocks = 90.9%") was measured on Darwin. Gating on Ubuntu measures a different denominator entirely.

### 3. Lint: gosec G115 in `internal/canonical/canonical.go:54`

```go
binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chain)))
```

gosec flags: `len()` returns `int`; on 64-bit, that can exceed `uint32` max. Walker caps at `MaxDepth=32` but canonical.go doesn't know that. Per global CLAUDE.md, `#nosec` is forbidden without explicit approval.

### 4. Security scan: `gosec.sarif` not created

`securego/gosec@master` exits non-zero when findings exist, aborting before the SARIF file is written. The subsequent upload step fails with "Path does not exist: gosec.sarif".

### 5. `publish-test-results`: 403 Forbidden on commit lookup

`EnricoMi/publish-unit-test-result-action@v2` calls the GitHub commits API and the default `GITHUB_TOKEN` lacks `contents: read`. Job only grants `checks: write` and `pull-requests: write`; with explicit permissions declared, other scopes default to `none`.

## Fixes

### File 1: `go.mod` and `go.sum`

Run `go mod tidy` locally; commit the resulting diff. Only expected change: go.mod/go.sum alignment with the 1.25 floor.

### File 2: `internal/canonical/canonical.go`

Add an explicit bounds guard before the conversion so gosec has proof the conversion is safe. No `#nosec`.

Approach: export a new error sentinel `ErrChainTooLong` and return it when `len(chain)` exceeds `math.MaxUint32`. Walker caps far below this in practice, but the guard satisfies gosec's static check and is a defensible runtime invariant for a library that commits to a stable canonical format.

```go
if len(chain) > math.MaxUint32 {
    return nil, ErrChainTooLong
}
binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chain)))
```

Add one canonical_test.go case exercising the error path if straightforward; skip if it requires absurd allocations.

### File 3: `.github/workflows/ci.yml`

Three edits:

1. **Move coverage gate + Codecov upload from ubuntu-latest to macos-latest.** Change both `if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'` lines to `matrix.os == 'macos-latest' && matrix.go-version == '1.26'`. Keeps "single leg to avoid duplicate reports" rationale, just on the OS that actually runs the walker code.

2. **Add `-no-fail` to gosec args.** Change `args: '-fmt sarif -out gosec.sarif ./...'` to `args: '-no-fail -fmt sarif -out gosec.sarif ./...'`. Lets SARIF upload succeed regardless of findings — GitHub's Security tab is the reporting surface, not CI pass/fail.

3. **Grant `contents: read` on `publish-test-results`.** Add to its `permissions:` block alongside the existing `checks: write` and `pull-requests: write`.

## Files touched

- `/Users/jason/workspace/pidchain/go.mod` — `go mod tidy` output
- `/Users/jason/workspace/pidchain/go.sum` — `go mod tidy` output
- `/Users/jason/workspace/pidchain/internal/canonical/canonical.go` — bounds check + new `ErrChainTooLong` sentinel
- `/Users/jason/workspace/pidchain/internal/canonical/canonical_test.go` — test for the bounds-check error path (if feasible)
- `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` — three small edits

## Out of scope

- Rethinking the coverage threshold value itself (88% stays; the gate just moves to the OS that exercises the covered code).
- README or doc changes.
- Memory updates.
- Revisiting the lint job's Go version.

## Verification

After edits, the user pushes and observes:
1. Windows test legs build successfully.
2. Ubuntu test legs still pass (they don't gate coverage).
3. macOS test legs pass the 88% gate.
4. Lint job passes (gosec G115 resolved by bounds check).
5. Security job uploads SARIF; findings visible in GitHub Security tab.
6. publish-test-results comments on the PR without 403.
