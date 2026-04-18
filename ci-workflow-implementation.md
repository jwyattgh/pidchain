# Implementation: GitHub Actions CI workflow

## Goal

Add a CI workflow that runs pidchain's tests on macOS, Windows, and Linux on every push and pull request. Closes the open follow-up from PC-Session-2026-04-18: `walker_windows_test.go` has never been exercised.

## File to create

`.github/workflows/ci.yml` — single workflow file, two jobs: a three-OS test matrix, and a Linux-only lint job.

## Workflow contents

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  test:
    name: Test
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache-dependency-path: go.sum

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test -race ./...

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache-dependency-path: go.sum

      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
            | sh -s -- -b $(go env GOPATH)/bin v2.6.2

      - name: Run golangci-lint
        run: golangci-lint run --timeout=5m
```

## Design notes

### Why a matrix, not separate jobs

The same steps (checkout, setup-go, build, vet, test) run on every OS. A matrix expresses this once; three parallel jobs would duplicate the step block three times.

### `fail-fast: false`

If Windows breaks, we still want to see whether macOS passed. The point of multi-OS CI is catching platform-specific regressions, so masking the other legs defeats the exercise.

### `go-version: '1.26'`

Tracks the `go` directive in `go.mod` (currently `go 1.26.1`). The bare `1.26` form selects the latest 1.26.x patch available in the setup-go cache, so patch bumps are picked up automatically.

### CGo on GitHub-hosted runners

No CGo configuration needed. Every runner ships with a C compiler and the SDKs pidchain's walker needs:

- `macos-latest`: Xcode Command Line Tools — clang, libproc headers, Security.framework.
- `windows-latest`: MinGW-w64 GCC and the Win32 SDK — `wincrypt.h` and the `crypt32` link library.
- `ubuntu-latest`: gcc — though `walker_other.go` imports no C so CGO_ENABLED is effectively don't-care for this leg.

`CGO_ENABLED=1` is the default when a compiler is present. Do not set it explicitly.

### `-race`

Both `Fingerprint` and `Chain` are documented as safe for concurrent use. `-race` catches any regression in that property. Cheap to run at pidchain's test count.

### Not included

- No Codecov upload or coverage gate. Premature until the test suite stabilizes.
- No binary build, no release workflow. pidchain is a library; there is no artifact.
- No gosec or Dependabot integration. Reasonable to add later; out of scope for this workflow.
- No status badge in `README.md` until the workflow is green at least once.
- No multi-Go-version matrix. Latest 1.26.x only.

### golangci-lint version pinned to v2.6.2

`@latest` would let a breaking golangci-lint release fail CI without a corresponding commit. Pinning forces the upgrade to be deliberate.

## Success criteria

On the first run of the workflow (on the PR that introduces it, or the first push after commit):

1. All three matrix legs of the `test` job complete successfully.
2. The macOS leg exercises `walker_darwin_test.go` against `/bin/ls`; all tests pass.
3. The Windows leg exercises `walker_windows_test.go` against `notepad.exe`; all tests pass. This is the first time these tests will have been run.
4. The Ubuntu leg exercises the unsupported-platform branch via `walker_other.go`; `TestUnsupportedPlatform_ReturnsErrPlatformUnsupported` passes.
5. The `lint` job completes with zero golangci-lint findings.
