# Implementation: CI pipeline upgrade (v1 → public-release grade)

## Context

pidchain already has CI v1 on disk:

- `.github/workflows/ci.yml` — three-OS matrix (macOS / Windows / Ubuntu), single Go version (1.26), `go build` + `go vet` + `go test -race`, and a Linux-only `lint` job running golangci-lint v2.6.2.
- `ci-workflow-implementation.md` at the repo root — the design doc that produced v1.

v1 closed the most urgent gap: `walker_windows_test.go` is now exercised on every push. It is not yet the pipeline a publicly released Go library needs. This doc specifies the delta from v1 to v2.

## Goal

Upgrade the existing pipeline to public-release grade: testing against the declared Go floor as well as latest, coverage gate with Codecov reporting, dedicated security scanning with SARIF upload, structured test reporting with PR-comment consolidation, and a tag-triggered release workflow that validates all supported platforms before cutting a release.

## Files to change

Listed in the order CC should apply them. The `go.mod` edit is a prerequisite: the CI matrix's 1.24 leg will fail to run until `go.mod` is lowered from 1.26.1 to 1.24.

1. **Edit** `go.mod` — change the `go` directive
2. **Create** `.golangci.yml`
3. **Edit** `.github/workflows/ci.yml` — additive changes only
4. **Create** `.github/workflows/release.yml`
5. **Delete** `ci-workflow-implementation.md` from the repo root — superseded by this doc

## Decisions baked into this doc

- **Go floor: 1.24.** pidchain's source uses no feature newer than Go 1.21. Matches another personal project and another consumer (both on 1.24), which lets them adopt pidchain without bumping their own Go versions. The `go` directive in `go.mod` is a hard floor since Go 1.21.
- **Go matrix: 1.24 and 1.26.** Floor and latest. Proves the "Requires Go 1.24+" claim and catches regressions against the newest release. Middle versions omitted because pidchain uses no language or stdlib feature that differs across 1.24 / 1.25 / 1.26.
- **Coverage gate: 88%.** Measured from `coverage.out` on disk: 80/88 blocks covered on Darwin = 90.9%. Gate at 88% gives ~3 points of noise tolerance.
- **Codecov upload:** single leg (ubuntu-latest / Go 1.26) to avoid duplicate reports.
- **`fail-fast` differs intentionally between CI and release.** CI uses `fail-fast: false` because when a regression lands, seeing which platforms or Go versions broke is diagnostic signal. Release uses `fail-fast: true` because if any supported platform is broken, the release must not proceed — the other legs' outcomes are not actionable.
- **gosec runs twice, intentionally.** Once inside golangci-lint (inline findings surface in PR file-diff view) and once as a standalone job that uploads SARIF to GitHub's Security tab. Different reporting surfaces; both valuable on a security-adjacent library.
- **pidchain does not use `-tags unit` / `-tags integration` build-tag conventions.** The only build tags present are platform tags (`//go:build darwin`, etc.) handled by GOOS. Bare `go test ./...` is correct.

## File 1: `go.mod` edit

Change the `go` directive on line 3 from:

```
go 1.26.1
```

to:

```
go 1.24
```

No other edits. `require golang.org/x/sys v0.43.0 // indirect` remains as-is.

## File 2: `.golangci.yml` (create)

Minimal baseline. Enables the defaults a public Go library should not ship without; leaves room to tighten over time. `timeout` is set here and not duplicated on the CLI.

```yaml
version: "2"

linters:
  default: none
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gosec
    - gocritic
    - revive

run:
  timeout: 5m
```

## File 3: `.github/workflows/ci.yml` (edit)

Apply these edits to the existing file. Do not rewrite it from scratch; preserve the existing structure.

### 3a. Add a Go version matrix to the `test` job

In the `test` job, change the `name` and `strategy.matrix` to add `go-version`:

**Current:**

```yaml
  test:
    name: Test
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
```

**Replace with:**

```yaml
  test:
    name: Test (${{ matrix.os }}, Go ${{ matrix.go-version }})
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
        go-version: ['1.24', '1.26']
    runs-on: ${{ matrix.os }}
```

### 3b. Update the `setup-go` step in the `test` job to use the matrix value

**Current:**

```yaml
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache-dependency-path: go.sum
```

**Replace with:**

```yaml
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}
          cache-dependency-path: go.sum
```

### 3c. Replace the existing `Test` step with gotestsum + coverage

**Current:**

```yaml
      - name: Test
        run: go test -race ./...
```

**Replace with:**

```yaml
      - name: Install gotestsum
        run: go install gotest.tools/gotestsum@latest

      - name: Test
        shell: bash
        run: |
          gotestsum \
            --junitfile "junit-${{ matrix.os }}-${{ matrix.go-version }}.xml" \
            --format testname -- \
            -race -coverprofile=coverage.out -covermode=atomic ./...

      - name: Upload JUnit results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: junit-${{ matrix.os }}-${{ matrix.go-version }}
          path: junit-${{ matrix.os }}-${{ matrix.go-version }}.xml

      - name: Coverage gate
        if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'
        shell: bash
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Total coverage: ${COVERAGE}%"
          THRESHOLD=88
          if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
            echo "::error::Coverage ${COVERAGE}% is below threshold ${THRESHOLD}%"
            exit 1
          fi
          echo "Coverage ${COVERAGE}% meets threshold ${THRESHOLD}%"

      - name: Upload coverage to Codecov
        if: matrix.os == 'ubuntu-latest' && matrix.go-version == '1.26'
        uses: codecov/codecov-action@v5
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          files: ./coverage.out
          fail_ci_if_error: false
```

### 3d. Add a `publish-test-results` job

Add this as a new top-level job, after the `test` job and before the `lint` job:

```yaml
  publish-test-results:
    name: Publish test results
    needs: test
    runs-on: ubuntu-latest
    if: always()
    permissions:
      checks: write
      pull-requests: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: junit-*
          merge-multiple: true

      - uses: EnricoMi/publish-unit-test-result-action@v2
        with:
          files: junit-*.xml
```

### 3e. Remove the CLI `--timeout` flag from the `lint` job

`.golangci.yml` sets `timeout: 5m`. Drop the CLI duplicate.

**Current:**

```yaml
      - name: Run golangci-lint
        run: golangci-lint run --timeout=5m
```

**Replace with:**

```yaml
      - name: Run golangci-lint
        run: golangci-lint run
```

### 3f. Add a `security` job

Add this as a new top-level job after the `lint` job:

```yaml
  security:
    name: Security scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: '-fmt sarif -out gosec.sarif ./...'

      - name: Upload gosec SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gosec.sarif
```

## File 4: `.github/workflows/release.yml` (create)

`verify` uses the same OS × Go matrix as CI so a release cannot ship that breaks the advertised Go floor. `fail-fast: true` — any broken leg aborts release.

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  verify:
    name: Verify (${{ matrix.os }}, Go ${{ matrix.go-version }})
    strategy:
      fail-fast: true
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
        go-version: ['1.24', '1.26']
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}
          cache-dependency-path: go.sum

      - name: Test
        run: go test -race ./...

  release:
    name: Create GitHub release
    needs: verify
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          prerelease: ${{ contains(github.ref_name, '-') }}
```

## File 5: delete `ci-workflow-implementation.md`

The existing `ci-workflow-implementation.md` at the repo root was v1's design doc and is superseded by this one. Remove it so the repo carries a single source of truth.

## Success criteria

On the first push after merging:

1. All six `test` matrix legs succeed (three OSes × two Go versions).
2. macOS legs run `walker_darwin_test.go` against `/bin/ls` — all tests pass.
3. Windows legs run `walker_windows_test.go` against `notepad.exe` — all tests pass.
4. Ubuntu legs run the unsupported-platform branch; `TestUnsupportedPlatform_ReturnsErrPlatformUnsupported` passes.
5. Coverage gate on ubuntu-latest / Go 1.26 passes at ≥88%.
6. `lint` job reports zero golangci-lint findings (or CC fixes what it flags before merging).
7. `security` job uploads a SARIF that GitHub's Security tab ingests.
8. PR comments show consolidated test results from all six matrix legs.

On the first `v*` tag push after CI is green:

9. `verify` succeeds on all six OS × Go combinations.
10. A GitHub release is created with auto-generated notes.
11. pkg.go.dev picks up the module within ~30 minutes of the tag.

## Prerequisites

1. `CODECOV_TOKEN` must exist as a repository secret. Without it, the upload step logs a failure but `fail_ci_if_error: false` keeps the job green.
2. GitHub Actions must be enabled on the repository.
3. The repo's default branch must be `main`.

## Deferred (intentionally out of scope for this doc)

- **Dependabot configuration** — separate `.github/dependabot.yml`, its own decision about update cadence.
- **Additional Go versions in the matrix** — 1.25 omitted; cost vs. marginal signal is low for this codebase.
- **Scheduled/cron runs** — code that hasn't changed doesn't need re-testing.
- **Binary or container artifacts** — pidchain is a library; no artifact beyond the module.
- **Benchmarks in CI** — nothing in pidchain benchmarks today; add when there's a reason.
- **README badges and Go-version line update** — small README edit (status badges, `1.26+` → `1.24+`) that pairs naturally with this change but is a README concern, not a CI concern.