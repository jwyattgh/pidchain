# 002a: Narrow the pull_request trigger in ci.yml

## Context

`.github/workflows/ci.yml` currently triggers on `push` to main, `pull_request` to main, and `workflow_dispatch`. On `pull_request`, the full workload runs: six-leg matrix (three OSes × two Go versions), lint, security, and publish-test-results.

The `pull_request` trigger was added in 001c without specific justification and has never fired in practice because no PRs have ever been opened against the repo. 002d enables Dependabot for the `gomod` ecosystem, which will open PRs. When that lands, every Dependabot PR would fire the full CI load. For a one-line dependency bump, that is overkill and it expands the blast radius if a bumped dependency contains compromised code.

This doc narrows `pull_request` to a single fast verification job, leaving the full matrix to run on `push` to main after merge.

## Goal

- On `pull_request`: run one job. ubuntu-latest, Go 1.26, build + vet + test + lint. No matrix, no security, no coverage gate, no publish-test-results.
- On `push` to main: run the current full workload unchanged.
- On `workflow_dispatch`: run the current full workload unchanged.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |

## Implementation

### Add a `pr-verify` job

Add a new top-level job after `security`:

```yaml
  pr-verify:
    name: PR verify (ubuntu-latest, Go 1.26)
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
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

      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
            | sh -s -- -b $(go env GOPATH)/bin v2.6.2

      - name: Run golangci-lint
        run: golangci-lint run
```

### Gate the existing jobs off pull_request

Add `if: github.event_name != 'pull_request'` to the `test`, `lint`, and `security` jobs as the first line under the job name.

For `publish-test-results`, change the existing `if: always()` to:

```yaml
    if: always() && github.event_name != 'pull_request'
```

### Why a separate job rather than matrix manipulation

GitHub Actions matrix syntax cannot cleanly express "run six legs on push, one leg on pull_request" without fragile conditional matrix construction. A separate `pr-verify` job is simpler and reads clearly at a glance.

### Why keep the piped-curl golangci-lint install here

002c replaces that install mechanism with the `golangci/golangci-lint-action` across all jobs. This doc does not depend on 002c and does not change the install mechanism — it only changes which jobs run on which trigger. 002c will update both the `lint` job and the `pr-verify` job in a single pass.

## Success criteria

After merge:

1. A `push` to main runs six `test` legs, `publish-test-results`, `lint`, `security`. No `pr-verify` job appears.
2. A `workflow_dispatch` run behaves identically to a push.
3. Opening a test PR (any branch, any trivial change) runs only `pr-verify`. No `test`, `publish-test-results`, `lint`, or `security` jobs appear on the PR.
4. The `pr-verify` job completes in under two minutes on a typical change.

## Out of scope

- Replacing the piped-curl golangci-lint install (002c).
- Adding `permissions:` blocks to the new or existing jobs (002b).
- Changing gosec tag pinning or the SARIF pipeline (002f).
- Adding govulncheck (002e).
- Changing the coverage gate threshold or per-OS split (002g).
- Configuring Dependabot (002d).
