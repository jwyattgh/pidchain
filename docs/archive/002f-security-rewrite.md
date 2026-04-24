# 002f: Rewrite security job with split SARIF pattern

## Context

The current `security` job in `.github/workflows/ci.yml` runs gosec and uploads its SARIF output to GitHub's Security tab:

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

This has three problems:

1. **`securego/gosec@master` tracks branch HEAD.** Whatever the maintainer has on `master` at run time executes. This is strictly worse than a tag pin.
2. **gosec duplicated in `.golangci.yml`.** gosec also runs as part of the `lint` job via golangci-lint's enabled linters. Same scanner, same code, run twice per push.
3. **When gosec finds issues, the SARIF upload silently drops the workflow signal.** gosec exits non-zero on findings. The upload step has `if: always()`, so SARIF is uploaded — but there is no step after the upload that converts "findings exist" back into a workflow failure. The workflow is red (because the first step exited non-zero), but the signal is fragile: if anyone later adds `-no-fail` to restore "clean" workflow runs, findings become invisible.

The desired outcome is specific: one gosec run, SARIF uploaded to the Security tab, workflow red when findings exist, no `-no-fail` flag hiding the signal.

## Supersedes 001e's -no-fail decision

001e proposed adding `-no-fail` to gosec's arguments so that SARIF would always upload, accepting that the workflow would be green even when findings exist. That trade is wrong for pidchain's posture: we want findings to fail the workflow AND the SARIF to reach the Security tab. The split-responsibility pattern in this doc achieves both. 001e's `-no-fail` change, if applied, should be reversed by this doc.

## Goal

Rewrite the `security` job so that:

1. gosec runs exactly once (in the `security` job).
2. gosec is pinned to `@v2` (major-version tag), not `@master`.
3. SARIF is uploaded to the Security tab regardless of findings.
4. The workflow is red when findings exist, via an explicit post-upload check of the SARIF file.
5. gosec is removed from `.golangci.yml` so it does not run a second time in the `lint` job.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |
| EDIT | `/Users/jason/workspace/pidchain/.golangci.yml` |

## Implementation

### Rewrite the `security` job

Replace the current three-step job with a four-step split-responsibility pattern:

```yaml
  security:
    name: Security scan
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run gosec (produce SARIF)
        uses: securego/gosec@v2
        continue-on-error: true
        with:
          args: '-fmt sarif -out gosec.sarif ./...'

      - name: Upload SARIF to Security tab
        if: always() && hashFiles('gosec.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gosec.sarif

      - name: Fail on gosec findings
        if: always()
        shell: bash
        run: |
          if [ ! -s gosec.sarif ]; then
            echo "::error::gosec did not produce a SARIF file"
            exit 1
          fi
          findings=$(jq '[.runs[].results[]] | length' gosec.sarif)
          if [ "$findings" -gt 0 ]; then
            echo "::error::gosec found $findings issue(s) — see Security tab"
            jq -r '.runs[].results[] | "\(.locations[0].physicalLocation.artifactLocation.uri):\(.locations[0].physicalLocation.region.startLine): \(.message.text)"' gosec.sarif
            exit 1
          fi
          echo "gosec found 0 issues"
```

Step-by-step:

- **Step 1 — Run gosec.** `continue-on-error: true` allows the step to exit non-zero (on findings) without halting the job. SARIF is written to disk.
- **Step 2 — Upload SARIF.** `if: always()` plus `hashFiles('gosec.sarif') != ''` guards against a crashed gosec that produced no output. If the file exists, it uploads; if not, this step is skipped silently.
- **Step 3 — Fail on findings.** `if: always()` makes this run regardless of earlier step outcomes. It checks for file existence (gosec crash) or any findings in the SARIF (actionable issues), and exits 1 in either case. Clean SARIF with zero findings passes.

### Permissions block

`contents: read` is new (was absent). `security-events: write` stays. Both are scoped to the minimum: read the repo, write SARIF.

### Pull-request guard

`if: github.event_name != 'pull_request'` is added for consistency with 002a — security scans run on push to main, not on PR. Dependabot bumps verify via `pr-verify` only.

### Remove gosec from .golangci.yml

Edit `.golangci.yml`:

Current:
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
```

Remove the `- gosec` line. Result:

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
    - gocritic
    - revive
```

This is the single-source-of-gosec change: after 002f, gosec runs only in the `security` job, not also in the `lint` job.

### Why tag pin `@v2` and not a SHA

Consistent with the project-wide stance documented in 002d: CI tooling (GitHub Actions themselves) stays on floating tag pins. `@v2` is strictly better than `@master` (no HEAD tracking), and good enough for CI tooling that does not ship with pidchain.

### jq availability

`jq` is pre-installed on `ubuntu-latest` runners. No install step required.

## Success criteria

After merge:

1. `.golangci.yml` no longer lists `gosec`.
2. The `lint` job's logs do not mention gosec.
3. On a push to main with clean code, the `security` job runs and passes. The "Fail on gosec findings" step logs "gosec found 0 issues".
4. On a push to main with a deliberate gosec-flagged issue (test with a known G-code violation), the workflow goes red. The SARIF is visible in the repo's Security → Code scanning alerts tab. The failing step prints the finding location and message.
5. gosec is invoked exactly once per push. Grep the workflow logs for "gosec" — it appears only inside the `security` job.
6. PR workflows do not run the `security` job (consistent with 002a).

## Out of scope

- Adding additional scanners (CodeQL, osv-scanner, Trivy). govulncheck covers the CVE-layer gap in 002e.
- Changing gosec rules or ignores. The repo currently has no gosec findings; any future findings are addressed at the time they appear.
- Configuring the Security tab notifications or triage workflow. That is a GitHub repo setting, not a workflow change.
- Replacing gosec with a non-pattern-based scanner. gosec is fine for its scope; 002e adds the layer gosec does not cover.
- Signing releases or generating SBOMs.
