# 002e: Add govulncheck job

## Context

`govulncheck` is the Go security team's official vulnerability scanner. It checks the current module and its dependencies (including the Go standard library) against the curated vulnerability database at `vuln.go.dev`. Unlike pattern-based scanners, govulncheck performs call-graph reachability analysis: it reports only vulnerabilities whose code paths the target program actually reaches. That eliminates the noise class typical of naive dependency scanners.

pidchain currently has no vulnerability scanning layer. gosec (lint) and gosec-via-SARIF (security job) scan for code patterns, not known CVEs. This doc adds the CVE layer.

## Goal

Add a `vuln` job to `.github/workflows/ci.yml` that runs `govulncheck` on `./...` on every push to main and on a weekly schedule. The job fails if `govulncheck` reports a reachable vulnerability.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |

## Implementation

### Add schedule trigger to the `on:` block

Add a `schedule:` trigger to the existing `on:` block:

```yaml
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 7 * * 1'  # Every Monday 07:00 UTC
  workflow_dispatch:
```

### Add the `vuln` job

Add a new top-level job after `security`:

```yaml
  vuln:
    name: Vulnerability scan
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache-dependency-path: go.sum

      - name: Run govulncheck
        uses: golang/govulncheck-action@v1
        with:
          go-version-input: '1.26'
```

### The `if:` guard

Consistent with 002a: full security jobs run on push/schedule/workflow_dispatch, not on pull_request. If a Dependabot PR bumps a dependency, that is exactly the case where a new CVE could appear — and the `pr-verify` job does not cover this. The tradeoff accepted here: `govulncheck` runs on main after merge, not before. This matches pidchain's single-maintainer posture and the 002a framing that PR verification is narrow and fast; substantive scans run post-merge and on a weekly schedule.

If future volume suggests running `govulncheck` on PR as well, a targeted single-step addition to `pr-verify` is the right change. Not done here.

### No SARIF output

govulncheck supports `-format sarif` but this doc does not configure it. SARIF complicates output handling (see 002f). The action's default output is a PR-check summary, which is sufficient and does not require the Security tab.

### Weekly schedule

`cron: '0 7 * * 1'` runs Monday 07:00 UTC. This catches newly-published CVEs against the current main even when pidchain sees no commits. Per GitHub's scheduled-workflow rules, this schedule continues to fire as long as the repo is active (any commit within 60 days). pidchain's Dependabot scans (002d) and normal development keep this condition true.

## Success criteria

After merge:

1. A push to main includes the `vuln` job in the run. Job passes if no reachable vulnerabilities exist.
2. The `vuln` job logs show `golang/govulncheck-action@v1` invoking govulncheck against the repo.
3. Manually triggering via `workflow_dispatch` runs `vuln` alongside the other jobs.
4. A pull_request does NOT run `vuln` (consistent with 002a).
5. The next Monday 07:00 UTC, the weekly schedule fires a workflow run that executes `vuln`.

If govulncheck reports a reachable vulnerability on the first run, that is a live finding. Resolve it (upgrade the dependency, remove the vulnerable import path, or accept the finding explicitly) before moving on to 002f. This is not 002e's scope to solve; it is 002e's scope to surface.

## Out of scope

- Remediation of any vulnerability govulncheck reports. Each finding becomes its own discussion.
- Running govulncheck on PRs.
- SARIF output for the Security tab.
- Replacing or supplementing govulncheck with osv-scanner, Trivy, or Snyk. govulncheck's Go reachability analysis is the only scanner that covers Go's stdlib and third-party Go dependencies with reachability pruning; other scanners either duplicate this (osv-scanner wraps govulncheck for Go) or do not apply (Trivy is container-focused).
- Adding CodeQL, Scorecard, or dependency-review-action.
- Signing releases, SLSA provenance, or SBOM generation.
