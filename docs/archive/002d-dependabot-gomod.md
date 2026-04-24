# 002d: Configure Dependabot for the gomod ecosystem

## Context

pidchain has one Go module dependency: `golang.org/x/sys v0.43.0` in `go.mod`. As a public library whose consumers install this dependency transitively, pidchain should surface upgrades deliberately: Dependabot opens a PR when upstream releases a new version; CI runs the narrowed PR verification (`pr-verify` from 002a); a human reviews; the PR merges.

This is NOT a recommendation to use Dependabot for the `github-actions` ecosystem. CI tooling (golangci-lint, gotestsum, GitHub Actions themselves) does not ship with pidchain. A compromise in a CI tool cannot propagate to consumers. The defense against CI-tool compromise is per-job `permissions:` scoping (002b) and narrowed PR triggers (002a), not SHA-pinning or Dependabot tracking. Those tools stay on floating tag refs (`@v4`, `@v5`, etc.) and update when the maintainer chooses.

The Dependabot configuration here is strictly scoped to `gomod`.

## Goal

Create `.github/dependabot.yml` that configures Dependabot to monitor the `gomod` ecosystem monthly and open PRs for dependency upgrades. No `github-actions` entry. No `docker`, `pip`, or any other ecosystem.

## Files

| Action | Path |
|---|---|
| CREATE | `/Users/jason/workspace/pidchain/.github/dependabot.yml` |

## Implementation

### File contents

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "monthly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "deps"
```

### Configuration rationale

- `package-ecosystem: "gomod"`: watches `go.mod` in the repository.
- `directory: "/"`: the module root (where `go.mod` lives).
- `interval: "monthly"`: scan and surface updates monthly. pidchain has one dependency today and `golang.org/x/sys` releases a handful of times per year. Weekly would produce mostly empty scans.
- `open-pull-requests-limit: 5`: default is 5; stated explicitly for clarity.
- `commit-message.prefix: "deps"`: consistent with common Go project conventions, and keeps Dependabot PRs visually distinguishable in the log.

### What this does NOT do

- Does not trigger any CI workflow on a schedule. Dependabot's scan runs on GitHub's infrastructure, not in this repository's workflow.
- Does not open PRs for `github-actions` references. Those stay on floating tag pins.
- Does not auto-merge anything. Every Dependabot PR requires a human merge.

### Interaction with 002a

Dependabot PRs trigger the `pull_request` event. `002a` narrows this to the `pr-verify` job only: ubuntu-latest, Go 1.26, build + vet + test + lint. A dependency bump that compiles and passes tests on Linux is trusted to pass on the other matrix legs; the full matrix re-runs on push to main after merge.

### Interaction with 002b

The `pr-verify` job (introduced by 002a, permissioned by 002b) has `contents: read` only. A Dependabot PR carrying compromised code runs under those minimal permissions and cannot push to the repo, cannot create releases, and cannot modify the Security tab.

## Success criteria

After merge:

1. The `.github/dependabot.yml` file exists in the repo root.
2. GitHub's Insights → Dependency graph → Dependabot tab shows the `gomod` entry as active.
3. No `github-actions` ecosystem is listed.
4. On the next monthly scan, if no dependency updates are available, no PR is opened and no CI workflow runs.
5. If `golang.org/x/sys` publishes a new version during the next scan window, Dependabot opens a PR titled something like "deps(gomod): bump golang.org/x/sys from 0.43.0 to 0.44.0". The PR triggers `pr-verify`. No other jobs run on the PR.

## Out of scope

- Dependabot for any other ecosystem.
- Auto-merge configuration for Dependabot PRs.
- Grouped updates (single PR for multiple deps). With one dependency today, grouping is irrelevant; revisit when pidchain has 5+ deps.
- SHA-pinning for GitHub Actions (actions stay on floating tags; see Context).
- Changes to the `go.mod` dependency list itself.
