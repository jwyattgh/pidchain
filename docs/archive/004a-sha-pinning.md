# 004a — SHA-Pin Actions and Pin gotestsum

## Goal

SHA-pin every third-party GitHub Action used in `ci.yml` and `release.yml`. Pin `gotestsum` install to a specific version. Add `github-actions` ecosystem to Dependabot so SHA pins stay current.

Implements `PC-Decision-2026-04-27-sha-pin-actions`.

## Files

- CHANGE: `.github/workflows/ci.yml`
- CHANGE: `.github/workflows/release.yml`
- CHANGE: `.github/dependabot.yml`

## Implementation

### SHA lookup

For each action `<owner>/<repo>@<tag>` referenced below, look up the current commit SHA at the tag at apply time:

````bash
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha
````

For sub-path actions (e.g. `github/codeql-action/upload-sarif@v4`), look up the SHA on the parent repo (`github/codeql-action`) at the same tag.

The replacement format is:

````yaml
uses: <owner>/<repo>@<full-40-char-sha> # <tag>
````

The trailing `# <tag>` comment is what Dependabot reads to know what version the SHA represents. Do not omit it.

Tooling alternatives if doing many at once: `stacklok/frizbee`, `mheap/pin-github-action`, or `sethvargo/ratchet` auto-generate the SHA + comment pair.

### `.github/workflows/ci.yml`

Replace each `uses:` line with the SHA-pinned form. Action references to update:

- `actions/checkout@v5` (4 occurrences: test, lint, security, vuln, plus publish-test-results uses download-artifact)
- `actions/setup-go@v6` (3 occurrences: test, lint, vuln)
- `actions/upload-artifact@v6` (1, in test job)
- `actions/download-artifact@v7` (1, in publish-test-results)
- `EnricoMi/publish-unit-test-result-action@v2` (1)
- `golangci/golangci-lint-action@v9` (1) — keep `with: version: v2.6.2` unchanged
- `securego/gosec@v2.25.0` (1)
- `github/codeql-action/upload-sarif@v4` (1)
- `codecov/codecov-action@v5` (1)
- `golang/govulncheck-action@v1` (1)

Replace the `gotestsum` install step:

````yaml
      - name: Install gotestsum
        run: go install gotest.tools/gotestsum@v1.13.0
````

Was `@latest`. Verify v1.13.0 is the current release at apply time via `go list -m -json gotest.tools/gotestsum@latest` and use whatever is current.

### `.github/workflows/release.yml`

Action references to update:

- `actions/checkout@v5` (2 occurrences: verify, release)
- `actions/setup-go@v6` (1, in verify)
- `softprops/action-gh-release@v2` (1, in release — though see 004c which removes the `release` job entirely)

If 004c lands first or in the same change, the `softprops/action-gh-release` reference is gone and only the `actions/checkout` and `actions/setup-go` references in `verify` remain to pin.

### `.github/dependabot.yml`

Add a second update entry for the `github-actions` ecosystem alongside the existing `gomod` entry:

````yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "monthly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "deps"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "ci"
````

## Success Criteria

1. `grep -rE 'uses: [^@]+@v[0-9]' .github/workflows/` returns no matches — every `uses:` line references a 40-char SHA.
2. `grep -r '@latest' .github/workflows/` returns no matches.
3. `grep -c 'package-ecosystem: "github-actions"' .github/dependabot.yml` returns 1.
4. CI run on the SHA-pinned workflow passes on all three OSes and both Go versions.
5. Pushing a test tag triggers a successful `release.yml` `verify` pass on the SHA-pinned workflow.
6. Within ~24h of the dependabot.yml change, Dependabot opens its first `ci`-prefixed PR if any pinned action has a newer release.

## Out of Scope

- Concurrency blocks (`PC-Decision-2026-04-27-no-concurrency-block`).
- harden-runner (`PC-Decision-2026-04-27-no-harden-runner`).
- Aggregator job (deferred until branch protection is decided post-public).
- Artifact attestations (`PC-Decision-2026-04-27-no-artifact-attestations`).