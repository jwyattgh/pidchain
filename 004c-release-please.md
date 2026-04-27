# 004c — release-please for Changelog Automation

## Goal

Adopt `googleapis/release-please-action` to automate semver bumps and `CHANGELOG.md` maintenance from Conventional Commits. Drives release tagging via PR-merge instead of manual `git tag && git push --tags`.

Replaces the existing `release` job in `release.yml`. Keeps the `verify` job as the tag-time gate — release-please pushes the tag, `verify` runs against it.

## Files

- ADD: `.github/workflows/release-please.yml`
- ADD: `release-please-config.json`
- ADD: `.release-please-manifest.json`
- ADD: `CHANGELOG.md` (initial empty file; release-please populates on first run)
- CHANGE: `.github/workflows/release.yml` (remove the `release` job; keep `verify`)

## Implementation

### `.github/workflows/release-please.yml`

````yaml
name: Release Please

on:
  push:
    branches: [main]

permissions: {}

jobs:
  release-please:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: googleapis/release-please-action@<sha> # v4.X.Y
        with:
          config-file: release-please-config.json
          manifest-file: .release-please-manifest.json
````

SHA-pin per 004a. Look up current v4 SHA at apply time via `gh api repos/googleapis/release-please-action/git/ref/tags/<v4-tag> --jq .object.sha`.

`contents: write` is required so release-please can push the tag. `pull-requests: write` is required so it can open and update the release PR.

### `release-please-config.json`

````json
{
  "release-type": "go",
  "packages": {
    ".": {
      "package-name": "pidchain",
      "include-component-in-tag": false,
      "changelog-sections": [
        { "type": "feat",     "section": "Features" },
        { "type": "fix",      "section": "Bug Fixes" },
        { "type": "perf",     "section": "Performance" },
        { "type": "deps",     "section": "Dependencies" },
        { "type": "docs",     "section": "Documentation", "hidden": false },
        { "type": "ci",       "section": "CI",            "hidden": true },
        { "type": "test",     "section": "Tests",         "hidden": true },
        { "type": "refactor", "section": "Refactoring",   "hidden": true },
        { "type": "chore",    "section": "Misc",          "hidden": true }
      ]
    }
  }
}
````

`release-type: go` is the standard preset for Go modules. `include-component-in-tag: false` produces tags like `v0.2.0` rather than `pidchain-v0.2.0` (matters for `pkg.go.dev` and `go get` semantics).

`hidden: true` on `ci`, `test`, `refactor`, `chore` keeps changelog noise low — these commits trigger no version bump and don't appear in user-facing release notes.

### `.release-please-manifest.json`

````json
{
  ".": "0.1.0"
}
````

This seeds the next-release version. The first release-please run after this lands will open a PR proposing `v0.1.0` (or higher if accumulated commits since manifest creation imply a bump).

### `CHANGELOG.md`

````markdown
# Changelog
````

Empty file with just the heading. release-please populates it on the first release PR.

### `.github/workflows/release.yml`

Remove the `release` job entirely. Keep `verify` as the only job. After this change, the file is:

````yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions: {}

jobs:
  verify:
    name: Verify (${{ matrix.os }}, Go ${{ matrix.go-version }})
    strategy:
      fail-fast: true
      matrix:
        os: [macos-latest, windows-latest, ubuntu-latest]
        go-version: ['1.25', '1.26']
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha> # v5

      - uses: actions/setup-go@<sha> # v6
        with:
          go-version: ${{ matrix.go-version }}
          cache-dependency-path: go.sum

      - name: Test
        run: go test -race ./...
````

Action SHAs come from 004a; `timeout-minutes: 15` from 004b. The `release` job is gone — release-please creates the GitHub Release as part of merging the release PR.

## Operational change

After this lands, the release process is:

1. Commit changes to `main` using Conventional Commits format (`feat: ...`, `fix: ...`).
2. Each push to `main` runs release-please, which opens or updates a "chore(main): release vX.Y.Z" PR.
3. When ready to release, merge that PR.
4. release-please tags `vX.Y.Z` and creates the GitHub Release populated with the changelog entries.
5. The tag push triggers `release.yml`'s `verify` job; verify failure is surfaced on the GitHub Release page (release stays published; downstream consumers see verify failed).

`git tag && git push --tags` is no longer the release interface.

## Success Criteria

1. `release-please-config.json`, `.release-please-manifest.json`, `CHANGELOG.md` exist at repo root.
2. `.github/workflows/release-please.yml` exists and triggers on push to `main`.
3. `release.yml` contains only the `verify` job; the `release` job is deleted.
4. After the commit landing this change, release-please opens its first release PR within ~5 minutes (visible at `https://github.com/jwyattgh/pidchain/pulls`).
5. Merging that PR creates tag `v0.1.0`, a GitHub Release for `v0.1.0`, and a `verify` workflow run against the tag.
6. `pkg.go.dev/github.com/jwyattgh/pidchain@v0.1.0` resolves within ~10 minutes after the tag push.

## Out of Scope

- Migration of any pre-existing release notes (none; pidchain is pre-1.0 and pre-public).
- Pre-commit hook for Conventional Commits format. The user adopted the VS Code Conventional Commits extension on 2026-04-27; that's the enforcement layer.