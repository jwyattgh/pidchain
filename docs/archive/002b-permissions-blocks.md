# 002b: Add permissions blocks to all jobs

## Context

GitHub workflows receive a `GITHUB_TOKEN` whose permissions default to a set that depends on repository age and org settings. Repositories created after 2 February 2023 default to read-only; older repos retain permissive legacy defaults. Either way, the safe posture is to declare `permissions:` explicitly at the workflow level and again at the job level, granting only the minimum each job requires.

Current state in `.github/workflows/ci.yml`:
- `publish-test-results` has `permissions:` (checks, pull-requests).
- `security` has `permissions:` (security-events).
- `test`, `lint`, and the new `pr-verify` job (added in 002a) have no `permissions:` block. They run with whatever default the repo supplies.

Current state in `.github/workflows/release.yml`:
- `release` has `permissions:` (contents: write).
- `verify` has no `permissions:` block.

The compromised-dependency scenario that motivated the rest of this 002 series lands its first real defense here: if a pull-request job runs untrusted code (via a bumped dependency), the blast radius is the `GITHUB_TOKEN` scopes available to that job. With `permissions: contents: read` and nothing else, a compromised job can read the repo — which is already public — and cannot push, cannot modify releases, cannot comment on PRs, cannot write to the Security tab. Combined with 002a's narrow PR pipeline, this bounds the PR-side risk.

## Goal

Every job in both workflows has an explicit `permissions:` block granting only the scopes that job requires. Workflow-level defaults are set to the empty object `{}` (no permissions) so that any job without an explicit block receives nothing.

## Files

| Action | Path |
|---|---|
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/ci.yml` |
| EDIT | `/Users/jason/workspace/pidchain/.github/workflows/release.yml` |

## Implementation

### ci.yml: workflow-level default

Directly below the `on:` block and before `jobs:`, add:

```yaml
permissions: {}
```

### ci.yml: per-job permissions

**test**: needs to check out the repo. Add as the first key under the job:

```yaml
    permissions:
      contents: read
```

**publish-test-results**: already has `checks: write` and `pull-requests: write`. Add `contents: read` to the existing block (required to look up the commit SHA when publishing results):

```yaml
    permissions:
      contents: read
      checks: write
      pull-requests: write
```

**lint**: needs to check out the repo. Add:

```yaml
    permissions:
      contents: read
```

**security**: already has `security-events: write`. Add `contents: read` to the existing block:

```yaml
    permissions:
      contents: read
      security-events: write
```

**pr-verify** (from 002a): needs to check out the repo. Add:

```yaml
    permissions:
      contents: read
```

### release.yml: workflow-level default

Directly below the `on:` block and before `jobs:`, add:

```yaml
permissions: {}
```

### release.yml: per-job permissions

**verify**: needs to check out the repo. Add:

```yaml
    permissions:
      contents: read
```

**release**: already has `contents: write`. Leave unchanged. This is the only job in either workflow that writes to the repo; it writes releases.

## Success criteria

After merge:

1. A push to main runs all existing jobs, they pass, no new permission errors appear in job logs.
2. `publish-test-results` continues to post its summary without 403 errors (the `contents: read` addition preserves its commit lookup).
3. A tag push triggers `verify` and `release`, both pass, release is created successfully.
4. Inspecting any job log in the "Set up job" section shows the permissions block reported as the intended set (e.g., `contents: read` only for read-only jobs).

## Out of scope

- OIDC setup for cloud credentials (not needed — no cloud actions here).
- `id-token: write` (reserved for future OIDC use; not needed today).
- Changes to the `test` matrix or `pr-verify` structure (002a).
- Permission changes for any future jobs not yet added (govulncheck in 002e will define its own permissions).
