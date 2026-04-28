# 004g — CodeQL, Scorecard, and Dependabot Alerts

## Goal

Complete the public-repo security baseline by adding three controls that were either skipped during public-prep or asserted-without-verifying in 004f's review session:

1. **CodeQL** — semantic SAST via GitHub's default setup. Catches a class of bug (taint flow across function boundaries, Go-specific vulnerability queries) that gosec's pattern-matching cannot.
2. **OpenSSF Scorecard** — supply-chain hygiene meta-score with weekly run and README badge. Promoted from `PC-Backlog-Security-NiceToHaves` (deleted earlier this session) per Jason's 2026-04-28 instruction.
3. **Dependabot Alerts + Security Updates** — repo settings flips. Enables proactive vulnerability flagging on the existing dep tree (currently disabled, returning HTTP 403 from `gh api .../dependabot/alerts`) and auto-PR generation for vulnerable deps.

This is a build doc. Three concrete artifacts ship: one repo-settings change for CodeQL, one new workflow file plus README badge for Scorecard, and two repo-settings flips for Dependabot. No source code changes. No memory writes are required by this doc itself; the corresponding Decision/Subsystem updates are listed in Out of Scope and handled in a follow-up.

## Files

| Action | Path |
|---|---|
| ADD | `.github/workflows/scorecard.yml` |
| CHANGE | `README.md` (add Scorecard badge near top) |
| CHANGE (via API) | Repository setting: CodeQL default setup → configured |
| CHANGE (via API) | Repository setting: Vulnerability alerts → enabled |
| CHANGE (via API) | Repository setting: Automated security fixes → enabled |

No changes to: `ci.yml`, `release-please.yml`, `dependabot.yml`, `release-please-config.json`, `.release-please-manifest.json`, the `main` branch ruleset, any source `.go` file.

## Implementation

### 1. CodeQL default setup

GitHub's hosted CodeQL configuration. No workflow file in `.github/workflows/`. GitHub manages the workflow internally; results appear in the Security tab as `tool.name == "CodeQL"`.

**Apply:**

```bash
gh api -X PUT repos/jwyattgh/pidchain/code-scanning/default-setup \
  -f state=configured \
  -f query_suite=default \
  -F 'languages[]=actions' \
  -F 'languages[]=go'
```

`query_suite=default` matches what the API currently reports as suggested (`gh api repos/jwyattgh/pidchain/code-scanning/default-setup` returns `"query_suite": "default"`). `security-extended` is a stricter suite; we are deliberately taking `default` here to keep this a one-click change. If a future incident or external request justifies stricter queries, that's a separate decision.

The first analysis run typically completes within 5–10 minutes of enabling. CodeQL default setup runs on every push to a default branch, every PR, and on a weekly schedule managed by GitHub.

### 2. OpenSSF Scorecard workflow

New file at `.github/workflows/scorecard.yml`.

```yaml
name: Scorecard

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'  # Monday 09:00 UTC, ~2h after CI's weekly slot
  workflow_dispatch:

permissions: {}

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      security-events: write   # upload SARIF to Security tab
      id-token: write           # publish results to OpenSSF (Sigstore signing)
      contents: read

    steps:
      - uses: actions/checkout@<sha>  # v5  (use same SHA as ci.yml's checkout)
        with:
          persist-credentials: false

      - name: Run Scorecard
        uses: ossf/scorecard-action@<sha>  # v2.X.Y  — look up at apply time
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true   # publishes to api.securityscorecards.dev for badge

      - name: Upload SARIF to Security tab
        uses: github/codeql-action/upload-sarif@<sha>  # v4 — same SHA as ci.yml's security job
        with:
          sarif_file: results.sarif
```

**SHA-pinning per 004a.** Look up at apply time:

- `actions/checkout`: reuse `93cb6efe18208431cddfb8368fd83d5badbf9bfd` (matches `ci.yml`).
- `github/codeql-action/upload-sarif`: reuse `95e58e9a2cdfd71adc6e0353d5c52f41a045d225` (matches `ci.yml`).
- `ossf/scorecard-action`: fetch current v2 SHA via `gh api repos/ossf/scorecard-action/git/ref/tags/v2.4.0 --jq .object.sha` (or whichever v2 tag is current at apply time).

**Permissions reasoning (per 002b):**

- `security-events: write` — required for SARIF upload to Security tab.
- `id-token: write` — required for `publish_results: true`. Scorecard signs published results via Sigstore using the workflow's OIDC token; this is how the badge endpoint at `api.securityscorecards.dev` verifies the score came from an unmodified workflow run.
- `contents: read` — to checkout.

All other permissions stay default-denied via the workflow-level `permissions: {}`.

**Schedule choice.** Monday 09:00 UTC, two hours after `ci.yml`'s 07:00 weekly govulncheck slot. Avoids overlapping schedules and keeps both visible in Monday-morning runs.

### 3. README badge

Add this line near the top of `README.md`, in the badges block (consistent with however the existing badges are arranged — adjust placement to match):

```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/jwyattgh/pidchain/badge)](https://scorecard.dev/viewer/?uri=github.com/jwyattgh/pidchain)
```

The badge endpoint returns "no data" until the first Scorecard run completes and publishes results (~10 minutes after the workflow's first execution). Don't worry if the badge looks broken for the first run.

### 4. Dependabot Alerts + Security Updates

**Apply:**

```bash
# Enable Dependabot Alerts
gh api -X PUT repos/jwyattgh/pidchain/vulnerability-alerts

# Enable automated security fixes (auto-PR for known-vuln deps)
gh api -X PUT repos/jwyattgh/pidchain/automated-security-fixes
```

Both endpoints return HTTP 204 No Content on success.

These are the API equivalents of the toggles at `Settings → Code security → Dependabot alerts → Enable` and `Dependabot security updates → Enable`.

## Apply order

Order doesn't strictly matter, but this sequence makes verification linear:

1. Enable Dependabot Alerts (immediate; verify by re-running `gh api .../dependabot/alerts` and seeing it return JSON instead of 403).
2. Enable Dependabot Security Updates (immediate).
3. Enable CodeQL default setup (immediate API call; first run takes 5–10 min).
4. Add `scorecard.yml` workflow file.
5. Add Scorecard badge to README.
6. Single commit for the two file changes:
   ```
   feat(security): add CodeQL, Scorecard, and Dependabot alerts
   ```
   `feat` so the next release-please PR surfaces this in the changelog under Features. Scope `security` matches the prior `chore(security): document post-public security posture review` from 004f for grep continuity.
7. Push. Watch Actions tab for the Scorecard run and the auto-fired CodeQL run.

## Success Criteria

Each is a single command CC can run after applying.

1. **CodeQL is configured:**
   ```bash
   gh api repos/jwyattgh/pidchain/code-scanning/default-setup | jq '{state, query_suite, languages}'
   # expect: {"state": "configured", "query_suite": "default", "languages": [...]}
   ```

2. **CodeQL has run at least once** (after waiting ~10 minutes):
   ```bash
   gh api repos/jwyattgh/pidchain/code-scanning/analyses | jq '[.[].tool.name] | unique'
   # expect to include "CodeQL" alongside "Golang security checks by gosec"
   ```

3. **Scorecard workflow exists and has run successfully:**
   ```bash
   gh run list --workflow=scorecard.yml --limit=1 --json conclusion
   # expect: [{"conclusion": "success"}]
   ```

4. **Scorecard SARIF appears in Security tab:**
   ```bash
   gh api repos/jwyattgh/pidchain/code-scanning/analyses | jq '[.[].tool.name] | unique'
   # expect to additionally include "Scorecard"
   ```

5. **Scorecard badge endpoint resolves:**
   ```bash
   curl -sI https://api.securityscorecards.dev/projects/github.com/jwyattgh/pidchain/badge | head -1
   # expect: HTTP/2 200
   ```

6. **Dependabot Alerts is enabled:**
   ```bash
   gh api repos/jwyattgh/pidchain/dependabot/alerts 2>&1 | head -3
   # expect: JSON array (possibly empty []), NOT "Dependabot alerts are disabled" 403
   ```

7. **Dependabot Security Updates is enabled:**
   ```bash
   gh api repos/jwyattgh/pidchain/automated-security-fixes
   # expect: {"enabled": true, "paused": false}
   ```

8. **Branch protection ruleset unchanged** (regression check — none of the above should touch the ruleset):
   ```bash
   gh api repos/jwyattgh/pidchain/rulesets | jq '.[] | {name, enforcement}'
   # expect: {"name": "main protection", "enforcement": "active"}
   gh api repos/jwyattgh/pidchain/rulesets/$(gh api repos/jwyattgh/pidchain/rulesets | jq -r '.[0].id') | jq '[.rules[].type]'
   # expect: ["deletion", "non_fast_forward", "required_linear_history"]
   ```

9. **CI on main is still green** (regression check):
   ```bash
   gh run list --workflow=ci.yml --limit=1 --json conclusion
   # expect: [{"conclusion": "success"}]
   ```

10. **After this doc lands and is moved to `docs/archive/`:**
    ```bash
    test -f docs/archive/004g-codeql-scorecard-dependabot-alerts.md && echo OK
    test ! -f 004g-codeql-scorecard-dependabot-alerts.md && echo "removed from root OK"
    ```

## Out of Scope

- **CodeQL `security-extended` query suite.** Default suite chosen for one-click simplicity. Promote to extended as a separate decision if/when justified by an incident or external request.

- **Custom CodeQL workflow file** (advanced setup with handwritten matrix, query selection, paths-ignore, etc.). Default setup is GitHub-managed; if customization becomes necessary later, that's a separate doc that would also turn off default setup before adding the custom workflow.

- **`release.yml` verify-on-tag job restoration.** 004c spec expected `release.yml` to retain its `verify` job after the `release` job was removed; the file was deleted entirely. This is a real implementation drift and gets its own doc (004h) — restoring or retroactively amending 004c. Bundling here would muddy the success criteria.

- **`PC-Decision-2026-04-28-add-scorecard` and `PC-Decision-2026-04-28-add-codeql` memory entities.** These should be written after CC verifies the apply succeeded, naming the reasoning ("standard public-repo baseline; previously parked / asserted-without-verifying; corrected"). CD writes them in a follow-up turn after CC reports success — not as part of this doc, since memory writes for not-yet-shipped work are premature.

- **`dependency-review-action`.** Still parked. The Dependabot Alerts + Security Updates flips here cover most of the threat model dependency-review addresses (vulnerable-dep introduction). If, after these land, there's still a gap that justifies dep-review, separate doc.

- **`.github/workflows/scorecard.yml` running on `pull_request`.** Not added — Scorecard's threat-model checks evaluate the published repo state, not a proposed change. Push + schedule is sufficient. (PR-time check would also fail Branch-Protection on every PR-from-fork, since fork CI can't observe the parent repo's branch protection.)

- **README badge layout polish.** This doc specifies adding the Scorecard badge; if the badges block needs reorganization (e.g., grouping by category, line-wrapping), that's a separate small docs commit.
