# 004e — Repository Protection and Workflow PR Permissions

## Goal

Resolve two blockers visible after the 004a–d release-prep commits landed:

1. **release-please can't create PRs.** The workflow declares `pull-requests: write` at the job level, but the repo-level "Allow GitHub Actions to create and approve pull requests" toggle is OFF (the GitHub default). No workflow can create a PR regardless of token permissions when this toggle is off.

2. **`main` is unprotected.** GitHub displays an "insecure branch" warning. main can be force-pushed, deleted, or have merge commits pushed to it — none match the intended workflow (rebase-only, release-please as the only writer of release tags).

This doc fixes both: workflow permission flip plus a repo ruleset for main. Investigation phase first, because the appropriate ruleset shape depends on existing repo state (pre-existing rulesets, classic branch protection, default-branch oddities).

Required status checks (the Path A vs Path B aggregator question from earlier discussion) are explicitly out of scope — handled in a follow-up doc once the post-public CI shape is decided.

## Files

No source files modified. This change applies via `gh api` against GitHub repository configuration. A throwaway `ruleset.json` at repo root is created during Operation 2 and deleted after the API call succeeds; not committed.

## Phase 1 — Investigate

CC runs the commands below and pastes output back. **Apply nothing in this phase.** The output determines whether Phase 2 lands as drafted or needs adjustment.

### Repo metadata

```bash
gh api repos/jwyattgh/pidchain \
  --jq '{visibility, default_branch, allow_squash_merge, allow_merge_commit, allow_rebase_merge, delete_branch_on_merge, allow_auto_merge}'
```

Expected: `default_branch: "main"`. If anything else, flag and stop — the ruleset targets `~DEFAULT_BRANCH`, not the literal string "main", but worth confirming.

### Workflow permissions (the release-please blocker)

```bash
gh api repos/jwyattgh/pidchain/actions/permissions/workflow
```

Expected fields:

- `default_workflow_permissions`: probably `"read"` (intended) or `"write"` (older default).
- `can_approve_pull_request_reviews`: probably `false` — this is the actual blocker.

If `default_workflow_permissions` is already `"write"`, flag — that's broader than this project wants. The CI workflows scope their own write permissions per job; the repo default should be `read`.

### Existing classic branch protection

```bash
gh api repos/jwyattgh/pidchain/branches/main/protection 2>&1 | head -40
```

Expected: `404 Not Found`. Anything else means a classic protection is already in place; rulesets layer on top of it, but report exact state before Phase 2.

### Existing rulesets

```bash
gh api repos/jwyattgh/pidchain/rulesets --jq '.[] | {id, name, target, enforcement}'
```

Expected: empty array. If any rulesets exist, report their IDs and configurations — Phase 2 may need to amend rather than create.

### release-please run history

```bash
gh run list --workflow=release-please.yml --limit 5
gh run view "$(gh run list --workflow=release-please.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --log-failed 2>&1 | tail -50
```

Confirm the failure mode is the workflow-permissions denial, not the GraphQL transient already observed or a config error in `release-please-config.json`. The expected error string is something like `Resource not accessible by integration` or a `403` on the PR-creation API call.

### Stop and report

Paste output back. Wait for explicit greenlight before Phase 2.

## Phase 2 — Apply

Apply only after Phase 1 output confirms baseline state.

### Operation 1: enable workflow PR creation

```bash
gh api -X PUT repos/jwyattgh/pidchain/actions/permissions/workflow \
  -F can_approve_pull_request_reviews=true \
  -f default_workflow_permissions=read
```

Flag-type note: `-F` for the boolean, `-f` for the string. Mixing them up returns a confusing error.

`default_workflow_permissions=read` is set explicitly even if already `read` — idempotent and prevents accidentally widening defaults if Phase 1 found `write`.

Verify:

```bash
gh api repos/jwyattgh/pidchain/actions/permissions/workflow
```

Expected:

```json
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": true
}
```

### Operation 2: protect main with a ruleset

Save this as `ruleset.json` at repo root:

```json
{
  "name": "main protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"}
  ]
}
```

Apply:

```bash
gh api -X POST repos/jwyattgh/pidchain/rulesets --input ruleset.json
```

The API returns the created ruleset including its `id`. Note the id — verification commands need it.

Verify:

```bash
gh api repos/jwyattgh/pidchain/rulesets --jq '.[] | {id, name, enforcement, target}'
```

Then delete the local `ruleset.json`:

```bash
rm ruleset.json
```

The API call is the source of truth; the JSON file was a request payload only and is not committed.

### What the rules do

- `deletion` — main can't be deleted.
- `non_fast_forward` — no force-push to main. Existing commits on remote main can never be rewritten in place.
- `required_linear_history` — merges to main must be fast-forward or rebase, no merge commits. Matches the rebase-only workflow and keeps release-please's commit-history scan clean.

### Behavioral change to surface in post-implementation report

The rebase-and-push pattern Jason just used to recover from divergent branches will no longer work against remote main. Going forward: do work on a feature branch, rebase the feature branch as much as needed locally, fast-forward main to the feature branch tip when ready. Worth flagging in the report so it isn't a surprise on the next push.

## Success Criteria

1. `gh api repos/jwyattgh/pidchain/actions/permissions/workflow --jq '.can_approve_pull_request_reviews'` returns `true`.
2. `gh api repos/jwyattgh/pidchain/actions/permissions/workflow --jq '.default_workflow_permissions'` returns `"read"`.
3. `gh api repos/jwyattgh/pidchain/rulesets --jq 'length'` returns at least 1; the new ruleset's `enforcement` is `"active"` and `target` is `"branch"`.
4. The new ruleset's `rules` array contains all three expected types:

```bash
   gh api repos/jwyattgh/pidchain/rulesets/<id> --jq '.rules | map(.type) | sort'
```

   Expected: `["deletion", "non_fast_forward", "required_linear_history"]`.

5. The ruleset's `conditions.ref_name.include` contains `"~DEFAULT_BRANCH"`:

```bash
   gh api repos/jwyattgh/pidchain/rulesets/<id> --jq '.conditions.ref_name.include'
```

6. The next release-please workflow run after Phase 2 (triggered by the next push to main, or by merging this 004e implementation commit) does not fail with a permissions-denial error. Acceptable conclusions: `success` (PR opened or "no release necessary" logged) — anything except permission-denied.
7. GitHub UI no longer displays the "insecure branch" warning on `main`. Visual check at `https://github.com/jwyattgh/pidchain`.

## Out of Scope

- **Required status checks on main.** Deferred until the Path A (list checks individually) vs Path B (aggregator job first) decision is made. Separate doc once that decision lands.
- **Required pull request reviews.** Solo development; PR-to-self adds friction without review benefit. Reconsider when contributors materialize.
- **Tag protection ruleset.** release-please pushes tags using a non-`GITHUB_TOKEN` identity (PAT or App, depending on how 004c's token was wired); tag protection would need that identity allowlisted. The threat model here is tj-actions-style tag-replay against pidchain itself, which is upstream-action-publisher concern, not consumer-of-actions concern. Reconsider only if pidchain ever publishes its own actions.
- **Required signed commits.** Worth doing eventually. Adds friction to Dependabot PRs (the `github-actions[bot]` signing identity would need allowlisting) and to release-please's automated release commit. Layer on later.
- **Public visibility flip itself.** Separate doc. This 004e is a prerequisite — main should be protected before the repo is publicly browsable — but `gh repo edit --visibility public` is its own gate.