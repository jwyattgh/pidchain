# 004f — Post-Public Security Posture Review

## Goal

Capture the outcome of the security posture review run after pidchain's public flip and 004e's repo-protection landing. Two new Decision entities were settled in memory during the review session; six additional candidates were considered and parked as nice-to-haves. This doc records both, plus a memory hygiene fix performed during the same session, so CC and future CD sessions have a single file to consult before re-pitching any of these items.

This is a documentation doc, not a build doc. Nothing in pidchain's code or workflows changes as a result of this doc landing. Memory writes already happened during the review session; this doc is the on-disk mirror of that work for review and historical record.

## Files

| Action | Path |
|---|---|
| ADD | `004f-post-public-security-review.md` at repo root; moves to `docs/archive/` after landing per the 002/004 series convention |

No source files, workflow files, dependabot config, rulesets, or other on-disk artifacts are modified by this doc.

## Decisions Settled

Two new Decision entities written to memory during the 2026-04-27 review session.

### No required status checks on `main`

**Memory entity:** `PC-Decision-2026-04-27-no-required-status-checks`
**Relation:** `Project-PidChain --has_decision--> PC-Decision-2026-04-27-no-required-status-checks`

The 004e ruleset (deletion, non_fast_forward, required_linear_history) is the full extent of branch protection. No `required_status_checks` rule will be added.

Load-bearing reasoning: the only failure mode required status checks defend against is merging or pushing on red CI. Jason's stated workflow is `git add -A && commit && push` directly to main, with self-review of CI before pushing. Required checks would defend a door no one walks through.

Supporting reasoning:

- Direct push and required status checks are mechanically incompatible. Rulesets enforce required checks on any update to the protected ref including direct pushes; checks fire on push, after the ref accepts it. Adopting required checks would force a feature-branch + fast-forward workflow Jason has explicitly rejected.
- The release-please path makes its own gate: release-please opens a PR, CI runs on the PR, Jason reviews before clicking merge. Required checks add no signal beyond the human review at the PR.

Re-pitching is justified only by new evidence: a Jason workflow change to feature-branch + PR (which would also resolve the direct-push incompatibility), or a contributor base materializing such that "I wouldn't merge on red" stops being a sufficient guarantee. Generic Paper 1 §3 guidance is not pidchain-specific evidence.

### No aggregator job in `ci.yml`

**Memory entity:** `PC-Decision-2026-04-27-no-aggregator-job`
**Relations:** `Project-PidChain --has_decision--> PC-Decision-2026-04-27-no-aggregator-job`; `PC-Decision-2026-04-27-no-aggregator-job --moot_per--> PC-Decision-2026-04-27-no-required-status-checks`

The Paper 1 §3 `all-green` aggregator pattern is not adopted in pidchain's `ci.yml`.

Reasoning: moot per the no-required-status-checks decision above. The aggregator's only purpose is to be the single name a branch-protection required-status-checks rule binds, so renaming or splitting upstream jobs doesn't orphan the required check. With no required-status-checks rule, the aggregator is a labeled status nobody reads — the workflow's overall run status already aggregates job statuses implicitly (red workflow = at least one red job, visible in the UI, PR check list, gh CLI, and API).

Confirmation from sibling repo: helm (`jwyattgh/helm`, similar author conventions) does not include an aggregator job either. `helm-pipeline.yml` gets aggregation from the DAG structure (`needs:` + `if: needs.X.result == 'success'` chains), not from a dedicated all-green job. "Match house style" does not argue for one.

Re-pitching is justified only if `PC-Decision-2026-04-27-no-required-status-checks` is reversed.

## Nice-to-Haves Considered and Parked

Six candidates evaluated during the review. None is declined outright (those would be PC-Decision-* entities). None is in flight. Each item below names what it is, why it's parked, and what would promote it.

### OpenSSF Scorecard

**What it is.** `ossf/scorecard-action` runs ~18 supply-chain hygiene checks (Branch-Protection, Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, SAST, Vulnerabilities, Dependency-Update-Tool, Maintained, Code-Review, etc.) and emits a 0-10 score. Companion: a README badge updated by the action.

**Cost.** ~25-line workflow file + 1 badge line in `README.md`. Most checks already pass on pidchain (SHA-pinned actions per 004a, least-privilege tokens per 002b, branch protection per 004e, CodeQL via GitHub default setup, govulncheck per 002e, Dependabot per 002d).

**Why parked.** Not load-bearing for security itself — the underlying properties Scorecard measures are already in place. The badge is signaling, not protection.

**Promote if:** (a) an enterprise consumer asks for the score, (b) Jason wants the badge in the README anyway as a one-evening task.

### dependency-review-action

**What it is.** GitHub-published action that runs on `pull_request` and blocks PRs introducing dependencies with known vulnerabilities at or above a configurable severity threshold. Backed by GHSA/OSV.

**Cost.** ~15-line workflow file.

**Why parked.** pidchain's coverage is already three-deep:

- Dependabot won't suggest known-vulnerable upgrades (consults the same database).
- Weekly govulncheck has reachability analysis stricter than dep-review's manifest scan.
- Jason is the only human PR author and reviews each one.

Marginal coverage is "between weekly govulncheck runs, a human PR introduces a freshly-disclosed vulnerable dep" — narrow window, low PR frequency.

**Promote if:** (a) PR volume increases (contributors materialize), (b) a specific incident makes the narrow window real.

### Signed commits

**What it is.** Ruleset rule requiring GPG/SSH-signed commits on `main`.

**Why parked.** Friction with bot signing identities. `release-please-bot` and `dependabot[bot]` both produce unsigned commits by default; allowlisting bot identities through a ruleset bypass is doable but adds maintenance. The commit-authorship integrity that matters for pidchain is already covered by the linear-history rule from 004e plus direct push only from Jason's machine.

**Promote if:** (a) a contributor base materializes (commit attribution starts to matter beyond Jason), (b) a compliance ask requires it.

### Tag protection ruleset

**What it is.** A separate ruleset on tag refs preventing tag deletion or reassignment.

**Why parked.** The threat model it defends (tj-actions-style tag-replay where an attacker repoints a published tag to a malicious commit) is an action-PUBLISHER's concern. pidchain consumes actions; it does not publish actions. Tags on pidchain are consumed by Go module path, where `sum.golang.org` provides immutability through the global checksum database — a repointed tag would change the checksum and consumer builds would fail with a hash mismatch rather than silently fetch malicious code.

**Promote if:** (a) pidchain ever publishes its own GitHub Action, (b) the Go module proxy ecosystem changes such that `sum.golang.org` is no longer the immutability guarantee.

### Required PR reviews

**What it is.** Ruleset rule requiring N approving reviews before a PR can merge.

**Why parked.** Solo maintainer; no second human to review. PR-to-self adds friction without review benefit.

**Promote if:** a contributor base materializes such that "review by someone other than the author" becomes a meaningful gate.

### Fuzz target on a schedule

**What it is.** `testing.F` fuzz targets running continuously via CI on a nightly schedule (or via OSS-Fuzz integration).

**Why parked.** Paper 2 §3's argument (any function taking `string`/`[]byte`/`io.Reader` from an untrusted caller deserves a fuzz target) does not bind to pidchain's surface. The exported API is two functions taking `int` PIDs; the data those functions then read (process ancestry, codesign info) comes from kernel-attested syscalls, not from caller-controlled bytes. The narrow input surface (negative ints, PID 0, PID 1, very large PIDs) is already covered by unit tests.

**Promote if:** pidchain's API ever grows a function accepting a `string` or `[]byte` from the caller (binary-path overrides, custom signing-data parsers, etc.).

## Memory Hygiene Performed

`PC-Decision-2026-04-27-no-harden-runner` previously contained an observation citing `PC-Decision-2026-04-27-no-sha-pinning-actions` for the threat-model argument. That entity does not exist — the SHA-pinning position was reversed (pidchain DOES SHA-pin; see `PC-Decision-2026-04-27-sha-pin-actions` and `004a-sha-pinning.md`). The threat-model argument the harden-runner decision relies on (CI compromise can't reach consumers via the Go-module path) is preserved in the sha-pin-actions decision's second observation.

The stale observation was deleted and replaced with a corrected version pointing to the correct entity, plus a separate observation explicitly noting the cross-reference correction.

## Items Explicitly Excluded from This Doc

For clarity, the following items are NOT covered here because they were already settled in prior sessions or are out of scope for the security review:

- `harden-runner` — already declined, see `PC-Decision-2026-04-27-no-harden-runner`.
- Concurrency block — already declined, see `PC-Decision-2026-04-27-no-concurrency-block`.
- Artifact attestations — already declined, see `PC-Decision-2026-04-27-no-artifact-attestations`.
- SHA-pinning actions — already adopted, see `PC-Decision-2026-04-27-sha-pin-actions` and `docs/archive/004a-sha-pinning.md`.
- CodeQL — already enabled via GitHub default setup (no workflow file needed; default setup is GitHub-managed).
- `.vscode/` gitignore — handled separately by Jason during this session.

## Success Criteria

This doc is documentation, not implementation. Verification confirms the memory artifacts exist as described and the file lands in the right place.

1. The two new Decision entities exist in memory:

   ```
   search_nodes "no-required-status-checks"   # returns PC-Decision-2026-04-27-no-required-status-checks
   search_nodes "no-aggregator-job"           # returns PC-Decision-2026-04-27-no-aggregator-job
   ```

   (Use `search_nodes`. Do NOT use `read_graph` per `Convention-Memory-Usage`.)

2. The three relations exist:

   ```
   Project-PidChain --has_decision--> PC-Decision-2026-04-27-no-required-status-checks
   Project-PidChain --has_decision--> PC-Decision-2026-04-27-no-aggregator-job
   PC-Decision-2026-04-27-no-aggregator-job --moot_per--> PC-Decision-2026-04-27-no-required-status-checks
   ```

   Visible via `open_nodes` on each entity.

3. The harden-runner cross-reference fix is in place:

   ```
   open_nodes ["PC-Decision-2026-04-27-no-harden-runner"]
   ```

   The observation referencing `no-sha-pinning-actions` is absent; a replacement observation references `sha-pin-actions`; a separate observation explicitly notes the cross-reference correction.

4. After this doc lands and is moved to `docs/archive/`:

   ```bash
   test -f docs/archive/004f-post-public-security-review.md && echo OK
   test ! -f 004f-post-public-security-review.md && echo "removed from root OK"
   ```

## Out of Scope

- Implementation of any nice-to-have. Each promote-if condition gates a future implementation doc; this doc only records the parked state.
- Reversal of any prior `PC-Decision-*` entity. Each prior decision specifies its own re-pitching criteria.
- Branch protection changes beyond what 004e shipped. The 004e ruleset is the full extent of `main` protection per the no-required-status-checks decision.
- README, `CONTRIBUTING.md`, or other documentation updates referencing the security posture. Those are separate doc passes if/when needed.
- Cleanup of unrelated stale memory entities. `Convention-Memory-Usage` holds the canonical rules; this doc only records the cross-reference fix performed during the review session.
