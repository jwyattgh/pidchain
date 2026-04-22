# Paper 1: GitHub Actions workflows as a mechanism

Workflows are the plumbing of a public Go repository. This paper treats them as infrastructure — what they are, what they can do, how to compose them well, and how they get exploited. What runs *inside* them (tests, linters, security scanners) is Paper 2's subject; when those topics appear here, they are acknowledged as payload and deferred.

## 1. The mental model

A GitHub Actions **workflow** is a YAML file under `.github/workflows/` that declares: an **event** that triggers it, one or more **jobs** that run when it triggers, and the **steps** inside each job. A job runs on a **runner** — a VM provisioned per-run (GitHub-hosted) or one you operate yourself (self-hosted). Each step is either a shell command or a **reusable action** identified by `owner/repo@ref`.

Four non-obvious facts anchor everything else:

1. Events are richer than "push" — they include `pull_request`, `pull_request_target`, `schedule` (cron), `workflow_dispatch` (manual), `workflow_call` (invoked by another workflow), `workflow_run` (fires when another workflow completes), `repository_dispatch` (external webhook), and `merge_group` (merge queues).
2. Jobs within a workflow run in parallel by default; use `needs:` to express a DAG. Jobs in *different* workflows are independent and may run concurrently unless you explicitly serialize them.
3. Every job receives a scoped, automatically-minted `GITHUB_TOKEN` whose permissions you can and should constrain.
4. Actions are just Git refs. `uses: some-org/some-action@v3` resolves a **mutable** tag; `@a1b2c3d…` resolves an **immutable** commit SHA. This one distinction is the hinge of workflow supply-chain security.

The rest of the paper lives on top of these four facts.

## 2. Landscape of what workflows do

Short definitions, with a canonical link for anything that warrants its own deep dive. Relevance is judged for a **pure-Go library** (source-only distribution via `go get`, no binary, no container, no service).

| Capability | What it is | Relevance | Deeper reading |
|---|---|---|---|
| **CI quality gates** | Build/test/lint/vuln/coverage on every push and PR. The core workload. Content is Paper 2. | **Core** | [golangci-lint-action](https://github.com/golangci/golangci-lint-action) |
| **Release automation** | Tag, changelog, GitHub Release. For a library the minimum is "push a semver tag"; `release-please` maintains a release PR driven by Conventional Commits without producing binaries. GoReleaser is aimed at CLIs and is usually overkill for a library. | High (release-please) | [release-please](https://github.com/googleapis/release-please) |
| **Dependency updates** | Dependabot (native, `.github/dependabot.yml`) or Renovate (Mend, `renovate.json`). Both handle `gomod` and `github-actions` ecosystems; Renovate has richer grouping, scheduling and shared presets, Dependabot is zero-setup. | High | [Renovate bot comparison](https://docs.renovatebot.com/bot-comparison/) |
| **Supply-chain artifacts** | SLSA provenance, signed releases (cosign/Sigstore), SBOMs (Syft, CycloneDX). GitHub's native **Artifact Attestations** GA'd 25 June 2024 and give SLSA v1.0 Build L2 by default. | Partial — see §4 below | [GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) |
| **Publishing** | For Go, *nothing to do.* pkg.go.dev is fed by `index.golang.org`, which is populated by the first `proxy.golang.org` fetch of a new semver tag. A pushed tag is the only required action. Container registries, Homebrew, Winget all live here for projects that ship binaries. | Automatic | [About pkg.go.dev](https://pkg.go.dev/about) |
| **Issue/PR triage** | Labelers (`actions/labeler`), stale bots (`actions/stale`), auto-assign, first-interaction welcomes, PR size labels. | Moderate | [actions/labeler](https://github.com/actions/labeler) |
| **Docs & Pages** | Build a docs site and deploy to GitHub Pages via `actions/deploy-pages` (modern) or `peaceiris/actions-gh-pages` (legacy). `godoc` renders automatically at pkg.go.dev — a separate Pages site is only worth it for narrative docs or a landing page. | Optional | [actions/deploy-pages](https://github.com/actions/deploy-pages) |
| **Scheduled jobs** | `on: schedule` with 5-field UTC cron. Timing is best-effort; scheduled workflows **auto-disable after 60 days without commit activity** (tag pushes do not count). | Moderate — useful for nightly `govulncheck`, weekly Scorecard | [Scheduled events docs](https://docs.github.com/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule) |
| **Matrix builds** | One job spec, N combinations. Core for Go-version × OS coverage. | Core — see §3 | [Using a matrix](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs) |
| **Reusable workflows** | Whole workflow invoked at job level via `workflow_call`, separate logs per called job, can receive `secrets: inherit`, max 4 levels nesting. | Low for a single library | [Reusing workflows](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations) |
| **Composite actions** | Multiple steps packaged as a single `uses:` step. Collapse into one log line, up to 10 levels nesting, no implicit secret access. | Low for a single library | Same doc |
| **Workflow-to-workflow triggering** | `workflow_run`, `repository_dispatch`, and `workflow_dispatch` chaining. Since Sep 2022 `GITHUB_TOKEN` can trigger the latter two. | Niche | [Events reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) |
| **Manual dispatch** | `workflow_dispatch` adds a "Run workflow" button and API; up to 25 typed inputs. | Yes — manual release cut, emergency reruns | [Manually running a workflow](https://docs.github.com/en/actions/managing-workflow-runs/manually-running-a-workflow) |
| **Environment protection** | Named environments with required reviewers (up to 6), wait timers, branch restrictions, and scoped secrets. Modeled on deployments. | Mostly no — a library has nothing to deploy. Useful only as a reviewer gate on a publish job. | [Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) |
| **Approval gates** | Required-reviewer environment + CODEOWNERS. | Yes, lightweight | [About CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) |
| **Artifacts** | `actions/upload-artifact@v4` / `download-artifact@v4`. v4 artifacts are immutable once uploaded; default 90-day retention. Useful for shuttling coverage profiles and JUnit reports between jobs. | Moderate | [upload-artifact](https://github.com/actions/upload-artifact) |
| **Larger / self-hosted runners** | Larger (paid, GA June 2023, up to 64 vCPU / 256 GiB, GPU/ARM SKUs). Self-hosted (you operate). Standard public-repo Linux/Windows runners are 4 vCPU / 16 GiB since Dec 2023. | Standard runners suffice for a library | [About larger runners](https://docs.github.com/actions/using-github-hosted-runners/about-larger-runners) |
| **Runner hardening** | `step-security/harden-runner` enforces egress policy per step and detects anomalies (this is how the tj-actions compromise was caught). | **Recommended baseline** | [Harden-Runner](https://www.stepsecurity.io/blog/github-actions-hardening) |
| **Beyond-CI automation** | ChatOps, auto-merge, project board automation, AI-assisted labeling (Sep 2025), backporting. | Moderate | [github.com/step-security/harden-runner](https://github.com/step-security/harden-runner) |

Three items from the brief deserve their own section rather than a table row: design patterns (§3), workflow security (§4), and anti-patterns (§5).

## 3. What "good" workflow design looks like

### One concern per file

The dominant pattern in well-run public Go repos is **one workflow file per logical concern**, not one monolithic `ci.yml`. Cobra, Hugo, and GoReleaser all split by trigger class and purpose: `test.yml`, `release.yml`, `codeql.yml`, `stale.yml`, `labeler.yml`. Stretchr/testify is the minimalist counter-example — a single 43-line `main.yml` — but testify is a deliberately tiny library. **The right unit is "one trigger class + one logical concern per file."** This makes required-check selection, permission scoping, and schedule reasoning tractable; it also keeps each file small enough for reviewers to actually read.

(Note that `kubernetes/kubernetes` uses Prow, not Actions, and `golang/go` uses Gerrit with its own LUCI-style coordinator. Neither is an Actions exemplar.)

### Reusable workflows, composite actions, and inlined YAML

These are not interchangeable. **Reusable workflows** are invoked at the job level; they contain full jobs with their own `runs-on`, log separately, can accept `secrets: inherit`, and nest up to four deep. **Composite actions** are invoked as a step; they collapse into a single log line, nest ten deep, and never receive secrets implicitly. The industry rule of thumb is pragmatic: default to **inlined YAML** until the same sequence appears in three or more workflows; reach for a composite action for step-level reuse across repos; reach for a reusable workflow when you need different runners per call, want OIDC `job_workflow_ref` scoping, or need a full multi-job pipeline template. Premature abstraction here is worse than duplication — abstracted workflows are famously harder to debug because expression evaluation at a distance becomes opaque. For a single Go library, the correct answer is almost always "inline it."

### Matrix strategies

A pure-Go library's matrix is driven by two axes: Go version and OS. The Go team officially supports **the two most recent major releases**, so `go-version: [oldstable, stable]` matches upstream policy. Adding `master` (Go tip) with `continue-on-error: true` gives free early warning of breakage against unreleased Go. Adding every Go release back to 1.17 is testify's choice and it is defensible only because testify is load-bearing for the ecosystem; most libraries should not do this.

For OS, `ubuntu-latest` is always in; `macos-latest` and `windows-latest` earn their place when the library touches paths, filesystem semantics, signals, or platform-specific syscalls. A pure compute/parsing library often skips macOS. Cost drives this more than correctness: against minute quotas, **Windows runners count 2× Linux and macOS counts 10×**.

Two matrix mistakes recur. The first is **leaving `fail-fast: true` on a test matrix**, which cancels every other leg at the first failure and destroys the diagnostic signal you ran the matrix to get. Set `fail-fast: false` on test matrices; leave it true only on matrices where legs are truly independent failure units (e.g., parallel deploys, which do not apply to a library). The second is **matrix explosion** — (Go versions) × (OSes) × (build tags) × (GOARCH) quickly produces 40+ legs, each with ~30s of fixed checkout/setup overhead, so 40 legs buys ~20 minutes of pure scaffolding before a single test runs. Use `include`/`exclude` to make the matrix sparse: full coverage on the common cell, exotic OS/Go only at the corners.

### Caching

Since v4, `actions/setup-go` caches `$GOMODCACHE` and `$GOCACHE` by default, keyed on `hashFiles('go.sum')` (or `go.mod` in v5+). **This default is enough for most Go libraries.** Disable it and you pay a cold module download on every run; layer `actions/cache` on top and you risk making things slower for small projects where the cache round-trip exceeds the work.

When manual caching is warranted (generated code, wasm builds, large tool binaries), three rules apply. Include OS, Go version, and `hashFiles('**/go.sum')` in the key. Provide a `restore-keys` prefix ladder so a partial miss still gets a warm partial cache. Include a **manual cache-busting suffix** (`-v2-`) you can bump to purge poisoned state without waiting for GitHub's 7-day LRU eviction to catch up. GitHub caches are branch-scoped (PR caches read from `main` but write to PR scope), which mitigates but does not eliminate cache-poisoning risk when untrusted input reaches the key.

### Job graph design

Run jobs in parallel by default; add `needs:` only where a later job literally consumes an earlier job's artifact. The anti-pattern is a sequential `checkout → deps → lint → test → build` pipeline on a single job when lint and test have no ordering requirement and the whole workflow should fan out from the start.

**The most important DAG pattern for a public library is the terminal aggregator job.** Define one final job — call it `all-green` — that `needs:` every other job, runs with `if: always()`, and asserts every dependency succeeded. Make only this aggregator a required check in branch protection. Now you can rename, add, or split upstream jobs freely without breaking required-check matching. Without this pattern, renaming a job from `test` to `tests` silently orphans a required check and either blocks PRs forever or (with "require up-to-date" off) merges them without the check running at all.

### Concurrency

Two canonical groups cover 95% of cases. For PR CI: group by workflow + ref, **cancel in progress** — superseded commits on an open PR should not keep burning minutes. For releases and deploys: group by workflow + ref, **do not cancel** — partial release state (half-updated tap, dangling draft release) is worse than a delayed release.

The subtle trick is to cancel-in-progress on PRs but never on `main`: key the group such that on the default branch it resolves to `github.run_id` (unique per run, so nothing ever matches) and on PRs it resolves to a stable per-PR identity. Getting this backwards causes mysterious cancellations on main.

### Trigger design

Naively writing `on: [push, pull_request]` produces **double runs on every PR**: one for the push to the branch, one for the `pull_request` synchronize. Doubled minutes, doubled flake probability, and GitHub confirms this is intended behavior rather than a bug. The fix is to scope push triggers to the default branch and tags — `push: branches: [main], tags: ['**']` — and rely on `pull_request` for PR coverage.

Path and branch filters earn their keep on large repos but have a nasty interaction with required checks: **a workflow skipped by `paths-ignore` reports as "pending," which blocks required-check-gated merges forever.** The workarounds are ugly (a dummy companion workflow that always passes, or moving the conditional logic inside a workflow that always runs and uses `dorny/paths-filter` internally). Choose path filters with this cost in mind.

### Required checks and branch protection

Branch protection is the enforcement surface without which all the CI above is advisory theater. **Repository rulesets** (2023+) have largely superseded classic branch protection: they stack, support evaluate-mode dry runs, match checks by integration source rather than exact string, and handle reusable-workflow name concatenation gracefully. For a new public library, start with a ruleset, require the `all-green` aggregator, require signed commits if that fits the team, and restrict force-pushes to `main`.

## 4. Security of the workflows themselves

Workflows are a supply-chain attack surface. They ingest third-party code every run and execute it with secrets and write access to the repo. The industry pattern of pulling `uses: popular-action@v3` is cheap; the industry pattern of auditing what that tag actually resolves to is rare. That gap is where compromises live.

### The tj-actions compromise is the canonical case study

On **14 March 2025 around 16:00 UTC**, `tj-actions/changed-files` — an action used by roughly 23,000 repositories — was compromised. The attacker had gained a personal access token belonging to `@tj-actions-bot` (via a chained compromise through SpotBugs → reviewdog → `tj-actions/eslint-changed-files`) and used it to retroactively **repoint every existing version tag, from v1.0.0 through v45.0.7, to a single malicious commit**. The payload dumped the runner's worker-process memory, double-base64-encoded any secrets found, and printed them to the workflow log — where, on public repositories, anyone could read them. GitHub removed the action at 14 March 14:00 UTC the next day and the tag history was cleaned twelve hours later. **CVE-2025-30066**, CVSS 8.6, CISA KEV. StepSecurity's [incident writeup](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) is the canonical postmortem; Wiz's [analysis](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066) and Palo Alto Unit 42's [reconstruction of the attack chain](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/) are companions.

The reason this attack was possible — despite tj-actions being a verified-creator marketplace action used by Coinbase, thousands of companies, and OSS projects — is that **every repository using it referenced a mutable tag**. Tags are pointers. They move. The attacker moved them.

### Pin by commit SHA, not by tag

GitHub's official security hardening guide is unambiguous: *"Pinning an action to a full-length commit SHA is currently the only way to use an action as an immutable release."* OpenSSF Scorecard's `Pinned-Dependencies` check enforces this. Since August 2025, GitHub enterprise policy can require SHA pinning at the org level and can blocklist actions by prefix for rapid incident response.

The real argument against SHA pinning is **maintenance cost** — you lose automatic minor/patch uptake. That argument collapses once Dependabot or Renovate is configured for the `github-actions` ecosystem: both update the pinned SHA and the trailing `# v1.2.3` comment on a schedule. The correct posture for a public Go library in 2026 is **SHA-pin every third-party action, let a bot keep them current, and review the bot's PRs**. Short SHAs are not acceptable — forked repos can publish colliding short SHAs that make your reference ambiguous. Use full 40-character SHAs.

A narrow exception: `slsa-framework/slsa-github-generator` deliberately requires tag pinning because its trust model depends on tag-bound build isolation. That is a specific carve-out, not a precedent.

### Principle of least privilege on GITHUB_TOKEN

For repositories created after 2 February 2023, the `GITHUB_TOKEN` default is read-only. **Repositories created before that date retain the permissive legacy default** and GitHub did not retroactively change them. If the repo you're about to make public is older, verify this in settings or declare permissions explicitly, because `contents: write` as an unintentional default has funded many of the worst incidents.

Best practice is to set `permissions: {}` at the workflow level and add the minimum scopes each job actually needs at the job level. OpenSSF Scorecard's `Token-Permissions` check enforces this. Critically, **`pull_request_target` events receive permissive defaults regardless of repo settings** unless `permissions:` is explicitly declared.

### OIDC instead of long-lived cloud secrets

If any workflow needs AWS, GCP, Azure, or HashiCorp Vault credentials, use OIDC. GitHub mints a short-lived JWT per run; your cloud IAM validates it and returns short-lived credentials scoped by repo, branch, workflow, or environment via `sub` claim matching. This eliminates the long-lived `AWS_ACCESS_KEY_ID` that tj-actions payloads were specifically hunting for. Requires only `permissions: id-token: write` and the cloud-specific action (`aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login`). Canonical reference: [OpenID Connect in GitHub Actions](https://docs.github.com/en/actions/concepts/security/openid-connect).

### The pull_request_target footgun

`pull_request_target` runs in the context of the base branch — with the base branch's secrets, the base branch's `GITHUB_TOKEN`, and permissive default permissions. It is triggered by pull requests from forks. The intended use is PR metadata automation: labelers, title linters, reviewer assignment. The dangerous use, known as the "pwn request," is checking out `pull_request.head.sha` and then running *anything* — `npm install`, `go build`, even shelling out — on that untrusted code, which now executes with base-repo secrets in its environment. CVE-2025-61671 (Microsoft `symphony`, CVSS 9.3) and GHSA-h25v-8c87-rvm8 (Spotipy) are the recent public examples; GitHub's Security Lab has a [canonical writeup](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/). The rule is simple: never check out untrusted code in a `pull_request_target` workflow. If you need to lint or build PR contents with access to write-scoped tokens, split the work — use an unprivileged `pull_request` workflow that uploads an artifact, then a privileged `workflow_run` workflow that downloads the artifact and treats its contents as untrusted data.

### Third-party action trust

GitHub Marketplace is a publication channel, not a review process. The "verified creator" badge attests to the publisher's identity, not the action's code. Star counts are not security signals — tj-actions had thousands of stars and 23,000 users. Meaningful signals are: is the action SHA-pinned to a known-good commit; is the source small enough to read; does it have active maintenance; does it sign its own releases; does it have a security policy. Use `Dependabot` or `Renovate` in the `github-actions` ecosystem so that the set of SHAs you trust is updated deliberately rather than silently.

### Self-hosted runners on public repos are almost always wrong

GitHub's own documentation is explicit: *"Self-hosted runners should almost never be used for public repositories... because any user can open pull requests against the repository and compromise the environment."* Non-ephemeral runners retain filesystem state and cached credentials between jobs; concurrent jobs can observe each other's secrets via `ps`. The November 2025 Shai-Hulud worm weaponized compromised self-hosted runners as GitHub.com-authenticated C2 backdoors. For a public Go library, use GitHub-hosted runners. If self-hosted is genuinely required, use **ephemeral / JIT runners** that deregister after a single job, enforce strict network egress with `step-security/harden-runner`, and never expose them to fork PRs.

### Secrets leakage is not just the obvious

GitHub masks configured secrets in logs — but not values *derived* from secrets, not base64-encoded secrets (which is why tj-actions used double-base64 specifically), and not anything written to artifacts. `actions/checkout` leaves `.git/config` containing `GITHUB_TOKEN` by default; Palo Alto's ArtiPACKED research found thousands of tokens leaked this way across top GitHub orgs. The `ACTIONS_RUNTIME_TOKEN`, which grants cache-poisoning capability, is not masked at all and is recoverable from runner memory. Debug mode (`ACTIONS_STEP_DEBUG`) can re-expose masked values. Treat secrets as "something attackers will try to extract by memory dumping and artifact mining," not as "something GitHub will redact for you."

## 5. Named anti-patterns

**Green CI that tests nothing.** A workflow that runs `go build ./...` but no `go test`, or tests that don't assert, or tests that early-return when a flag is unset. Suspiciously fast CI (under ten seconds total) is often this. Counter with a coverage floor and an assertion linter.

**No required checks.** A workflow that runs but does not block merges is advisory only. New contributors learn quickly that red CI is optional. Enforce via rulesets against the `all-green` aggregator job.

**SARIF uploaded, never triaged.** Running CodeQL or gosec and uploading the SARIF to the Security tab, where no one has notifications configured, is theater. Either wire up notifications and assign an owner, or have the job fail on high-severity findings in PR context.

**"It's a small package, so skip security workflows."** This is the most common and most corrosive pattern in the Go ecosystem. A 300-line utility imported by thousands of repos is exactly where supply-chain attackers want to plant code, because it has a long dependency tree reaching it and a short maintainer-attention tree watching it. The good version: on day one of going public, a minimum of `govulncheck` on a schedule, `actions/dependency-review-action` on PRs, CodeQL, `step-security/harden-runner` on every job, SHA-pinned actions, and least-privilege `GITHUB_TOKEN`. The cost is a couple of hours once; the ongoing maintenance is reading bot PRs. "Small package" is precisely the wrong reason to skip this — attackers pick the packages whose maintainers will skip it.

**Monolithic 800-line `ci.yml`.** Unreviewable, untestable, entangled triggers, impossible to permission correctly. Split by concern.

**Unreviewed marketplace actions.** Using `uses: somebody/something@v1` because a Stack Overflow answer said so, unpinned, unread. Cost: the next tj-actions.

**Secrets leaked via logs or `pull_request_target` misuse.** See §4.

**Caches that persist bad state.** A poisoned or corrupted cache silently serves wrong bytes. Key design and manual cache-busting suffixes are the fix.

**Expensive jobs on doc-only changes.** Full matrix builds on a README typo. Mitigated with care — path filters plus required checks is a known-sharp combination (§3), so prefer conditional steps within an always-runs workflow over skipped workflows.

**No concurrency control on deploy/release.** Rapid successive tags racing each other corrupt release state. Concurrency groups without `cancel-in-progress` serialize them.

**CI drift.** The laptop runs Go 1.23 and `golangci-lint v1.62`; CI runs Go 1.22 and `golangci-lint v1.55`. "Works on my machine" and "works in CI" diverge from each other and from production. Pin CI's Go version to `go-version-file: go.mod`, pin linter versions everywhere, and ship a Makefile or `tools/tools.go` that developers and CI both consume.

**Dependabot auto-merged without human review.** This is a real debate. Filippo Valsorda's [Geomys Standard of Care](https://words.filippo.io/standard-of-care/) argues that Go libraries specifically should **not** run Dependabot on their own dependencies, because upgrading to a newly-released version before the ecosystem has detected supply-chain attacks in it expands your attack surface. The stronger practice for a public Go library is: Dependabot/Renovate *only* for the `github-actions` ecosystem (keep pinned SHAs fresh, human-review each bump), plus a scheduled `govulncheck` and "build against latest deps" job. Reserve `gomod` updates for deliberate review.

## 6. Cost, speed, and developer experience

Public repositories using GitHub-hosted standard runners are **free** as of 2026 and GitHub has publicly committed to keeping them free. For private repos, the OS multipliers against your minute quota are the knob that matters: **Linux 1×, Windows 2×, macOS 10×**. GitHub announced pricing reductions effective 1 January 2026 and a new $0.002/minute platform charge on self-hosted runners effective 1 March 2026; the multiplier structure is stable.

For a pure-Go library, target **under two minutes at p50 and under five at p95** for PR feedback. Past that, developers start context-switching away and the PR review loop breaks. The lever that moves this most is splitting a fast-feedback tier (lint plus one cell of the test matrix, always required) from a comprehensive tier (full matrix, race detector, fuzz, integration) run on main and nightly. Caching, parallelization within the matrix, and avoiding macOS unless needed are the other major levers.

Flaky CI is a developer-experience killer distinct from slow CI. Teams faced with flakes learn to re-run until green, which silently trains them to ignore real failures. Retry actions (`nick-fields/retry`, `go test -count=N`) paper over ordering bugs, races, and network flakes; they are a smell, not a solution. Quarantine flakes behind a build tag, fix them, or delete them. `go test -race` catches a meaningful fraction at test time.

## 7. Where GitHub Actions is good and where it isn't

Actions is genuinely good at tight GitHub integration — PR checks, deployments API, OIDC, auto-minted scoped tokens — at the breadth of its marketplace (setup-go, goreleaser-action, golangci-lint-action, the CodeQL action), and at being free for public repositories. For a public Go library this combination is hard to beat.

It is genuinely weak at three things. **Debugging** — no native SSH to the runner (third-party `mxschmitt/action-tmate` is the common workaround), restricted expression language, opaque evaluation of `if:` conditions, no dry-run mode for rulesets outside evaluate-mode. **Local reproduction** — `nektos/act` approximates running a workflow locally but diverges on matrix, secrets, and networking, so "works in CI but not locally" is endemic. **Complex DAGs** — `needs:` is the only primitive, with no conditional edges ("run B only if A produced artifact X"), no YAML anchors for DRY, and conditionals that become hairy once nested. For a library, none of these are blockers. For large orchestration graphs they are the reason teams end up on Buildkite, GitLab CI, or back to Jenkins.

GitLab CI has stronger DAG primitives and a built-in container registry; CircleCI has historically been faster and has better macOS/ARM pricing; Buildkite decouples control plane from runners and is strong at bare-metal scale; Jenkins is infinitely configurable and correspondingly painful. None of these is a better choice than Actions for a public, GitHub-hosted Go library in 2026 — but it is worth knowing what the other options are good at, because workflows you write for Actions will embed assumptions that are specific to Actions.