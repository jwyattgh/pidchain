# Paper 2: What runs inside the pipeline

Paper 1 covered the pipeline mechanism. **This paper covers what fills it.** The question is not "how do we run tests" but "what tests, linters, and scanners are worth running on a pure-Go library whose sole job is to be imported and called." The answer is more opinionated than the Go community usually admits on linting and mocking, and more nuanced than the AI-skeptical discourse admits on coverage. Everything below is scoped to a library — no servers, no CLIs, no databases — because that scope changes which tools are load-bearing and which are theater.

## 1. What "testing a public Go library" actually means

A library is a building block installed into somebody else's program. Its tests have four distinct jobs, and confusing them produces bad test suites. First, they **prove the function works** against its specified behavior. Second, they **document expected behavior** for consumers who will read the tests as a secondary reference after the godoc. Third, they **catch regressions** on behalf of downstream consumers who cannot easily roll back a dependency. Fourth, they **prove no trivial attack breaks the library** — parser panics, unbounded allocations, reflect misuse on caller-supplied input.

This scope differs materially from testing a service or a CLI. There is no long-running state, no database, no HTTP surface, no flag parsing, no terminal UX. What remains is almost entirely exercising exported functions with inputs and checking outputs. That narrowness is a gift: it means the test suite can be near-total. It also raises the bar — there is no "we couldn't test that part" excuse for uncovered code.

The audience shift also matters. When consumers are other Go developers, the exported API becomes a **contract**: every public identifier is something you will have to keep working, or break loudly with a major-version bump. The `internal/` subtree is not contract — the Go tool enforces that only siblings can import it, which is why designating code as `internal/` is a design decision about the public surface, not a directory-organization decision. Example functions (`ExampleFoo`) become executable documentation rendered on pkg.go.dev — for a library, they are among the highest-leverage test artifacts available because they double as docs and force you to keep your stated usage pattern compiling.

## 2. The genuine debate: unit versus integration

The unit-vs-integration debate is real, and pretending it is settled produces bad advice. Two schools have been arguing since the early 2000s. Neither is wrong; they are optimizing for different things.

**The classicist (or "Detroit/Chicago") school**, associated with Kent Beck, Martin Fowler's later writing, and the Go standard library's own test style, says: test behavior end-to-end within a meaningful component, use real dependencies wherever feasible, mock only what you truly cannot use in-process (network, databases, clocks). Classicists prefer **sociable tests** (Fowler's term, via Jay Fields) that let collaborators participate in the test. The Go standard library's tests for `math`, `time`, `net/http`, and `encoding/json` are almost entirely classicist.

**The mockist (or "London") school**, canonized in Freeman and Pryce's *Growing Object-Oriented Software, Guided by Tests*, says: test units in strict isolation, replace every collaborator with a test double, verify interactions rather than just state. Mockists prefer **solitary tests** and use mocks to drive design toward small injectable interfaces.

**The Go community leans classicist** by culture. Rob Pike's proverb "a little copying is better than a little dependency" points the same direction. Dave Cheney's "SOLID Go Design" and Bill Kennedy's Ardan Labs posts have argued for years that interfaces should be declared by the consumer, not the producer, and that adding interfaces purely to enable mocking is an anti-pattern ("interface pollution"). Yet `gomock` (now `go.uber.org/mock`, forked from the archived `golang/mock` in June 2023) and `testify/mock` and `matryer/moq` all exist, are widely used, and the community has never reached consensus. Small Go interfaces make mockist-style tractable, which partly defeats the classicist argument by making the cost of mocking low.

**A position worth engaging with**: unit tests test only *our* code; anything imported — stdlib, third-party SDKs, the OS — is already tested by its authors, so replace it with a test double in unit tests. Integration tests then prove our code integrates correctly with those real dependencies across environments. This position is coherent and it maps cleanly onto the mockist school. It is also defensible. But three industry objections deserve direct engagement, not dismissal.

*Objection 1: mock too eagerly and you test your mocks, not your code.* The interface between your code and a dependency is part of your code. If you stub out `net/http.Client` with a fake that always returns 200, you have not tested that your retry logic handles 503s — you have tested that your code does what your fake said. The fix is not to abandon the position but to be honest about what it proves: unit tests with doubles prove the *shape* of the integration is correct given an assumed contract; integration tests prove the assumed contract matches reality.

*Objection 2: "our code vs their code" blurs fast.* A thin wrapper around an AWS SDK call is mostly their code with a handful of our decisions layered on top. Generated code (protobuf, mockgen output) is nobody's and everybody's. The practical rule: if you wrote it or chose its behavior, it's yours and deserves tests; if you imported it verbatim, it isn't. Wrappers sit on the boundary and usually need both a mocked unit test (proving your decisions) and an integration test (proving the wrapped call actually works).

*Objection 3: integration tests are slow, flaky, and hard to reproduce, so mocks become the dominant signal whether you intended that or not.* This is the most damaging objection, and the honest response is: build the integration tier with discipline or you will get a false sense of coverage. For a pure-Go library with no external services, this objection is weaker — there is rarely a real external dependency to integrate against in the first place.

**The synthesis that actually holds up**: the unit/integration line is about **scope, not technique**. A unit test exercises the smallest meaningful piece of *your* code; an integration test exercises how that piece connects to something it depends on. Test doubles are a tool usable in either, though in practice they dominate unit tests. The mockist position ("doubles for our code's dependencies, real calls for integration") is a defensible organizing principle as long as you stay honest about what it does and does not prove — and as long as the integration tier actually exists and runs.

For the specific case of a pure-Go library with no services, the debate collapses substantially. There is often nothing to integrate against. Classicist and mockist converge: exercise exported functions, handle any I/O abstractions with a fake, call it done.

## 3. The full Go testing toolkit

Every item below is worth knowing for a public library. The table summarizes; the prose covers what the table cannot.

| Tool | Built-in? | What it solves | Canonical reference |
|---|---|---|---|
| Table-driven tests | Idiom | Compact expression of many input/expected cases | [Cheney, "Prefer table driven tests"](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests) |
| Subtests (`t.Run`) | Go 1.7 | Hierarchical naming, selective execution, `t.Parallel` | [go.dev/wiki/TableDrivenTests](https://go.dev/wiki/TableDrivenTests) |
| Example functions | Built-in | Compile-checked docs rendered on pkg.go.dev | [pkg.go.dev/testing#hdr-Examples](https://pkg.go.dev/testing#hdr-Examples) |
| Fuzzing | Go 1.18 | Coverage-guided semi-random inputs, auto-minimized corpus | [go.dev/doc/security/fuzz](https://go.dev/doc/security/fuzz/) |
| Property-based | External | Invariant-over-all-inputs with automatic shrinking | [pgregory.net/rapid](https://pgregory.net/rapid/) |
| Race detector | Built-in | Runtime data-race detection | [go.dev/doc/articles/race_detector](https://go.dev/doc/articles/race_detector) |
| Benchmarks + benchstat | Built-in + x/perf | Statistical perf comparison across commits | [pkg.go.dev/golang.org/x/perf/cmd/benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) |
| `testing/synctest` | Go 1.25 | Deterministic concurrency with virtual time | [go.dev/blog/testing-time](https://go.dev/blog/testing-time) |
| Golden files | External pattern | Large-output comparison with `-update` flag | Various (`sebdah/goldie`, `hexops/autogold`) |

**Table-driven tests** are not a framework — they are the idiom the Go community converged on. A single `Test` function contains a slice (or map) of input/expected-output rows, iterated with `t.Run(name, …)`. The payoffs are compactness, expressive failure messages (each row runs under its own named subtest), and trivially easy extension. They are the default shape of a Go unit test. The only real pitfall is naming: if rows share a struct field called `want` of a single type, you cannot easily mix success and error cases — a common minor refactor is to add a `wantErr` field or split into two tables.

**Subtests** via `t.Run` arrived in Go 1.7. They do three things worth understanding independently of table-driven style: hierarchical test names let you filter with `go test -run=TestFoo/specific_case`; per-subtest `t.Parallel()` lets you fan out cases; and they make failures per-row instead of per-function, so the first failure doesn't mask the others.

**Example functions** are a feature unique to Go and underused on public libraries. `func ExampleSplit()` with a trailing `// Output: …` comment compiles, runs as part of `go test`, asserts the stdout matches the Output comment, and renders on pkg.go.dev as a runnable documentation example. Variants (`ExampleType`, `ExampleType_Method`, `ExampleType_method_variantName`) attach the example to the appropriate godoc location. For a library, this is the single highest-leverage test form because every example is simultaneously a regression test, a compile check against API drift, and documentation. Shipping a public library without examples means missing both a test surface and a documentation surface.

**Fuzzing** shipped natively in Go 1.18. `FuzzXxx(f *testing.F)` functions register seed inputs with `f.Add(…)` and a target with `f.Fuzz(func(t *testing.T, args…))`; `go test -fuzz=…` mutates inputs continuously, uses coverage feedback to prioritize inputs that explore new paths, and writes any failing input to `testdata/fuzz/FuzzXxx/`, where it joins the seed corpus as a permanent regression. For any library that parses, validates, or transforms caller-supplied input, fuzzing is the highest-ROI test mode available. It routinely finds panics, encoding inconsistencies, and unbounded allocations that no unit test would reach. OSS-Fuzz supports the native Go 1.18 engine directly — a public library used widely enough to matter can apply for continuous OSS-Fuzz coverage for free.

**Property-based testing** is distinct from fuzzing. Fuzzing generates random byte-ish input and looks for crashes; property-based testing asserts invariants that must hold *for all* inputs (e.g., `Decode(Encode(x))` equals `x`, or `Sort(xs)` is sorted and has the same multiset as `xs`), generates structured values of arbitrary types, and **shrinks** a failing case to a minimal counterexample automatically. The legacy `testing/quick` in the standard library does primitive property generation without shrinking and is effectively frozen. `gopter` is the older third-party library. **`pgregory.net/rapid` by Gregory Petrosyan is the modern choice**: it uses a bitstream-based generator that enables fully automatic shrinking without user-written shrinkers, supports state-machine testing, and interoperates with `go test -fuzz`. For a library with any mathematical or transformational structure, property-based tests catch whole classes of bugs that table-driven tests miss by construction.

**The race detector** is not a test type; it is a compile mode. `go test -race` instruments memory accesses and reports at runtime when two goroutines touch the same location without synchronization. It runs several times slower and uses significantly more memory, so it is not free, but for any library that touches goroutines it should run on every CI job. Races caught by `-race` are almost never caught by non-race tests, and shipping a public library with a racy internal helper is the kind of bug that downstream consumers cannot work around.

**Benchmarks** via `testing.B` and the `b.N` loop are built in. The discipline most teams skip is **benchstat** (`golang.org/x/perf/cmd/benchstat`), which runs `go test -bench` multiple times on two revisions and reports whether the delta is statistically significant. Benchmark numbers without benchstat are noise. For a public library, performance regressions are real bugs for consumers — a 30% slowdown in a hot-path function is a breaking change even if no API changed. Tracking benchmarks in CI with `benchstat` comparing against `main` is valuable and commonly skipped.

**`testing/synctest`** stabilized in Go 1.25 (released August 12, 2025), after one release as an experiment in 1.24. `synctest.Test(t, func(t *testing.T) { … })` runs its body inside a "bubble" where the `time` package uses a virtual clock and time advances only when every goroutine in the bubble is durably blocked. `synctest.Wait()` blocks until the bubble quiesces. This makes tests for code using `time.After`, `context.WithTimeout`, tickers, or goroutine coordination **deterministic and near-instantaneous** — a 60-second timeout test runs in milliseconds. The older `synctest.Run` from Go 1.24 is deprecated; new code should use `Test`. For any library with concurrency or time-based logic, this is the biggest testing improvement Go has shipped in years. It directly replaces the flaky-sleep pattern that caused most historical flakes in Go test suites.

**Golden / snapshot tests** store expected output in a `testdata/` file and compare. A common convention is a `-update` flag that regenerates the golden. They are genuinely contested. Classicists like them for output that is tedious to encode as Go literals (formatted text, generated code, large JSON). Purists dislike the implicit "just re-record when it drifts" loop, which lets semantic regressions slip past review as formatting diffs. The pattern works if code review treats golden-file diffs with real scrutiny; it degrades to rubber-stamping when it isn't. `sebdah/goldie` and `hexops/autogold` are the commonly-used helpers.

## 4. Test doubles: the taxonomy the industry conflates

The industry calls everything a "mock." The vocabulary predates that sloppiness by twenty years. Gerard Meszaros codified the terms in *xUnit Test Patterns*; Martin Fowler popularized them in ["Mocks Aren't Stubs"](https://martinfowler.com/articles/mocksArentStubs.html) (2004, rev. 2007) and the ["TestDouble"](https://martinfowler.com/bliki/TestDouble.html) bliki. All five are **test doubles**; the word "mock" is one of them.

| Double | What it does | Can fail a test? | Typical Go form |
|---|---|---|---|
| Dummy | Satisfies a parameter slot, never used | No | `nil` or `struct{}` passed in |
| Stub | Returns canned values to queries | No (except compile) | Hand-written struct with fixed methods |
| Fake | Working lightweight implementation | Yes, if behavior wrong | In-memory store, `httptest.Server` |
| Spy | Stub that records calls for later assertion | Yes, on assertions after | `FooCalls []argStruct` field |
| Mock | Pre-programmed with expectations, verifies during run | Yes, on unmet expectation | `gomock`, `testify/mock` generated |

The distinctions matter because they change what your test proves and how brittle it is. A **stub** says "assume the dependency returns X; given that, does my code do Y?" A **fake** says "here is a simplified but real implementation; does my code work against it?" A **mock** says "I expect my code to call this dependency with exactly these arguments in this order." Mocks tightly couple tests to the implementation's call sequence; refactoring the call order breaks the mock even if the behavior is unchanged. Fakes do not.

For the mockist position described in §2, what most use cases actually want is a **fake** (in-memory replacement) or a **stub** (canned response), not a true mock with expectations. A hand-written fake — 30 lines of struct with a `map[string]Record` backing store — is usually more readable and more refactor-robust than a generated mock. `uber-go/mock` (the successor to the archived `golang/mock`) and `testify/mock` and `matryer/moq` generate mocks; none of them generate fakes, because a fake requires understanding the dependency's semantics. The industry preference for generated mocks is largely a preference for the path of least typing. For a library with a handful of injection points, hand-written fakes are nearly always the better investment.

One reflexive response deserves pushback: "Go interfaces are so small that mocking is trivially easy." True, and that is exactly why hand-written fakes are also trivially easy — a single-method interface needs one struct with one method field, not a code generator.

## 5. Coverage: the vanity metric debate, and why AI changes the answer

Go's built-in coverage: `go test -cover` gives a percentage; `-coverprofile=c.out` writes a profile; `go tool cover -html=c.out` renders a per-line HTML view. Since Go 1.20, `go build -cover` instruments whole binaries, which write counter and meta files to `GOCOVERDIR` on exit, and `go tool covdata` merges and reports across multiple runs — this extends coverage measurement from unit tests to binaries exercised by integration tests ([go.dev/blog/integration-test-coverage](https://go.dev/blog/integration-test-coverage)). `-covermode=set` records whether a statement executed (default), `count` records how many times, `atomic` is `count` but race-safe — required if the code under test uses goroutines.

What coverage measures: whether a statement (or, with tooling, a branch) executed during tests. What coverage **does not** measure: whether the executing test actually asserted on the behavior, or whether uncovered code is reachable at all. That gap drives the industry debate.

The skeptic camp — Martin Fowler's ["TestCoverage"](https://martinfowler.com/bliki/TestCoverage.html) bliki, Kent Beck's recent Substack writing, most experienced TDD practitioners — argues that **coverage is a vanity metric**. Setting a coverage floor incentivizes tests that execute code without asserting anything meaningful (the toothless `assert.NotNil(result)` pattern), obscures real bugs behind green numbers, and produces false confidence. Brian Marick's 1999 note, quoted by Fowler, is the canonical statement: "I expect a high level of coverage. Sometimes managers require one. There's a subtle difference."

The floor-advocate camp — [Google's "Code Coverage Best Practices"](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html) post, most large OSS projects — responds that while the skeptic is right in the limit, in the real world the much more common failure mode is "code shipped with no tests at all." A coverage floor catches that. A test that executes without asserting is visible to human review; a PR with no test file is visible to an automated check. The argument is asymmetric: coverage does not prove tests are good, but absence of coverage proves tests are missing.

**The AI-assisted development context changes the calculus materially.** The skeptic's argument assumes a human author acting in good faith, who might game a coverage metric but could be caught in review. That assumption does not match AI-assisted development. The documented failure modes of LLM-generated tests are precisely the ones the skeptic trusts review to catch: [tests that pass without asserting](https://dev.to/toniantunovic/ai-agents-generate-code-that-passes-your-tests-that-is-the-problem-56jb), assertions that mirror the implementation so any bug is reflected in the test, tests that cover the happy path but no boundaries, and — Kent Beck himself has noted this in ["Augmented Coding"](https://tidyfirst.substack.com/p/augmented-coding-beyond-the-vibes) (2025) — LLMs that quietly delete or disable failing tests to get back to green. Against that threat model, a coverage floor is not a vanity metric. It is the simplest available mechanism to verify that tests exist at all, and it raises the bar on what the LLM has to fake in order to cheat. For a public Go library with AI-assisted development, **a coverage floor is load-bearing, not cosmetic.**

Sensible numbers for a library: **70-80% is a common industry floor**; 90%+ is achievable for a small pure-Go library and worth pursuing because the surface is small and the return is high; 100% produces diminishing returns and often forces contortions to test error branches that will never fire. Coverage exclusions — generated code, `main.go` for libraries that incidentally have one, `vendor/` — should be explicit in the config and reviewed, not accumulated silently. The anti-pattern of quietly excluding "hard to test" files until the reported number looks good is addressed in §10.

The skeptic is still correct about the limit case: a high coverage number with useless assertions is possible. Mutation testing is the backstop.

## 6. Mutation testing: the quality-of-tests backstop

Mutation testing mutates the production code — flips booleans, changes `<` to `<=`, removes statements, swaps arithmetic operators — and reruns the tests. A mutation the tests catch is a "killed mutant"; a mutation the tests miss is a "surviving mutant," meaning the test suite did not actually depend on the original behavior. Mutation score = killed / generated. A suite at 95% line coverage but 40% mutation score is tests that execute but don't check — exactly the failure mode the coverage skeptic warned about and the AI-assisted context makes more likely.

The Go ecosystem's tooling is less mature than Java's PIT or JavaScript's Stryker. `zimmski/go-mutesting` was the original and has been effectively unmaintained for some time — an [open issue](https://github.com/zimmski/go-mutesting/issues/100) explicitly asks about its abandonment. The `avito-tech/go-mutesting` fork is somewhat more active but still sporadic. `gtramontina/ooze` is a more recent alternative with a cleaner approach (the mutation runs itself as a Go test, via `go:build mutation`). None of these is a drop-in production tool on the level of PIT.

Practical guidance: mutation testing is the right conceptual answer to "are my tests actually asserting things?" but its Go tooling is not mature enough to run on every PR. The realistic use is periodic — weekly or monthly cron, on main, with results reviewed by a human. For a small library (a few hundred lines, one or two packages), the full mutation run may complete quickly enough to be tractable. Either way, treat it as a code-health check, not a gate. Industry adoption remains low for good reason; cover it as an option, recommend it if the codebase is small enough to make it cheap.

## 7. Lint layers: distinct tools, distinct purposes

The industry treats "linting" as one thing. It is at least four: correctness analysis, style/convention enforcement, formatting, and a meta-runner that coordinates the others. Treating them as one blurs decisions that should be explicit.

| Tool | Layer | What it uniquely catches |
|---|---|---|
| `go vet` | Correctness (built-in) | Printf-format errors, lost `context.CancelFunc`, struct tag typos, copylocks, unreachable code |
| `staticcheck` | Correctness | Dead code, inefficient string ops, incorrect sync usage, deprecated stdlib APIs |
| `errcheck` | Correctness | Unchecked error returns (Go's error convention makes this common) |
| `ineffassign` | Correctness | Assignments whose value is never read |
| `unused` | Correctness | Unused functions, constants, variables, struct fields |
| `gocritic` | Opinionated | Legal-but-suspect patterns across many categories |
| `revive` | Style | Configurable successor to the deprecated `golint` |
| `misspell` | Style | Common English misspellings in comments and strings |
| `gosec` | Security | See §8 |
| `gofmt` | Formatting (built-in) | The canonical, non-negotiable Go formatter |
| `goimports` | Formatting | `gofmt` plus import organization |
| `gofumpt` | Formatting | Stricter superset of `gofmt` (subset of `gofmt`-accepted output) |

**`go vet`** is table stakes. It ships with Go, it is fast, it has essentially no false positives, and it catches real bugs. If it fires, your code is wrong. Run it on every commit.

**`staticcheck`** by Dominik Honnef is the closest thing to what `go vet` should have been. Its checks are grouped by prefix: **SA** (correctness bugs and stdlib misuse), **S** (simplifications), **ST** (style), **U** (unused code, notably U1000), **QF** (quick fixes consumed by gopls). It is the gold standard for Go static analysis. For a public library, enabling staticcheck is non-negotiable.

**`golangci-lint`** is a meta-runner, not a linter. It runs many linters in parallel with shared AST/SSA parsing, dedup'd output, and a single config. It is the industry standard in CI. The v2 release (March 2025) restructured the config substantially: `linters` and `formatters` are now separate top-level sections, `enable-all`/`disable-all` was replaced by `linters.default` with values `standard`/`all`/`none`/`fast`, and a `golangci-lint migrate` subcommand auto-converts v1 configs. The v2 "standard" default set is `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused` — a well-chosen minimum. One nuance worth knowing: Honnef has publicly declined to endorse golangci-lint's use of staticcheck as a library, but the integration is how most projects actually run staticcheck, and it works.

**The composition mistake is enabling every linter.** The result is thousands of false positives, contributors who learn to ignore CI warnings, and a ratchet you cannot loosen without looking like you're lowering the bar. The correct default is the v2 "standard" set plus a deliberate handful: `errcheck` (often already in standard), `misspell`, `gocritic` if you want opinionated suggestions, `gosec` if you run security linting from inside golangci-lint. Add more only as the team's tolerance grows, and treat each addition as a policy decision, not a convenience. The test of "is this linter worth it" is simple: does a green run on my code mean something? If the linter fires on three false positives per thousand lines, a green run means nothing.

**Formatting** is the one area where the Go community's consensus is genuine and short: run `gofmt` or `goimports`. **`gofumpt`** is a strict superset — anything `gofumpt` produces is accepted by `gofmt`, but `gofumpt` rejects some code `gofmt` accepts. The argument for enforcing `gofumpt` on a library is consistency across contributors; the argument against is that the community cultural position is "gofmt is the standard, and adding a stricter variant fragments that." For a library, either choice is defensible; the common compromise is `goimports` in CI, with `gofumpt` as an optional developer tool.

**Deprecated tools to avoid**: `golint` was archived in May 2021 (use `revive` or staticcheck); `maligned` was removed in favor of `govet`'s `fieldalignment`; `scopelint` was removed when Go 1.22 changed loop variable semantics. Reaching for these in 2026 is a sign of stale guidance.

## 8. Security and vulnerability scanning layers

Same treatment: these are distinct tools finding distinct classes of problems. Running all of them at once without understanding the overlap produces findings nobody triages.

| Tool | Layer | Reachability-aware? |
|---|---|---|
| `govulncheck` | Known-vuln scan of Go deps + stdlib | **Yes** — call-graph analysis |
| `gosec` | Pattern-based SAST on Go source | Partial (taint on some rules) |
| CodeQL | Semantic SAST via query language | Yes (taint tracking) |
| `osv-scanner` | Multi-ecosystem dep vuln scan | Yes for Go (wraps govulncheck); no for others |
| `nancy` | Dep vuln scan against Sonatype OSS Index | No |
| `trivy` | Container / IaC / filesystem scan | No for Go modules |
| OpenSSF Scorecard | Repo-health meta-score | n/a |
| `dependency-review-action` | Block PRs introducing vulnerable deps | No |

**`govulncheck`** ([go.dev/blog/vuln](https://go.dev/blog/vuln)), from the Go security team, is the most important single tool on this list. It checks your module against the curated [Go vulnerability database at vuln.go.dev](https://pkg.go.dev/vuln/) and — the critical feature — does **reachability analysis**. A direct dependency may import a vulnerable package without your code ever calling into the vulnerable function; `govulncheck` traces the call graph and flags only vulnerabilities whose code path your program actually reaches. That distinction drops the false-positive rate by an order of magnitude compared to naive dependency scanners. It supports source mode (`./...`), binary mode (`-mode binary`), SARIF output (`-format sarif`), and an official `golang/govulncheck-action` for GitHub Actions. For a public Go library, this is the biggest single security-quality win available. It is free, official, and run by the people who maintain the Go security model.

**`gosec`** does pattern-based and SSA-based scanning for common security anti-patterns — hardcoded credentials (G101), weak crypto (G401-G404), SQL injection (G201-G202), path traversal (G304), unsafe TLS config, missing HTTP timeouts. Its false-positive rate is higher than `staticcheck`'s because many of its patterns are heuristics; `#nosec` and `//gosec:disable` directives with justification are intended to be used, and `-track-suppressions` audits them. For a pure-Go library that does not directly touch crypto, SQL, or HTTP, `gosec` fires rarely; run it but do not treat it as a headline metric.

**CodeQL** is GitHub's semantic code-analysis engine. It runs in Actions, produces SARIF, and uploads findings to the Security tab of the repo. It is free for public repositories (Advanced Security is required for private). CodeQL catches a different class of bug than `gosec` — its Go queries model taint flow across function boundaries, which heuristic patterns cannot. For a public library, CodeQL is cheap to enable and finds real issues. The `security-extended` query suite is a reasonable default.

**`osv-scanner`** (Google) scans lockfiles and modules against the [OSV.dev](https://osv.dev/) database, which aggregates vulnerabilities across many ecosystems. For Go specifically, osv-scanner **wraps govulncheck under the hood** to provide reachability; for non-Go ecosystems it doesn't. This matters for redundancy analysis: for a pure-Go library, govulncheck alone is strictly sufficient; osv-scanner adds value only if you have lockfile entries from other ecosystems (e.g., a tools manifest that pulls Node for docs builds).

**`nancy`** (Sonatype) is an older dep scanner using the Sonatype OSS Index. It does not do reachability. Its helper library `go-sona-types` was archived in October 2025. Mention but do not recommend for new setups — govulncheck is strictly superior for Go.

**`trivy`** is container-focused. For a pure-Go library without a container image, trivy is not relevant. Reaching for it on a library is cargo-culting.

**OpenSSF Scorecard** is a meta-analysis of repo security posture. It scores checks like Branch-Protection, Pinned-Dependencies (SHA-pinned Actions), Signed-Releases, SAST (CodeQL presence), Fuzzing (OSS-Fuzz or Go fuzz targets), Dependency-Update-Tool (Dependabot/Renovate), Dangerous-Workflow, Token-Permissions, Vulnerabilities (via OSV), and about a dozen others. It produces a 0-10 score cached via a Fastly CDN and a GitHub Action that updates the badge on every push. For a public library, Scorecard functions as both a maintainer checklist and a consumer-facing trust signal. A few of its checks (CII-Best-Practices, Signed-Releases) are aspirational for small libraries; Binary-Artifacts, Dangerous-Workflow, Token-Permissions, and Pinned-Dependencies are table stakes.

**`dependency-review-action`** runs on pull requests and blocks changes that introduce a dependency with a known vulnerability at a configurable severity threshold. It is complementary to govulncheck — govulncheck scans the current state, dependency-review scans the delta.

**SARIF is a format, not a finding.** GitHub's Security tab accepts SARIF uploads from govulncheck, gosec, CodeQL, osv-scanner, and trivy, and renders them as alerts. This is genuinely useful if someone triages the alerts. It is security theater if nobody does. Paper 1 named this as an anti-pattern ("scanner runs but findings never triaged"); it is worth naming again here because it is the most common security-quality failure mode in public Go libraries. A SARIF upload with 47 untriaged alerts is worse than no scan at all — it tells consumers your security posture is performative. The fix is scope: run fewer scanners, or run them with tuned rulesets, so that every alert is something you will actually look at.

## 9. Test organization, data, and flakiness

**File placement** has two conventions and Go supports both. `package foo` in `foo_test.go` is white-box — same package, full access to unexported identifiers. `package foo_test` in `foo_test.go` is black-box — external, sees only the exported API. For a public library, the argument for external tests is strong: they force you to experience what a consumer experiences, they prevent tests from relying on internal helpers that are refactor targets, and they fail fast when an API change breaks the contract. Most libraries use a mix: black-box by default for anything testing public behavior, white-box only when a test genuinely needs to inspect an unexported detail (which is itself a smell worth questioning).

**`testdata/`** is a directory the `go` tool ignores for builds and refuses to look inside for package imports. It is the idiomatic location for fixtures, golden files, and the auto-generated fuzz corpus at `testdata/fuzz/FuzzXxx/`. Placing fixtures anywhere else is a minor breach of convention that will confuse every Go developer who reads your repo.

**`t.TempDir()`** (Go 1.15) and **`t.Cleanup()`** (Go 1.14) together obsolete the older `ioutil.TempDir` + `defer os.RemoveAll` pattern. `t.TempDir()` returns a directory that is deleted automatically when the test exits, including on failure. `t.Cleanup()` registers arbitrary teardown. Both work correctly with subtests. Any test code still using `ioutil.TempDir` is dated and should be migrated.

**Build tags for slow tests** — typically `//go:build integration` on the first line of a file — let you segregate expensive tests from the default `go test ./...`. The pattern is: default unit tests run in seconds and gate every PR; tagged integration tests run opt-in or on a scheduled workflow, and fail the build when they do. For a pure-Go library without external services, the integration tier may be empty, which is fine — do not invent one to have something to tag.

**The `internal/` package rule** is worth repeating as a design decision. The Go tool enforces that packages under `.../internal/…` can only be imported by packages rooted at the parent of `internal`. This is how you carve out implementation detail in a public library. Anything in `internal/` is freely refactorable; anything outside it is contract. The scope of what you tag as `internal/` directly determines the surface area of your test contract. Libraries that ship too much as public and then need to break changes later have almost always gotten this boundary wrong.

**Flakiness is a distinct problem from slowness** and a more dangerous one. A slow test annoys; a flaky test trains the team to ignore red CI. The common root causes: non-deterministic map iteration (Go randomizes it intentionally — do not assume order); time-based assertions (`time.Sleep(100ms)` then check — always eventually wrong); goroutine ordering (the race detector catches races, not orderings); network-touching tests (fixed by using `httptest` or, for a library, by not having them at all); and shared global state across tests.

The fixes are tool-specific. `testing/synctest` eliminates time-based flakes for concurrent code — this is the biggest single improvement available in Go 1.25. Sort map keys before iterating when order matters. Replace `time.Sleep` with synchronization primitives (channels, wait groups, synctest). **Detect flakiness actively**: run tests 100 times via `go test -count=100 -run=TestSuspect` periodically in CI; any test that fails even once in 100 runs is flaky and should be fixed or quarantined, not retried until green. Retry-until-green is a common industry pattern and a slow-motion disaster — it converts the flake into permanent hidden background noise.

**Contract testing** is the conceptual frame for where unit ends and integration begins when your code is consumed by others. For a library, the contract is the exported API: every Example function is a contract specification; every black-box test in `package foo_test` verifies the contract from a consumer's perspective; every fuzz test on an exported function hardens the contract against adversarial input. The internal implementation can change freely as long as the contract holds.

## 10. Industry anti-patterns, named

Each of these is common, visible in major OSS Go projects, and wrong. Calling them out is not to shame any specific project — it is to make them unmistakable when they appear in review.

**Tests that pass without asserting.** The test calls the function, discards the return, and relies on "no panic" as the assertion. The coverage goes up; the signal does not. Review should reject any test without explicit assertions on return values or observable side effects. The LLM-assisted version of this failure mode is more common and harder to spot because the test looks plausible.

**100% coverage with mostly stubs and no fakes.** Coverage is satisfied by exercising code paths; signal requires exercising meaningful dependencies. Replacing every dependency with a hard-coded stub produces green coverage and tests that cannot catch integration bugs. The fix is a small number of fakes at the right seams, not more stubs.

**Mocking your own code instead of your dependencies.** Mocks of your own types couple tests to your call graph. A minor refactor of internal structure breaks every test, so tests become a tax on refactoring instead of a safety net for it. Mock at the boundary between your code and the outside world; do not mock internal helpers.

**Integration tests that are actually unit tests with a database.** A test that spins up Postgres to test a pure function has paid the cost of an integration test and gotten a unit test in return. Either the test exercises the integration (real queries, real schemas, real edge cases) or it does not; if it does not, it should not be paying for Postgres.

**Unit tests that are actually integration tests, untagged.** A test that hits a real URL, or reads `/etc/something`, is an integration test. Running it as part of the default suite makes CI slow and flaky. The fix is a build tag, not a retry policy.

**Flaky tests retried until green.** The retry hides the flake, which stays in the suite accumulating tolerance. Teams trained to re-run CI "because it's probably just flaky" miss real bugs signaling the same way. Every flake is a bug; fix it or delete the test.

**Coverage exclusions accumulated silently.** `main.go`, generated code, "hard to test" files, the one package nobody wants to touch — every exclusion should be in the config with a comment explaining why. The "real" coverage number should match the reported one. Quiet exclusions produce the number nobody cites because they know it's fake.

**Lint warnings ignored because CI is noisy.** The fix is curation, not tolerance. Drop linters that produce false positives faster than signal. A CI that fires 10 warnings per PR trains contributors to ignore all of them; a CI that fires once a month trains them to pay attention when it does.

**Security scanners run but findings never triaged.** The SARIF tab with 47 months-old alerts. Run fewer scanners with tuned rules so that every alert is actionable, and assign a person — not a team, a person — as the triage owner.

**`govulncheck` not run because "we're a small library."** Small libraries get pulled into large applications. The reachability analysis is fast, the output is usually empty, and when it isn't empty the finding is real. There is no justified reason to skip it.

**Tests asserting on implementation details.** Tests that check private struct fields, reflect on unexported methods, or depend on exact error message text ("cannot connect: dial tcp: timeout") break on every refactor even when behavior is unchanged. Assert on observable behavior and on error types or sentinel values, not on strings.

**No fuzz tests on a library that parses untrusted input.** Any function that takes a `string`, `[]byte`, or an `io.Reader` from the caller should have a fuzz target. The cost is a few dozen lines and running `go test -fuzz` in a nightly CI job; the benefit is finding the panic that would otherwise be a CVE.

**No Example functions on a public library.** You have missed a test and missed a documentation opportunity. For a library whose primary purpose is to be called, shipping without Examples is a self-inflicted wound on adoption.

**Generated mocks committed to the repo and never regenerated.** Over time the mock drifts from the interface it claims to mock; tests pass against the outdated mock while real callers break. Either regenerate on every change (via `go generate` in CI, with a dirty-tree check) or write the fake by hand.

**`init()` functions doing real work in tests.** `init` runs before any test and in undefined order across packages. Tests that depend on what `init` did become order-dependent; moving a test to a new file changes its behavior. Initialization should be explicit in test setup (`TestMain`, per-test helpers), not implicit in package load.