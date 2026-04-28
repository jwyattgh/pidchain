# Changelog

## 0.1.0 (2026-04-28)


### Features

* add MIT license, security policy, public README, and godoc examples ([0e7d040](https://github.com/jwyattgh/pidchain/commit/0e7d0402c9e2923580f8862dd98102eda332358c))
* MIT license, security policy, public README, godoc examples  Establishes the consumer-facing surface for v0.1.0.  - LICENSE: MIT, Copyright 2026 Jason Wyatt. - SECURITY.md: threat model anchored in CWE-312/313/522/256/922.   In-scope: same-user impersonation, on-disk binary tampering, ancestor   swap. Out-of-scope: kernel compromise, OS code-signing compromise,   same-user privileged process, supply-chain attack on a signed parent. - README.md: rewritten around the no-stored-credential framing (no   secret at rest, no secret transmitted), the consumer ACL pattern, and   the stdio integration test as the canonical verification path.   Corrects post-003c error sentinel references. - doc.go: drops the IPC channel enumeration (moved to README), adds a   concurrency note. - ExampleFingerprint and ExampleChain in pidchain_test.go. - 003-series implementation docs moved to docs/archive/.  Implements 004d. ([0e7d040](https://github.com/jwyattgh/pidchain/commit/0e7d0402c9e2923580f8862dd98102eda332358c))


### Bug Fixes

* keep pre-1.0 versioning until explicit 1.0 cut ([0f37ccc](https://github.com/jwyattgh/pidchain/commit/0f37ccc7a7b20377fb80904307c3a9fae2f4f98d))


### Misc

* pin first release to 0.1.0 ([4358fec](https://github.com/jwyattgh/pidchain/commit/4358fec2200f13986f4ebae81a87ca0d68245c1d))

## Changelog
