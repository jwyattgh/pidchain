# 004d — Public Release Documentation

## Goal

Produce all repo-level documentation needed for pidchain to flip public:

- `LICENSE` (MIT)
- `SECURITY.md` with threat model
- `doc.go` rewritten to drop the IPC channel enumeration
- `README.md` rewritten to drop channel bullets, fix `ErrMaxDepthExceeded` reference, fill in license, expand the "what pidchain does" reasoning
- `ExampleFingerprint` and `ExampleChain` added to `pidchain_test.go`
- 003-series implementation docs moved from repo root to `docs/archive/`

## Files

- ADD: `LICENSE`
- ADD: `SECURITY.md`
- CHANGE: `doc.go`
- CHANGE: `README.md`
- CHANGE: `pidchain_test.go` (add two Example functions)
- MOVE: `003a-types-and-fingerprint.md` → `docs/archive/`
- MOVE: `003b-tighten-pidchain-tests.md` → `docs/archive/`
- MOVE: `003c-refactor-walker.md` → `docs/archive/`
- MOVE: `003d-windows-catalog-signature.md` → `docs/archive/`
- MOVE: `003e-v4.md` → `docs/archive/`

## Implementation

### `LICENSE`

Standard MIT text. Replace `<COPYRIGHT HOLDER>` with the legal name to appear in the copyright line.

````
MIT License

Copyright (c) 2026 <COPYRIGHT HOLDER>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
````

### `SECURITY.md`

````markdown
# Security Policy

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories on this repository: <https://github.com/jwyattgh/pidchain/security/advisories/new>.

Do not open a public issue for a suspected vulnerability. Allow up to 7 days for an initial response.

## Supported versions

pidchain is pre-1.0. Only the latest minor release receives security fixes. Once 1.0 ships, this section will be updated with a longer-window policy.

## Threat model

pidchain is designed to defeat the **stored-credential pattern** for same-host IPC authentication described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922. The fingerprint is regenerated from kernel-attested process state on every call; nothing secret is stored on or transmitted by the caller.

### In scope

- A same-host attacker running as the same user as the legitimate caller, attempting to impersonate it. pidchain prevents this because the attacker cannot make the kernel lie about its own process ancestry.
- Tampering with the binary on disk between the original pairing and a subsequent call. pidchain detects this because the code-signing identity collected from the modified binary differs, producing a different fingerprint.
- Replacement of an ancestor binary in the chain (e.g. a compromised launcher). Same detection mechanism: the ancestor's signing identity changes, the fingerprint changes.

### Out of scope

- **Remote callers.** pidchain depends on kernel-attested peer-credential primitives that only exist for same-host connections. For remote authentication use mTLS or a transport-layer mechanism.
- **Kernel compromise.** pidchain trusts the kernel's reporting of process ancestry. An attacker with kernel-level capability can forge any system call response, including those pidchain depends on.
- **OS code-signing infrastructure compromise.** pidchain trusts the platform's code-signing verification (Security.framework on macOS, Authenticode/Crypt API on Windows). An attacker who can forge or bypass the OS-level code-signing check can produce a binary that pidchain identifies as legitimate.
- **Same-user privileged process.** A process running as the same user with `ptrace` or `task_for_pid` capability can read and modify the calling process's memory directly. pidchain does not protect against an attacker who already has process-internal access; at that point the credential abstraction is moot.
- **Supply-chain attack on a signed parent.** If a legitimately signed binary in the caller's ancestry is itself compromised at build time (a malicious version published with a valid signature), pidchain has no way to distinguish the malicious build from a legitimate one. This is the same trust model as any code-signing-based identity scheme.

### Not a defense against

- Transport security failures. Use pidchain alongside, not instead of, TLS for any cross-host communication.
- Authorization. pidchain identifies; the consumer's ACL decides what the identified caller is allowed to do.
- Kernel rootkits, compromised OSes, or attackers with administrative privileges on the host.
````

### `doc.go`

Replace the entire file with:

````go
// Package pidchain produces SHA256 fingerprints identifying local process
// callers, for same-host IPC authentication without stored credentials.
//
// The consumer obtains a peer PID from the kernel and calls Fingerprint
// with it. The returned string identifies the caller's full process
// ancestry; identical ancestry produces an identical fingerprint.
// Callers store the fingerprint as the verification value in their own
// authentication record. On every inbound call, the consumer re-derives
// the fingerprint from kernel state and compares it against the stored
// value.
//
// Identity comes from a fresh kernel query per call. Nothing secret is
// stored on the client, nothing is transmitted by the client. The
// credential cannot be stolen because the credential does not exist at
// rest. This addresses the cleartext-credential pattern described by
// CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922.
//
// # Supported platforms
//
// pidchain supports macOS and Windows. Linux and other platforms compile
// but return ErrPlatformUnsupported at runtime.
//
// # Concurrency
//
// Both Fingerprint and Chain do a fresh kernel walk on every call. The
// package holds no state and is safe for concurrent use from multiple
// goroutines.
package pidchain
````

The previous `# Supported platforms and IPC` section is replaced with `# Supported platforms`. The IPC channel enumeration (stdio / UDS / named pipes) is removed entirely. The library accepts any PID; documenting consumer-side transport choices is out of scope for the package godoc.

### `README.md`

Replace the entire file with:

````markdown
# pidchain

Same-host IPC authentication without stored credentials.

## The problem

Local app-to-app authentication typically stores a bearer token — a secret the client keeps in a config file or a keychain entry and transmits to prove identity. Any process running as the same user can read that file and impersonate the client. This is the stored-credential pattern described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922: the credential is stealable because it exists at rest.

Encrypting the file does not fix it; the decryption key has the same storage problem. The only fix is removing the stored credential entirely.

## What pidchain does

The kernel already knows which process is on the other end of a local IPC connection. pidchain walks that process's ancestry, extracts each ancestor's code-signing identity (team ID, bundle/subject identifier, signing authority), and hashes the result into a SHA256 fingerprint.

Consumers store the fingerprint as the verification value in their own ACL, keyed by a caller name they assigned at pairing time. On every call, the consumer asks the kernel for the peer PID, re-derives the fingerprint from scratch, and compares.

Two properties make this stronger than a stored token:

1. **No secret at rest on the client.** The "credential" is reconstructed from kernel state on every call. There is nothing in a config file, nothing in a keychain entry, nothing persistently in process memory. A process that reads everything the client has access to gains no credential to replay.
2. **No secret transmitted by the client.** The client doesn't send a fingerprint or any other identifier. The consumer derives the fingerprint independently from the kernel-reported peer PID. A network tap or man-in-the-middle on the IPC channel sees nothing identity-relevant.

A compromised same-user process cannot fake a fingerprint because it cannot make the kernel lie about its own process ancestry or its on-disk binary's code signature.

## Usage

```go
import "github.com/jwyattgh/pidchain"

// Server side, after obtaining the peer PID from the kernel — e.g.
// directly from cmd.Process.Pid for a child spawned over stdio.
fp, err := pidchain.Fingerprint(peerPID)
if err != nil {
    // ErrProcessDead, ErrPlatformUnsupported
}

// pseudocode — your ACL implementation:
switch acl.Lookup(callerName) {
case NotPaired:
    // First contact. Run your pairing flow, store (callerName, fp).
case Paired(stored) where stored == fp:
    // Authenticated. Apply this caller's permissions.
case Paired(stored) where stored != fp:
    // SECURITY EVENT: known caller, unexpected ancestry. Investigate
    // before re-pairing.
}
```

For diagnostic output (pairing prompts, debugging), `pidchain.Chain(pid)` returns the structured ancestor list the fingerprint was computed over.

## How we test it

The integration test (`pidchain_stdio_integration_test.go`) exercises the canonical MCP-style stdio bridge pattern: a probe binary at `testdata/integration/probe/` is built into a temp directory, launched via `exec.Command`, and calls `pidchain.Chain(os.Getppid())` to fingerprint the test process that spawned it. Three runs verify that the fingerprint is deterministic across invocations and that the on-disk codesign path actually fires (at least one ancestor has a non-empty BundleIdentifier).

The library accepts any PID. If you obtain a peer PID through another kernel-attested mechanism — `LOCAL_PEERPID` over a Unix domain socket, `GetNamedPipeClientProcessId` over a Windows named pipe, or some other transport — pidchain will return a fingerprint just fine. We don't ship integration tests for those paths; if you use them, validate against your own test fixtures.

## Platforms

| Platform | Status |
| --- | --- |
| macOS | supported — libproc + Security.framework via CGo |
| Windows | supported — Toolhelp32 + Crypt API via CGo |
| Linux and other | compiles; returns `ErrPlatformUnsupported` at runtime |

## Install

```
go get github.com/jwyattgh/pidchain
```

Requires Go 1.25+. Builds with CGo enabled on macOS and Windows. CGo is required because pidchain uses the platform's native code-signing APIs (Security.framework on macOS, Crypt API on Windows) directly rather than shelling out to CLI tools.

## API reference

Full API documentation: [pkg.go.dev/github.com/jwyattgh/pidchain](https://pkg.go.dev/github.com/jwyattgh/pidchain).

The public surface is two functions, one type alias, one struct, two error sentinels. Everything else lives under `internal/` and can change without affecting consumers.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what's in and out of scope, and how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).
````

Diff vs current README:

- "When to use it" section dropped (purpose is auth without stored creds, not transport).
- "How we test it" section added — names the stdio integration test explicitly as the tested path; calls out that the library works for any PID without promising untested transports.
- "What pidchain does" expanded with the two-property explanation (no-at-rest, no-in-transit).
- Error switch corrected: `ErrProcessDead, ErrPlatformUnsupported` only. `ErrMaxDepthExceeded` removed.
- License: MIT (was TBD).
- API reference line corrected: "two error sentinels" not three.

### `pidchain_test.go`

Append two `Example*` functions to the existing file. They render as runnable code on `pkg.go.dev` and double as compile-checked regression tests.

````go
// ExampleFingerprint demonstrates the typical server-side usage: obtain
// the peer PID via a kernel-attested mechanism, derive the fingerprint,
// compare against an ACL.
func ExampleFingerprint() {
	// In a real server, peerPID comes from the kernel — cmd.Process.Pid
	// for a spawned child, LOCAL_PEERPID for a UDS peer, etc. Here we
	// use the current process for illustration.
	peerPID := os.Getpid()

	fp, err := pidchain.Fingerprint(peerPID)
	if err != nil {
		// errors.Is(err, pidchain.ErrProcessDead),
		// errors.Is(err, pidchain.ErrPlatformUnsupported)
		_ = err
		return
	}

	// fp is a 64-character lowercase hex SHA256.
	_ = fp
}

// ExampleChain demonstrates the diagnostic / pairing-prompt usage: get
// the structured ancestor list to display to a human (or to log) before
// committing to store the corresponding fingerprint.
func ExampleChain() {
	chain, err := pidchain.Chain(os.Getpid())
	if err != nil {
		_ = err
		return
	}

	// chain.Entries is the ordered ancestry, queried PID first.
	// chain.Fingerprint is the same value Fingerprint() would return.
	for _, e := range chain.Entries {
		_ = e.BinaryPath
		_ = e.TeamID
		_ = e.BundleIdentifier
		_ = e.AuthorityLeaf
	}
}
````

These do not include `// Output:` comments because actual output depends on the test environment. Without `// Output:`, `godoc` still renders them as syntax-highlighted runnable code on `pkg.go.dev` and `go test` still compiles them — which catches API drift on every CI run.

`os` is already imported in `pidchain_test.go` for the existing tests; no import change needed.

### Move 003-series docs to `docs/archive/`

````bash
mkdir -p docs/archive
git mv 003a-types-and-fingerprint.md docs/archive/
git mv 003b-tighten-pidchain-tests.md docs/archive/
git mv 003c-refactor-walker.md docs/archive/
git mv 003d-windows-catalog-signature.md docs/archive/
git mv 003e-v4.md docs/archive/
````

Use `git mv` so history is preserved. The convention from `Project-QS` and the existing `docs/archive/001*` and `002*` series is that completed implementation docs move to `docs/archive/` after landing.

## Success Criteria

1. `LICENSE` exists at repo root with MIT text and a real copyright holder.
2. `SECURITY.md` exists at repo root and contains the threat-model section.
3. `grep -E 'unix domain|UDS|LOCAL_PEERPID|named pipe|GetNamedPipe' doc.go` returns no matches.
4. `grep -c 'ErrMaxDepthExceeded' README.md` returns 0.
5. `grep 'TBD' README.md` returns nothing for the license section; `grep 'MIT' README.md` returns at least one match.
6. `go test ./...` passes; example functions compile.
7. `go doc -all .` lists `ExampleFingerprint` and `ExampleChain`.
8. `ls 003*.md 2>/dev/null` at repo root returns nothing; `ls docs/archive/003*.md` lists all five.

## Out of Scope

- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` (skipped — small library, single maintainer; revisit if a contributor base materializes).
- `CHANGELOG.md` (created empty by 004c, populated by release-please).
- Updating any code comments that reference the IPC channel enumeration (a separate grep pass after this lands; expected to be zero hits since the channels were never in code, only in docs).