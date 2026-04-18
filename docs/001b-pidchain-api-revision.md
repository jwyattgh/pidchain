# pidchain — Implementation Doc 001b: API Revision and Repo Layout

## Goal

Restructure the pidchain package from its current flat scaffold into a shape suitable for public release. This revision lands the final public API (two functions), moves implementation details into `internal/` subpackages, and produces a README that explains what pidchain is for.

This supersedes 001. 001 is retired.

## What pidchain is

pidchain is a Go library for same-host caller authentication without stored credentials. The consumer obtains a peer PID from the kernel — via `SO_PEERCRED` (Linux), `LOCAL_PEERPID` (macOS), `GetNamedPipeClientProcessId` (Windows), or equivalent peer-credential syscall — and passes it to pidchain. pidchain walks the process's ancestry, collects platform-specific code-signing identity at each position, and returns a SHA256 fingerprint over the chain.

The consumer stores the fingerprint as the verification value in its own authentication record. On every inbound call, the consumer gets the current peer PID, calls `pidchain.Fingerprint`, and compares against the stored value. Identity comes from a fresh kernel query per call; nothing secret is stored on the client, nothing is transmitted by the client.

The problem pidchain addresses is the cleartext-credential pattern described by CWE-312, CWE-313, CWE-522, CWE-256, and CWE-922. The industry default for local app-to-app auth is a bearer token in a config file — any same-user process can read it, copy it, and impersonate the client. pidchain has no credential at rest because the credential is re-derived from kernel state every time.

Scope is deliberately narrow. pidchain works for same-host callers where the consumer can obtain a peer PID from the kernel. It does not work for remote callers; remote callers need mTLS, OAuth, or another transport-layer mechanism. The mechanism is not MCP-specific.

## Repo layout

```
pidchain/
  go.mod
  go.sum
  LICENSE                   // choose at repo-init time
  README.md

  pidchain.go               // package pidchain — Fingerprint, Chain, types, errors
  pidchain_test.go
  doc.go                    // package-level godoc with overview + example

  internal/
    canonical/
      canonical.go          // package canonical — Bytes(chain) ([]byte, error)
      canonical_test.go

    walker/
      walker.go             // package walker — platform interface, Walk function, maxDepth constant
      walker_darwin.go      // build: darwin  — libproc walker + Security.framework codesign collector
      walker_windows.go     // build: windows — Toolhelp walker + Crypt API Authenticode collector
      walker_other.go       // build: !darwin && !windows — ErrPlatformUnsupported stub
      walker_test.go
      walker_darwin_test.go    // build: darwin
      walker_windows_test.go   // build: windows
```

Rationale for `internal/canonical/` and `internal/walker/`: the Go tool enforces that packages under `internal/` cannot be imported from outside the module. The only compatibility commitment pidchain makes is the shape of `package pidchain` itself. Internal packages can be restructured freely without breaking consumers.

## Implementation approach: CGo is used

pidchain uses CGo where interfacing with the operating system directly produces a better result than pure-Go alternatives. Darwin uses `libproc` (`proc_pidpath`, `proc_pidinfo`) for kernel-attested PID lookups and `Security.framework` (`SecStaticCodeCreateWithPath`, `SecCodeCopySigningInformation`) for codesign data. Windows uses the native Crypt API (`CryptQueryObject`, `CertGetNameStringW`) for Authenticode. the prototype probe's Darwin implementation in `kernel_darwin.go` is a direct reference for the walker portion.

The `codesign` CLI shell-out that appeared in earlier drafts of this spec is rejected for pidchain. `codesign` can hang indefinitely under TCC, its text output is brittle to parse, and there is no reason to accept those drawbacks when `Security.framework` provides the same data directly.

## Public API

```go
// Package pidchain produces SHA256 fingerprints identifying local process
// callers, for same-host authentication without stored credentials.
//
// The consumer obtains a peer PID from the kernel (SO_PEERCRED, LOCAL_PEERPID,
// GetNamedPipeClientProcessId, or equivalent) and calls Fingerprint with it.
// The returned string identifies the caller's full process ancestry; identical
// ancestry produces an identical fingerprint. Callers store the fingerprint
// as the verification value in their own authentication record.
//
// For remote callers, use mTLS or OAuth. pidchain is same-host only.
package pidchain

// Fingerprint returns a lowercase hex-encoded SHA256 identifying the full
// process ancestry rooted at pid. Deterministic: identical ancestry
// produces an identical fingerprint. Any change to any ancestor's
// code-signing identity produces a different fingerprint.
//
// Runtime authentication uses this function. Pass in the peer PID the
// kernel reported, compare the result against a stored fingerprint.
func Fingerprint(pid int) (string, error)

// Chain returns the walked process ancestry as structured data. Intended
// for diagnostics, setup-time UI, and pairing prompts that show a human
// "a process signed by X wants to connect."
//
// Not for runtime authentication. The fingerprint already commits to the
// chain; re-inspecting the chain on every call duplicates work the hash
// comparison already did. Use Fingerprint for auth, Chain for display.
func Chain(pid int) (ProcessChain, error)
```

Exported types:

```go
// ProcessChain is the ordered sequence of ancestors. Index 0 is the PID
// passed to Chain; index 1 is its parent; and so on to the terminator.
type ProcessChain []ProcessInfo

// ProcessInfo is a single ancestor's kernel-attested identity.
type ProcessInfo struct {
    PID              int    // the PID this entry describes
    ParentPID        int    // parent of PID at walk time
    BinaryPath       string // absolute executable path, kernel-attested
    TeamID           string // platform-specific publisher identifier
    BundleIdentifier string // platform-specific application identifier
    AuthorityLeaf    string // platform-specific signing-authority label
}
```

Exported error sentinels:

```go
var (
    ErrPlatformUnsupported = errors.New("pidchain: platform not supported")
    ErrProcessDead         = errors.New("pidchain: process not found")
    ErrMaxDepthExceeded    = errors.New("pidchain: walk exceeded max depth")
)
```

That is the complete exported surface. `Identify`, `Walk`, `Canonical`, `Identity`, and the `callerName` parameter from the current scaffold are all removed. The function returning the chain is named `Chain`; the type is `ProcessChain` to avoid the function-name-equals-type-name compile error.

## Per-call semantics

Both `Fingerprint` and `Chain` do a fresh kernel walk on every invocation. No `init()`, no cached state, no struct holding previous results. Each call is independent and safe for concurrent use from multiple goroutines. The package holds no package-level state.

Caching is deliberately not supported. The kernel-attested-per-call property is the whole point; caching defeats it. Per-call matches the mechanism's intent: identity is what the kernel reports right now, not what it reported earlier.

## Canonical bytes format

The canonical-bytes layout is what gets SHA256-hashed to produce the fingerprint. It must be byte-identical for identical chains across runs, machines, Go versions, and library versions. There is no version tag: changing this layout is a breaking change, would invalidate every stored fingerprint for every consumer of this library, and is not something we do. If a future library truly needs a different layout, that is a different library with a different module path — not a version bump inside pidchain.

Layout:

```
<len(chain) as 4-byte big-endian uint32>   // ancestor count
for each ancestor, in walk order (start PID first, parent next, up to terminator):
  <TeamID bytes>           "\x00"
  <BundleIdentifier bytes> "\x00"
  <AuthorityLeaf bytes>    "\x00"
  "\x1e"                                   // record separator (ASCII 0x1E)
```

Rules:

- NUL (`\x00`) is the intra-field terminator. `canonical.Bytes` returns an error if any field contains NUL. In practice codesign data never contains NUL; this check is a safety net against corruption.
- Empty fields are permitted and contribute zero bytes before their terminator. An ancestor with all-empty fields still produces `\x00\x00\x00\x1e` (three empty NUL-terminated fields plus record separator).
- The length prefix ensures "N empty ancestors" and "N+1 empty ancestors" hash differently.
- Chain entries appear in walk order: index 0 is the starting PID, index 1 is its parent, through to the terminator.

### Canonical bytes tests

Tests for the canonical-bytes layout verify that `canonical.Bytes(chain)` produces the exact byte sequence specified above. Expected values are hand-constructed byte slices written directly into the test. SHA256 is not tested here — it's imported from `crypto/sha256` and is the Go standard library's responsibility, not ours.

Required test cases:

**Empty chain.** Input: `ProcessChain{}`. Expected: `[]byte{0x00, 0x00, 0x00, 0x00}` — four bytes of big-endian zero-count. Total length: 4 bytes.

**Single ancestor, all fields populated.** Input: `ProcessChain{{TeamID: "Q6L2SF6YDW", BundleIdentifier: "com.anthropic.claudefordesktop", AuthorityLeaf: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"}}`. Expected: hand-construct the byte slice as `[]byte{0x00, 0x00, 0x00, 0x01}` followed by the three field bytes each NUL-terminated, followed by `0x1e`. Write the assembled bytes directly into the test.

**Three-ancestor chain matching the prototype probe's CD-spawned output.** Input positions matching the real CD chain: `{"", "a.out", ""}`, `{"Q6L2SF6YDW", "disclaimer", "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"}`, `{"Q6L2SF6YDW", "com.anthropic.claudefordesktop", "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"}`. Expected: hand-construct the byte slice. This is the test that confirms pidchain produces sensible output for a real-world chain.

**Prefix-differ test.** Two chains sharing their first N ancestors but differing at position N+1 must produce different canonical bytes. Asserts the length prefix and record separators work as intended.

**NUL-rejection tests.** `canonical.Bytes` with NUL in `TeamID`, `BundleIdentifier`, or `AuthorityLeaf` returns an error. Three separate assertions.

### Public-API consistency test

One integration-style test confirms that `pidchain.Fingerprint(pid)` equals `hex.EncodeToString(sha256.Sum256(canonical.Bytes(chain)))` where `chain` is the result of `pidchain.Chain(pid)` for the same PID. This proves the two public functions are internally consistent — same walk, same canonical bytes, same hash.

## Behavior of `Fingerprint` and `Chain`

### Walk semantics (shared between both functions)

1. Start at the given PID.
2. For each PID, collect parent PID and binary path from the kernel; collect code-signing identity from the binary.
3. Walk to the parent. Repeat.
4. Terminate when:
   - Platform-specific kernel terminator is reached (on macOS, `proc_pidinfo` returning 0, typically at PID 1; on Windows, parent PID 0).
   - An ancestor PID lookup fails (process exited mid-walk). The walk stops at the last successfully probed ancestor; not an error.
   - Max depth of 32 is reached. Returns `ErrMaxDepthExceeded` with the 32-entry partial chain.
5. If an ancestor's binary cannot have its signature inspected, its `TeamID`, `BundleIdentifier`, and `AuthorityLeaf` fields are empty strings. The entry still appears in the chain. Not an error.

### Errors

| Condition | `Fingerprint` returns | `Chain` returns |
|---|---|---|
| Platform is neither Darwin nor Windows | `("", ErrPlatformUnsupported)` | `(nil, ErrPlatformUnsupported)` |
| Start PID cannot be looked up | `("", ErrProcessDead)` | `(nil, ErrProcessDead)` |
| Ancestor PID fails mid-walk | partial fingerprint, `nil` error | partial chain, `nil` error |
| Ancestor signature inspection fails | partial fingerprint (that ancestor's identity fields are empty), `nil` error | partial chain (that ancestor's identity fields are empty), `nil` error |
| Walk reaches max depth 32 | 32-entry fingerprint, `ErrMaxDepthExceeded` | 32-entry chain, `ErrMaxDepthExceeded` |

The OS-level errors (sysctl failures, `OpenProcess` access denied, Crypt API failures) are caught inside the walker and translated to the sentinels above. Consumers only ever see the three exported errors, never raw OS errno values.

`ErrMaxDepthExceeded` is the only case where a non-nil error is paired with a populated return value. This deviates from the usual Go convention of "error means zero return" because returning an empty chain at max depth would silently lose the 32 entries we did successfully collect; consumers need them to decide whether to accept the partial fingerprint or reject the call.

## Platform details

### Darwin implementation (`internal/walker/walker_darwin.go`)

**Walker.** Use CGo to call `libproc`:

- `proc_pidpath(pid, buf, len)` for the absolute executable path.
- `proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd))` for the parent PID.

Walk terminates when:
- `proc_pidinfo` returns 0 (unprivileged callers can't see PID 1's info; this is the clean terminator), or
- Max depth (32) reached.

the prototype probe's `probe/kernel_darwin.go` implements this walker today. Reuse the approach directly.

**Codesign collector.** Use CGo to call `Security.framework`:

- `SecStaticCodeCreateWithPath` with the binary's absolute path, producing a `SecStaticCodeRef`.
- `SecCodeCopySigningInformation` with `kSecCSSigningInformation` returns a `CFDictionary` containing the signing attributes.
- Extract `kSecCodeInfoTeamIdentifier` → `TeamID`, `kSecCodeInfoIdentifier` → `BundleIdentifier`, and the first element of `kSecCodeInfoCertificates` (the leaf cert) with `SecCertificateCopySubjectSummary` → `AuthorityLeaf`.

On any failure (unsigned binary, ad-hoc signed binary with no team identifier, API error), the corresponding fields are empty strings. Not a fatal error.

### Windows implementation (`internal/walker/walker_windows.go`)

**Walker.** Use `golang.org/x/sys/windows` for process enumeration (these bindings are standard and do not require CGo):

- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`, then iterate with `Process32FirstW` / `Process32NextW` to find the entry where `th32ProcessID == pid`. Yields parent PID.
- For the full path: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)` followed by `QueryFullProcessImageNameW`.

Walk terminates when:
- Parent PID is 0, or
- `OpenProcess` returns `ERROR_ACCESS_DENIED` or `ERROR_INVALID_PARAMETER` (SYSTEM-owned or gone), or
- Max depth (32) reached.

**Authenticode collector.** Use CGo to call the native Crypt API (`wincrypt.h`):

- `CryptQueryObject` with `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED` on the binary path to obtain the embedded signature's crypto message.
- `CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, ...)` to obtain the signer info.
- `CertFindCertificateInStore` to locate the signer's certificate in the message's cert store.
- `CertGetNameStringW` with `CERT_NAME_ATTR_TYPE` to extract Subject O, Subject CN, and Issuer CN.

Map to pidchain fields:
- Subject O → `TeamID`
- Subject CN → `BundleIdentifier`
- Issuer CN → `AuthorityLeaf`

On any failure (unsigned binary, API error, access denied), all three fields are empty strings. Not a fatal error.

### Other platforms (`internal/walker/walker_other.go`)

Build tag `!darwin && !windows`. The `walker` package's exported functions return `ErrPlatformUnsupported`. `Fingerprint` and `Chain` propagate this unchanged.

## README

Ship `README.md` at the repo root with these sections:

1. **What pidchain does** — one paragraph. Same-host caller authentication without stored credentials.
2. **The problem it solves** — two paragraphs. The CWE-312/313/522/256/922 class, and why "no stored credential" is different from "better-encrypted stored credential."
3. **Quickstart** — code example showing a consumer getting peer PID from a Unix domain socket, calling `pidchain.Fingerprint`, comparing against a stored value.
4. **What the fingerprint represents** — a worked example using the prototype probe's CD-spawned chain (3 ancestors), showing the chain data and the resulting fingerprint.
5. **Limitations** — same-host only; for remote auth use mTLS or OAuth. macOS and Windows in v1; Linux stub.
6. **License, contributing, versioning policy.**

Do not describe pidchain as an MCP library. MCP stdio is one use case among many.

## Success criteria

### Unit tests

- All canonical-bytes test cases listed above pass with hand-constructed expected byte slices.
- Running `Fingerprint` twice on the same live process produces identical output.
- `Fingerprint(pid)` equals `hex(sha256(canonical.Bytes(Chain(pid))))` for a live process (public-API consistency test).
- Other-platform build has a test that `Fingerprint` returns `ErrPlatformUnsupported`.

### Integration tests (Darwin; build tag `darwin`)

- `pidchain.Fingerprint(os.Getpid())` returns a 64-character lowercase hex string and a nil error.
- `pidchain.Chain(os.Getpid())` returns a non-empty `ProcessChain`. First entry has `PID == os.Getpid()` and `BinaryPath` matches `os.Executable()`.
- **Cross-check against the prototype probe.** Invoke `the prototype probe:get_caller_signature` and `pidchain.Chain(os.Getpid())` from the same test binary. The two chains must have the same number of entries, and the `(TeamID, BundleIdentifier, AuthorityLeaf)` tuple at each position must match. The fingerprints will NOT match between the prototype probe and pidchain — they use different canonical formats — so the test compares chain contents, not hashes.

### Integration tests (Windows; build tag `windows`, run manually in VMware)

- Same shape as the Darwin tests.
- Walker handles SYSTEM-owned ancestors (`ERROR_ACCESS_DENIED` on `OpenProcess`) without crashing — walk terminates cleanly, fingerprint computed over the accumulated chain.
- Authenticode collection on `C:\Windows\System32\notepad.exe` populates all three signing fields.

### Repo-level

- `go build ./...` succeeds on Darwin and Windows with CGo enabled.
- `go test ./...` passes on Darwin (Windows tested manually in VMware).
- `go vet ./...` is clean.
- External code in a sibling repo attempts to `import "pidchain/internal/canonical"` and fails to compile with the expected Go tool error (confirms `internal/` enforcement).
- README renders cleanly on the chosen hosting platform.

## Out of scope

- Linux support beyond the unsupported stub.
- Pure-Go walker paths. CGo is the chosen approach; see "Implementation approach" above.
- `codesign` CLI shell-out on macOS. `Security.framework` is used directly.
- Caching across calls.
- Any additional public API beyond the two functions and exported types listed.
- Publication of the repo (module path, hosting, first tagged release) — separate activity once the code lands.
- Migration of another consumer's existing `probe/` package onto pidchain — separate spec once pidchain is available.
- Diagnostic tooling, CLIs, or auxiliary binaries. pidchain is a library; additional tooling is a separate product decision.
