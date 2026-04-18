# pidchain — Implementation Doc 001: Core Library

## Goal

Reusable Go library that, given a PID, walks the process ancestry to the kernel terminator, collects codesign data at each position, and returns both the raw chain and a SHA256 fingerprint of canonical bytes covering the full chain.

Consumers at v1: DynaRelay (server-side attestation of connecting clients) and QuestScribe (replaces QS's existing `probe/` package). Any future tool needing caller identity can import the same library.

The library is stateless, thread-safe, and requires no special privileges. It does one thing: walk, collect, hash.

## Files

```
pidchain.go          // public API (Identify, Walk, Fingerprint, Canonical)
types.go             // ProcessInfo, Chain, Identity
canonical.go         // canonical-bytes layout + SHA256 fingerprint
errors.go            // exported error sentinels
platform.go          // internal platform interface
platform_darwin.go   // build: darwin  — walker + codesign collector
platform_windows.go  // build: windows — walker + Authenticode collector
platform_other.go    // build: !darwin && !windows — unsupported stub

canonical_test.go
pidchain_test.go
platform_darwin_test.go    // build: darwin
platform_windows_test.go   // build: windows
```

Module path, repo location, and go.mod contents are decided during repo setup, not in this doc.

## Implementation

### Constraints

- **Zero CGo.** All platform primitives via `golang.org/x/sys/unix` (Darwin) and `golang.org/x/sys/windows` (Windows). Caller-probe's `kernel_darwin.go` uses CGo (`import "C"`); pidchain must not. Translate the same libproc calls to the pure-Go sysctl path.
- **Darwin (macOS) and Windows (x86-64 and ARM64) in v1.** Linux and other platforms return `ErrPlatformUnsupported`.
- **No policy, no caching, no daemon behavior.** Each call runs fresh.
- **Canonical bytes format is stable and versioned.** Any change to the format requires bumping the version tag and is a breaking change for every consumer's paired-client store.
- **Every decision in this library is code-owned and deterministic.** Given identical inputs and identical kernel/signing state, outputs are byte-identical. There is no judgment, no policy, no configuration that changes behavior at runtime. Consumers that need policy layer it on top of the returned `Chain`.

### Types (`types.go`)

```go
type ProcessInfo struct {
    PID              int    // the PID this entry describes
    ParentPID        int    // parent of PID at walk time
    BinaryPath       string // absolute executable path, kernel-attested
    TeamID           string // platform-specific publisher identifier
    BundleIdentifier string // platform-specific app identifier
    AuthorityLeaf    string // platform-specific signing authority
}

// Chain is the ordered sequence of ancestors. Index 0 is the PID the walk
// started from; index 1 is its parent; and so on to the terminator.
type Chain []ProcessInfo

// Identity bundles a chain with the SHA256 of its canonical bytes.
type Identity struct {
    Chain       Chain
    Fingerprint string // lowercase hex-encoded SHA256 of canonical bytes
}
```

Field meaning by platform:

| Field | Darwin source | Windows source |
|---|---|---|
| TeamID | `codesign` TeamIdentifier | Authenticode Subject O |
| BundleIdentifier | `codesign` Identifier | Authenticode Subject CN |
| AuthorityLeaf | `codesign` Authority (first entry) | Authenticode Issuer CN |

The field names are neutral labels. A paired client connecting from macOS will always be identified by Apple codesign fields; a paired Windows client by Authenticode fields. Consumers do not interpret field values beyond fingerprint comparison.

### Functions (`pidchain.go`)

```go
// Identify is the primary entry point. Walks from startPID toward the
// kernel terminator, collects codesign data per ancestor, computes the
// fingerprint, and returns the complete Identity.
func Identify(startPID int) (Identity, error)

// Walk returns the chain without computing canonical bytes or fingerprint.
// For consumers that want raw ancestry data only.
func Walk(startPID int) (Chain, error)

// Canonical returns the deterministic byte sequence that Fingerprint hashes.
// Exposed for debugging and for consumers with alternate hash needs.
func Canonical(chain Chain) ([]byte, error)

// Fingerprint returns the lowercase hex-encoded SHA256 of Canonical(chain).
func Fingerprint(chain Chain) (string, error)
```

All four functions are safe for concurrent use. The library holds no package-level state.

### Canonical bytes format (`canonical.go`)

Adapted from `caller-probe/probe/canonical.go` with three changes: `start_time` is removed so fingerprints survive ancestor restarts, `caller_name` is removed because consumers maintain separate paired-client stores and don't need in-hash scoping, and the version tag is `"PC1\x00"` to scope the format to pidchain.

Layout:

```
"PC1\x00"                                  // 4-byte version tag (literal)
<len(chain) as 4-byte big-endian uint32>
for each ProcessInfo in chain (walk order):
  <TeamID bytes>           "\x00"
  <BundleIdentifier bytes> "\x00"
  <AuthorityLeaf bytes>    "\x00"
  "\x1e"                                   // record separator (ASCII 0x1E)
```

Rules:

- NUL (0x00) is the intra-field terminator. If `TeamID`, `BundleIdentifier`, or `AuthorityLeaf` contains NUL, `Canonical` returns `ErrNullByteInField`.
- Empty strings are permitted and contribute zero bytes before the terminator. An ancestor with all-empty codesign fields still occupies a position; the length prefix ensures "N empty ancestors" and "N+1 empty ancestors" produce different bytes.
- Chain entries appear in walk order: starting PID first, then its parent, up to the terminator.
- `Fingerprint` returns `hex.EncodeToString(sha256.Sum256(Canonical(chain)))` using lowercase hex.

### Errors (`errors.go`)

```go
var (
    ErrPlatformUnsupported = errors.New("pidchain: platform not supported")
    ErrProcessDead         = errors.New("pidchain: process not found")
    ErrNullByteInField     = errors.New("pidchain: null byte in canonical field")
    ErrMaxDepthExceeded    = errors.New("pidchain: walk exceeded max depth")
)
```

Handling rules:

- `Walk` and `Identify` return `ErrPlatformUnsupported` on non-Darwin non-Windows systems.
- If the **start** PID cannot be looked up, return `(nil, ErrProcessDead)` from `Walk`, or `(Identity{}, ErrProcessDead)` from `Identify`.
- If an **ancestor** PID lookup fails mid-walk, the walk stops there. The chain accumulated up to that point is returned with a `nil` error. Consumers that care about truncation can check whether the final entry's `ParentPID` is nonzero.
- If an ancestor's binary cannot be signature-inspected (codesign CLI fails, Authenticode API returns no signer, permission denied), the entry's `TeamID`, `BundleIdentifier`, and `AuthorityLeaf` are empty strings. The entry still appears in the chain. Codesign failure is **not** an error.
- Max walk depth is 32. If the walk reaches 32 entries without terminating, `Identify` returns `(Identity{Chain: <32-entry partial>, Fingerprint: <computed over partial>}, ErrMaxDepthExceeded)` and `Walk` returns `(<32-entry partial chain>, ErrMaxDepthExceeded)`. Both return values are populated so consumers can decide whether to use the partial fingerprint or treat the error as fatal. This is the only case where a non-nil error is paired with a populated return value; for every other error, the chain/Identity is zero.

### Internal platform interface (`platform.go`)

```go
type platform interface {
    lookup(pid int) (pidLookup, error)
    codesign(path string) (teamID, bundleID, authority string, err error)
}

type pidLookup struct {
    ParentPID  int
    BinaryPath string
}

// newPlatform is provided by platform_<goos>.go via build tags.
// platform.go declares only the signature.
func newPlatform() platform
```

`Walk` and `Identify` drive the walk through this interface; the rest of the library stays platform-agnostic.

### Darwin implementation (`platform_darwin.go`)

**Walker.** Use `golang.org/x/sys/unix` for kernel lookups. Per PID:

- Call sysctl with `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}` to retrieve `kinfo_proc`. Yields parent PID.
- For the binary path: sysctl with `KERN_PROCARGS2` returns argv + env; the path is obtainable from the first argv slot (kernel-attested). If `KERN_PROCARGS2` access is denied, fall back to `os.Executable()` for self or leave empty for ancestors.

**Pre-implementation verification required.** `caller-probe/probe/kernel_darwin.go` uses CGo because `libproc` (proc_pidpath, proc_pidinfo) is a native macOS API. The sysctl path above is the documented pure-Go alternative, but CC should verify during pre_implementation that `golang.org/x/sys/unix` exposes the needed primitives with usable Go signatures. If the sysctl path is impractical, the fallback is `syscall.Syscall6` with raw Darwin syscall numbers — `proc_pidinfo` is syscall 336, `proc_pidpath` is syscall 336 with flavor `PROC_PIDPATHINFO`. Either pure-Go path is acceptable; CGo is not.

Terminate when:
- PID is 1 (launchd), or
- sysctl returns ESRCH / zero-byte result (the "proc_pidinfo returns 0 for launchd to an unprivileged caller" terminator observed in caller-probe), or
- Max depth (32) reached.

**Codesign.** Shell out to the `codesign` CLI:

```
codesign --display --verbose=4 <binary_path>
```

Bound each invocation with a 10-second `context.WithTimeout` (matching caller-probe's `codesignTimeout`). TCC and sandbox restrictions can hang codesign indefinitely; the timeout is mandatory.

Parse lines of form `Key=Value`:
- `TeamIdentifier=` → TeamID
- `Identifier=` → BundleIdentifier
- `Authority=` (may repeat; take first) → AuthorityLeaf

On timeout, exec failure, or missing line, the corresponding field is an empty string. Not a fatal error.

Known limitation: the `codesign` CLI is fragile — slow, can hang under TCC, text parsing is brittle. Accepted for v1 because it's the only zero-CGo path and matches caller-probe's proven approach. Switching to the native `Security.framework` would require CGo; future work, not blocking.

### Windows implementation (`platform_windows.go`)

**Walker.** Use `golang.org/x/sys/windows` for all kernel lookups. Per PID:

- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` then iterate with `Process32FirstW` / `Process32NextW` to find the entry where `th32ProcessID == pid`. Yields `th32ParentProcessID` (parent PID) and `szExeFile` (binary basename only).
- For the full path: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)` followed by `QueryFullProcessImageNameW`. `PROCESS_QUERY_LIMITED_INFORMATION` is the minimum privilege and works on most ancestors without admin.

Terminate when:
- Parent PID is 0 (kernel reports "no parent" for top-level processes), or
- `OpenProcess` returns `ERROR_ACCESS_DENIED` or `ERROR_INVALID_PARAMETER` (SYSTEM-owned or gone), or
- Max depth (32) reached.

**Authenticode.** Use `golang.org/x/sys/windows` to call the Crypt API:

- `CryptQueryObject` with `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED` on the binary path.
- From the resulting crypto message, extract the signer's certificate.
- `CertGetNameStringW` to extract Subject O, Subject CN, and Issuer CN from the signer certificate.

**Pre-implementation verification required.** The specific `x/sys/windows` call shapes for `CryptQueryObject` and `CertGetNameStringW` have not been verified against the current package surface. CC should confirm available bindings during pre_implementation. If the Crypt API path is impractical via `x/sys/windows` alone, CC should raise this to CD for redesign rather than silently falling back to a PowerShell shell-out; per-ancestor PowerShell invocation is unacceptably slow for a chain walk.

Map to pidchain fields:
- Subject O → TeamID
- Subject CN → BundleIdentifier
- Issuer CN → AuthorityLeaf

On any failure (unsigned binary, API error, access denied), all three fields are empty strings. Not a fatal error.

### Other platforms (`platform_other.go`)

Build tag `!darwin && !windows`:

```go
func newPlatform() platform { return unsupportedPlatform{} }

type unsupportedPlatform struct{}

func (unsupportedPlatform) lookup(int) (pidLookup, error) {
    return pidLookup{}, ErrPlatformUnsupported
}
func (unsupportedPlatform) codesign(string) (string, string, string, error) {
    return "", "", "", ErrPlatformUnsupported
}
```

All public functions propagate `ErrPlatformUnsupported` from the first platform call.

## Success Criteria

### Unit tests (all platforms)

- `Canonical(nil)` returns exactly `"PC1\x00" + "\x00\x00\x00\x00"` (version tag, zero ancestor count).
- `Canonical([]ProcessInfo{{TeamID: "y\x00"}})` returns `ErrNullByteInField`.
- `Canonical([]ProcessInfo{{BundleIdentifier: "y\x00"}})` returns `ErrNullByteInField`.
- `Canonical([]ProcessInfo{{AuthorityLeaf: "y\x00"}})` returns `ErrNullByteInField`.
- Table-driven test with a known `Chain` → known canonical bytes → known SHA256. Lock the expected bytes into the test so any accidental format change fails immediately.
- Running `Fingerprint(chain)` twice with identical input produces identical output.
- Running with different chains produces different fingerprints — including chains that differ only in an ancestor position having empty fields (verifies the length prefix + record separator distinguish "N empty ancestors" from "N+1 empty ancestors").

### Integration tests (Darwin; build tag `darwin`)

- `Identify(os.Getpid())` returns an `Identity` with non-empty `Chain`. First entry has `PID == os.Getpid()` and `BinaryPath` matches `os.Executable()`.
- Chain terminates at PID 1 or at a documented truncation reason; no infinite loops.
- Running `Identify(os.Getpid())` twice from the same test binary produces matching fingerprints (proves determinism under real kernel conditions).
- `Identify` on a chain verified against a live `caller-probe:get_caller_signature` report produces a chain with the same number of entries and the same codesign identities at each position.

### Integration tests (Windows; build tag `windows`, run manually in VMware)

- Equivalent of the Darwin tests on Windows.
- Walker handles SYSTEM-owned ancestors (ACCESS_DENIED on OpenProcess) without crashing — the walk terminates cleanly at that point with the accumulated chain.
- Authenticode collection on a known-signed binary (the test binary itself, if `go test` produces a signed exe, or `C:\Windows\System32\notepad.exe` as a known-signed target) populates all three signing fields.

## Out of Scope

- Linux implementation beyond the unsupported stub.
- Native `Security.framework` codesign collection on Darwin (requires CGo).
- Caching of codesign results across `Identify` calls.
- Chain-level policy evaluation (e.g., "is there an unbroken Anthropic-signed span?" — that is the consumer's job, operating on the `Chain` returned by `Walk`).
- PID-reuse defense via `start_time` tuples. pidchain does not record or verify start_time in v1; per the DR pairing model, fingerprints must survive ancestor restarts. Consumers that want liveness checks add their own layer.
- DynaRelay's pairing flow, pairing-code exchange, paired-client store — DR features, not library features.
- Removal of QS's existing `probe/` package — separate implementation doc once pidchain ships and QS migrates.

## Consumers (informational)

### DynaRelay

On every inbound connection, DR obtains the peer PID from the kernel via the bus transport (`SO_PEERCRED`, `LOCAL_PEERPID`, or `GetNamedPipeClientProcessId`) and calls `pidchain.Identify(peerPID)`. DR compares `.Fingerprint` against its paired-clients store. No fingerprint header is sent by the caller; identity is entirely DR-derived from kernel state. This is an improvement over the header-based model in DR's 005e design doc.

### QuestScribe

QS replaces its `probe/` package with a thin wrapper that calls `pidchain.Identify(os.Getpid())` at MCP server startup and caches the result for the process lifetime. The MCP tool previously served by `probe/` returns fields derived from the cached `Identity`. QS's `probe/probe.go`, `probe/canonical.go`, `probe/kernel_darwin.go`, and associated code are deleted in a follow-up doc once pidchain is available.
